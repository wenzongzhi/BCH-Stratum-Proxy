#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bch_stratum_proxy_v5.py

功能概览:
    - 作为一个极简的 BCH 专用 Stratum 代理 (局域网/单机)
    - 拉取 getblocktemplate (GBT)
    - 将 GBT 转换为 Stratum mining.notify 下发矿机
    - 接收矿机 mining.submit, 在代理端重建区块并在满足网络目标时 submitblock
    - 线程安全、带重试以及常见字段兼容处理

使用:
    1) 编辑下方 RPC_USER / RPC_PASS 等配置
    2) 启动: python bch_stratum_proxy_v5.py
    3) 矿机连接: stratum+tcp://<你的机器局域网IP>:3333

依赖:
    pip install requests
"""

import socket
import threading
import time
import json
import os
import struct
import binascii
from hashlib import sha256
import requests
from typing import List, Dict, Any, Optional, Tuple

# ===========================
# === 用户配置区（必须修改）===
# ===========================
RPC_USER = "your_rpc_user"       # bitcoin.conf 中的 rpcuser
RPC_PASS = "your_rpc_password"   # bitcoin.conf 中的 rpcpassword
RPC_HOST = "127.0.0.1"
RPC_PORT = 8332

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3333

# 轮询间隔（秒），建议 10-30；越短越耗 RPC
GBT_POLL_INTERVAL = 20

# extranonce: 代理分配给每个矿工的 extranonce1 字节数 (通常 4)
EXTRANONCE1_BYTES = 4
# 矿机会提供的 extranonce2 大小（默认使用 4）
EXTRANONCE2_BYTES = 4

# 如果 coinbasetxn 中没有明确的占位符，我们会在 coinbase 末尾追加 extranonces
# （多数 BCH GBT 会包含 coinbasetxn.data，并且会包含占位符）
EXTRANONCE_PLACEHOLDER = "00" * (EXTRANONCE1_BYTES + EXTRANONCE2_BYTES)

# RPC 调用超时和重试
RPC_TIMEOUT = 10
RPC_MAX_RETRIES = 3
RPC_RETRY_BACKOFF = 2  # 指数退避基数

# 日志输出开关
DEBUG = True

# ===========================
# === 全局状态（内部使用）===
# ===========================
_current_gbt: Optional[Dict[str, Any]] = None
_current_job: Optional[Dict[str, Any]] = None
_current_height: int = -1

# 管理所有连接的矿机 handler 列表
_miners_lock = threading.Lock()
_miners: List["StratumMinerHandler"] = []

# 保护 GBT 与 job 的锁
_gbt_lock = threading.Lock()

# ===========================
# === 辅助函数（序列化/哈希/编码）===
# ===========================
def log(*args):
    if DEBUG:
        print("[PROXY]", *args)

def dsha256(data: bytes) -> bytes:
    """双重 SHA256"""
    return sha256(sha256(data).digest()).digest()

def hex_to_bytes(h: str) -> bytes:
    return binascii.unhexlify(h.encode() if isinstance(h, str) else h)

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

def reverse_hex(h: str) -> str:
    """字节序反转 (hex 字符串)"""
    return bytes_to_hex(hex_to_bytes(h)[::-1])

def int_to_le_hex(n: int, length: int) -> str:
    return n.to_bytes(length, 'little').hex()

def varint_encode(n: int) -> str:
    if n < 0xfd:
        return int_to_le_hex(n, 1)
    elif n <= 0xffff:
        return "fd" + int_to_le_hex(n, 2)
    elif n <= 0xffffffff:
        return "fe" + int_to_le_hex(n, 4)
    else:
        return "ff" + int_to_le_hex(n, 8)

def compact_to_target(compact_int: int) -> int:
    """
    将 compact (bits) 转换为目标 target 值
    compact_int: 4 字节整数 (big-endian interpreted)
    """
    # compact: 1 byte exponent, 3 byte mantissa
    exponent = compact_int >> 24
    mantissa = compact_int & 0x007fffff
    if compact_int & 0x00800000:
        # sign bit set -> negative (should not occur)
        mantissa = -mantissa
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    return target

def bits_hex_to_int(bits_hex: str) -> int:
    """
    bits_hex 可能是 "1a2b3c4d" 格式 (32-bit hex)
    将其解析为 int（按 big-endian）
    """
    return int(bits_hex, 16)

# ===========================
# === RPC 封装（带重试）===
# ===========================
def rpc_call(method: str, params: Optional[List[Any]] = None) -> Optional[Any]:
    url = f"http://{RPC_HOST}:{RPC_PORT}"
    headers = {"content-type": "application/json"}
    payload = {"jsonrpc": "2.0", "id": "proxy", "method": method, "params": params or []}
    attempt = 0
    while attempt < RPC_MAX_RETRIES:
        try:
            resp = requests.post(url, json=payload, headers=headers, auth=(RPC_USER, RPC_PASS), timeout=RPC_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            if data.get("error"):
                log(f"RPC error for {method}: {data['error']}")
                return None
            return data.get("result")
        except Exception as e:
            attempt += 1
            log(f"RPC call {method} attempt {attempt} failed: {e}")
            time.sleep(RPC_RETRY_BACKOFF ** (attempt - 1))
    log(f"RPC call {method} failed after {RPC_MAX_RETRIES} attempts.")
    return None

# ===========================
# === GBT -> Job 转换与广播 ===
# ===========================
def build_job_from_gbt(gbt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    将 GBT 转换为内部 job 结构，便于下发给矿机与用于 submit。
    返回 job dict:
        {
            'job_id': str,
            'gbt': gbt,
            'prevhash_be': ...,
            'version_be': ...,
            'nbits_be': ...,
            'ntime_be': ...,
            'coinb1': ...,
            'coinb2': ...,
            'merkle_branch': [...],   # txids as BE hex strings
            'extranonce1': ... (代理分配长度 bytes*2 hex),
            'extranonce2_size': int
        }
    """
    try:
        # 1) header components
        version = gbt.get('version', 0)
        # Stratum 通常期望大端(hex)用于显示，但 core RPC 的整数是主机整数，转换如下:
        version_be = version.to_bytes(4, 'big').hex()

        # previousblockhash 从 RPC 返回是常规的 hex (big-endian), Stratum mining.notify 的 prevhash 字段通常传 BE
        prevhash_rpc = gbt.get('previousblockhash', '')
        prevhash_be = prevhash_rpc  # 保持 RPC 返回的表示（BE）

        # bits: 有时是 "1a2b3c4d" 字符串，也可能是十进制，请尝试处理
        bits = gbt.get('bits')
        if isinstance(bits, int):
            nbits_be = bits.to_bytes(4, 'big').hex()
        else:
            # 假设 bits 是 hex string
            nbits_be = bits

        # curtime -> ntime (int -> 4 byte BE hex)
        curtime = gbt.get('curtime', int(time.time()))
        ntime_be = curtime.to_bytes(4, 'big').hex()

        # 2) coinbase 处理: 优先使用 coinbasetxn.data (BCH 节点常见)
        coinbasetxn = gbt.get('coinbasetxn')
        coinbase_hex = None
        coinb1 = ""
        coinb2 = ""
        if coinbasetxn and isinstance(coinbasetxn, dict) and 'data' in coinbasetxn:
            coinbase_hex = coinbasetxn['data']  # 这是 raw tx hex 模板，通常包含 extranonce 占位
            # 尝试在 coinbase_hex 中定位占位符（连续全零）
            placeholder = EXTRANONCE_PLACEHOLDER
            if placeholder and placeholder in coinbase_hex:
                # 在第一次出现占位符处拆分 coinb1/coinb2
                parts = coinbase_hex.split(placeholder, 1)
                coinb1 = parts[0]
                coinb2 = parts[1]
            else:
                # 占位符未找到：我们采取简易方式 —— 将 coinbase_template 放在 coinb1，coinb2 为空
                # 然后在真实提交时将 extranonce1+extranonce2 追加到 coinb1 的末尾
                coinb1 = coinbase_hex
                coinb2 = ""
        else:
            # 如果 coinbasetxn 不存在，则从 gbt['coinbaseaux'/'coinbasevalue'] 等手动构造coinbase
            # 这里做一个简单构造：将 coinbase 空壳作为 coinb1, coinb2 为空
            coinb1 = ""  # 表示我们没有模板
            coinb2 = ""

        # 3) merkle branch: 用 GBT 的 transactions 列表中的 txid 字段 (RPC 返回通常是 BE hex)
        transactions = gbt.get('transactions', [])
        merkle_branch = [tx.get('txid') for tx in transactions if 'txid' in tx]

        # 4) extranonce1 由代理生成并写入job（每个矿机仍会覆盖自己的extranonce1）
        # 这里生成一个 job-level extranonce1，以确保coinbase模板能包含至少一个代理extranonce1占位
        extranonce1 = os.urandom(EXTRANONCE1_BYTES).hex()
        extranonce2_size = EXTRANONCE2_BYTES

        job_id = f"{int(time.time())}_{prevhash_be[-8:]}"

        job = {
            "job_id": job_id,
            "gbt": gbt,
            "prevhash_be": prevhash_be,
            "version_be": version_be,
            "nbits_be": nbits_be,
            "ntime_be": ntime_be,
            "coinb1": coinb1,
            "coinb2": coinb2,
            "merkle_branch": merkle_branch,
            "extranonce1": extranonce1,
            "extranonce2_size": extranonce2_size,
        }
        return job
    except Exception as e:
        log("构建 job 失败:", e)
        return None

def broadcast_job_to_miners(job: Dict[str, Any]):
    """将 job 广播给所有已订阅并已授权的矿机（线程安全）"""
    with _miners_lock:
        miners_copy = list(_miners)
    for m in miners_copy:
        try:
            m.send_job(job)
        except Exception as e:
            log("向矿机广播 job 失败，移除矿机:", e)
            try:
                m.close()
            except:
                pass

# ===========================
# === GBT 轮询线程 (后台) ===
# ===========================
def gbt_poller():
    global _current_gbt, _current_job, _current_height
    log("GBT 轮询器启动, 间隔:", GBT_POLL_INTERVAL, "秒")
    last_txids = None
    while True:
        try:
            # 请求 getblocktemplate，要求 coinbasetxn 支持
            # params 可根据节点支持调整
            gbt = rpc_call("getblocktemplate", [{"capabilities": ["coinbasetxn", "workid"]}])
            if not gbt:
                time.sleep(GBT_POLL_INTERVAL)
                continue

            height = gbt.get('height', -1)
            # 获取 txid 列表（以便检测 mempool 更新）
            txids = tuple(tx.get('txid') for tx in gbt.get('transactions', []))

            need_broadcast = False
            reason = ""
            with _gbt_lock:
                if _current_gbt is None:
                    need_broadcast = True
                    reason = "初始化 GBT"
                elif gbt.get('previousblockhash') != _current_gbt.get('previousblockhash'):
                    need_broadcast = True
                    reason = f"检测到新区块，高度 {height}"
                elif txids != last_txids:
                    need_broadcast = True
                    reason = f"检测到 Mempool 变化，tx_count={len(txids)}"
                elif gbt.get('coinbasevalue') != _current_gbt.get('coinbasevalue'):
                    need_broadcast = True
                    reason = "检测到 coinbasevalue 变化"

                # 更新缓存
                if need_broadcast:
                    _current_gbt = gbt
                    _current_job = build_job_from_gbt(gbt)
                    _current_height = height
                    last_txids = txids

            if need_broadcast and _current_job:
                log("广播新工作:", reason, "height=", height, "txs=", len(txids))
                broadcast_job_to_miners(_current_job)
            time.sleep(GBT_POLL_INTERVAL)
        except Exception as e:
            log("GBT 轮询异常:", e)
            time.sleep(GBT_POLL_INTERVAL)

# ===========================
# === Stratum 矿工 Handler ===
# ===========================
class StratumMinerHandler(threading.Thread):
    """
    每个矿机连接一个 Handler 线程（简易 Stratum 协议）
    支持:
      - mining.subscribe / mining.extranonce.subscribe
      - mining.authorize
      - mining.submit
      - 下发 mining.notify (基于当前 _current_job)
    """
    def __init__(self, conn: socket.socket, addr: Tuple[str, int]):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.running = True

        # 矿工状态
        self.subscribed = False
        self.authorized = False
        self.worker_name = "unknown"

        # 为每个连接分配一个 extranonce1（代理唯一标识）
        self.extranonce1 = os.urandom(EXTRANONCE1_BYTES).hex()
        self.extranonce2_size = EXTRANONCE2_BYTES

        # 当前分配的 job id (string)
        self.current_job_id: Optional[str] = None

        # socket读buffer
        self._buffer = ""

        # 注册自己到全局矿工列表
        with _miners_lock:
            _miners.append(self)

    def run(self):
        log("矿机连接来自", self.addr)
        try:
            self.conn.settimeout(30)
            while self.running:
                try:
                    data = self.conn.recv(4096)
                except socket.timeout:
                    continue
                except Exception:
                    break
                if not data:
                    break
                try:
                    text = data.decode(errors='ignore')
                except:
                    text = ''
                self._buffer += text
                while '\n' in self._buffer:
                    line, self._buffer = self._buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except Exception as e:
                        log("无效 JSON 来自矿机:", e)
                        continue
                    try:
                        self.handle_message(msg)
                    except Exception as e:
                        log("处理矿机消息异常:", e)
        finally:
            self.close()
            log("矿机断开:", self.addr)

    def close(self):
        self.running = False
        try:
            with _miners_lock:
                if self in _miners:
                    _miners.remove(self)
        except:
            pass
        try:
            self.conn.close()
        except:
            pass

    # -----------------------
    # --- 发送/响应方法 ---
    # -----------------------
    def send_json(self, obj: Dict[str, Any]):
        try:
            data = (json.dumps(obj) + '\n').encode()
            self.conn.sendall(data)
        except Exception as e:
            log("发送给矿机失败:", e)
            self.close()

    def send_subscription_response(self, req_id):
        # Stratum 标准: 返回 extranonce1 和 extranonce2_size
        resp = {
            "id": req_id,
            "result": [
                [["mining.notify", "session"]],
                self.extranonce1,
                self.extranonce2_size
            ],
            "error": None
        }
        self.subscribed = True
        self.send_json(resp)

    def send_authorize_response(self, req_id, ok=True):
        resp = {"id": req_id, "result": ok, "error": None}
        if ok:
            self.authorized = True
        self.send_json(resp)

    def send_job(self, job: Dict[str, Any]):
        """
        将 job 发送给矿机 (mining.notify)
        Stratum mining.notify 参数 (简化)：
        [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
        注意：不同矿机固件对 coinb1/coinb2 解析敏感，下面采取较保守的处理：
          - 若 job 中 coinb1/coinb2 是模板（包含占位符），将把代理的 extranonce1 插入 coinb1
          - 若 coinb1 是完整 coinbase（无占位符），则 coinb1 保持原样，coinb2 为空
        """
        if not job:
            return
        # 生成每个矿机专属 coinb1（包含矿机的 extranonce1）
        coinb1 = job.get('coinb1', '')
        coinb2 = job.get('coinb2', '')

        # 如果 coinb1 中包含占位符 (EXTRANONCE_PLACEHOLDER)，则替换为代理extranonce1（job-level或conn-level）
        placeholder = EXTRANONCE_PLACEHOLDER
        if placeholder and placeholder in coinb1:
            coinb1_filled = coinb1.replace(placeholder, self.extranonce1, 1)
        else:
            # 否则，把代理的extranonce1附加到coinb1（大多数简单节点兼容）
            coinb1_filled = coinb1 + self.extranonce1

        # job id
        jid = job.get('job_id')
        self.current_job_id = jid

        params = [
            jid,
            job.get('prevhash_be'),
            coinb1_filled,
            coinb2 or "",
            job.get('merkle_branch', []),
            job.get('version_be'),
            job.get('nbits_be'),
            job.get('ntime_be'),
            True
        ]
        notify = {"id": None, "method": "mining.notify", "params": params}
        self.send_json(notify)
        log(f"下发 job -> miner {self.addr}, job_id={jid}")

    # -----------------------
    # --- 消息处理入口 ---
    # -----------------------
    def handle_message(self, msg: Dict[str, Any]):
        method = msg.get('method')
        req_id = msg.get('id')
        params = msg.get('params', [])
        if method == "mining.subscribe":
            self.send_subscription_response(req_id)
            # 订阅完成后若已有当前 job 则立即下发
            with _gbt_lock:
                if _current_job:
                    self.send_job(_current_job)
        elif method == "mining.extranonce.subscribe":
            # 简易实现，直接返回 true
            self.send_json({"id": req_id, "result": True, "error": None})
        elif method == "mining.authorize":
            worker = params[0] if params else "unknown"
            self.worker_name = worker
            self.send_authorize_response(req_id, ok=True)
            # 授权后下发 job
            with _gbt_lock:
                if _current_job:
                    self.send_job(_current_job)
        elif method == "mining.submit":
            # params: [workername, job_id, extranonce2, ntime, nonce]
            # 也可能包含额外字段（取前5个）
            try:
                worker, job_id, extranonce2, ntime_hex, nonce_hex = (params + [None]*5)[:5]
            except Exception:
                worker, job_id, extranonce2, ntime_hex, nonce_hex = (None, None, None, None, None)
            threading.Thread(target=self.handle_submit, args=(req_id, worker, job_id, extranonce2, ntime_hex, nonce_hex), daemon=True).start()
        else:
            # 未知方法，返回默认 ok
            self.send_json({"id": req_id, "result": None, "error": None})

    # -----------------------
    # --- 提交处理 (可能较慢) ---
    # -----------------------
    def handle_submit(self, req_id, worker, job_id, extranonce2, ntime_hex, nonce_hex):
        """
        1) 验证 job_id 匹配
        2) 使用 conn.extranonce1 + extranonce2 构造完整 coinbase
        3) 构建 merkle root, 构造区块头, 检查 share 是否满足 target
        4) 如果满足网络目标, 构建完整区块并提交 submitblock
        5) 向矿机返回 submit 结果
        """
        try:
            with _gbt_lock:
                job = _current_job
                gbt = _current_gbt

            if not job or job_id != job.get('job_id'):
                log("提交被拒绝: 无效的 job_id", job_id, "来自", self.addr)
                self.send_json({"id": req_id, "result": False, "error": [21, "Job not found", None]})
                return

            # 2) 构造 coinbase hex
            coinb1 = job.get('coinb1', '')
            coinb2 = job.get('coinb2', '')

            # 使用连接级别的 extranonce1（独一无二）和矿工提供的 extranonce2
            extranonce1 = self.extranonce1
            extranonce2 = extranonce2 or ""
            # 将 EXTRANONCE_PLACEHOLDER 替换（若存在）
            if EXTRANONCE_PLACEHOLDER and EXTRANONCE_PLACEHOLDER in coinb1:
                coinbase_hex = coinb1.replace(EXTRANONCE_PLACEHOLDER, extranonce1 + extranonce2, 1) + coinb2
            else:
                # fallback：将 extranonce1/extranonce2 附加到 coinb1
                coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2

            # 3) 计算 coinbase tx hash (双sha256), 注意: 传入 dsha256 的应为原始 bytes (tx raw hex)
            coinbase_hash = dsha256(binascii.unhexlify(coinbase_hex))

            # 4) 将 GBT transactions 列表的 txid 转换为 LE bytes，并构建 merkle 根（使用小端格式进行内部哈希）
            tx_hashes_le = [coinbase_hash]  # coinbase hash already raw bytes (big-endian? dsha256 结果是 bytes in network-order)
            for tx in job.get('merkle_branch', []):
                # RPC 中 txid 通常以 big-endian hex 表示，我们需要转换为 little-endian bytes
                try:
                    txid_be = tx
                    txid_le = binascii.unhexlify(txid_be)[::-1]
                    tx_hashes_le.append(txid_le)
                except Exception:
                    # 忽略无法解析的 txid
                    pass

            merkle_root_le = build_merkle_root_from_leaves(tx_hashes_le)
            merkle_root_le_hex = bytes_to_hex(merkle_root_le)

            # 5) 构建区块头 (小端序列化)
            # version (LE)
            version_le = int(job['gbt'].get('version', 0)).to_bytes(4, 'little').hex()
            # prevhash: gbt['previousblockhash'] 通常是 BE hex, 转为 LE hex
            prevhash_rpc = job['gbt'].get('previousblockhash', '')
            prevhash_le_hex = reverse_hex(prevhash_rpc)
            # merkle root is already LE hex
            merkle_le_hex = merkle_root_le_hex
            # ntime: miner 提供的 ntime_hex 通常是 BE hex string of 4 bytes; 若矿机传入为 decimal string 则尝试解析
            try:
                if ntime_hex is None:
                    ntime_int = job['gbt'].get('curtime', int(time.time()))
                    ntime_le_hex = int_to_le_hex(ntime_int, 4)
                else:
                    # 如果是 hex string like "5f5e100" or decimal string; 尝试解析十六进制，否则十进制
                    if all(c in "0123456789abcdefABCDEF" for c in ntime_hex) and len(ntime_hex) <= 8:
                        ntime_bytes = binascii.unhexlify(ntime_hex)
                        # BE -> LE
                        ntime_le_hex = bytes_to_hex(ntime_bytes[::-1])
                    else:
                        ntime_le_hex = int_to_le_hex(int(ntime_hex), 4)
            except Exception:
                ntime_le_hex = int_to_le_hex(job['gbt'].get('curtime', int(time.time())), 4)

            # nonce: 矿机发来的 nonce_hex 通常是 BE hex (4 bytes)
            try:
                nonce_le_hex = bytes_to_hex(binascii.unhexlify(nonce_hex))[::-1] if nonce_hex else "00000000"
            except Exception:
                try:
                    nonce_le_hex = int_to_le_hex(int(nonce_hex or 0), 4)
                except:
                    nonce_le_hex = "00000000"

            # bits: GBT 提供的 bits 为 BE hex; 转为 LE hex 用于 header
            bits_field = job['gbt'].get('bits')
            if isinstance(bits_field, int):
                bits_be_hex = bits_field.to_bytes(4, 'big').hex()
            else:
                bits_be_hex = bits_field
            bits_le_hex = reverse_hex(bits_be_hex)

            header_hex = (
                version_le +
                prevhash_le_hex +
                merkle_le_hex +
                ntime_le_hex +
                bits_le_hex +
                nonce_le_hex
            )
            header_bytes = binascii.unhexlify(header_hex)

            # 6) 计算 block header hash (double sha256)
            block_hash = dsha256(header_bytes)  # bytes
            # block_hash 的常见展示是 LE hex of the dsha256 result
            block_hash_le_hex = bytes_to_hex(block_hash)

            # 7) 计算目标 target 并验证 share
            # bits_be_hex -> compact int (big-endian)
            compact_int = bits_hex_to_int(bits_be_hex)
            target_int = compact_to_target(compact_int)
            # header hash interpreted as big integer (dsha256 returns bytes; we interpret as little-endian)
            # 注意：在比对时，比较的是 header hash interpreted as little-endian integer vs target
            header_hash_int = int.from_bytes(block_hash, byteorder='little')
            is_valid_share = header_hash_int <= target_int

            log(f"提交 from {self.addr} job={job_id} worker={worker} hash_le={block_hash_le_hex} valid={is_valid_share}")

            if not is_valid_share:
                # 这是一个普通的 share，不满足网络难度 — 返回 accepted False (或 accepted True 取决于策略)
                # 这里我们返回 accepted True（矿机看到 accepted）但不提交到网络，除非你想对所有 share 都做记录
                # 为演示，我们仍然向矿机返回 True 表示 share accepted（矿池会根据 solo/pool 策略决定）
                self.send_json({"id": req_id, "result": True, "error": None})
                return

            # 8) 如果满足网络目标，构建完整区块并 submitblock
            # tx count = 1 + len(gbt.transactions)
            txs = []
            # coinbase tx raw hex: coinbase_hex (上面构造)
            txs.append(coinbase_hex)
            # gbt.transactions 中通常包含 'data' 字段（原始 tx hex）
            for tx in job['gbt'].get('transactions', []):
                txdata = tx.get('data')
                if txdata:
                    txs.append(txdata)
                else:
                    # 如果没有原始 tx data，我们不能构建完整区块；中断并记录
                    log("GBT 中 transaction 缺少 data 字段，无法构建完整区块 -> 提交中断")
                    self.send_json({"id": req_id, "result": False, "error": [22, "Missing tx data in GBT", None]})
                    return

            tx_count_hex = varint_encode(len(txs))
            block_hex = header_hex + tx_count_hex + "".join(txs)

            # 9) submitblock RPC
            submit_result = rpc_call("submitblock", [block_hex])
            # Bitcoin Core 返回 None 表示接受 (RPC成功), 返回 error string 表示失败
            if submit_result is None:
                log("!!! 区块被节点接受！Block hash (LE):", block_hash_le_hex)
                self.send_json({"id": req_id, "result": True, "error": None})
            else:
                log("submitblock 返回:", submit_result)
                self.send_json({"id": req_id, "result": False, "error": [22, str(submit_result), None]})
        except Exception as e:
            log("处理 submit 异常:", e)
            self.send_json({"id": req_id, "result": False, "error": [23, "Internal proxy error", None]})

# ===========================
# === 辅助：Merkle 树构造（小端哈希）===
# ===========================
def build_merkle_root_from_leaves(leaves: List[bytes]) -> bytes:
    """
    leaves: list of leaf hashes as bytes (little-endian byte order expected)
    返回 merkle root as little-endian bytes
    """
    if not leaves:
        return b'\x00' * 32
    nodes = list(leaves)
    while len(nodes) > 1:
        if len(nodes) % 2 != 0:
            nodes.append(nodes[-1])
        next_level = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i+1]
            next_level.append(dsha256(combined))
        nodes = next_level
    return nodes[0]

# ===========================
# === Stratum 主服务循环 ===
# ===========================
def start_stratum_server(listen_host: str, listen_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((listen_host, listen_port))
    sock.listen(100)
    log(f"Stratum 代理监听 {listen_host}:{listen_port}")
    try:
        while True:
            conn, addr = sock.accept()
            handler = StratumMinerHandler(conn, addr)
            handler.start()
    except KeyboardInterrupt:
        log("收到退出信号，关闭服务器")
    finally:
        try:
            sock.close()
        except:
            pass

# ===========================
# === 主程序入口 ===
# ===========================
if __name__ == "__main__":
    # 最基本的配置检查
    if RPC_USER == "your_rpc_user" or RPC_PASS == "your_rpc_password":
        print("请先在脚本顶部配置 RPC_USER 和 RPC_PASS（bitcoin.conf 中的 rpc 用户/密码）")
        exit(1)

    # 启动 GBT 轮询线程
    poller_thread = threading.Thread(target=gbt_poller, daemon=True)
    poller_thread.start()

    # 启动 Stratum TCP 服务（阻塞）
    start_stratum_server(LISTEN_HOST, LISTEN_PORT)
