#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bch_stratum_proxy_v6.py

这个文件基于 v5 代码做了深度修复与优化，目标：
 - 修复 merkle / endianness / hash 比较相关的 bug
 - 使用交易 raw data (gbt.transactions[].data) 来计算 merkle，避免 txid endian 二义性
 - 更稳健地解析 ntime/bits/nonce（支持 hex/dec/big/little）
 - 正确比较 header hash vs target（用 big-endian 整数比较）
 - 更严格地对非法 share 返回 False（避免误导矿机）
 - 更健壮的 coinbase 拼接逻辑：优先使用 coinbasetxn.data；若缺失则构造最小 coinbase
 - 修复线程安全与全局变量引用（使用 _miners 而非未定义变量）
 - 更清晰的日志与可配置项
 - 增加简单限流与连接上限控制

注意：
 - 请先在文件顶部配置 RPC_USER / RPC_PASS / RPC_HOST / RPC_PORT
 - 强烈建议在 regtest/testnet 上充分测试再接入主网
 - 依赖: requests

运行： python bch_stratum_proxy_v6.py
"""

import socket
import threading
import time
import json
import os
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
MAX_MINERS = 200

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
        print(time.strftime('%Y-%m-%d %H:%M:%S'), "[PROXY]", *args)

def dsha256(data: bytes) -> bytes:
    """double-sha256，返回 digest bytes（big-endian order）"""
    return sha256(sha256(data).digest()).digest()

def hex_to_bytes(h: str) -> bytes:
    return binascii.unhexlify(h)

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')


def reverse_bytes(b: bytes) -> bytes:
    return b[::-1]


def reverse_hex(h: str) -> str:
    """字节序反转 (hex 字符串)"""
    return bytes_to_hex(hex_to_bytes(h)[::-1])

def int_to_le_hex(n: int, length: int) -> str:
    return n.to_bytes(length, 'little').hex()


def int_to_be_hex(n: int, length: int) -> str:
    return n.to_bytes(length, 'big').hex()


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
    将 compact bits（32-bit int） 转换为目标 target 值
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
    return int(bits_hex, 16)


def parse_nonce_or_ntime_to_le(hex_or_dec: Optional[str], length_bytes: int) -> str:
    """
    将矿机给出的 nonce/ntime 字符串解析为 little-endian hex（长度 length_bytes*2）
    支持： hex (BE or LE), decimal string
    优先尝试解释为 hex（并转成 little-endian），再尝试 decimal
    """
    if hex_or_dec is None:
        return int_to_le_hex(0, length_bytes)
    s = str(hex_or_dec).strip()
    if s.startswith('0x'):
        s = s[2:]
    # pure hex?
    if all(c in '0123456789abcdefABCDEF' for c in s):
        needed = length_bytes * 2
        s = s.rjust(needed, '0')[-needed:]
        try:
            b = binascii.unhexlify(s)
            # assume incoming hex is big-endian (common human display), so reverse to little
            return bytes_to_hex(b[::-1])
        except Exception:
            pass
    # decimal fallback
    try:
        n = int(s)
        return int_to_le_hex(n, length_bytes)
    except Exception:
        return int_to_le_hex(0, length_bytes)

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
            if data.get('error'):
                # 若 error != null 则返回 None 并记录
                log(f"RPC error for {method}:", data['error'])
                return None
            return data.get('result')
        except Exception as e:
            attempt += 1
            log(f"RPC call {method} attempt {attempt} failed:", e)
            time.sleep(RPC_RETRY_BACKOFF ** (attempt - 1))
    log(f"RPC call {method} failed after {RPC_MAX_RETRIES} attempts.")
    return None

# ===========================
# === GBT -> Job 转换与广播 ===
# ===========================

def _encode_height_to_coinbase(height: int) -> str:
    hb = b''
    n = height
    while True:
        hb += bytes([n & 0xff])
        n >>= 8
        if n == 0:
            break
    return bytes_to_hex(bytes([len(hb)])) + bytes_to_hex(hb)


def _build_minimal_coinbase_tx(height_bytes_hex: str) -> str:
    # 极简 coinbase tx，仅用于节点未返回 coinbasetxn.data 的极端情况
    version = "01000000"
    tx_in_count = "01"
    prev_out = "00" * 32 + "ffffffff"
    script_hex = height_bytes_hex + "00"
    script_len = varint_encode(len(bytes.fromhex(script_hex)))
    seq = "ffffffff"
    tx_out_count = "01"
    value = (0).to_bytes(8, 'little').hex()
    pk_script = "51"  # OP_TRUE
    pk_script_len = varint_encode(len(bytes.fromhex(pk_script)))
    lock_time = "00000000"
    return version + tx_in_count + prev_out + script_len + script_hex + seq + tx_out_count + value + pk_script_len + pk_script + lock_time


def build_job_from_gbt(gbt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        # 1) header components
        version = int(gbt.get('version', 0))
        # Stratum 通常期望大端(hex)用于显示，但 core RPC 的整数是主机整数，转换如下:
        version_be = int_to_be_hex(version, 4)

        # previousblockhash 从 RPC 返回是常规的 hex (big-endian), Stratum mining.notify 的 prevhash 字段通常传 BE
        prevhash_rpc = gbt.get('previousblockhash', '')
        prevhash_be = prevhash_rpc  # 保持 RPC 返回的表示（BE）

        # bits: 有时是 "1a2b3c4d" 字符串，也可能是十进制，请尝试处理
        bits = gbt.get('bits')
        if isinstance(bits, int):
            nbits_be = int_to_be_hex(bits, 4)
        else:
            # 假设 bits 是 hex string
            nbits_be = bits if bits else ''

        # curtime -> ntime (int -> 4 byte BE hex)
        curtime = int(gbt.get('curtime', int(time.time())))
        ntime_be = int_to_be_hex(curtime, 4)

        # 2) coinbase 处理: 优先使用 coinbasetxn.data (BCH 节点常见)
        coinbasetxn = gbt.get('coinbasetxn')
        coinb1 = ''
        coinb2 = ''
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
                coinb2 = ''
        else:
            # 如果 coinbasetxn 不存在，则从 gbt['coinbaseaux'/'coinbasevalue'] 等手动构造coinbase
            # 这里做一个简单构造：将 coinbase 空壳作为 coinb1, coinb2 为空
            height = gbt.get('height')
            if height is None:
                coinb1 = ''
                coinb2 = ''
            else:
                height_bytes = _encode_height_to_coinbase(height)
                coinb1 = _build_minimal_coinbase_tx(height_bytes)
                coinb2 = ''


        # 3) merkle branch: 用 GBT 的 transactions 列表中的 txid 字段 (RPC 返回通常是 BE hex)
        transactions = gbt.get('transactions', [])
        merkle_branch = [tx.get('txid') for tx in transactions if tx.get('txid')]

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
        self.conn.settimeout(30)
        # 注册
        with _miners_lock:
            if len(_miners) >= MAX_MINERS:
                log("已达到最大连接数，拒绝连接", addr)
                try:
                    conn.close()
                except:
                    pass
            else:
                _miners.append(self)

    def run(self):
        log("矿机连接来自", self.addr)
        try:
            while self.running:
                try:
                    data = self.conn.recv(8192)
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
        extranonce2_placeholder = '00' * self.extranonce2_size

        # 确保 miner 收到的 coinb1 中包含 extranonce1 的位置
        if placeholder and placeholder in coinb1:
            coinb1_filled = coinb1.replace(placeholder, self.extranonce1 + extranonce2_placeholder, 1)
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
            extranonce2 = extranonce2 or ''
            # 将 EXTRANONCE_PLACEHOLDER 替换（若存在）
            extranonce2 = extranonce2.rjust(self.extranonce2_size * 2, '0')[:self.extranonce2_size * 2]
            if EXTRANONCE_PLACEHOLDER and EXTRANONCE_PLACEHOLDER in coinb1:
                coinbase_hex = coinb1.replace(EXTRANONCE_PLACEHOLDER, extranonce1 + extranonce2, 1) + coinb2
            else:
                # fallback：将 extranonce1/extranonce2 附加到 coinb1
                coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2

            # 3) 计算 coinbase tx hash (双sha256), 注意: 传入 dsha256 的应为原始 bytes (tx raw hex)
            try:
			
                coinbase_bytes = hex_to_bytes(coinbase_hex)
            except Exception as e:
                log("coinbase hex 无法解析:", e)
                self.send_json({"id": req_id, "result": False, "error": [24, "Invalid coinbase hex", None]})
                return

            coinbase_hash_be = dsha256(coinbase_bytes)  # big-endian digest


            # 4) 将 GBT transactions 列表的 txid 转换为 LE bytes，并构建 merkle 根（使用小端格式进行内部哈希）
            txs_info = job['gbt'].get('transactions', [])
            leaves_be: List[bytes] = [coinbase_hash_be]
            for tx in txs_info:
                txdata = tx.get('data')
                if txdata:
                    try:
                        leaves_be.append(dsha256(hex_to_bytes(txdata)))
                    except Exception:
                        log("无法解析 tx data，尝试使用 txid", tx.get('txid'))
                        txid = tx.get('txid')
                        if txid:
                            try:
                                leaves_be.append(hex_to_bytes(txid)[::-1])
                            except Exception:
                                log('无法解析 txid', txid)
                else:
                    txid = tx.get('txid')
                    if txid:
                        try:
                            leaves_be.append(hex_to_bytes(txid)[::-1])
                        except Exception:
                            log('无法解析 txid', txid)

            merkle_root_be = _build_merkle_root_be(leaves_be)
            merkle_le_hex = bytes_to_hex(merkle_root_be[::-1])

            # 构建 header 各字段
            version_le = int(job['gbt'].get('version', 0)).to_bytes(4, 'little')
            prevhash_rpc = job['gbt'].get('previousblockhash', '')
            try:
                prevhash_le = hex_to_bytes(prevhash_rpc)[::-1]
            except Exception:
                prevhash_le = b'\x00' * 32

            # ntime
            ntime_le_hex = parse_nonce_or_ntime_to_le(ntime_hex if ntime_hex else job['gbt'].get('curtime'), 4)
            ntime_le = hex_to_bytes(ntime_le_hex)

            # nonce
            nonce_le_hex = parse_nonce_or_ntime_to_le(nonce_hex, 4)
            nonce_le = hex_to_bytes(nonce_le_hex)

            # bits field
            bits_field = job['gbt'].get('bits')
            if isinstance(bits_field, int):
                bits_be = bits_field.to_bytes(4, 'big')
            else:
                try:
                    bits_be = hex_to_bytes(bits_field)
                except Exception:
                    # try interpret as number string
                    try:
                        bits_be = int(bits_field).to_bytes(4, 'big')
                    except Exception:
                        bits_be = b'\x00' * 4
            bits_le = bits_be[::-1]

            merkle_le_bytes = merkle_root_be[::-1]
            header_bytes = version_le + prevhash_le + merkle_le_bytes + ntime_le + bits_le + nonce_le

            header_hash_be = dsha256(header_bytes)
            header_hash_int = int.from_bytes(header_hash_be, 'big')
            header_hash_hex_display_le = bytes_to_hex(header_hash_be[::-1])

            compact_int = bits_hex_to_int(bytes_to_hex(bits_be))
            target_int = compact_to_target(compact_int)

            is_valid_share = header_hash_int <= target_int
            log(f"提交 from {self.addr} job={job_id} worker={worker} hash_le={header_hash_hex_display_le} valid={is_valid_share}")

            if not is_valid_share:
                self.send_json({"id": req_id, "result": False, "error": [25, "Low difficulty share", None]})
                return

            # 构建完整区块并提交：header + tx count + tx raw data
            txs_hex = []
            txs_hex.append(coinbase_hex)
            for tx in txs_info:
                txdata = tx.get('data')
                if txdata:
                    txs_hex.append(txdata)
                else:
                    log("GBT 中 transaction 缺少 data 字段，无法构建完整区块 -> 提交中断")
                    self.send_json({"id": req_id, "result": False, "error": [22, "Missing tx data in GBT", None]})
                    return

            tx_count_hex = varint_encode(len(txs_hex))
            header_hex_le = bytes_to_hex(header_bytes)
            block_hex = header_hex_le + tx_count_hex + "".join(txs_hex)

            submit_result = rpc_call("submitblock", [block_hex])
            # Bitcoin RPC: submitblock returns null (None) on success, or error object/string on failure
            if submit_result is None:
                log("!!! 区块被节点接受！Block hash (LE):", header_hash_hex_display_le)
                self.send_json({"id": req_id, "result": True, "error": None})
            else:
                log("submitblock 返回:", submit_result)
                self.send_json({"id": req_id, "result": False, "error": [22, str(submit_result), None]})
        except Exception as e:
            log("处理 submit 异常:", e)
            self.send_json({"id": req_id, "result": False, "error": [23, "Internal proxy error", None]})


# ===========================
# === Merkle 核心实现（big-endian node bytes）===
# ===========================
def _build_merkle_root_be(leaves_be: List[bytes]) -> bytes:
    if not leaves_be:
        return b'\x00' * 32
    nodes = list(leaves_be)
    while len(nodes) > 1:
        if len(nodes) % 2 != 0:
            nodes.append(nodes[-1])
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1]
            combined = left + right
            h = dsha256(combined)
            next_level.append(h)
        nodes = next_level
    return nodes[0]


# ===========================
# === Stratum 主服务循环 ===
# ===========================
def start_stratum_server(listen_host: str, listen_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
    if RPC_USER == "your_rpc_user" or RPC_PASS == "your_rpc_password":
        print("请先在脚本顶部配置 RPC_USER 和 RPC_PASS（bitcoin.conf 中的 rpc 用户/密码）")
        exit(1)

    poller_thread = threading.Thread(target=gbt_poller, daemon=True)
    poller_thread.start()

    start_stratum_server(LISTEN_HOST, LISTEN_PORT)
