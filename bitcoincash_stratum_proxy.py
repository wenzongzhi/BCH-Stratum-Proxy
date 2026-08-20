"""
Copyright 2026 温中志 (Wen Zhongzhi)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from ecashaddress import convert
import base58  # pip install base58
import socket
import threading
import time
import json
import os
import binascii
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
import requests
from typing import List, Dict, Any, Optional, Tuple
from queue import Empty, Full, Queue
from runtime_status import RuntimeStatsRegistry, RuntimeStatusWriter

# ===========================
# === User configuration area (must be modified) ===
# ===========================
RPC_USER = "your_rpc_user"       # rpcuser in bitcoin.conf
RPC_PASS = "your_rpc_password"   # rpcpassword in bitcoin.conf
RPC_HOST = "127.0.0.1"
RPC_PORT = 8332

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3333

# Polling interval (seconds), recommended 10-30; shorter intervals result in higher RPC costs.
GBT_POLL_INTERVAL = 20

# extranonce: The size of extranonce1 bytes allocated to each miner by the agent
EXTRANONCE1_BYTES = 4
# The size of extranonce2 provided by the ASIC miner
EXTRANONCE2_BYTES = 4

COINBASE_TAG = b"/BitcoinCash Stratum Proxy/"

# Default payment address (used when the miner does not provide one)
DEFAULT_PAYOUT_ADDRESS = "bitcoincash:your_default_address_here"

# Share difficulty announced to connected miners. 2048 gives Bitaxe and
# NerdQaxe devices regular health-check shares without affecting solo blocks.
MIN_SHARE_DIFF = 2_048
# Proposal mode is useful for diagnostics, but production solo mining should
# submit a solved block immediately instead of adding another RPC round trip.
ENABLE_BLOCK_PROPOSAL_CHECK = False

# Stratum difficulty 1 uses Bitcoin's historical difficulty-1 target.
DIFF1_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
VERSION_ROLLING_SERVER_MASK = 0x1FFFE000
MAX_JOBS_PER_MINER = 8
MAX_SUBMISSIONS_PER_MINER = 4096
SUBMIT_QUEUE_STOP = object()
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60

# RPC call timeout and retries
RPC_TIMEOUT = 10
RPC_MAX_RETRIES = 3
RPC_RETRY_BACKOFF = 2  # Index retreat base

# enable/disable log output
DEBUG = True
MAX_MINERS = 20
PROXY_VERSION = "1.0"
RUNTIME_STATUS_INTERVAL = 1.0
RUNTIME_STATUS_FILE = os.environ.get(
    "BCH_RUNTIME_STATUS_FILE",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "runtime_status.json",
    ),
)

# ===========================
# === Global states (for internal use) ===
# ===========================
_current_gbt: Optional[Dict[str, Any]] = None
_current_job: Optional[Dict[str, Any]] = None
_current_height: int = -1

# Manage the list of all connected miner handlers
# use thread lock to make sure same resource only changed by one thread
_miners_lock = threading.Lock()
_miners: List["StratumMinerHandler"] = []

# lock protecting GBT and job
_gbt_lock = threading.Lock()

# ===========================
# === Auxiliary functions (serialization/hashing/encoding) ===
# ===========================
def log(*args):
    if DEBUG:
        print(time.strftime('%Y-%m-%d %H:%M:%S'), "[PROXY]", *args)

RUNTIME_STATS = RuntimeStatsRegistry(
    service_name="bitcoincash-stratum-proxy",
    service_version=PROXY_VERSION,
    network="mainnet",
    listen_host=LISTEN_HOST,
    listen_port=LISTEN_PORT,
    max_miners=MAX_MINERS,
    default_difficulty=MIN_SHARE_DIFF,
    rpc_host=RPC_HOST,
    rpc_port=RPC_PORT,
    gbt_poll_interval_seconds=GBT_POLL_INTERVAL,
)

def dsha256(data: bytes) -> bytes:
    """ double-sha256, return digest bytes（big-endian order）"""
    return sha256(sha256(data).digest()).digest()

def hex_to_bytes(h: str) -> bytes:
    #return binascii.unhexlify(h)
    return binascii.unhexlify(h.strip())

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

def reverse_bytes(b: bytes) -> bytes:
    return b[::-1]

def reverse_hex(h: str) -> str:
    """ Reverse byte order (hex string) """
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

def compact_to_target(nbits_hex: str) -> int:
    """
    convert nbits (hex string, big-endian) to target (int)
    for example, "1a2b3c4d" -> target = 0x2b3c4d << (8 * (0x1a - 3))
    """
    try:
        nbits_bytes = hex_to_bytes(nbits_hex)
        if len(nbits_bytes) != 4:
            return 0

        # Big-endian reading 32-bit
        compact = int.from_bytes(nbits_bytes, 'big')
        size = compact >> 24
        mantissa = compact & 0xFFFFFF  # 24-bit

        if size <= 3:
            target = mantissa >> (8 * (3 - size))
        else:
            target = mantissa << (8 * (size - 3))

        # Prevent overflow
        if target.bit_length() > 256:
            target = (1 << 256) - 1

        return target
    except Exception as e:
        log("compact_to_target error:", e)
        return 0


def difficulty_to_target(difficulty: float) -> int:
    """Convert Stratum difficulty to its inclusive share target."""
    if isinstance(difficulty, bool) or not isinstance(difficulty, (int, float)):
        raise ValueError("difficulty must be positive")
    difficulty_fraction = Fraction(str(difficulty))
    if difficulty_fraction <= 0:
        raise ValueError("difficulty must be positive")
    return max(
        1,
        DIFF1_TARGET
        * difficulty_fraction.denominator
        // difficulty_fraction.numerator,
    )


def hash_to_difficulty(hash_value: int) -> float:
    """Return standard Stratum/Bitcoin difficulty for a positive hash value."""
    if hash_value < 0:
        raise ValueError("hash value must not be negative")
    return DIFF1_TARGET / max(1, hash_value)


def _parse_fixed_hex(value: Any, byte_length: int, field_name: str) -> str:
    """Validate and normalize a fixed-size big-endian hexadecimal field."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a hexadecimal string")
    normalized = value.strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) != byte_length * 2:
        raise ValueError(f"{field_name} must be exactly {byte_length} bytes")
    if any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError(f"{field_name} contains non-hexadecimal characters")
    return normalized


def apply_version_rolling(
    job_version_hex: str,
    version_bits_hex: Optional[str],
    enabled: bool,
    mask: int,
) -> int:
    """Apply BIP310 version bits and return the resulting uint32 version."""
    job_version = int(_parse_fixed_hex(job_version_hex, 4, "job version"), 16)
    if not enabled:
        if version_bits_hex is not None:
            raise ValueError("version rolling was not negotiated")
        return job_version

    if version_bits_hex is None:
        return job_version
    version_bits = int(
        _parse_fixed_hex(version_bits_hex, 4, "version_bits"),
        16,
    )
    if version_bits & ~mask:
        raise ValueError("version_bits contains bits outside the negotiated mask")
    return (job_version & ~mask) | (version_bits & mask)


def stratum_prevhash_to_header_hex(prevhash_hex: str) -> str:
    """Convert Stratum V1 word-swapped prevhash to serialized header bytes."""
    normalized = _parse_fixed_hex(prevhash_hex, 32, "previous block hash")
    return "".join(
        reverse_hex(normalized[index:index + 8])
        for index in range(0, 64, 8)
    )


def validate_ntime(
    ntime_hex: str,
    gbt: Dict[str, Any],
    now: Optional[int] = None,
) -> int:
    """Validate a submitted block timestamp against GBT and BCH time limits."""
    ntime = int(_parse_fixed_hex(ntime_hex, 4, "ntime"), 16)
    minimum = int(gbt.get("mintime", gbt.get("curtime", 0)))
    if ntime < minimum:
        raise ValueError(
            f"ntime {ntime} is below template mintime {minimum}"
        )

    local_now = int(time.time()) if now is None else int(now)
    node_time = int(gbt.get("curtime", local_now))
    maximum = max(local_now, node_time) + MAX_FUTURE_BLOCK_TIME
    if ntime > maximum:
        raise ValueError(
            f"ntime {ntime} exceeds maximum allowed time {maximum}"
        )
    return ntime

def bits_hex_to_int(bits_hex: str) -> int:
    return int(bits_hex, 16)

def _clean_hex(s: str, length: int) -> str:
    s = str(s).strip()
    if s.startswith('0x'):
        s = s[2:]
    s = s.ljust(length, '0')[:length]
    return s

def parse_nonce_or_ntime_to_le(hex_or_dec: Optional[str], length_bytes: int) -> str:
    """
    Parse a miner nonce/ntime value as fixed-width little-endian hex.
    support: hex (BE or LE), decimal string
    First try to interpret it as hex (and convert to little-endian), then try decimal
    """
    if not hex_or_dec:
        return int_to_le_hex(0, length_bytes)

    s = str(hex_or_dec).strip()
    if s.startswith('0x'):
        s = s[2:]
    s = s.lower()
    # Force padding to 8 characters
    needed = length_bytes * 2
    s = s.rjust(needed, '0')[-needed:]

    # Valid hexadecimal values are reversed directly.
    if all(c in '0123456789abcdef' for c in s):
        try:
            b = binascii.unhexlify(s)
            return bytes_to_hex(b[::-1])  # BE -> LE reverse
        except Exception:
            pass  # continue decimal

    # decimal fallback
    try:
        n = int(s, 10)
        return int_to_le_hex(n, length_bytes)
    except Exception:
    # Final safety operate
        return int_to_le_hex(0, length_bytes)

# ==== normalization nbits_be ====
def normalize_nbits_be(bits: Any) -> str:
    """Convert bits (int or str) to 8-character hex big-endian"""
    if isinstance(bits, int):   # judge whether bits is int type
        return int_to_be_hex(bits, 4)   # transfer bits to 4 Bytes Hex big-endian string
    s = str(bits).strip()   # remove all space characters at both ends of the string
    if s.startswith("0x"):  # if string start with 0x, remove the 0x
        s = s[2:]
    # if all content of bits string are hex characters
    if all(c in '0123456789abcdefABCDEF' for c in s):
        if len(s) != 8:
            raise ValueError(f"Invalid bits length: {len(s)} (must be 8 characters)")
        return s.lower()   # convert the processed string to all lowercase and return it

# =====================================
# === RPC encapsulation (with retry)===
# =====================================
# '= None' means List is optional params
@dataclass(frozen=True)
class RpcResult:
    ok: bool
    result: Any = None
    error: Any = None


def rpc_call(method: str, params: Optional[List[Any]] = None) -> RpcResult:
    url = f"http://{RPC_HOST}:{RPC_PORT}"   # f key word is mean format the string
    headers = {"content-type": "application/json"}
    payload = {"jsonrpc": "2.0", "id": "proxy", "method": method, "params": params or []}
    attempt = 0
    while attempt < RPC_MAX_RETRIES:
        try:
            resp = requests.post(
                url,
                json=payload,
                headers=headers,
                auth=(RPC_USER, RPC_PASS),
                timeout=RPC_TIMEOUT,
            )
            # requests.post(url, json, headers, auth, timeout)
            resp.raise_for_status()     # If there is an HTTP error, throw an exception.
            data = resp.json()
            if data.get('error'):
                log(f"RPC error for {method}:", data['error'])
                return RpcResult(ok=False, error=data['error'])
            return RpcResult(ok=True, result=data.get('result'))
        except Exception as e:
            attempt += 1
            log(f"RPC call {method} attempt {attempt} failed:", e)
            time.sleep(RPC_RETRY_BACKOFF ** (attempt - 1))
    log(f"RPC call {method} failed after {RPC_MAX_RETRIES} attempts.")
    return RpcResult(
        ok=False,
        error=f"RPC transport failed after {RPC_MAX_RETRIES} attempts",
    )

# ===========================
# === GBT -> Job Conversion and Broadcast ===
# ===========================
def _encode_height_to_coinbase(height: int) -> str:
    """Encode the BIP34 block-height push used at the start of scriptSig."""
    if height < 0:
        raise ValueError("block height must be non-negative")

    if height == 0:
        encoded = b""
    else:
        encoded_bytes = bytearray()
        value = height
        while value:
            encoded_bytes.append(value & 0xff)
            value >>= 8
        if encoded_bytes[-1] & 0x80:
            encoded_bytes.append(0)
        encoded = bytes(encoded_bytes)

    if len(encoded) > 75:
        raise ValueError("block height encoding is unexpectedly large")
    return bytes([len(encoded)]).hex() + encoded.hex()

def _build_minimal_coinbase_tx(height_bytes_hex: str) -> str:
    # Unused reference helper; production jobs use build_coinbase_1/2.
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
    return (
        version + tx_in_count + prev_out + script_len + script_hex + seq
        + tx_out_count + value + pk_script_len + pk_script + lock_time
    )

def build_coinbase_1(height: int, coinbase_aux: Optional[Dict[str, Any]] = None) -> str:
    """
    Build the transaction prefix before extranonce1/extranonce2.

    The miner constructs the full transaction as:
    coinb1 + extranonce1 + extranonce2 + coinb2.
    02000000                     version
    01                           input_count
    00...00ffffffff              null_prevout fixed by 32 bytes "00" txid + 4 bytes "ffffffff" vout
    size of coinbase script      include script length and extranonce1 + extranonce2 size
    script_prefix                height_push + COINBASE_TAG
    """
    height_push = bytes.fromhex(_encode_height_to_coinbase(height))
    aux_data = b""
    if coinbase_aux is not None and not isinstance(coinbase_aux, dict):
        raise ValueError("GBT coinbaseaux must be an object")
    for key, value in (coinbase_aux or {}).items():
        if not isinstance(value, str):
            raise ValueError(f"GBT coinbaseaux {key!r} must be hexadecimal")
        if not value:
            continue
        try:
            aux_data += bytes.fromhex(value)
        except ValueError as e:
            raise ValueError(
                f"GBT coinbaseaux {key!r} contains invalid hexadecimal"
            ) from e

    script_prefix = height_push + aux_data + COINBASE_TAG
    extranonce_size = EXTRANONCE1_BYTES + EXTRANONCE2_BYTES
    script_sig_size = len(script_prefix) + extranonce_size
    if not 2 <= script_sig_size <= 100:
        raise ValueError(
            f"coinbase scriptSig size {script_sig_size} is outside consensus limits"
        )

    version = int_to_le_hex(2, 4)
    input_count = varint_encode(1)
    null_prevout = ("00" * 32) + "ffffffff"
    script_length = varint_encode(script_sig_size)
    return version + input_count + null_prevout + script_length + script_prefix.hex()

def _address_to_script_pubkey(payout_address: str) -> str:
    """
    P2PKH
    - 76a914
    - <20-byte hash160>
    - 88ac

    P2SH
    - a914
    - <20-byte script hash>
    - 87
    """
    if not isinstance(payout_address, str):
        raise ValueError("payout address must be a string")

    address = payout_address.strip()
    if not address:
        raise ValueError("payout address must not be empty")

    # CashAddr is case-insensitive only when the whole address uses one case.
    # Normalize it because mining software commonly omits "bitcoincash:".
    if ':' in address or address[0].lower() in ('q', 'p'):
        if address.lower() != address and address.upper() != address:
            raise ValueError("CashAddr must not mix uppercase and lowercase")

        address = address.lower()
        if ':' not in address:
            address = 'bitcoincash:' + address
        elif not address.startswith('bitcoincash:'):
            raise ValueError("only Bitcoin Cash mainnet CashAddr is supported")

    try:
        legacy = convert.to_legacy_address(address)
    except Exception as e:
        raise ValueError(f"invalid Bitcoin Cash payout address: {payout_address}") from e

    try:
        decoded = base58.b58decode_check(legacy)
    except Exception as e:
        raise ValueError(f"invalid legacy payout address: {payout_address}") from e

    if len(decoded) != 21:
        raise ValueError("payout address payload must contain a 20-byte hash")

    version = decoded[0]
    payload_hex = decoded[1:].hex()
    if version == 0x00:
        return "76a914" + payload_hex + "88ac"
    if version == 0x05:
        return "a914" + payload_hex + "87"
    raise ValueError(
        f"unsupported payout address network/version 0x{version:02x}; "
        "Bitcoin Cash mainnet address required"
    )

def _validated_payout_address(payout_address: str) -> str:
    """Return a trimmed usable address, raising ValueError when it is invalid."""
    address = payout_address.strip()
    _address_to_script_pubkey(address)
    return address

def build_coinbase_2(payout_address: str, coinbase_value: int) -> str:
    """
    Build the transaction suffix after extranonce1/extranonce2.
    ffffffff            sequence, fixed value
    01                  output_count
    1a6d291200000000    block reward
    script_pubkey
    00000000            lock_time, no lock fixed at 00000000
    """
    if not 0 < coinbase_value <= 0xffffffffffffffff:
        raise ValueError("coinbase value must be a positive uint64")

    script_pubkey = _address_to_script_pubkey(payout_address)
    sequence = "ffffffff"
    output_count = varint_encode(1)
    output = (
        int_to_le_hex(coinbase_value, 8)
        + varint_encode(len(bytes.fromhex(script_pubkey)))
        + script_pubkey
    )
    lock_time = "00000000"
    return sequence + output_count + output + lock_time

def _compute_merkle_branch(tx_hashes_internal: List[bytes]) -> List[str]:
    """
    Build the sibling path for the coinbase leaf at index zero.

    None represents the subtree containing the coinbase. The returned branch
    therefore depends only on non-coinbase transactions.
    """
    if not tx_hashes_internal:
        return []

    nodes: List[Optional[bytes]] = [None] + tx_hashes_internal
    branch: List[str] = []

    while len(nodes) > 1:
        sibling = nodes[1]
        if sibling is None:
            raise ValueError("coinbase merkle sibling must not be empty")
        branch.append(bytes_to_hex(sibling))

        next_nodes: List[Optional[bytes]] = []
        for index in range(0, len(nodes), 2):
            left = nodes[index]
            right = nodes[index + 1] if index + 1 < len(nodes) else left
            if left is None or right is None:
                next_nodes.append(None)
            else:
                next_nodes.append(dsha256(left + right))
        nodes = next_nodes

    return branch


def _get_template_tx_hashes(transactions: List[Dict[str, Any]]) -> List[bytes]:
    """
    Return transaction hashes in the internal byte order used by the Merkle tree.

    BCHN has already calculated and validated these transaction IDs. The proxy
    only decodes them; it does not hash every raw transaction again.
    """
    hashes: List[bytes] = []
    for index, tx in enumerate(transactions):
        txid = tx.get('txid') or tx.get('hash')
        if not isinstance(txid, str) or len(txid) != 64:
            raise ValueError(f"GBT transaction {index} has no valid txid/hash")
        try:
            hashes.append(reverse_bytes(hex_to_bytes(txid)))
        except (binascii.Error, ValueError) as e:
            raise ValueError(
                f"GBT transaction {index} contains an invalid txid/hash"
            ) from e
    return hashes


def _get_template_transaction_data(
    transactions: List[Dict[str, Any]],
) -> List[str]:
    """Return every raw template transaction, failing on incomplete templates."""
    raw_transactions: List[str] = []
    for index, tx in enumerate(transactions):
        data = tx.get("data")
        if not isinstance(data, str) or not data:
            raise ValueError(f"GBT transaction {index} has no raw data")
        try:
            hex_to_bytes(data)
        except (binascii.Error, ValueError) as e:
            raise ValueError(
                f"GBT transaction {index} contains invalid raw data"
            ) from e
        raw_transactions.append(data)
    return raw_transactions


def _template_supports_proposal(gbt: Dict[str, Any]) -> bool:
    capabilities = gbt.get("capabilities", [])
    return (
        isinstance(capabilities, list)
        and "proposal" in capabilities
    )


def _build_block_rpc_params(
    block_hex: str,
    workid: Any = None,
) -> List[Any]:
    params: List[Any] = [block_hex]
    if workid is not None:
        params.append({"workid": workid})
    return params


def validate_block_proposal(
    block_hex: str,
    gbt: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """
    Validate a solved block without its proof-of-work check.

    Explicit proposal rejection stops submission. RPC/transport failures are
    fail-open so a valid solo block is never lost because of the extra check.
    """
    if not ENABLE_BLOCK_PROPOSAL_CHECK or not _template_supports_proposal(gbt):
        return True, None

    request: Dict[str, Any] = {
        "mode": "proposal",
        "data": block_hex,
    }
    if gbt.get("workid") is not None:
        request["workid"] = gbt["workid"]

    proposal = rpc_call("getblocktemplate", [request])
    if not proposal.ok:
        log("Block proposal check unavailable; submitting anyway:", proposal.error)
        return True, None
    if proposal.result is None:
        return True, None
    return False, str(proposal.result)


def build_job_from_gbt(gbt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        # 1) header components, version
        # RPC version 536870912 is sent by Stratum as 20000000.
        version = int(gbt.get('version', 0))
        # Stratum require the big end (hex) to be used for display
        version_be = int_to_be_hex(version, 4)  # 20000000

        # RPC previous block hash:          000000000000000000000da8aa8662f051cd0fec6eeca157eff33ea207923ec3
        # the hash notify to ASIC miner:    07923ec3eff33ea26eeca15751cd0fecaa8662f000000da80000000000000000
        # Convert RPC hash to Stratum V1 prevhash format
        prevhash_rpc = str(gbt.get('previousblockhash', ''))
        if len(prevhash_rpc) != 64:
            raise ValueError("GBT previousblockhash must be 32 bytes")
        words = [prevhash_rpc[i:i+8] for i in range(0, 64, 8)]
        prevhash_stratum_word_swapped = ''.join(reversed(words))

        # bits: for example "180170da"
        # bits = gbt.get('bits')
        # nbits_be = normalize_nbits_be(bits) # unused function
        bits = gbt.get('bits', '')
        nbits_be = bits

        # curtime -> ntime (int -> 4 byte BE hex)
        curtime = int(gbt.get('curtime', int(time.time())))
        ntime_be = int_to_be_hex(curtime, 4)

        # Build a mutable coinbase around the per-connection extranonce and
        # payout address. This path requires the template's coinbasevalue.
        height = gbt.get('height')
        coinbase_value = gbt.get('coinbasevalue')
        if height is None:
            raise ValueError("GBT has no next-block height")
        if not isinstance(coinbase_value, int) or coinbase_value <= 0:
            if gbt.get("coinbasetxn"):
                raise ValueError(
                    "GBT returned coinbasetxn without coinbasevalue; "
                    "custom per-miner payout construction is unsupported"
                )
            raise ValueError("GBT has no valid coinbasevalue")
        coinb1 = build_coinbase_1(height, gbt.get('coinbaseaux'))
        transactions = gbt.get('transactions', [])
        tx_hashes_internal = _get_template_tx_hashes(transactions)
        merkle_branch = _compute_merkle_branch(tx_hashes_internal)

        job_id = (
            f"{time.time_ns():x}_"
            f"{prevhash_stratum_word_swapped[-8:]}"
        )

        job = {
            "job_id": job_id,
            "gbt": gbt,
            "prevhash_stratum_word_swapped": (
                prevhash_stratum_word_swapped
            ),
            "version_be": version_be,
            "nbits_be": nbits_be,
            "ntime_be": ntime_be,
            "coinb1": coinb1,
            "coinbase_value": coinbase_value,
            "merkle_branch": merkle_branch,
        }
        return job
    except Exception as e:
        log("Job build failed: ", e)
        return None

def broadcast_job_to_miners(job: Dict[str, Any]):
    """Broadcast the job to all subscribed and authorized mining machines (thread safe)"""
    with _miners_lock:
        miners_copy = list(_miners)
    for m in miners_copy:
        if not m.subscribed or not m.authorized:
            continue
        try:
            m.send_job(job)
        except Exception as e:
            log("Broadcast job to mining machine failed, remove mining machine:", e)
            try:
                m.close()
            except Exception:
                pass

# ======================================
# === GBT Polling thread (background)===
# ======================================
def gbt_poller():
    global _current_gbt, _current_job, _current_height
    log("GBT polling start, Interval:", GBT_POLL_INTERVAL, "seconds")
    last_txids = None
    while True:
        try:
            rpc_result = rpc_call(
                "getblocktemplate",
                [{
                    "capabilities": [
                        "coinbasevalue",
                        "proposal",
                        "workid",
                    ]
                }],
            )
            if not rpc_result.ok or not isinstance(rpc_result.result, dict):
                RUNTIME_STATS.record_gbt_error(rpc_result.error)
                time.sleep(GBT_POLL_INTERVAL)
                continue
            gbt = rpc_result.result

            height = gbt.get('height', -1)  # if can't get valid height value, return -1
            # Track ordered txids to detect template transaction changes.
            txids = tuple(tx.get('txid') for tx in gbt.get('transactions', []))

            network_target = compact_to_target(str(gbt.get('bits', '')))
            network_difficulty = (
                hash_to_difficulty(network_target)
                if network_target > 0
                else None
            )
            RUNTIME_STATS.update_gbt(
                height=height if isinstance(height, int) else None,
                previous_block_hash=gbt.get('previousblockhash'),
                bits=gbt.get('bits'),
                network_difficulty=network_difficulty,
                template_tx_count=len(txids) + 1,  # include coinbase
            )

            need_broadcast = False
            clean_jobs = False
            job_to_broadcast = None
            reason = ""
            with _gbt_lock:
                if _current_gbt is None:
                    need_broadcast = True
                    clean_jobs = True
                    reason = "initial GBT"
                elif gbt.get('previousblockhash') != _current_gbt.get('previousblockhash'):
                    need_broadcast = True
                    clean_jobs = True
                    reason = f"detected new block, height is {height}"
                elif txids != last_txids:
                    need_broadcast = True
                    reason = f"detected Mempool changed, tx_count={len(txids)}"
                elif gbt.get('coinbasevalue') != _current_gbt.get('coinbasevalue'):
                    need_broadcast = True
                    reason = "detected coinbasevalue changed"

                # update cache
                if need_broadcast:
                    candidate_job = build_job_from_gbt(gbt)
                    if candidate_job:
                        candidate_job["clean_jobs"] = clean_jobs
                        _current_gbt = gbt
                        _current_job = candidate_job
                        _current_height = height
                        last_txids = txids
                        job_to_broadcast = candidate_job
                        RUNTIME_STATS.update_job(candidate_job.get("job_id"))

            if job_to_broadcast:
                log("boardcast new job to ASIC:", reason, "height=", height, "txs=", len(txids))
                broadcast_job_to_miners(job_to_broadcast)
            time.sleep(GBT_POLL_INTERVAL)
        except Exception as e:
            RUNTIME_STATS.record_gbt_error(e)
            log("GBT polling exception", e)
            time.sleep(GBT_POLL_INTERVAL)

# ===========================
# === Stratum Miner Handler ===
# ===========================
class StratumMinerHandler(threading.Thread):
    """
    each miner is connected to one Handler thread (Simplified Stratum Protocol).
    support:
      - mining.subscribe / mining.extranonce.subscribe
      - mining.authorize
      - mining.submit
      - proxy mining.notify to ASIC (base on _current_job)
    """
    def __init__(self, conn: socket.socket, addr: Tuple[str, int]):
        super().__init__(daemon=True)
        # for example, conn=<socket>, addr=('192.168.1.100', 40231)
        self.conn = conn
        self.addr = addr
        self.connection_id = f"{addr[0]}:{addr[1]}"
        self.running = True

        # Miner status
        self.subscribed = False
        self.authorized = False
        self.worker_name = "unknown"
        self.payout_address: Optional[str] = None

        self.difficulty = MIN_SHARE_DIFF
        self.version_rolling = False
        self.version_rolling_mask = 0

        # Each miner connection gets a stable proxy-assigned extranonce1.
        self.extranonce1 = os.urandom(EXTRANONCE1_BYTES).hex()
        self.extranonce2_size = EXTRANONCE2_BYTES

        # assign the job id (string)
        self.current_job_id: Optional[str] = None
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.submitted_shares: Dict[Tuple[str, ...], None] = {}
        self.jobs_lock = threading.Lock()

        # use fifo to put and get the sumbit data of ASIC miner
        self.submit_queue = Queue(maxsize=1000)
        RUNTIME_STATS.register_miner(
            self.connection_id,
            remote_ip=str(addr[0]),
            remote_port=int(addr[1]),
            initial_difficulty=self.difficulty,
        )
        self.submit_thread = self.start_submit_worker()

        # socket read buffer
        self._buffer = ""
        self.conn.settimeout(30)

        # register
        with _miners_lock:
            _miners.append(self)

    def run(self):
        log("Miner IP ", self.addr)
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
                except Exception:
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
                        log("Invalid JSON from a miner:", e)
                        continue
                    try:
                        self.handle_message(msg)
                    except Exception as e:
                        log("Handling miner message anomalies:", e)
        finally:
            self.close()
            log("miner disconnected:", self.addr)

    def close(self):
        if not self.running:
            return
        self.running = False

        # Wake the submit worker and discard queued shares for this connection.
        while True:
            try:
                self.submit_queue.get_nowait()
                self.submit_queue.task_done()
            except Empty:
                break
        try:
            self.submit_queue.put_nowait(SUBMIT_QUEUE_STOP)
        except Full:
            pass

        try:
            with _miners_lock:
                if self in _miners:
                    _miners.remove(self)
        except Exception:
            pass

        RUNTIME_STATS.unregister_miner(self.connection_id)

        try:
            self.conn.close()
        except Exception:
            pass

    # -----------------------
    # --- send / response function---
    # -----------------------
    def send_json(self, obj: Dict[str, Any]):
        """Send JSON messages uniformly, with compressed format + ensure \n"""
        try:
            # compress JSON: remove spaces to reduce file size
            data = (json.dumps(obj, separators=(',', ':')) + '\n').encode('utf-8')
            self.conn.sendall(data)
        except Exception as e:
            log("Failed to send to miner:", e)
            self.close()

    def send_subscription_response(self, req_id):
        # Stratum standard: return extranonce1 and extranonce2_size
        resp = {
            "id": req_id,
            "result": [
                [
                    ["mining.set_difficulty", "1"],
                    ["mining.notify", "1"]
                ],
                self.extranonce1,
                self.extranonce2_size
            ],
            "error": None
        }
        self.subscribed = True
        RUNTIME_STATS.set_subscribed(self.connection_id, True)
        self.send_json(resp)
        if self.authorized:
            with _gbt_lock:
                if _current_job:
                    self.send_job(_current_job, force_clean_jobs=True)

    def send_set_difficulty(self, difficulty):
        self.difficulty = difficulty
        RUNTIME_STATS.set_difficulty(self.connection_id, difficulty)

        self.send_json({
            "id": None,
            "method": "mining.set_difficulty",
            "params": [difficulty]
        })

    def send_set_extranonce(self):
        self.send_json({
            "id": None,
            "method": "mining.set_extranonce",
            "params": [
                self.extranonce1,
                self.extranonce2_size
            ]
        })

    def send_configure_response(self, req_id, params):
        if (
            not isinstance(params, list)
            or len(params) < 2
            or not isinstance(params[0], list)
            or not isinstance(params[1], dict)
        ):
            self.send_json({
                "id": req_id,
                "result": None,
                "error": [20, "Invalid mining.configure parameters", None],
            })
            return

        extensions = params[0]
        options = params[1]
        if any(not isinstance(extension, str) for extension in extensions):
            self.send_json({
                "id": req_id,
                "result": None,
                "error": [20, "Invalid mining.configure extension list", None],
            })
            return

        result = {}

        if "version-rolling" in extensions:
            try:
                requested_mask = int(
                    _parse_fixed_hex(
                        options.get("version-rolling.mask", "ffffffff"),
                        4,
                        "version-rolling.mask",
                    ),
                    16,
                )
                negotiated_mask = VERSION_ROLLING_SERVER_MASK & requested_mask
                minimum_bits = int(
                    options.get("version-rolling.min-bit-count", 0)
                )
                if minimum_bits < 0:
                    raise ValueError("minimum bit count must not be negative")
                if negotiated_mask.bit_count() < minimum_bits:
                    log(
                        f"Miner {self.addr} requested {minimum_bits} "
                        "version-rolling bits, but only "
                        f"{negotiated_mask.bit_count()} are available; "
                        "continuing in degraded mode"
                    )

                self.version_rolling = True
                self.version_rolling_mask = negotiated_mask
                result["version-rolling"] = True
                result["version-rolling.mask"] = f"{negotiated_mask:08x}"
            except (TypeError, ValueError) as e:
                self.version_rolling = False
                self.version_rolling_mask = 0
                result["version-rolling"] = str(e)

        if "minimum-difficulty" in extensions:
            try:
                requested_difficulty = options["minimum-difficulty.value"]
                if isinstance(requested_difficulty, bool):
                    raise ValueError("minimum difficulty must be numeric")
                requested_difficulty = float(requested_difficulty)
                if requested_difficulty < 0:
                    raise ValueError(
                        "minimum difficulty must not be negative"
                    )
                self.difficulty = max(
                    float(MIN_SHARE_DIFF),
                    requested_difficulty,
                )
                result["minimum-difficulty"] = True
            except (KeyError, TypeError, ValueError) as e:
                result["minimum-difficulty"] = str(e)

        if "subscribe-extranonce" in extensions:
            result["subscribe-extranonce"] = True

        if "info" in extensions:
            result["info"] = True

        for extension in extensions:
            result.setdefault(extension, False)

        self.send_json({
            "id": req_id,
            "result": result,
            "error": None
        })

    def send_authorize_response(self, req_id, ok=True):
        resp = {"id": req_id, "result": ok, "error": None}
        if ok:
            self.authorized = True
            if self.payout_address is not None:
                RUNTIME_STATS.set_authorized(
                    self.connection_id,
                    worker_name=self.worker_name,
                    payout_address=self.payout_address,
                )
        self.send_json(resp)

    def send_job(self, job: Dict[str, Any], force_clean_jobs: bool = False):
        """
        send the job to ASIC miners (mining.notify)
        Stratum mining.notify
        [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
        The miner constructs:
        coinb1 + connection extranonce1 + miner extranonce2 + coinb2.
        """
        if not job:
            return
        if not self.payout_address:
            raise ValueError("miner has no validated payout address")
        # coinb2 is specific to this miner's validated payout address.
        coinb1 = job.get('coinb1', '')
        coinbase_value = int(job.get('coinbase_value', 0))
        coinb2 = build_coinbase_2(self.payout_address, coinbase_value)
        clean_jobs = force_clean_jobs or bool(job.get("clean_jobs", False))
        job_for_miner = dict(job)
        job_for_miner["coinb2"] = coinb2
        job_for_miner["clean_jobs"] = clean_jobs
        jid = str(job_for_miner.get('job_id'))

        with self.jobs_lock:
            if clean_jobs:
                self.jobs.clear()
                self.submitted_shares.clear()
            self.jobs[jid] = job_for_miner
            while len(self.jobs) > MAX_JOBS_PER_MINER:
                oldest_job_id = next(iter(self.jobs))
                self.jobs.pop(oldest_job_id, None)

        extranonce2_placeholder = '00' * self.extranonce2_size

        full_coinb_hex = (
            coinb1 + self.extranonce1 + extranonce2_placeholder + coinb2
        )
        # 长度校验
        if len(full_coinb_hex) < 100 or len(full_coinb_hex) > 5000:
            log(
                "Warning: abnormal coinbase length, "
                f"len={len(full_coinb_hex)} job_id={job.get('job_id')}"
            )
        self.current_job_id = jid
        RUNTIME_STATS.set_miner_job(self.connection_id, jid)

        branch = job.get('merkle_branch', [])
        if len(branch) > 20:
            log(f"merkle_branch too longer {len(branch)}, cut off")
            #branch = branch[:20]

        params = [
            jid,
            job.get('prevhash_stratum_word_swapped'),
            coinb1,
            coinb2 or "",
            branch,  # Cut-off security branch
            job.get('version_be'),
            job.get('nbits_be'),
            job.get('ntime_be'),
            clean_jobs
        ]
        notify = {"id": None, "method": "mining.notify", "params": params}
        self.send_json(notify)
        log(
            f"proxy send job -> miner {self.addr}, job_id={jid}, "
            f"coinb1_len={len(coinb1)}, coinb2_len={len(coinb2)}"
        )

    def start_submit_worker(self) -> threading.Thread:
        t = threading.Thread(
            target=self.submit_worker,
            daemon=True
        )
        t.start()
        return t

    def submit_worker(self):
        while self.running:
            item = self.submit_queue.get()

            try:
                if item is SUBMIT_QUEUE_STOP:
                    return
                self.handle_submit(*item)
            except Exception as e:
                log("submit worker error:", e)
            finally:
                self.submit_queue.task_done()

    # -----------------------
    # --- Proxy receive the message from ASIC miner ---
    # -----------------------
    def handle_message(self, msg: Dict[str, Any]):
        if not isinstance(msg, dict):
            self.send_json({
                "id": None,
                "result": False,
                "error": [20, "Invalid Stratum request", None],
            })
            return

        method = msg.get('method')
        req_id = msg.get('id')
        params = msg.get('params', [])
        if method == "client.get_version":
            self.send_json({
                "id": req_id,
                "result": f"BitcoinCash-Stratum-Proxy/{PROXY_VERSION}",
                "error": None,
            })
        elif method == "mining.ping":
            self.send_json({"id": req_id, "result": True, "error": None})
        elif method == "mining.subscribe":
            self.send_subscription_response(req_id)
        elif method == "mining.extranonce.subscribe":
            # A simple implementation would be to return true directly.
            self.send_json({"id": req_id, "result": True, "error": None})
        elif method == "mining.configure":
            self.send_configure_response(req_id, params)
        elif method == "mining.suggest_difficulty":
            if not isinstance(params, list) or not params:
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [20, "Missing suggested difficulty", None],
                })
                return
            try:
                suggested_difficulty = params[0]
                if isinstance(suggested_difficulty, bool):
                    raise ValueError("suggested difficulty must be numeric")
                suggested_difficulty = float(suggested_difficulty)
                if suggested_difficulty <= 0:
                    raise ValueError(
                        "suggested difficulty must be positive"
                    )
            except (TypeError, ValueError) as e:
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [20, str(e), None],
                })
                return

            self.difficulty = max(
                float(MIN_SHARE_DIFF),
                suggested_difficulty,
            )
            self.send_json({"id": req_id, "result": True, "error": None})
            if self.authorized:
                self.send_set_difficulty(self.difficulty)
                with _gbt_lock:
                    if self.subscribed and _current_job:
                        self.send_job(
                            _current_job,
                            force_clean_jobs=True,
                        )
        elif method == "mining.get_transactions":
            if not isinstance(params, list) or not params:
                self.send_json({
                    "id": req_id,
                    "result": None,
                    "error": [20, "Missing job ID", None],
                })
                return
            with self.jobs_lock:
                job = self.jobs.get(str(params[0]))
            if not job:
                self.send_json({
                    "id": req_id,
                    "result": None,
                    "error": [21, "Job not found", None],
                })
                return
            try:
                transactions = _get_template_transaction_data(
                    job.get("gbt", {}).get("transactions", [])
                )
            except ValueError as e:
                self.send_json({
                    "id": req_id,
                    "result": None,
                    "error": [20, str(e), None],
                })
                return
            self.send_json({
                "id": req_id,
                "result": transactions,
                "error": None,
            })
        elif method == "mining.multi_version":
            self.version_rolling = True
            self.version_rolling_mask = VERSION_ROLLING_SERVER_MASK
            self.send_json({"id": req_id, "result": True, "error": None})
        elif method == "mining.authorize":
            if not isinstance(params, list) or not params:
                self.send_authorize_response(req_id, ok=False)
                return
            full_worker = params[0] if params else "unknown"
            # Address resolution: Supports user.worker, user, or address.
            parts = str(full_worker).split('.', 1)
            submitted_address = parts[0]
            try:
                address = _validated_payout_address(submitted_address)
            except ValueError as e:
                log(
                    f"Miner {self.addr} submitted invalid payout address "
                    f"{submitted_address!r}; using default address: {e}"
                )
                try:
                    address = _validated_payout_address(
                        DEFAULT_PAYOUT_ADDRESS
                    )
                except ValueError as default_error:
                    log(
                        "Rejecting authorization because both miner and "
                        f"default payout addresses are invalid: {default_error}"
                    )
                    self.send_authorize_response(req_id, ok=False)
                    return

            self.payout_address = address
            self.worker_name = parts[1] if len(parts) > 1 else ""
            self.send_authorize_response(req_id, ok=True)

            self.send_set_difficulty(self.difficulty)

            # Deliver the current job after subscription and authorization.
            with _gbt_lock:
                if self.subscribed and _current_job:
                    self.send_job(_current_job, force_clean_jobs=True)
        elif method == "mining.submit":
            RUNTIME_STATS.record_submit(self.connection_id)
            if not self.subscribed:
                RUNTIME_STATS.record_rejected(self.connection_id, "not_subscribed")
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [25, "Not subscribed", None],
                })
                return
            if not self.authorized:
                RUNTIME_STATS.record_rejected(self.connection_id, "unauthorized")
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [24, "Unauthorized worker", None],
                })
                return

            # params: worker, job_id, extranonce2, ntime, nonce,
            # and optionally version_bits.
            if not isinstance(params, list) or len(params) < 5:
                RUNTIME_STATS.record_rejected(self.connection_id, "invalid_params")
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [20, "Invalid mining.submit parameters", None],
                })
                return

            worker = params[0]
            job_id = params[1]
            extranonce2 = params[2]
            ntime_hex = params[3]
            nonce_hex = params[4]
            version_bits = params[5] if len(params) > 5 else None

            share_key = tuple(
                str(value).strip().lower()
                for value in (
                    job_id,
                    extranonce2,
                    ntime_hex,
                    nonce_hex,
                    version_bits or "",
                )
            )
            with self.jobs_lock:
                duplicate_share = share_key in self.submitted_shares
                if not duplicate_share:
                    self.submitted_shares[share_key] = None
                    while (
                        len(self.submitted_shares)
                        > MAX_SUBMISSIONS_PER_MINER
                    ):
                        oldest_share = next(iter(self.submitted_shares))
                        self.submitted_shares.pop(oldest_share, None)
            if duplicate_share:
                RUNTIME_STATS.record_rejected(self.connection_id, "duplicate")
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [22, "Duplicate share", None],
                })
                return

            try:
                self.submit_queue.put_nowait(
                    (
                        req_id,
                        worker,
                        job_id,
                        extranonce2,
                        ntime_hex,
                        nonce_hex,
                        version_bits,
                    )
                )
            except Full:
                RUNTIME_STATS.record_rejected(self.connection_id, "queue_full")
                with self.jobs_lock:
                    self.submitted_shares.pop(share_key, None)
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [20, "Submit queue full", None],
                })
            except Exception as e:
                RUNTIME_STATS.record_rejected(self.connection_id, "queue_error")
                log("Failed to queue submit:", e)
        else:
            self.send_json({
                "id": req_id,
                "result": False,
                "error": [20, "Unknown method", None],
            })

    # -----------------------
    # --- Submit processing (may be slow) ---
    # -----------------------
    def handle_submit(
        self,
        req_id,
        worker,
        job_id,
        extranonce2,
        ntime_hex,
        nonce_hex,
        version_bits=None,
    ):
        """
        1. verify job_id
        2. Concatenate extranonces (without refactoring coinbase)
        3. Calculate the Merkle root (preferably using a hash).
        4. Construct the BE block header + complete block
        5. Verification difficulty + submitblock
        """
    # ==================== 6. handle_submit (core) ====================
        try:
            with self.jobs_lock:
                job = self.jobs.get(str(job_id))
            if not job:
                RUNTIME_STATS.record_rejected(self.connection_id, "stale")
                self.send_json({"id": req_id, "result": False, "error": [21, "Stale", None]})
                return
            gbt = job.get("gbt")
            if not isinstance(gbt, dict):
                raise ValueError("job has no block template")

            # ---------- 1. coinbase ----------
            coinb1 = job.get('coinb1', '')
            coinb2 = job.get("coinb2")
            if not isinstance(coinb2, str):
                raise ValueError("job has no miner-specific coinbase2")
            ex2 = _parse_fixed_hex(
                extranonce2,
                self.extranonce2_size,
                "extranonce2",
            )

            coinbase_hex = coinb1 + self.extranonce1 + ex2 + coinb2

            # ---------- 2. merkle ----------
            merkle_root_internal = dsha256(hex_to_bytes(coinbase_hex))
            for sibling_hex in job.get('merkle_branch', []):
                merkle_root_internal = dsha256(
                    merkle_root_internal + hex_to_bytes(sibling_hex)
                )
            #version_le = int_to_le_hex(gbt.get('version', 0), 4)
            header_version = apply_version_rolling(
                job['version_be'],
                version_bits,
                self.version_rolling,
                self.version_rolling_mask,
            )
            version_le = int_to_le_hex(header_version, 4)
            prevhash_header_le = stratum_prevhash_to_header_hex(
                job.get('prevhash_stratum_word_swapped')
            )

            merkle_root_le = bytes_to_hex(merkle_root_internal)
            ntime = validate_ntime(ntime_hex, gbt)
            ntime_le = int_to_le_hex(ntime, 4)
            nbits_le = reverse_hex(job.get('nbits_be'))  # BE hex -> LE hex
            #ntime_le = reverse_hex((ntime_hex or '').rjust(8, '0')[:8])# BE hex -> LE hex
            #nonce_le = reverse_hex((nonce_hex or '').rjust(8, '0')[:8])# BE hex → LE hex
            nonce_le = reverse_hex(_parse_fixed_hex(nonce_hex, 4, "nonce"))

            header_le = (
                version_le + prevhash_header_le + merkle_root_le +
                ntime_le + nbits_le + nonce_le
            )
            header_le_bytes = hex_to_bytes(header_le)

            header_hash_le_bytes = dsha256(header_le_bytes)

            # More directly: header_hash_int uses little-endian internal bytes.
            header_hash_int = int.from_bytes(header_hash_le_bytes, 'little')  # FIXED

            # network target (input job['nbits_be'], big-endian hex)
            network_target = compact_to_target(job.get('nbits_be'))
            if network_target == 0:
                RUNTIME_STATS.record_rejected(self.connection_id, "invalid_target")
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [20, "Invalid target", None],
                })
                return

            # share difficulty
            share_target = difficulty_to_target(self.difficulty)
            share_diff = hash_to_difficulty(header_hash_int)
            RUNTIME_STATS.record_share_difficulty(
                self.connection_id,
                share_diff,
            )

            # 1. Difficulty too low -> reject
            if header_hash_int > share_target:
                RUNTIME_STATS.record_rejected(self.connection_id, "low_difficulty")
                self.send_json({
                    "id": req_id,
                    "result": False,
                    "error": [23, "Low difficulty share", None],
                })
                log(
                    f"Reject share: diff={share_diff:.3f} "
                    f"(required {self.difficulty})"
                )
                return

            # 2. Reaching network difficulty -> submitblock
            if header_hash_int <= network_target:
                RUNTIME_STATS.record_block_candidate(self.connection_id)
                # Construct the complete block and commit
                txs = [coinbase_hex] + _get_template_transaction_data(
                    gbt.get('transactions', [])
                )

                block_bytes = hex_to_bytes(header_le)  # notice use header_le
                block_bytes += hex_to_bytes(varint_encode(len(txs)))
                for t in txs:
                    block_bytes += hex_to_bytes(t)

                block_hex = bytes_to_hex(block_bytes)
                proposal_ok, proposal_error = validate_block_proposal(
                    block_hex,
                    gbt,
                )
                if not proposal_ok:
                    RUNTIME_STATS.record_rejected(self.connection_id, "proposal_rejected")
                    self.send_json({
                        "id": req_id,
                        "result": False,
                        "error": [
                            20,
                            f"Block proposal rejected: {proposal_error}",
                            None,
                        ],
                    })
                    log("Block proposal rejected:", proposal_error)
                    return

                rpc_result = rpc_call(
                    "submitblock",
                    _build_block_rpc_params(
                        block_hex,
                        gbt.get("workid"),
                    ),
                )
                accepted = rpc_result.ok and rpc_result.result is None
                submit_error = None
                if not accepted:
                    submit_error = [
                        20,
                        str(
                            rpc_result.error
                            if not rpc_result.ok
                            else rpc_result.result
                        ),
                        None,
                    ]
                if accepted:
                    RUNTIME_STATS.record_accepted(
                        self.connection_id,
                        self.difficulty,
                    )
                    RUNTIME_STATS.record_block_accepted(self.connection_id)
                else:
                    RUNTIME_STATS.record_rejected(
                        self.connection_id,
                        "block_submit_rejected",
                    )
                self.send_json({
                    "id": req_id,
                    "result": accepted,
                    "error": submit_error,
                })
                log(
                    f"Block submit: {'accepted' if accepted else 'rejected'} "
                    f"share_diff={share_diff:.3f} hash={header_hash_int:064x}"
                )
            else:
                # Accept a proxy share that is below network difficulty.
                RUNTIME_STATS.record_accepted(
                    self.connection_id,
                    self.difficulty,
                )
                self.send_json({"id": req_id, "result": True, "error": None})
                log(
                    f"Accept share: diff={share_diff:.3f} "
                    "(below network difficulty)"
                )
            return
        except ValueError as e:
            RUNTIME_STATS.record_rejected(self.connection_id, "invalid_share")
            log("Invalid share submission:", e)
            self.send_json({
                "id": req_id,
                "result": False,
                "error": [20, str(e), None],
            })
        except Exception as e:
            RUNTIME_STATS.record_rejected(self.connection_id, "internal_error")
            log("Handling submit exceptions:", e)
            self.send_json({
                "id": req_id,
                "result": False,
                "error": [20, "Internal proxy error", None],
            })

def _build_merkle_root_internal(leaves_internal: List[bytes]) -> bytes:
    """Build a Merkle root from hashes in internal uint256 byte order."""
    hashes = leaves_internal.copy()
    if not hashes:
        return b'\x00' * 32
    while len(hashes) > 1:
        new_hashes: List[bytes] = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else hashes[i]
            new_hashes.append(dsha256(left + right))
        hashes = new_hashes
    return hashes[0]

# ===========================
# === Stratum Main service loop ===
# ===========================
def start_stratum_server(listen_host: str, listen_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_host, listen_port))
    sock.listen(100)
    log(f"Stratum proxy listen {listen_host}:{listen_port}")
    try:
        while True:
            # for example, conn=<socket>, addr=('192.168.1.100', 40231)
            conn, addr = sock.accept()  # if don't have new TCP socket, code flow will block in here

            with _miners_lock:
                if len(_miners) >= MAX_MINERS:
                    log("ASIC Maximum number of connections reached, connection rejected.", addr)
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue

            handler = StratumMinerHandler(conn, addr)
            handler.start()
    except KeyboardInterrupt:
        log("received the exit signal, shut down the server.")
    finally:
        try:
            sock.close()
        except Exception:
            pass

def main():
    if RPC_USER == "your_rpc_user" or RPC_PASS == "your_rpc_password":
        print(
            "Configure RPC_USER and RPC_PASS from bitcoin.conf "
            "at the top of the script."
        )
        exit(1)

    status_writer = RuntimeStatusWriter(
        RUNTIME_STATS,
        RUNTIME_STATUS_FILE,
        interval_seconds=RUNTIME_STATUS_INTERVAL,
        log_fn=log,
    )
    status_writer.start()
    log("Runtime status file:", RUNTIME_STATUS_FILE)

    # 'daemon=True' means if main thread is end, this child Thread will be killed.
    poller_thread = threading.Thread(target=gbt_poller, daemon=True)
    poller_thread.start()   # run child thread gbt_poller

    try:
        start_stratum_server(LISTEN_HOST, LISTEN_PORT)
    finally:
        status_writer.stop()
        status_writer.join(timeout=2.0)
        RUNTIME_STATS.set_service_state("stopped")
        try:
            status_writer.write_once()
        except Exception as e:
            log("Failed to write final runtime status:", e)

# ===========================
# === mainloop entry ===
# ===========================
# Run main only when this file is executed directly.
if __name__ == "__main__":
    main()
