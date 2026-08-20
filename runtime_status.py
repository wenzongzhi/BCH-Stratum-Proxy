from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable


HASHES_PER_DIFF1 = 2 ** 32
HASHRATE_WINDOWS = (60, 300, 900)
MAX_SHARE_SAMPLE_AGE = max(HASHRATE_WINDOWS)


@dataclass
class MinerRuntime:
    connection_id: str
    remote_ip: str
    remote_port: int
    connected_at: float
    difficulty: float
    subscribed: bool = False
    authorized: bool = False
    worker_name: str = ""
    payout_address: str | None = None
    current_job_id: str | None = None
    last_submit_at: float | None = None
    last_accepted_at: float | None = None
    last_rejected_at: float | None = None
    submitted_shares: int = 0
    accepted_shares: int = 0
    rejected_shares: int = 0
    rejected_by_reason: dict[str, int] = field(default_factory=dict)
    best_difficulty: float = 0.0
    last_share_difficulty: float | None = None
    block_candidates: int = 0
    blocks_accepted: int = 0
    # (accepted_at, assigned_stratum_difficulty)
    accepted_share_samples: deque[tuple[float, float]] = field(default_factory=deque)


class RuntimeStatsRegistry:
    """Thread-safe in-memory telemetry for the Stratum proxy.

    This object never performs network or file I/O. Mining threads only update
    small counters/timestamps under a short-lived lock.
    """

    def __init__(
        self,
        *,
        service_name: str,
        service_version: str,
        network: str,
        listen_host: str,
        listen_port: int,
        max_miners: int,
        default_difficulty: float,
        rpc_host: str,
        rpc_port: int,
        gbt_poll_interval_seconds: float,
    ) -> None:
        self._lock = threading.RLock()
        self._started_at = time.time()
        self._started_monotonic = time.monotonic()
        self._state = "running"

        self._service_name = service_name
        self._service_version = service_version
        self._network = network
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._max_miners = max_miners
        self._default_difficulty = float(default_difficulty)
        self._rpc_host = rpc_host
        self._rpc_port = rpc_port
        self._gbt_poll_interval_seconds = float(gbt_poll_interval_seconds)

        self._miners: dict[str, MinerRuntime] = {}

        # Process-lifetime counters. They do not decrease when a miner disconnects.
        self._shares_submitted_total = 0
        self._shares_accepted_total = 0
        self._shares_rejected_total = 0
        self._block_candidates_total = 0
        self._blocks_accepted_total = 0
        self._best_difficulty = 0.0

        # Latest BCHN / GBT state.
        self._gbt_ok = False
        self._last_gbt_at: float | None = None
        self._last_gbt_error: str | None = None
        self._template_height: int | None = None
        self._previous_block_hash: str | None = None
        self._bits: str | None = None
        self._network_difficulty: float | None = None
        self._template_tx_count: int = 0
        self._current_job_id: str | None = None
        self._last_job_at: float | None = None

    def set_service_state(self, state: str) -> None:
        with self._lock:
            self._state = state

    def register_miner(
        self,
        connection_id: str,
        remote_ip: str,
        remote_port: int,
        initial_difficulty: float,
    ) -> None:
        with self._lock:
            self._miners[connection_id] = MinerRuntime(
                connection_id=connection_id,
                remote_ip=remote_ip,
                remote_port=remote_port,
                connected_at=time.time(),
                difficulty=float(initial_difficulty),
            )

    def unregister_miner(self, connection_id: str) -> None:
        with self._lock:
            self._miners.pop(connection_id, None)

    def set_subscribed(self, connection_id: str, subscribed: bool = True) -> None:
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.subscribed = subscribed

    def set_authorized(
        self,
        connection_id: str,
        *,
        worker_name: str,
        payout_address: str,
    ) -> None:
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.authorized = True
                miner.worker_name = worker_name
                miner.payout_address = payout_address

    def set_difficulty(self, connection_id: str, difficulty: float) -> None:
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.difficulty = float(difficulty)

    def set_miner_job(self, connection_id: str, job_id: str | None) -> None:
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.current_job_id = job_id

    def record_submit(self, connection_id: str) -> None:
        now = time.time()
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.last_submit_at = now
                miner.submitted_shares += 1
            self._shares_submitted_total += 1

    def record_share_difficulty(self, connection_id: str, difficulty: float) -> None:
        difficulty = max(0.0, float(difficulty))
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.last_share_difficulty = difficulty
                miner.best_difficulty = max(miner.best_difficulty, difficulty)
            self._best_difficulty = max(self._best_difficulty, difficulty)

    def record_accepted(self, connection_id: str, assigned_difficulty: float) -> None:
        now = time.time()
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.last_accepted_at = now
                miner.accepted_shares += 1
                miner.accepted_share_samples.append(
                    (now, max(0.0, float(assigned_difficulty)))
                )
                self._prune_samples_locked(miner, now)
            self._shares_accepted_total += 1

    def record_rejected(self, connection_id: str, reason: str) -> None:
        now = time.time()
        reason = reason.strip() or "unknown"
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.last_rejected_at = now
                miner.rejected_shares += 1
                miner.rejected_by_reason[reason] = (
                    miner.rejected_by_reason.get(reason, 0) + 1
                )
            self._shares_rejected_total += 1

    def record_block_candidate(self, connection_id: str) -> None:
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.block_candidates += 1
            self._block_candidates_total += 1

    def record_block_accepted(self, connection_id: str) -> None:
        with self._lock:
            miner = self._miners.get(connection_id)
            if miner:
                miner.blocks_accepted += 1
            self._blocks_accepted_total += 1

    def update_gbt(
        self,
        *,
        height: int | None,
        previous_block_hash: str | None,
        bits: str | None,
        network_difficulty: float | None,
        template_tx_count: int,
    ) -> None:
        with self._lock:
            self._gbt_ok = True
            self._last_gbt_at = time.time()
            self._last_gbt_error = None
            self._template_height = height
            self._previous_block_hash = previous_block_hash
            self._bits = bits
            self._network_difficulty = network_difficulty
            self._template_tx_count = max(0, int(template_tx_count))

    def record_gbt_error(self, error: Any) -> None:
        with self._lock:
            self._gbt_ok = False
            self._last_gbt_error = str(error)

    def update_job(self, job_id: str | None) -> None:
        with self._lock:
            self._current_job_id = job_id
            self._last_job_at = time.time() if job_id else None

    def _prune_samples_locked(self, miner: MinerRuntime, now: float) -> None:
        cutoff = now - MAX_SHARE_SAMPLE_AGE
        while miner.accepted_share_samples:
            if miner.accepted_share_samples[0][0] >= cutoff:
                break
            miner.accepted_share_samples.popleft()

    def _hashrate_locked(
        self,
        miner: MinerRuntime,
        now: float,
        window_seconds: int,
    ) -> float:
        self._prune_samples_locked(miner, now)
        cutoff = now - window_seconds
        work = sum(
            difficulty * HASHES_PER_DIFF1
            for timestamp, difficulty in miner.accepted_share_samples
            if timestamp >= cutoff
        )
        # Do not divide a brand-new connection by a full 5/15 minute window.
        elapsed = min(float(window_seconds), max(1.0, now - miner.connected_at))
        return work / elapsed

    def _miner_snapshot_locked(self, miner: MinerRuntime, now: float) -> dict[str, Any]:
        hashrate = {
            "1m_hs": round(self._hashrate_locked(miner, now, 60), 3),
            "5m_hs": round(self._hashrate_locked(miner, now, 300), 3),
            "15m_hs": round(self._hashrate_locked(miner, now, 900), 3),
        }
        return {
            "connection_id": miner.connection_id,
            "remote_ip": miner.remote_ip,
            "remote_port": miner.remote_port,
            "connected_at": miner.connected_at,
            "connected_seconds": round(max(0.0, now - miner.connected_at), 3),
            "subscribed": miner.subscribed,
            "authorized": miner.authorized,
            "worker_name": miner.worker_name,
            "payout_address": miner.payout_address,
            "difficulty": miner.difficulty,
            "current_job_id": miner.current_job_id,
            "last_submit_at": miner.last_submit_at,
            "last_accepted_at": miner.last_accepted_at,
            "last_rejected_at": miner.last_rejected_at,
            "shares": {
                "submitted": miner.submitted_shares,
                "accepted": miner.accepted_shares,
                "rejected": miner.rejected_shares,
                "rejected_by_reason": dict(miner.rejected_by_reason),
            },
            "last_share_difficulty": miner.last_share_difficulty,
            "best_difficulty": miner.best_difficulty,
            "hashrate": hashrate,
            "block_candidates": miner.block_candidates,
            "blocks_accepted": miner.blocks_accepted,
        }

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            miners = [
                self._miner_snapshot_locked(miner, now)
                for miner in self._miners.values()
            ]
            miners.sort(key=lambda item: (item["remote_ip"], item["remote_port"]))

            total_hashrate = {
                key: round(sum(m["hashrate"][key] for m in miners), 3)
                for key in ("1m_hs", "5m_hs", "15m_hs")
            }
            subscribed_miners = sum(1 for m in miners if m["subscribed"])
            authorized_miners = sum(1 for m in miners if m["authorized"])

            template_height = self._template_height
            tip_height = (
                template_height - 1
                if isinstance(template_height, int) and template_height > 0
                else None
            )

            return {
                "schema_version": 1,
                "generated_at": now,
                "service": {
                    "id": self._service_name,
                    "version": self._service_version,
                    "state": self._state,
                    "pid": os.getpid(),
                    "started_at": self._started_at,
                    "uptime_seconds": round(
                        max(0.0, time.monotonic() - self._started_monotonic),
                        3,
                    ),
                },
                "stratum": {
                    "listen_host": self._listen_host,
                    "listen_port": self._listen_port,
                    "max_miners": self._max_miners,
                    "default_difficulty": self._default_difficulty,
                    "connected_miners": len(miners),
                    "subscribed_miners": subscribed_miners,
                    "authorized_miners": authorized_miners,
                },
                "node": {
                    "rpc_host": self._rpc_host,
                    "rpc_port": self._rpc_port,
                    "gbt_poll_interval_seconds": self._gbt_poll_interval_seconds,
                    "gbt_ok": self._gbt_ok,
                    "last_gbt_at": self._last_gbt_at,
                    "last_gbt_error": self._last_gbt_error,
                },
                "chain": {
                    "network": self._network,
                    "tip_height": tip_height,
                    "template_height": template_height,
                    "previous_block_hash": self._previous_block_hash,
                    "bits": self._bits,
                    "network_difficulty": self._network_difficulty,
                    "template_tx_count": self._template_tx_count,
                    "current_job_id": self._current_job_id,
                    "last_job_at": self._last_job_at,
                },
                "summary": {
                    "hashrate": total_hashrate,
                    "best_difficulty": self._best_difficulty,
                    "shares_submitted_total": self._shares_submitted_total,
                    "shares_accepted_total": self._shares_accepted_total,
                    "shares_rejected_total": self._shares_rejected_total,
                    "block_candidates_total": self._block_candidates_total,
                    "blocks_accepted_total": self._blocks_accepted_total,
                },
                "miners": miners,
            }


class RuntimeStatusWriter(threading.Thread):
    """Best-effort heartbeat writer using same-directory atomic replacement."""

    def __init__(
        self,
        registry: RuntimeStatsRegistry,
        path: str | os.PathLike[str],
        *,
        interval_seconds: float = 1.0,
        log_fn: Callable[..., None] | None = None,
    ) -> None:
        super().__init__(name="runtime-status-writer", daemon=True)
        self._registry = registry
        self._path = Path(path)
        self._interval_seconds = max(0.2, float(interval_seconds))
        self._stop_event = threading.Event()
        self._log_fn = log_fn

    @property
    def path(self) -> Path:
        return self._path

    def stop(self) -> None:
        self._stop_event.set()

    def write_once(self) -> None:
        snapshot = self._registry.snapshot()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._path.with_name(self._path.name + ".tmp")

        with temp_path.open("w", encoding="utf-8", newline="\n") as f:
            json.dump(
                snapshot,
                f,
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            f.write("\n")

        # temp and target are in the same directory/filesystem.
        os.replace(temp_path, self._path)

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.write_once()
            except Exception as exc:
                # Telemetry must never bring down the mining service.
                if self._log_fn is not None:
                    self._log_fn("runtime status writer error:", exc)

            self._stop_event.wait(self._interval_seconds)
