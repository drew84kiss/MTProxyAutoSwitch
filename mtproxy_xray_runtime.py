from __future__ import annotations

import atexit
import base64
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import ssl
import struct
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen


DEFAULT_XRAY_SUBSCRIPTIONS = [
    "https://mifa.world/turbo#MIFA%20%20%7C%20%20Turbo",
    "https://mifa.world/vless#MIFA%20%20%7C%20%20Vless",
    "https://mifa.world/trojan",
    "https://mifa.world/hysteria",
    "https://mifa.world/vmess",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
]

TELEGRAM_PROBE_TARGETS = [
    ("api.telegram.org", 443, "api.telegram.org"),
    ("telegram.org", 443, "telegram.org"),
]
TELEGRAM_DCS = [
    ("149.154.167.50", 443),
    ("149.154.167.51", 443),
    ("149.154.167.91", 443),
]
TELEGRAM_XRAY_PROBE_TOTAL = 1 + len(TELEGRAM_DCS)
XRAY_SPEED_TEST_HOST = "speed.cloudflare.com"
XRAY_SPEED_TEST_PATH = "/__down?bytes=262144"
XRAY_SPEED_TEST_BYTES = 262144

XRAY_PROTOCOLS = {"vless", "vmess", "trojan"}
SING_BOX_PROTOCOLS = {"hysteria", "hysteria2", "hy2"}
XRAY_GOOD_DOWNLOAD_KBPS = 512.0


@dataclass
class XrayRuntimeConfig:
    subscription_urls: list[str] = field(default_factory=lambda: list(DEFAULT_XRAY_SUBSCRIPTIONS))
    socks_host: str = "127.0.0.1"
    socks_port: int = 10808
    probe_workers: int = 4
    probe_timeout_sec: float = 8.0
    max_servers: int = 250
    xray_binary_path: str = ""
    sing_box_binary_path: str = ""
    selection_strategy: str = "sticky_session"
    manual_upstream_url: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.socks_host}:{int(self.socks_port)}"


@dataclass
class XrayNode:
    protocol: str
    raw_url: str
    name: str
    host: str
    port: int
    credential: str
    query: dict[str, str] = field(default_factory=dict)
    source_url: str = ""
    runtime: str = "xray"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, int, str]:
        digest = hashlib.sha256(str(self.credential or "").encode("utf-8", errors="ignore")).hexdigest()[:16]
        return (self.protocol, self.host, int(self.port), digest)

    def title(self) -> str:
        return self.name or f"{self.protocol}://{self.host}:{self.port}"


@dataclass
class XrayProbeResult:
    node: XrayNode
    accepted: bool
    reason: str
    latency_ms: float | None
    successes: int
    attempts: int
    runtime: str
    api_latency_ms: float | None = None
    dc_latency_ms: float | None = None
    download_kbps: float | None = None

    def row(self) -> dict[str, Any]:
        return {
            "url": self.node.raw_url,
            "protocol": self.node.protocol,
            "runtime": self.runtime,
            "name": self.node.title(),
            "host": self.node.host,
            "port": self.node.port,
            "accepted": self.accepted,
            "reason": self.reason,
            "latency_ms": self.latency_ms,
            "api_latency_ms": self.api_latency_ms,
            "dc_latency_ms": self.dc_latency_ms,
            "download_kbps": self.download_kbps,
            "successes": self.successes,
            "attempts": self.attempts,
            "source": self.node.source_url,
        }


class XrayCoreRuntime:
    def __init__(
        self,
        config: XrayRuntimeConfig,
        *,
        root_dir: Path,
        out_dir: Path,
        log_sink: Callable[[str], None] | None = None,
        event_sink: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = config
        self.root_dir = root_dir
        self.out_dir = out_dir
        self.log_sink = log_sink
        self.event_sink = event_sink
        self._lock = threading.RLock()
        self._process: subprocess.Popen | None = None
        self._config_path: str = ""
        self._pid_path = self.out_dir / "xray_runtime.pid"
        self._cleanup_stale_processes()
        atexit.register(self.stop)
        self.active_result: XrayProbeResult | None = None
        self.last_working: list[XrayProbeResult] = []
        self.last_rejected: list[XrayProbeResult] = []
        self.discovered_nodes: list[XrayNode] = []
        self.last_error = ""
        self.last_refresh_finished_at = 0.0
        self._round_robin_cursor = 0
        self._sticky_key: tuple[str, str, int, str] | None = None
        self._load_cached_results()

    def is_running(self) -> bool:
        proc = self._process
        return bool(proc and proc.poll() is None)

    @property
    def local_tg_url(self) -> str:
        return f"tg://socks?server={self.config.socks_host}&port={int(self.config.socks_port)}"

    @property
    def local_proxy_url(self) -> str:
        return self.local_tg_url

    def start(self) -> bool:
        with self._lock:
            if self.is_running():
                return True
            if self.active_result is None:
                self.refresh()
            if self.is_running():
                return True
            if self.last_working:
                self._select_active_result(advance_round_robin=True)
            if self.active_result is None:
                self.last_error = "No accepted xray/sing-box nodes"
                self._log(f"[xray] start skipped: {self.last_error}")
                return False
            try:
                self._start_node(self.active_result.node, int(self.config.socks_port))
                self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                return True
            except Exception as exc:
                self.last_error = str(exc)
                self._log(f"[xray] start failed: {exc}")
                self._emit("xray_state", running=False, error=str(exc))
                return False

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            proc = self._process
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=timeout)
            elif proc is None:
                stale_pid = self._read_pid_file()
                if stale_pid:
                    _terminate_pid_tree(stale_pid, timeout=timeout)
            self._process = None
            self._unlink_pid_file()
            if self._config_path:
                with contextlib.suppress(Exception):
                    Path(self._config_path).unlink(missing_ok=True)
                self._config_path = ""
            self._emit("xray_state", running=False)

    def _read_pid_file(self) -> int | None:
        try:
            payload = json.loads(self._pid_path.read_text(encoding="utf-8"))
            pid = int(payload.get("pid") or 0)
            return pid if pid > 0 else None
        except Exception:
            return None

    def _write_pid_file(self, proc: subprocess.Popen, config_path: str, binary: str) -> None:
        with contextlib.suppress(Exception):
            self.out_dir.mkdir(parents=True, exist_ok=True)
            self._pid_path.write_text(
                json.dumps(
                    {
                        "pid": int(proc.pid),
                        "binary": str(binary),
                        "config": str(config_path),
                        "started_at": time.time(),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

    def _unlink_pid_file(self) -> None:
        with contextlib.suppress(Exception):
            self._pid_path.unlink(missing_ok=True)

    def _cleanup_stale_processes(self) -> None:
        stale_pid = self._read_pid_file()
        if stale_pid:
            _terminate_pid_tree(stale_pid, timeout=2.0)
            self._unlink_pid_file()
        _cleanup_stale_bundle_cores(self.root_dir, self.out_dir)

    def restart(self) -> bool:
        self.stop()
        return self.start()

    def probe_active_latency(self, timeout: float | None = None) -> float | None:
        if not self.is_running():
            return None
        probe_timeout = float(timeout if timeout is not None else self.config.probe_timeout_sec or 8.0)
        for host, target_port in TELEGRAM_DCS:
            latency = _socks_mtproto_latency(
                self.config.socks_host,
                int(self.config.socks_port),
                host,
                target_port,
                min(5.0, max(2.0, probe_timeout)),
            )
            if latency is not None:
                return latency
        return None

    def refresh(self, cancel_event: threading.Event | None = None) -> None:
        self._log("[xray] fetching subscriptions")
        previous_working = list(self.last_working)
        previous_active = self.active_result
        nodes = collect_subscription_nodes(
            self.config.subscription_urls,
            timeout=float(self.config.probe_timeout_sec or 8.0),
            max_servers=int(self.config.max_servers or 250),
            log_sink=self._log,
        )
        if cancel_event and cancel_event.is_set():
            raise RuntimeError("refresh_cancelled")
        self.discovered_nodes = list(nodes)
        if not self.last_working:
            self.last_rejected = [
                XrayProbeResult(node, False, "pending", None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
                for node in nodes
            ]
        self.last_error = ""
        self._log(f"[xray] parsed {len(nodes)} nodes")
        outcomes: list[XrayProbeResult] = []
        completed = 0
        workers = max(1, int(self.config.probe_workers or 1))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-probe") as executor:
            futures = {executor.submit(self._probe_node, node): node for node in nodes}
            for future in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                node = futures[future]
                completed += 1
                self._emit("xray_probe_progress", index=completed, total=len(nodes), node=node.title())
                outcome = future.result()
                outcomes.append(outcome)
                working_now = [item for item in outcomes if item.accepted]
                pending_keys = {future_node.key for future, future_node in futures.items() if not future.done()}
                rejected_now = [item for item in outcomes if not item.accepted]
                rejected_now.extend(
                    XrayProbeResult(pending_node, False, "pending", None, 0, TELEGRAM_XRAY_PROBE_TOTAL, pending_node.runtime)
                    for pending_node in nodes
                    if pending_node.key in pending_keys
                )
                if working_now:
                    self.last_working = sorted(
                        working_now,
                        key=_xray_result_sort_key,
                    )
                    self.active_result = self._best_working_result()
                self.last_rejected = rejected_now
                status = "ok" if outcome.accepted else outcome.reason
                latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                self._log(f"[xray] {node.protocol} {node.host}:{node.port} -> {status} {latency}")

        new_working = sorted(
            (item for item in outcomes if item.accepted),
            key=_xray_result_sort_key,
        )
        new_rejected = [item for item in outcomes if not item.accepted]
        if new_working:
            self.last_working = new_working
            self.last_rejected = new_rejected
            self._select_active_result(advance_round_robin=True)
        else:
            self.last_working = previous_working
            self.last_rejected = new_rejected
            self.active_result = previous_active
        if not new_working and self.active_result is None:
            self.last_error = _reason_summary(self.last_rejected) or "No accepted xray/sing-box nodes"
        else:
            self.last_error = ""
        self.last_refresh_finished_at = time.time()
        self._export_results()
        self._emit(
            "xray_refresh_complete",
            working=len(self.last_working),
            rejected=len(self.last_rejected),
            total=len(nodes),
            reason_counts=_reason_counts(self.last_rejected),
        )
        if new_working and self.active_result is not None:
            self.stop()
            try:
                self._start_node(self.active_result.node, int(self.config.socks_port))
                self._emit("xray_state", running=True, endpoint=self.config.endpoint)
            except Exception as exc:
                self.last_error = str(exc)
                self._log(f"[xray] start failed after refresh: {exc}")
                self._emit("xray_state", running=False, error=str(exc))

    def quick_sort_by_ping(self, cancel_event: threading.Event | None = None) -> int:
        with self._lock:
            nodes = [item.node for item in self.last_working]
        if not nodes:
            self.refresh(cancel_event=cancel_event)
            return len(self.last_working)

        self._log(f"[xray] quick ping sort for {len(nodes)} accepted nodes")
        previous_working = list(self.last_working)
        previous_active = self.active_result
        outcomes: list[XrayProbeResult] = []
        workers = max(1, int(self.config.probe_workers or 1))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-ping") as executor:
            futures = {executor.submit(self._probe_node_ping, node): node for node in nodes}
            completed = 0
            for future in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                node = futures[future]
                completed += 1
                self._emit("xray_probe_progress", index=completed, total=len(nodes), node=node.title())
                outcome = future.result()
                outcomes.append(outcome)
                status = "ok" if outcome.accepted else outcome.reason
                latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                self._log(f"[xray] quick {node.protocol} {node.host}:{node.port} -> {status} {latency}")

        with self._lock:
            old_rejected = [item for item in self.last_rejected if item.reason != "quick_ping_failed"]
            new_working = sorted((item for item in outcomes if item.accepted), key=_xray_result_sort_key)
            self.last_rejected = old_rejected + [item for item in outcomes if not item.accepted]
            if new_working:
                self.last_working = new_working
                self._select_active_result(advance_round_robin=True)
            else:
                self.last_working = previous_working
                self.active_result = previous_active
                self.last_error = _reason_summary([item for item in outcomes if not item.accepted]) or self.last_error
            self.last_refresh_finished_at = time.time()
            self._export_results()
            if new_working and self.active_result is not None and self.is_running():
                self.stop()
                self._start_node(self.active_result.node, int(self.config.socks_port))
                self._emit("xray_state", running=True, endpoint=self.config.endpoint)
        self._emit(
            "xray_refresh_complete",
            working=len(self.last_working),
            rejected=len(self.last_rejected),
            total=len(self.last_working) + len(self.last_rejected),
            reason_counts=_reason_counts(self.last_rejected),
        )
        return len(self.last_working)

    def snapshot(self) -> dict[str, Any]:
        rows = [item.row() for item in self.last_working]
        rejected_rows = [item.row() for item in self.last_rejected]
        pool_rows = rows + rejected_rows
        active = self.active_result.row() if self.active_result else None
        running = self.is_running()
        if active:
            latency_value = active.get("latency_ms")
            latency = ""
            if latency_value is not None:
                latency_number = float(latency_value)
                latency = f" · {'<1' if latency_number < 1 else str(int(round(latency_number)))} ms"
            active_text = (
                f"{active.get('protocol')} via {active.get('runtime')} · "
                f"{active.get('host')}:{active.get('port')} · {active.get('name')}{latency}"
            )
        else:
            active_text = ""
        return {
            "mode": "xray_core",
            "running": running,
            "local_running": running,
            "local_tg_url": self.local_tg_url,
            "local_url": self.local_proxy_url,
            "endpoint": self.config.endpoint,
            "status_text": "sing-box активен" if running else (self.last_error or ("sing-box ожидает перезапуск" if self.active_result else "sing-box остановлен")),
            "best_proxy": active_text,
            "active_node": active,
            "pool_rows": pool_rows,
            "xray_rejected_rows": rejected_rows,
            "working_count": len(rows),
            "rejected_count": len(rejected_rows),
            "unique_count": len(pool_rows),
            "balancer_strategy": _normalize_selection_strategy(self.config.selection_strategy),
            "manual_upstream_url": self.config.manual_upstream_url,
            "last_refresh_finished_at": self.last_refresh_finished_at,
            "reason_counts": _reason_counts(self.last_rejected),
            "xray_binary_found": bool(_resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")),
            "sing_box_binary_found": bool(_resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")),
        }

    def update_selection(self, selection_strategy: str, manual_upstream_url: str = "", *, restart: bool = True) -> None:
        with self._lock:
            self.config.selection_strategy = _normalize_selection_strategy(selection_strategy)
            self.config.manual_upstream_url = str(manual_upstream_url or "").strip()
            if self.config.manual_upstream_url and self.last_working and self._find_working_by_url(self.config.manual_upstream_url) is None:
                raise ValueError("xray node not found in accepted list")
            previous = self.active_result.node.key if self.active_result else None
            self._select_active_result(advance_round_robin=True)
            current = self.active_result.node.key if self.active_result else None
            if restart and previous != current and self.is_running():
                self.stop()
                if self.active_result is not None:
                    self._start_node(self.active_result.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)

    def _find_working_by_url(self, raw_url: str) -> XrayProbeResult | None:
        raw_url = str(raw_url or "").strip()
        return next((item for item in self.last_working if item.node.raw_url == raw_url), None)

    def _best_working_result(self) -> XrayProbeResult | None:
        return min(self.last_working, key=_xray_result_sort_key) if self.last_working else None

    def _select_active_result(self, *, advance_round_robin: bool) -> XrayProbeResult | None:
        ordered = sorted(self.last_working, key=_xray_result_sort_key)
        if not ordered:
            self.active_result = None
            return None

        manual = self._find_working_by_url(self.config.manual_upstream_url)
        if manual is not None:
            self.active_result = manual
            return manual

        strategy = _normalize_selection_strategy(self.config.selection_strategy)
        if strategy == "round_robin":
            index = self._round_robin_cursor % len(ordered)
            chosen = ordered[index]
            if advance_round_robin:
                self._round_robin_cursor = (self._round_robin_cursor + 1) % max(1, len(ordered))
        elif strategy == "consistent_hash":
            session_key = f"{self.config.socks_host}:{int(self.config.socks_port)}"
            digest = hashlib.blake2b(session_key.encode("utf-8", errors="ignore"), digest_size=8).digest()
            chosen = ordered[int.from_bytes(digest, "big") % len(ordered)]
        else:
            chosen = next((item for item in ordered if item.node.key == self._sticky_key), None)
            if chosen is None:
                chosen = ordered[0]
                self._sticky_key = chosen.node.key
        self.active_result = chosen
        return chosen

    def _probe_node(self, node: XrayNode) -> XrayProbeResult:
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path] if node.runtime == "xray" else [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            time.sleep(0.8)
            if proc.poll() is not None:
                return XrayProbeResult(node, False, "core exited", None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
            api_latencies: list[float] = []
            for host, target_port, server_name in TELEGRAM_PROBE_TARGETS[:1]:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    float(self.config.probe_timeout_sec or 8.0),
                )
                if latency is not None:
                    api_latencies.append(latency)
            total_probes = TELEGRAM_XRAY_PROBE_TOTAL
            if not api_latencies:
                return XrayProbeResult(node, False, "telegram_api_unreachable", None, 0, total_probes, node.runtime)

            dc_latencies: list[float] = []
            for host, target_port in TELEGRAM_DCS:
                latency = _socks_mtproto_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    float(self.config.probe_timeout_sec or 8.0),
                )
                if latency is not None:
                    dc_latencies.append(latency)
                    break
            if not dc_latencies:
                return XrayProbeResult(node, False, "telegram_dc_unreachable", None, len(api_latencies), total_probes, node.runtime)
            if not dc_latencies:
                return XrayProbeResult(node, False, "telegram_data_unreachable", None, 0, total_probes, node.runtime)
            api_latency = min(api_latencies)
            dc_latency = min(dc_latencies)
            accepted = dc_latency < 5000
            download_kbps = _xray_download_speed("127.0.0.1", port, float(self.config.probe_timeout_sec or 8.0)) if accepted else None
            return XrayProbeResult(
                node,
                accepted,
                "ready" if accepted else "slow",
                dc_latency,
                len(api_latencies) + len(dc_latencies),
                total_probes,
                node.runtime,
                api_latency_ms=api_latency,
                dc_latency_ms=dc_latency,
                download_kbps=download_kbps,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def _probe_node_ping(self, node: XrayNode) -> XrayProbeResult:
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            time.sleep(0.45)
            if proc.poll() is not None:
                return XrayProbeResult(node, False, "core exited", None, 0, len(TELEGRAM_DCS), node.runtime)
            dc_latencies: list[float] = []
            for host, target_port in TELEGRAM_DCS:
                latency = _socks_mtproto_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    float(self.config.probe_timeout_sec or 8.0),
                )
                if latency is not None:
                    dc_latencies.append(latency)
                    break
            if not dc_latencies:
                return XrayProbeResult(node, False, "quick_ping_failed", None, 0, len(TELEGRAM_DCS), node.runtime)
            dc_latency = min(dc_latencies)
            accepted = dc_latency < 5000
            download_kbps = _xray_download_speed("127.0.0.1", port, float(self.config.probe_timeout_sec or 8.0)) if accepted else None
            return XrayProbeResult(
                node,
                accepted,
                "ready" if accepted else "slow",
                dc_latency,
                len(dc_latencies),
                len(TELEGRAM_DCS),
                node.runtime,
                dc_latency_ms=dc_latency,
                download_kbps=download_kbps,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, len(TELEGRAM_DCS), node.runtime)
        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def _start_node(self, node: XrayNode, port: int) -> None:
        binary = self._binary_for_node(node)
        if not binary:
            raise RuntimeError(f"{node.runtime} binary not found")
        self.stop()
        config_path = _write_temp_config(self._build_config(node, port))
        self._process = subprocess.Popen(
            [binary, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=_subprocess_no_window(),
        )
        self._config_path = config_path
        self._write_pid_file(self._process, config_path, binary)
        time.sleep(0.5)
        if self._process.poll() is not None:
            self._unlink_pid_file()
            raise RuntimeError(f"{node.runtime} exited during startup")

    def _build_config(self, node: XrayNode, port: int) -> dict[str, Any]:
        if node.runtime == "sing-box":
            return _sing_box_config(node, "127.0.0.1", port)
        return _xray_config(node, "127.0.0.1", port)

    def _binary_for_node(self, node: XrayNode) -> str:
        if node.runtime == "sing-box":
            return _resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")
        return _resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")

    def _export_results(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "xray_working.json").write_text(
            json.dumps([item.row() for item in self.last_working], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (self.out_dir / "xray_rejected.json").write_text(
            json.dumps([item.row() for item in self.last_rejected], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _load_cached_results(self) -> None:
        working_path = self.out_dir / "xray_working.json"
        rejected_path = self.out_dir / "xray_rejected.json"
        self.last_working = self._load_result_file(working_path, accepted=True)
        self.last_rejected = self._load_result_file(rejected_path, accepted=False)
        if self.last_working:
            self.last_refresh_finished_at = working_path.stat().st_mtime
            self._select_active_result(advance_round_robin=False)
            self._log(f"[xray] loaded {len(self.last_working)} cached accepted nodes")

    def _load_result_file(self, path: Path, *, accepted: bool) -> list[XrayProbeResult]:
        if not path.exists():
            return []
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        results: list[XrayProbeResult] = []
        if not isinstance(rows, list):
            return results
        for row in rows:
            if not isinstance(row, dict):
                continue
            result = _result_from_row(row, accepted=accepted)
            if result is not None:
                results.append(result)
        return sorted(results, key=_xray_result_sort_key)

    def _log(self, message: str) -> None:
        if self.log_sink is not None:
            self.log_sink(str(message))

    def _emit(self, event_name: str, **payload: Any) -> None:
        if self.event_sink is not None:
            self.event_sink(event_name, payload)


def collect_subscription_nodes(
    urls: list[str],
    *,
    timeout: float,
    max_servers: int,
    log_sink: Callable[[str], None] | None = None,
) -> list[XrayNode]:
    nodes: dict[tuple[str, str, int, str], XrayNode] = {}
    source_urls = [str(url).strip() for url in urls if str(url).strip()]
    per_source_limit = 0
    if max_servers > 0 and source_urls:
        per_source_limit = max(1, (max_servers + len(source_urls) - 1) // len(source_urls))
    for source_url in source_urls:
        try:
            text = _fetch_text(source_url, timeout=timeout)
        except Exception as exc:
            if log_sink is not None:
                log_sink(f"[xray] source failed {source_url}: {exc}")
            continue
        source_added = 0
        for raw in _subscription_lines(text):
            node = parse_node_link(raw, source_url=source_url)
            if node is None:
                continue
            if node.key not in nodes:
                nodes[node.key] = node
                source_added += 1
            if per_source_limit > 0 and source_added >= per_source_limit:
                break
    result = list(nodes.values())
    return result[:max_servers] if max_servers > 0 else result


def _reason_counts(results: list[XrayProbeResult]) -> dict[str, int]:
    return dict(Counter(str(item.reason or "unknown") for item in results))


def _xray_result_sort_key(item: XrayProbeResult) -> tuple[int, float, float, str]:
    latency = item.dc_latency_ms if item.dc_latency_ms is not None else item.latency_ms
    speed = float(item.download_kbps or 0.0)
    speed_bucket = 0 if speed >= XRAY_GOOD_DOWNLOAD_KBPS else 1 if speed > 0 else 2
    return (
        speed_bucket,
        latency if latency is not None else 10_000_000.0,
        -speed,
        item.node.raw_url,
    )


def _normalize_selection_strategy(strategy: str) -> str:
    normalized = str(strategy or "").strip()
    if normalized not in {"round_robin", "consistent_hash", "sticky_session"}:
        return "sticky_session"
    return normalized


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _reason_summary(results: list[XrayProbeResult], *, limit: int = 3) -> str:
    counts = Counter(str(item.reason or "unknown") for item in results)
    if not counts:
        return ""
    parts = [f"{reason}: {count}" for reason, count in counts.most_common(limit)]
    return "No accepted nodes. " + ", ".join(parts)


def _result_from_row(row: dict[str, Any], *, accepted: bool) -> XrayProbeResult | None:
    node = parse_node_link(str(row.get("url") or ""), source_url=str(row.get("source") or "cache"))
    if node is None:
        return None
    try:
        latency = row.get("latency_ms")
        api_latency = row.get("api_latency_ms")
        dc_latency = row.get("dc_latency_ms")
        download = row.get("download_kbps")
        return XrayProbeResult(
            node=node,
            accepted=bool(row.get("accepted", accepted)),
            reason=str(row.get("reason") or ("ready" if accepted else "cached")),
            latency_ms=float(latency) if latency is not None else None,
            successes=int(row.get("successes") or (TELEGRAM_XRAY_PROBE_TOTAL if accepted else 0)),
            attempts=int(row.get("attempts") or TELEGRAM_XRAY_PROBE_TOTAL),
            runtime=str(row.get("runtime") or node.runtime),
            api_latency_ms=float(api_latency) if api_latency is not None else None,
            dc_latency_ms=float(dc_latency) if dc_latency is not None else None,
            download_kbps=float(download) if download is not None else None,
        )
    except (TypeError, ValueError):
        return None


def parse_node_link(raw_url: str, *, source_url: str = "") -> XrayNode | None:
    raw_url = str(raw_url or "").strip()
    if not raw_url:
        return None
    scheme = raw_url.split(":", 1)[0].lower()
    if scheme == "vmess":
        return _parse_vmess(raw_url, source_url)
    if scheme in {"vless", "trojan", "hysteria", "hysteria2", "hy2"}:
        return _parse_uri_node(raw_url, source_url)
    return None


def _parse_vmess(raw_url: str, source_url: str) -> XrayNode | None:
    payload = raw_url.split("://", 1)[1]
    decoded = _decode_base64(payload)
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    host = str(data.get("add") or data.get("host") or "").strip()
    port = int(data.get("port") or 0)
    uuid = str(data.get("id") or "").strip()
    if not host or not port or not uuid:
        return None
    query = {
        "security": str(data.get("tls") or data.get("security") or ""),
        "network": str(data.get("net") or "tcp"),
        "path": str(data.get("path") or ""),
        "host": str(data.get("host") or data.get("sni") or ""),
        "sni": str(data.get("sni") or ""),
        "alpn": str(data.get("alpn") or ""),
        "fp": str(data.get("fp") or ""),
    }
    return XrayNode(
        protocol="vmess",
        raw_url=raw_url,
        name=str(data.get("ps") or host),
        host=host,
        port=port,
        credential=uuid,
        query=query,
        source_url=source_url,
        runtime="xray",
        extra=data,
    )


def _parse_uri_node(raw_url: str, source_url: str) -> XrayNode | None:
    parsed = urlparse(raw_url)
    protocol = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = int(parsed.port or 0)
    credential = unquote(parsed.username or "")
    if not host or not port or not credential:
        return None
    query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
    name = unquote(parsed.fragment or "") or f"{protocol}://{host}:{port}"
    runtime = "sing-box" if protocol in SING_BOX_PROTOCOLS else "xray"
    if protocol == "hy2":
        protocol = "hysteria2"
    return XrayNode(
        protocol=protocol,
        raw_url=raw_url,
        name=name,
        host=host,
        port=port,
        credential=credential,
        query=query,
        source_url=source_url,
        runtime=runtime,
    )


def _subscription_lines(text: str) -> list[str]:
    text = str(text or "").strip()
    decoded = _decode_base64(text)
    candidates = decoded if "://" in decoded else text
    lines: list[str] = []
    for line in candidates.replace("\r", "\n").split("\n"):
        value = line.strip()
        if value:
            lines.append(value)
    return lines


def _fetch_text(url: str, *, timeout: float) -> str:
    clean_url = str(url or "").strip()
    req = Request(clean_url, headers={"User-Agent": "MTProxyAutoSwitch/1.0"})
    with urlopen(req, timeout=max(2.0, timeout)) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _decode_base64(value: str) -> str:
    compact = "".join(str(value or "").strip().split())
    if not compact:
        return ""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        with contextlib.suppress(Exception):
            padded = compact + "=" * (-len(compact) % 4)
            decoded = decoder(padded.encode("ascii"))
            text = decoded.decode("utf-8", errors="replace")
            stripped = text.lstrip()
            if "://" in text or "\n" in text or stripped.startswith(("{", "[")):
                return text
    return value


def _xray_config(node: XrayNode, listen_host: str, listen_port: int) -> dict[str, Any]:
    outbound = _xray_outbound(node)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": listen_host,
                "port": listen_port,
                "protocol": "socks",
                "settings": {"udp": False, "auth": "noauth"},
            }
        ],
        "outbounds": [outbound],
    }


def _xray_outbound(node: XrayNode) -> dict[str, Any]:
    q = node.query
    stream = _xray_stream_settings(q)
    if node.protocol == "vless":
        user = {"id": node.credential, "encryption": q.get("encryption") or "none"}
        if q.get("flow"):
            user["flow"] = q["flow"]
        return {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    if node.protocol == "vmess":
        user = {"id": node.credential, "alterId": int(node.extra.get("aid") or 0), "security": node.extra.get("scy") or "auto"}
        return {
            "protocol": "vmess",
            "tag": "proxy",
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    if node.protocol == "trojan":
        return {
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {"servers": [{"address": node.host, "port": node.port, "password": node.credential}]},
            "streamSettings": stream,
        }
    raise ValueError(f"Unsupported xray protocol: {node.protocol}")


def _xray_stream_settings(query: dict[str, str]) -> dict[str, Any]:
    network = (query.get("type") or query.get("network") or query.get("net") or "tcp").strip()
    if network == "h2":
        network = "http"
    security = query.get("security") or query.get("tls") or ""
    stream: dict[str, Any] = {"network": network}
    if security and security != "none":
        stream["security"] = security
    sni = query.get("sni") or query.get("serverName") or query.get("host") or ""
    if security == "tls":
        tls: dict[str, Any] = {}
        if sni:
            tls["serverName"] = sni
        if _truthy(query.get("allowInsecure") or query.get("allow_insecure") or query.get("insecure")):
            tls["allowInsecure"] = True
        if query.get("fp") or query.get("fingerprint"):
            tls["fingerprint"] = query.get("fp") or query.get("fingerprint")
        if query.get("alpn"):
            tls["alpn"] = [item.strip() for item in str(query.get("alpn") or "").split(",") if item.strip()]
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality: dict[str, Any] = {}
        if sni:
            reality["serverName"] = sni
        for source, target in [("pbk", "publicKey"), ("publicKey", "publicKey"), ("sid", "shortId"), ("fp", "fingerprint"), ("fingerprint", "fingerprint"), ("spx", "spiderX")]:
            if query.get(source):
                reality[target] = query[source]
        stream["realitySettings"] = reality
    if network == "ws":
        ws: dict[str, Any] = {}
        if query.get("path"):
            ws["path"] = query["path"]
        if query.get("host"):
            ws["headers"] = {"Host": query["host"]}
        stream["wsSettings"] = ws
    elif network == "tcp":
        header_type = query.get("headerType") or query.get("header") or ""
        if header_type and header_type != "none":
            tcp: dict[str, Any] = {"header": {"type": header_type}}
            if header_type == "http":
                request: dict[str, Any] = {}
                if query.get("host"):
                    request["headers"] = {"Host": [item.strip() for item in query["host"].split(",") if item.strip()]}
                if query.get("path"):
                    request["path"] = [item.strip() for item in query["path"].split(",") if item.strip()]
                if request:
                    tcp["header"]["request"] = request
            stream["tcpSettings"] = tcp
    elif network == "http":
        http: dict[str, Any] = {}
        if query.get("host"):
            http["host"] = [item.strip() for item in query["host"].split(",") if item.strip()]
        if query.get("path"):
            http["path"] = query["path"]
        stream["httpSettings"] = http
    elif network == "grpc":
        service = query.get("serviceName") or query.get("service") or ""
        stream["grpcSettings"] = {"serviceName": service}
        if query.get("authority"):
            stream["grpcSettings"]["authority"] = query["authority"]
    elif network == "httpupgrade":
        httpupgrade: dict[str, Any] = {}
        if query.get("path"):
            httpupgrade["path"] = query["path"]
        if query.get("host"):
            httpupgrade["host"] = query["host"]
        stream["httpupgradeSettings"] = httpupgrade
    elif network in {"splithttp", "xhttp"}:
        xhttp: dict[str, Any] = {}
        if query.get("path"):
            xhttp["path"] = query["path"]
        if query.get("host"):
            xhttp["host"] = query["host"]
        if query.get("mode"):
            xhttp["mode"] = query["mode"]
        stream["splithttpSettings"] = xhttp
    return stream


def _sing_box_config(node: XrayNode, listen_host: str, listen_port: int) -> dict[str, Any]:
    outbound: dict[str, Any] = {
        "type": node.protocol,
        "tag": "proxy",
        "server": node.host,
        "server_port": node.port,
    }
    if node.protocol == "hysteria":
        outbound["auth_str"] = node.credential
        outbound["up_mbps"] = int(node.query.get("upmbps") or node.query.get("up_mbps") or node.query.get("up") or 100)
        outbound["down_mbps"] = int(node.query.get("downmbps") or node.query.get("down_mbps") or node.query.get("down") or 100)
    else:
        outbound["password"] = node.credential
    sni = node.query.get("sni") or node.query.get("peer") or node.query.get("host") or ""
    tls = {"enabled": True, **({"server_name": sni} if sni else {})}
    if _truthy(node.query.get("insecure") or node.query.get("allowInsecure") or node.query.get("allow_insecure")):
        tls["insecure"] = True
    if node.query.get("alpn"):
        tls["alpn"] = [item.strip() for item in node.query["alpn"].split(",") if item.strip()]
    outbound["tls"] = tls
    if node.query.get("obfs"):
        obfs_type = node.query.get("obfs")
        if obfs_type == "1":
            obfs_type = "salamander"
        outbound["obfs"] = {"type": obfs_type, "password": node.query.get("obfs-password") or node.query.get("obfsPassword") or node.query.get("obfs_password") or ""}
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": listen_host, "listen_port": listen_port}],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }


def _write_temp_config(config: dict[str, Any]) -> str:
    handle = tempfile.NamedTemporaryFile("w", prefix="mtproxy-autoswitch-core-", suffix=".json", delete=False, encoding="utf-8")
    with handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
    return handle.name


def _terminate_process_tree(proc: subprocess.Popen, *, timeout: float = 5.0) -> None:
    if proc.poll() is not None:
        return
    with contextlib.suppress(Exception):
        proc.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=max(0.1, timeout))
    if proc.poll() is None:
        _terminate_pid_tree(int(proc.pid), timeout=max(1.0, timeout))
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=1.0)


def _terminate_pid_tree(pid: int, *, timeout: float = 5.0) -> None:
    if pid <= 0:
        return
    if os.name == "nt":
        with contextlib.suppress(Exception):
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(1.0, timeout),
                creationflags=_subprocess_no_window(),
                check=False,
            )
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, 15)
    deadline = time.monotonic() + max(0.1, timeout)
    while time.monotonic() < deadline:
        if not _pid_exists(pid):
            return
        time.sleep(0.05)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, 9)


def _pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            output = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2.0,
                creationflags=_subprocess_no_window(),
                check=False,
            ).stdout
            return str(pid) in output
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _cleanup_stale_bundle_cores(root_dir: Path, out_dir: Path) -> None:
    if os.name != "nt":
        return
    roots = [root_dir.resolve()]
    bundle_root = Path(str(getattr(sys, "_MEIPASS", "") or ""))
    if bundle_root:
        with contextlib.suppress(Exception):
            roots.append(bundle_root.resolve())
    module_root = Path(__file__).resolve().parent
    with contextlib.suppress(Exception):
        roots.append(module_root.resolve())
    root_literals = []
    for root in roots:
        text = str(root)
        if text and text not in root_literals:
            root_literals.append(text)
    if not root_literals:
        return
    ps_roots = "@(" + ",".join("'" + item.replace("'", "''") + "'" for item in root_literals) + ")"
    script = f"""
$roots = {ps_roots}
Get-CimInstance Win32_Process |
  Where-Object {{
    $exe = $_.ExecutablePath
    ($_.Name -in @('xray.exe','sing-box.exe')) -and
    ($_.CommandLine -match ' run -c ') -and
    ($_.CommandLine -match 'mtproxy-autoswitch-core-|tmp[a-z0-9]+\\.json') -and
    ($roots | Where-Object {{ $exe -like ($_.TrimEnd('\\') + '\\*') }})
  }} |
  ForEach-Object {{ taskkill /PID $_.ProcessId /T /F | Out-Null }}
"""
    with contextlib.suppress(Exception):
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4.0,
            creationflags=_subprocess_no_window(),
            check=False,
        )


def _resolve_binary(override_path: str, root_dir: Path, name: str) -> str:
    candidates: list[Path] = []
    if override_path:
        candidates.append(Path(override_path))
    exe = f"{name}.exe" if os.name == "nt" else name
    bundle_root = Path(str(getattr(sys, "_MEIPASS", "") or ""))
    if bundle_root:
        candidates.extend([bundle_root / "bin" / exe, bundle_root / exe])
    module_root = Path(__file__).resolve().parent
    candidates.extend(
        [
            root_dir / "bin" / exe,
            root_dir / exe,
            module_root / "bin" / exe,
            module_root / exe,
            Path(exe),
        ]
    )
    for path in candidates:
        if path.exists():
            return str(path.resolve())
    found = shutil.which(exe)
    if found:
        return found
    return ""


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _socks_open_connection(socks_host: str, socks_port: int, target_host: str, target_port: int, timeout: float) -> socket.socket | None:
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            sock.close()
            return None
        host_bytes = target_host.encode("idna")
        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + int(target_port).to_bytes(2, "big")
        sock.sendall(request)
        header = _recv_exact(sock, 4)
        if len(header) < 4 or header[1] != 0:
            sock.close()
            return None
        atyp = header[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            length = _recv_exact(sock, 1)
            if not length:
                sock.close()
                return None
            _recv_exact(sock, length[0])
        elif atyp == 4:
            _recv_exact(sock, 16)
        _recv_exact(sock, 2)
        return sock
    except Exception:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        return None


def _socks_https_latency(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float,
) -> float | None:
    started = time.perf_counter()
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            response = tls_sock.recv(32)
            if not response.startswith(b"HTTP/"):
                return None
            return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _xray_download_speed(socks_host: str, socks_port: int, timeout: float) -> float | None:
    return _socks_https_download_kbps(
        socks_host,
        socks_port,
        XRAY_SPEED_TEST_HOST,
        443,
        XRAY_SPEED_TEST_HOST,
        XRAY_SPEED_TEST_PATH,
        XRAY_SPEED_TEST_BYTES,
        min(5.0, max(2.0, timeout)),
    )


def _socks_https_download_kbps(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    max_bytes: int,
    timeout: float,
) -> float | None:
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            buffer = b""
            body_bytes = 0
            started: float | None = None
            deadline = time.perf_counter() + timeout
            while body_bytes < max_bytes and time.perf_counter() < deadline:
                chunk = tls_sock.recv(min(65536, max_bytes - body_bytes + 4096))
                if not chunk:
                    break
                if started is None:
                    buffer += chunk
                    header_end = buffer.find(b"\r\n\r\n")
                    if header_end < 0:
                        continue
                    headers = buffer[:header_end]
                    if not headers.startswith(b"HTTP/"):
                        return None
                    status = headers.split(b" ", 2)[1:2]
                    if not status or not status[0].startswith(b"2"):
                        return None
                    body = buffer[header_end + 4 :]
                    body_bytes += len(body)
                    started = time.perf_counter()
                    buffer = b""
                else:
                    body_bytes += len(chunk)
            if started is None or body_bytes <= 0:
                return None
            elapsed = max(0.001, time.perf_counter() - started)
            return (body_bytes / 1024.0) / elapsed
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _encode_abridged_packet(data: bytes) -> bytes:
    length = len(data) >> 2
    if length < 127:
        return struct.pack("B", length) + data
    return b"\x7f" + int(length).to_bytes(3, "little") + data


def _read_abridged_packet(sock: socket.socket) -> bytes:
    first = _recv_exact(sock, 1)
    if not first:
        return b""
    length = first[0]
    if length >= 127:
        extra = _recv_exact(sock, 3)
        if len(extra) < 3:
            return b""
        length = int.from_bytes(extra + b"\0", "little")
    return _recv_exact(sock, length << 2)


def _socks_mtproto_latency(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
) -> float | None:
    started = time.perf_counter()
    sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
    if sock is None:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\xef")
        nonce = secrets.randbits(127)
        nonce_bytes = nonce.to_bytes(16, "little", signed=True)
        body = struct.pack("<I", 0xBE7E8EF1) + nonce_bytes
        message_id = int(time.time() * (2**32)) & ~3
        payload = struct.pack("<q", 0) + struct.pack("<q", message_id) + struct.pack("<i", len(body)) + body
        sock.sendall(_encode_abridged_packet(payload))
        response = _read_abridged_packet(sock)
        if len(response) < 40 or response[:8] != b"\0" * 8:
            return None
        body_len = struct.unpack("<i", response[16:20])[0]
        if body_len <= 0 or 20 + body_len > len(response):
            return None
        response_body = response[20 : 20 + body_len]
        if nonce_bytes not in response_body:
            return None
        return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        with contextlib.suppress(Exception):
            sock.close()


def _subprocess_no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)
