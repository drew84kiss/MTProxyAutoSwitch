from __future__ import annotations

import contextlib
import ctypes
import json
import os
import shutil
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mtproxy_collector import (
    CollectorConfig,
    CollectorRunResult,
    DEFAULT_SOURCES,
    ProbeOutcome,
    ProbeSettings,
    ProxyRecord,
    build_report,
    outcome_sort_key,
    parse_proxy_link,
    probe_all,
    run_collection,
    run_async,
)
from mtproxy_local_proxy import LocalMTProxyServer, ProxyPool
from mtproxy_telegram import (
    DEFAULT_SOURCE_MAX_AGE_DAYS,
    DEFAULT_SOURCE_MAX_PROXIES,
    DEFAULT_SOURCE_MAX_MESSAGES,
    DEFAULT_TELEGRAM_SOURCE_URLS,
    TELEGRAM_USER_ERROR_PREFIX,
    MediaProbeResult,
    TelegramAuthConfig,
    auth_is_configured,
    collect_telegram_sources_proxies,
    collect_thread_proxies,
    complete_login,
    deep_media_probe,
    get_auth_status,
    light_media_probe,
    logout,
    normalize_telegram_phone,
    qr_login_flow,
    request_login_code,
    send_proxy_list_to_saved_messages,
)


def runtime_root() -> Path:
    if getattr(sys, "frozen", False):
        executable_path = Path(sys.executable).resolve()
        if sys.platform == "darwin":
            app_bundle = _macos_app_bundle_path(executable_path)
            if app_bundle is not None:
                bundle_parent = app_bundle.parent
                if any((bundle_parent / name).exists() for name in ("config.json", ".env", "list")):
                    return bundle_parent
                if os.access(bundle_parent, os.W_OK):
                    return bundle_parent
                support_dir = Path.home() / "Library" / "Application Support" / _runtime_app_dir_name()
                support_dir.mkdir(parents=True, exist_ok=True)
                return support_dir
        return executable_path.parent
    return Path(__file__).resolve().parent


def _macos_app_bundle_path(executable_path: Path) -> Path | None:
    macos_dir = executable_path.parent
    if macos_dir.name != "MacOS":
        return None
    contents_dir = macos_dir.parent
    if contents_dir.name != "Contents":
        return None
    app_bundle = contents_dir.parent
    if app_bundle.suffix != ".app":
        return None
    return app_bundle


def _runtime_app_dir_name() -> str:
    return "MTProxyAutoSwitch"


def bundled_resource_roots() -> list[Path]:
    roots: list[Path] = []
    if getattr(sys, "frozen", False):
        executable_path = Path(sys.executable).resolve()
        roots.append(Path(getattr(sys, "_MEIPASS", executable_path.parent)))
        roots.append(executable_path.parent)
        if sys.platform == "darwin":
            app_bundle = _macos_app_bundle_path(executable_path)
            if app_bundle is not None:
                roots.append(app_bundle.parent)
                roots.append(app_bundle / "Contents" / "Resources")
    roots.append(Path(__file__).resolve().parent)
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        marker = str(root.resolve())
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(root)
    return unique


def persistent_state_root(install_dir: Path) -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        root = base / _runtime_app_dir_name()
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support" / _runtime_app_dir_name()
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
        root = base / _runtime_app_dir_name()
    root.mkdir(parents=True, exist_ok=True)
    return root


DEFAULT_MAX_PROXIES = 500
DEFAULT_DEEP_MEDIA_TOP_N = 0
DEFAULT_FAST_LIST_LIMIT = 24
FAST_LIST_FILE_NAME = "fast_list.txt"
DEFAULT_LOCAL_SECRET = "274763e0d711fd394e833938dd93c8c3"
DEFAULT_TELEGRAM_API_PROXY_URL = (
    "https://t.me/proxy?server=max.ru.rightarion.ru&port=443"
    "&secret=eedcaae509a2455bbfc6165f1708fd5c586d61782e7275"
)
BALANCER_STRATEGIES = {
    "round_robin",
    "consistent_hash",
    "sticky_session",
}
REMOVED_WEB_SOURCES = {
    "https://mtpro.xyz/socks5-ru",
}


@dataclass
class AppConfig:
    sources: list[str] = field(default_factory=lambda: list(DEFAULT_SOURCES))
    out_dir: str = "list"
    duration: float = 35.0
    interval: float = 3.0
    timeout: float = 8.0
    workers: int = 25
    fetch_timeout: float = 15.0
    max_latency_ms: float = 300.0
    min_success_rate: float = 0.7
    max_high_latency_ratio: float = 0.6
    high_latency_streak: int = 3
    max_proxies: int = DEFAULT_MAX_PROXIES
    fast_list_limit: int = DEFAULT_FAST_LIST_LIMIT
    local_host: str = "127.0.0.1"
    local_port: int = 1443
    local_secret: str = DEFAULT_LOCAL_SECRET
    balancer_strategy: str = "sticky_session"
    manual_upstream_url: str = ""
    auto_start_local: bool = True
    autostart_enabled: bool = False
    start_minimized_to_tray: bool = False
    close_behavior: str = "ask"
    telegram_sources_enabled: bool = False
    telegram_sources: list[str] = field(default_factory=lambda: list(DEFAULT_TELEGRAM_SOURCE_URLS))
    thread_source_enabled: bool = False
    thread_source_url: str = "https://t.me/strbypass/237103"
    telegram_source_max_age_days: int = DEFAULT_SOURCE_MAX_AGE_DAYS
    telegram_source_max_messages: int = DEFAULT_SOURCE_MAX_MESSAGES
    telegram_source_max_proxies: int = DEFAULT_SOURCE_MAX_PROXIES
    live_probe_interval_sec: int = 20
    live_probe_duration_sec: float = 4.0
    live_probe_top_n: int = 12
    deep_media_enabled: bool = False
    rf_whitelist_check_enabled: bool = False
    deep_media_top_n: int = DEFAULT_DEEP_MEDIA_TOP_N
    appearance: str = "auto"
    auto_update_enabled: bool = True
    telegram_api_id: int = 0
    telegram_api_hash: str = ""
    telegram_api_proxy_enabled: bool = False
    telegram_api_proxy_url: str = DEFAULT_TELEGRAM_API_PROXY_URL
    telegram_phone: str = ""
    telegram_session_file: str = "telegram_user.sec"


LIST_DIR_NAME = "list"
LIST_FILE_NAME = "proxy_list.txt"
FAST_LIST_FILE_NAME = "fast_list.txt"
REJECTED_FILE_NAME = "rejected_list.txt"
ALL_FILE_NAME = "all_list.txt"
SOCKS5_FILE_NAME = "socks5_list.txt"
REPORT_FILE_NAME = "report.json"
SOURCE_AUDIT_FILE_NAME = "source_audit.txt"
LEGACY_OUT_DIR_NAME = "mtproxy_output"
LEGACY_WORKING_FILE_NAME = "mtproxy_working.txt"
LEGACY_REJECTED_FILE_NAME = "mtproxy_rejected.txt"
LEGACY_ALL_FILE_NAME = "mtproxy_all.txt"
LEGACY_SOCKS5_FILE_NAME = "socks5_all.txt"
LEGACY_REPORT_FILE_NAME = "mtproxy_report.json"
CONFIG_FILE_NAME = "config.json"
DATA_DIR_NAME = "data"
TELEGRAM_AUTH_STATE_FILE_NAME = "telegram_auth.json"
FILE_ATTRIBUTE_HIDDEN = 0x02
RECOMMENDED_WEB_SOURCE_ADDITIONS = [
    "https://t.me/s/ProxyFree_Ru",
]
RECOMMENDED_TELEGRAM_SOURCE_ADDITIONS = [
    "https://t.me/telemtrs/16160",
    "https://t.me/telemtfreeproxy",
    "https://t.me/ProxyFree_Ru",
]
SAVED_MESSAGES_EXPORT_LIMIT = 20


def is_public_release() -> bool:
    return True


def _read_env_file(root_dir: Path) -> dict[str, str]:
    env_path = root_dir / ".env"
    if not env_path.exists():
        return {}
    values: dict[str, str] = {}
    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    except Exception:
        return {}
    return values


class AppRuntime:
    def __init__(
        self,
        *,
        log_sink: Any | None = None,
        event_sink: Any | None = None,
    ) -> None:
        self.install_dir = runtime_root()
        self.root_dir = self.install_dir
        self.state_root = persistent_state_root(self.install_dir)
        self._migrate_legacy_state()
        self.state_dir = self.state_root / DATA_DIR_NAME
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _hide_windows_path(self.state_dir)
        self.env_values = {
            **_read_env_file(self.install_dir),
            **_read_env_file(self.state_root),
        }
        self.config_path = self.install_dir / CONFIG_FILE_NAME
        self.config = self._load_config()
        self._migrate_legacy_telegram_session()
        self.pool = ProxyPool()
        self.log_sink = log_sink
        self.event_sink = event_sink
        self.local_server = LocalMTProxyServer(
            self.pool,
            host=self.config.local_host,
            port=self.config.local_port,
            secret=self.config.local_secret,
            selection_strategy=self.config.balancer_strategy,
            log_sink=self._log,
            event_sink=self._emit,
        )
        self.last_result: CollectorRunResult | None = None
        self.last_outcomes: list[ProbeOutcome] = []
        self.last_working: list[ProbeOutcome] = []
        self.last_rejected: list[ProbeOutcome] = []
        self.last_export: dict[str, str] = {}
        self.last_refresh_started_at: float = 0.0
        self.last_refresh_finished_at: float = 0.0
        self.seed_source: str = ""
        self.seed_loaded_at: float = 0.0
        self.thread_status: str = "not_checked"
        self.thread_proxy_count: int = 0
        self._latest_deep_media_scores: dict[tuple[str, int, str], MediaProbeResult] = {}
        self.telegram_lock = threading.RLock()
        self._last_quick_probe_at: float = 0.0
        self._refresh_in_progress = threading.Event()
        with contextlib.suppress(Exception):
            stale_cache_path = self.state_dir / "proxy_list_persist.txt"
            if stale_cache_path.exists():
                stale_cache_path.unlink()
        self._load_initial_pool()
        self._apply_manual_override_from_config()
        self.live_probe_stop = threading.Event()
        self._last_focused_probe_at: float = 0.0
        self._last_broad_probe_at: float = 0.0
        self._last_media_pulse_at: float = 0.0
        self._last_media_activity_at: float = 0.0
        self._last_heavy_upload_at: float = 0.0
        self._last_media_accel_probe_at: float = 0.0
        self._health_cycle_lock = threading.Lock()
        self.live_probe_thread = threading.Thread(target=self._live_probe_loop, daemon=True, name="mtproxy-live-probe")
        self.live_probe_thread.start()
        self._auth_code_hash: str = ""
        self._auth_code_phone: str = ""
        if self.config.auto_start_local and self.pool.count() > 0:
            self.start_local_server(
                raise_on_verify_failure=False,
                pre_probe=False,
                verify=False,
            )

    @property
    def auth_config(self) -> TelegramAuthConfig:
        env_api_id = str(self.env_values.get("MTPROXY_TELEGRAM_API_ID") or os.environ.get("MTPROXY_TELEGRAM_API_ID") or "").strip()
        env_api_hash = str(self.env_values.get("MTPROXY_TELEGRAM_API_HASH") or os.environ.get("MTPROXY_TELEGRAM_API_HASH") or "").strip()
        config_api_id = int(self.config.telegram_api_id or 0)
        config_api_hash = self.config.telegram_api_hash.strip()
        return TelegramAuthConfig(
            api_id=int(env_api_id or config_api_id or 0),
            api_hash=(env_api_hash or config_api_hash or ""),
            session_path=self.telegram_session_path,
            phone=self.config.telegram_phone.strip(),
        )

    @property
    def telegram_session_path(self) -> Path:
        session_name = Path(str(self.config.telegram_session_file or "telegram_user.sec")).name
        return (self.state_dir / session_name).resolve()

    def shutdown(self) -> None:
        self.live_probe_stop.set()
        if self.live_probe_thread.is_alive():
            self.live_probe_thread.join(timeout=3.0)
        self.stop_local_server()

    def save_config(self) -> None:
        payload = self._config_payload(self.config)
        self.config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self._save_persistent_telegram_auth(payload)

    @staticmethod
    def _config_payload(config: AppConfig) -> dict[str, Any]:
        payload = asdict(config)
        payload["telegram_session_file"] = Path(str(payload.get("telegram_session_file") or "telegram_user.sec")).name
        payload.pop("fast_list_limit", None)
        return payload

    def _migrate_legacy_state(self) -> None:
        if self.state_root == self.install_dir:
            return
        self.state_root.mkdir(parents=True, exist_ok=True)
        for name in (CONFIG_FILE_NAME, LIST_DIR_NAME, LEGACY_OUT_DIR_NAME, "app_state"):
            source_path = self.state_root / name
            target_path = self.install_dir / name
            if not source_path.exists() or target_path.exists():
                continue
            with contextlib.suppress(Exception):
                if source_path.is_dir():
                    shutil.copytree(source_path, target_path)
                else:
                    shutil.copy2(source_path, target_path)

    def _migrate_legacy_telegram_session(self) -> None:
        session_name = Path(str(self.config.telegram_session_file or "telegram_user.sec")).name or "telegram_user.sec"
        target_session = self.state_dir / session_name
        target_key = self.state_dir / "session_key.bin"
        legacy_dirs = [
            self.install_dir / DATA_DIR_NAME,
            self.install_dir / "app_state",
            self.state_root / "app_state",
        ]
        legacy_session_names = {
            session_name,
            "telegram_user.sec",
            "telegram_user.session",
            "telegram_user",
        }
        for legacy_dir in legacy_dirs:
            if not legacy_dir.exists() or legacy_dir.resolve() == self.state_dir.resolve():
                continue
            for legacy_name in legacy_session_names:
                source_session = legacy_dir / legacy_name
                if not source_session.exists() or target_session.exists():
                    continue
                with contextlib.suppress(Exception):
                    shutil.copy2(source_session, target_session)
                    _hide_windows_path(target_session)
                break
            source_key = legacy_dir / "session_key.bin"
            if source_key.exists() and not target_key.exists():
                with contextlib.suppress(Exception):
                    shutil.copy2(source_key, target_key)
                    _hide_windows_path(target_key)
        _hide_windows_path(self.state_dir)

    @staticmethod
    def _normalize_config(config: AppConfig) -> AppConfig:
        normalized = AppConfig(**asdict(config))
        if int(normalized.max_proxies or 0) <= 0:
            normalized.max_proxies = DEFAULT_MAX_PROXIES
        if int(normalized.fast_list_limit or 0) <= 0:
            normalized.fast_list_limit = DEFAULT_FAST_LIST_LIMIT
        if str(normalized.balancer_strategy or "").strip() not in BALANCER_STRATEGIES:
            normalized.balancer_strategy = "sticky_session"
        normalized.manual_upstream_url = str(normalized.manual_upstream_url or "").strip()
        normalized.local_secret = str(normalized.local_secret or DEFAULT_LOCAL_SECRET).strip().lower()
        try:
            bytes.fromhex(normalized.local_secret[2:] if normalized.local_secret.startswith(("dd", "ee")) else normalized.local_secret)
        except ValueError:
            normalized.local_secret = DEFAULT_LOCAL_SECRET
        normalized.telegram_api_proxy_url = str(
            normalized.telegram_api_proxy_url or DEFAULT_TELEGRAM_API_PROXY_URL
        ).strip()
        if normalized.telegram_api_proxy_url and parse_proxy_link(
            normalized.telegram_api_proxy_url,
            "telegram_api_proxy",
            "telegram_api_proxy",
        ) is None:
            normalized.telegram_api_proxy_url = DEFAULT_TELEGRAM_API_PROXY_URL
        normalized.telegram_session_file = Path(
            str(normalized.telegram_session_file or "telegram_user.sec")
        ).name or "telegram_user.sec"
        if int(normalized.telegram_source_max_age_days or 0) <= 0:
            normalized.telegram_source_max_age_days = DEFAULT_SOURCE_MAX_AGE_DAYS
        if int(normalized.telegram_source_max_messages or 0) <= 0:
            normalized.telegram_source_max_messages = DEFAULT_SOURCE_MAX_MESSAGES
        if int(normalized.telegram_source_max_proxies or 0) <= 0:
            normalized.telegram_source_max_proxies = DEFAULT_SOURCE_MAX_PROXIES
        if int(normalized.deep_media_top_n or 0) < 0:
            normalized.deep_media_top_n = DEFAULT_DEEP_MEDIA_TOP_N
        return normalized

    @staticmethod
    def _local_server_signature(config: AppConfig) -> tuple[object, ...]:
        return (
            config.local_host,
            int(config.local_port),
            config.local_secret,
        )

    def apply_config(self, config: AppConfig) -> bool:
        normalized = self._normalize_config(config)
        current = self._normalize_config(self.config)
        if normalized == current:
            self.config = normalized
            self._apply_manual_override_from_config()
            return False

        restart_local_server = self._local_server_signature(normalized) != self._local_server_signature(current)
        self.config = normalized
        self.save_config()
        was_running = self.local_server.is_running()
        if restart_local_server:
            if was_running:
                self.stop_local_server()
            self.local_server = LocalMTProxyServer(
                self.pool,
                host=self.config.local_host,
                port=self.config.local_port,
                secret=self.config.local_secret,
                selection_strategy=self.config.balancer_strategy,
                log_sink=self._log,
                event_sink=self._emit,
            )
            if was_running and self.config.auto_start_local and self.pool.count() > 0:
                self.start_local_server(raise_on_verify_failure=False)
        else:
            self.local_server.set_selection_strategy(self.config.balancer_strategy)
        self._apply_manual_override_from_config()
        return True

    def start_local_server(
        self,
        *,
        raise_on_verify_failure: bool = True,
        pre_probe: bool = True,
        verify: bool = True,
    ) -> bool:
        if self.pool.count() <= 0:
            self._log("[local] start skipped: no working proxies")
            return False
        try:
            if pre_probe:
                self.quick_probe_pool(limit=min(self.config.live_probe_top_n, max(4, self.pool.count())), reason="startup")
            self.local_server.start()
            if verify:
                self._verify_local_server()
            return True
        except Exception as exc:
            self.local_server.stop()
            self._log(f"[local] start self-test failed: {exc}")
            self._emit(
                "local_server_state",
                running=False,
                host=self.config.local_host,
                port=self.config.local_port,
                error=str(exc),
            )
            if raise_on_verify_failure:
                raise
            return False

    def stop_local_server(self) -> None:
        self.local_server.stop()

    def _restart_local_server_if_running(self, *, reason: str) -> None:
        if not self.local_server.is_running():
            return
        self._log(f"[local] restarting frontend ({reason})")
        self.local_server.stop()
        self.local_server.start()
        self._verify_local_server()

    def _verify_local_server(self) -> None:
        local_proxy = parse_proxy_link(self.local_server.local_proxy_url, "local", "local")
        if local_proxy is None:
            raise RuntimeError("local_proxy_url_invalid")
        settings = ProbeSettings(
            duration=5.0,
            interval=0.8,
            timeout=max(5.0, min(float(self.config.timeout or 8.0), 8.0)),
            max_latency_ms=max(2000.0, float(self.config.max_latency_ms or 0) * 4.0),
            min_success_rate=0.25,
            max_high_latency_ratio=1.0,
            high_latency_streak=max(5, int(self.config.high_latency_streak or 0)),
            unreachable_failures=3,
        )
        failures: list[str] = []
        for attempt in range(1, 3):
            outcome = run_async(
                probe_all(
                    proxies=[local_proxy],
                    settings=settings,
                    concurrency=1,
                    verbose=False,
                    log_sink=self._log,
                    event_sink=None,
                )
            )[0]
            if outcome.accepted:
                suffix = f" attempt={attempt}" if attempt > 1 else ""
                self._log(
                    f"[local] self-test ok {outcome.successes}/{outcome.attempts} "
                    f"avg={int(round(outcome.avg_latency_ms or 0))}ms{suffix}"
                )
                return
            failures.append(f"{outcome.reason}:{outcome.successes}/{outcome.attempts}")
            time.sleep(0.35)
        raise RuntimeError(f"local_proxy_self_test_failed:{';'.join(failures)}")

    def _active_media_transfer_pressure(self) -> dict[str, int]:
        pressure = self.pool.media_pressure()
        return {
            "active_media": int(pressure.get("active_media", 0)),
            "active_heavy": int(pressure.get("active_heavy", 0)),
            "recent_media": int(pressure.get("recent_media", 0)),
        }

    def _wait_for_media_idle(
        self,
        *,
        reason: str,
        cancel_event: threading.Event | None = None,
        max_wait_seconds: float | None = None,
    ) -> bool:
        waiting_announced = False
        started_at = time.monotonic()
        while self.local_server.is_running():
            pressure = self._active_media_transfer_pressure()
            if pressure["active_media"] <= 0 and pressure["active_heavy"] <= 0:
                if waiting_announced:
                    self._emit("runtime_refresh_resumed", reason=reason)
                return True
            if cancel_event is not None and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            if not waiting_announced:
                self._log(
                    f"[runtime] waiting for media session to finish before {reason} "
                    f"(active_media={pressure['active_media']} active_heavy={pressure['active_heavy']})"
                )
                self._emit("runtime_refresh_waiting", reason=reason, **pressure)
                waiting_announced = True
            if max_wait_seconds is not None and (time.monotonic() - started_at) >= max_wait_seconds:
                self._log(
                    f"[runtime] media wait timed out before {reason}; continuing refresh "
                    f"(active_media={pressure['active_media']} active_heavy={pressure['active_heavy']})"
                )
                self._emit("runtime_refresh_wait_timeout", reason=reason, **pressure)
                return False
            time.sleep(0.5)
        return True

    @staticmethod
    def _raise_if_cancelled(cancel_event: threading.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise RuntimeError("refresh_cancelled")

    def run_refresh(self, *, cancel_event: threading.Event | None = None) -> None:
        self._refresh_in_progress.set()
        try:
            self.last_refresh_started_at = time.time()
            self.thread_status = "disabled"
            self.thread_proxy_count = 0
            self._latest_deep_media_scores = {}
            config = CollectorConfig(
                sources=list(self.config.sources),
                out_dir=(self.install_dir / self.config.out_dir).resolve(),
                duration=self.config.duration,
                interval=self.config.interval,
                timeout=self.config.timeout,
                workers=self.config.workers,
                max_latency_ms=self.config.max_latency_ms,
                min_success_rate=self.config.min_success_rate,
                max_high_latency_ratio=self.config.max_high_latency_ratio,
                high_latency_streak=self.config.high_latency_streak,
                max_proxies=self.config.max_proxies,
                fetch_timeout=self.config.fetch_timeout,
                verbose=True,
            )

            self._log("[runtime] refreshing proxy pool")
            base_result = run_collection(
                config,
                log_sink=self._log,
                event_sink=self._emit,
                write_output=False,
                cancel_event=cancel_event,
            )
            self._raise_if_cancelled(cancel_event)
            combined_outcomes = list(base_result.outcomes)
            known_keys = {item.proxy.key for item in combined_outcomes}
            best_upstream = next((item.proxy for item in sorted(base_result.working, key=self._working_priority_key)), None)

            known_proxies = [
                proxy
                for proxy in self._load_known_working_proxy_records()
                if proxy.key not in known_keys
            ]
            if known_proxies:
                self._log(f"[runtime] rechecking {len(known_proxies)} known proxies from existing lists")
                known_outcomes = run_async(
                    probe_all(
                        proxies=known_proxies,
                        settings=self._known_proxy_probe_settings(),
                        concurrency=max(1, min(max(self.config.workers, 32), 48)),
                        verbose=False,
                        log_sink=self._log,
                        event_sink=None,
                        cancel_event=cancel_event,
                    )
                )
                combined_outcomes.extend(known_outcomes)
                known_keys.update(item.proxy.key for item in known_outcomes)
                known_working = [item for item in known_outcomes if item.accepted]
                self._log(
                    f"[runtime] known-list recheck complete: "
                    f"{len(known_working)} working / {len(known_outcomes)}"
                )
                if best_upstream is None and known_working:
                    best_upstream = next((item.proxy for item in sorted(known_working, key=self._working_priority_key)), None)

            telegram_sources = self._collect_enabled_telegram_sources()
            if telegram_sources:
                try:
                    with self.telegram_lock:
                        thread_proxies = self._run_telegram_api_call(
                            "telegram-sources",
                            lambda upstream: collect_telegram_sources_proxies(
                                telegram_sources,
                                self.auth_config,
                                upstream_proxy=upstream,
                                log_sink=self._log,
                                event_sink=self._emit,
                                total_timeout=max(45.0, float(self.config.fetch_timeout) * 4.0),
                                request_timeout=max(8.0, float(self.config.fetch_timeout)),
                                max_messages=int(self.config.telegram_source_max_messages or DEFAULT_SOURCE_MAX_MESSAGES),
                                max_proxies=int(self.config.telegram_source_max_proxies or DEFAULT_SOURCE_MAX_PROXIES),
                                max_age_days=int(self.config.telegram_source_max_age_days or DEFAULT_SOURCE_MAX_AGE_DAYS),
                                cancel_event=cancel_event,
                            ),
                            preferred=best_upstream,
                        )
                    self.thread_proxy_count = len(thread_proxies)
                    self.thread_status = f"loaded:{len(thread_proxies)}"
                    new_proxies = [item for item in thread_proxies if item.key not in known_keys]
                    if new_proxies:
                        self._log(f"[telegram] probing {len(new_proxies)} new proxies from Telegram sources")
                        self._emit("telegram_sources_probing_started", total_proxies=len(new_proxies))
                        extra_outcomes = run_async(
                            probe_all(
                                proxies=new_proxies,
                                settings=self._probe_settings(),
                                concurrency=max(1, min(self.config.workers, 10)),
                                verbose=False,
                                log_sink=self._log,
                                event_sink=None,
                                cancel_event=cancel_event,
                            )
                        )
                        combined_outcomes.extend(extra_outcomes)
                        self._emit("telegram_sources_probing_finished", total_proxies=len(new_proxies))
                    elif thread_proxies:
                        self._log(f"[telegram] sources parsed, all {len(thread_proxies)} proxies were duplicates")
                except Exception as exc:
                    self.thread_status = f"skipped:{exc}"
                    self._log(f"[telegram] skipped: {exc}")
            else:
                self.thread_status = "disabled"
            self._raise_if_cancelled(cancel_event)

            combined_working = sorted((item for item in combined_outcomes if item.accepted), key=outcome_sort_key)
            combined_rejected = sorted(
                (item for item in combined_outcomes if not item.accepted),
                key=lambda item: (item.reason, outcome_sort_key(item)),
            )

            if (self.config.deep_media_enabled or self.config.rf_whitelist_check_enabled) and combined_working:
                combined_working, combined_rejected = self._run_deep_media_checks(
                    combined_working,
                    combined_rejected,
                    strict=self.config.rf_whitelist_check_enabled,
                    cancel_event=cancel_event,
                )
            self._raise_if_cancelled(cancel_event)
            self.last_result = base_result
            self.last_outcomes = combined_outcomes
            self.last_working = combined_working
            self.last_rejected = combined_rejected
            self._wait_for_media_idle(reason="apply_results", cancel_event=cancel_event, max_wait_seconds=2.0)
            self.pool.replace_outcomes(combined_working)
            self._apply_manual_override_from_config()
            self._apply_latest_deep_media_scores()

            self._raise_if_cancelled(cancel_event)
            self._export_combined_results(base_result, combined_outcomes, combined_working, combined_rejected)
            self.last_refresh_finished_at = time.time()

            self._raise_if_cancelled(cancel_event)
            if self.config.auto_start_local and combined_working:
                self.start_local_server(raise_on_verify_failure=False)

            self._emit(
                "runtime_refresh_complete",
                working=len(combined_working),
                rejected=len(combined_rejected),
                unique=len({item.proxy.key for item in combined_outcomes}),
            )
        finally:
            self._refresh_in_progress.clear()

    def run_auth_status(self) -> dict[str, Any]:
        cfg = self.auth_config
        # FIX: не вызываем API если credentials не настроены — иначе при старте
        # приложения показывается ошибка "telegram_api_credentials_missing".
        if not auth_is_configured(cfg):
            session_path = self.telegram_session_path
            return {
                "authorized": False,
                "display": "",
                "phone": "",
                "session_exists": session_path.exists(),
                "credentials_configured": False,
                "reason": "credentials_missing",
            }
        with self.telegram_lock:
            result = self._run_telegram_api_call(
                "auth-status",
                lambda upstream: get_auth_status(cfg, upstream_proxy=upstream),
            )
        result["credentials_configured"] = True
        if result.get("session_exists") and not result.get("authorized"):
            result["reason"] = "session_not_authorized"
        return result

    def request_auth_code(self, phone: str) -> dict[str, Any]:
        normalized_phone = normalize_telegram_phone(phone)
        self._auth_code_hash = ""
        self._auth_code_phone = normalized_phone
        with self.telegram_lock:
            result = self._run_telegram_api_call(
                "request-code",
                lambda upstream: request_login_code(
                    self.auth_config,
                    phone=normalized_phone,
                    upstream_proxy=upstream,
                ),
            )
        self._auth_code_hash = result.get("phone_code_hash", "")
        self._auth_code_phone = str(result.get("phone") or normalized_phone)
        return result

    def complete_auth(self, phone: str, code: str, password: str = "") -> dict[str, Any]:
        if not self._auth_code_hash:
            raise RuntimeError("phone_code_hash_missing")
        normalized_phone = normalize_telegram_phone(phone)
        if self._auth_code_phone and normalized_phone != self._auth_code_phone:
            raise RuntimeError("Запросите новый код для текущего номера телефона.")
        with self.telegram_lock:
            result = self._run_telegram_api_call(
                "complete-login",
                lambda upstream: complete_login(
                    self.auth_config,
                    phone=normalized_phone,
                    code=code,
                    phone_code_hash=self._auth_code_hash,
                    password=password,
                    upstream_proxy=upstream,
                ),
            )
        if result.get("authorized"):
            self._auth_code_hash = ""
            self._auth_code_phone = ""
        return result

    def logout_auth(self) -> None:
        with self.telegram_lock:
            self._run_telegram_api_call(
                "logout",
                lambda upstream: logout(self.auth_config, upstream_proxy=upstream),
            )

    def run_qr_login(self, *, password: str = "") -> dict[str, Any]:
        with self.telegram_lock:
            return self._run_telegram_api_call(
                "qr-login",
                lambda upstream: qr_login_flow(
                    self.auth_config,
                    upstream_proxy=upstream,
                    password=password,
                    qr_ready=lambda payload: self._emit("telegram_qr_ready", payload),
                ),
            )

    def send_working_proxies_to_saved_messages(self) -> dict[str, Any]:
        urls = [item.proxy.url for item in self.last_working[:SAVED_MESSAGES_EXPORT_LIMIT]]
        with self.telegram_lock:
            return self._run_telegram_api_call(
                "send-proxy-list",
                lambda upstream: send_proxy_list_to_saved_messages(
                    self.auth_config,
                    urls,
                    upstream_proxy=upstream,
                ),
            )

    def snapshot(self) -> dict[str, Any]:
        working_rows = self.pool.snapshot()
        current_best = self.pool.best()
        return {
            "working_count": len(self.last_working),
            "rejected_count": len(self.last_rejected),
            "unique_count": len({item.proxy.key for item in self.last_outcomes}),
            "pool_rows": working_rows,
            "local_running": self.local_server.is_running(),
            "local_url": self.local_server.local_proxy_url,
            "local_tg_url": self.local_server.local_proxy_tg_url,
            "best_proxy": current_best.proxy.url if current_best is not None else "",
            "balancer_strategy": self.config.balancer_strategy,
            "manual_upstream_url": self.config.manual_upstream_url,
            "telegram_api_proxy_url": self.config.telegram_api_proxy_url,
            "last_refresh_started_at": self.last_refresh_started_at,
            "last_refresh_finished_at": self.last_refresh_finished_at,
            "exports": dict(self.last_export),
            "seed_source": self.seed_source,
            "seed_loaded_at": self.seed_loaded_at,
            "thread_status": self.thread_status,
            "thread_proxy_count": self.thread_proxy_count,
        }

    def _probe_settings(self) -> ProbeSettings:
        return ProbeSettings(
            duration=self.config.duration,
            interval=self.config.interval,
            timeout=self.config.timeout,
            max_latency_ms=self.config.max_latency_ms,
            min_success_rate=self.config.min_success_rate,
            max_high_latency_ratio=self.config.max_high_latency_ratio,
            high_latency_streak=self.config.high_latency_streak,
            unreachable_failures=3,
        )

    def _known_proxy_probe_settings(self) -> ProbeSettings:
        return ProbeSettings(
            duration=max(5.0, min(9.0, float(self.config.timeout or 8.0) + 1.0)),
            interval=1.0,
            timeout=max(4.0, min(6.0, float(self.config.timeout or 8.0))),
            max_latency_ms=max(1500.0, float(self.config.max_latency_ms or 300.0) * 5.0),
            min_success_rate=0.25,
            max_high_latency_ratio=1.0,
            high_latency_streak=6,
            unreachable_failures=2,
        )

    def _run_deep_media_checks(
        self,
        working: list[ProbeOutcome],
        rejected: list[ProbeOutcome],
        *,
        strict: bool,
        cancel_event: threading.Event | None = None,
    ) -> tuple[list[ProbeOutcome], list[ProbeOutcome]]:
        working = sorted(working, key=self._working_priority_key)
        if self.local_server.is_running():
            idle_reached = self._wait_for_media_idle(
                reason="deep_media_check",
                cancel_event=cancel_event,
                max_wait_seconds=20.0,
            )
            if not idle_reached:
                self._log("[media] skipped deep media check during active Telegram traffic")
                return working, rejected
        with self.telegram_lock:
            auth_status = self._run_telegram_api_call(
                "media-auth-status",
                lambda upstream: get_auth_status(self.auth_config, upstream_proxy=upstream),
            )
        if not auth_status.get("authorized"):
            reason = "rf_whitelist" if strict else "deep_media"
            self._log(f"[media] skipped: telegram_session_not_authorized ({reason})")
            self._emit("telegram_auth_required", feature=reason)
            return working, rejected
        configured_limit = int(self.config.deep_media_top_n or 0)
        candidate_limit = len(working) if configured_limit <= 0 else max(1, configured_limit)
        if strict:
            candidate_limit = max(candidate_limit, min(20, max(10, len(working))))
        top_candidates = working[:candidate_limit]
        self._log(f"[media] deep-checking {len(top_candidates)} proxies")
        self._emit(
            "deep_media_started",
            total=len(top_candidates),
            strict=strict,
        )
        rejected_keys: set[tuple[str, int, str]] = set()
        for index, outcome in enumerate(top_candidates, start=1):
            self._raise_if_cancelled(cancel_event)
            with self.telegram_lock:
                result = run_async(deep_media_probe(outcome.proxy, self.auth_config))
            self._latest_deep_media_scores[result.proxy_key] = result
            self.pool.update_deep_media_score(
                result.proxy_key,
                result.score,
                result.note,
                upload_kbps=result.upload_kbps,
                download_kbps=result.download_kbps,
                aux_kbps=result.aux_kbps,
            )
            self._log(f"[media] {outcome.proxy.host}:{outcome.proxy.port} -> {result.note}")
            self._emit(
                "deep_media_progress",
                index=index,
                total=len(top_candidates),
                host=outcome.proxy.host,
                port=outcome.proxy.port,
                score=result.score,
                note=result.note,
                strict=strict,
            )
            if strict and (result.score is None or result.score < 0.75):
                rejected_keys.add(result.proxy_key)

        self._emit(
            "deep_media_finished",
            total=len(top_candidates),
            strict=strict,
            rejected=len(rejected_keys),
        )

        if not strict or not rejected_keys:
            return sorted(working, key=self._working_priority_key), rejected

        filtered_working: list[ProbeOutcome] = []
        for outcome in working:
            if outcome.proxy.key in rejected_keys:
                rejected.append(
                    ProbeOutcome(
                        proxy=outcome.proxy,
                        attempts=outcome.attempts,
                        successes=outcome.successes,
                        failures=outcome.failures,
                        success_rate=outcome.success_rate,
                        avg_latency_ms=outcome.avg_latency_ms,
                        p95_latency_ms=outcome.p95_latency_ms,
                        min_latency_ms=outcome.min_latency_ms,
                        max_latency_ms=outcome.max_latency_ms,
                        high_latency_ratio=outcome.high_latency_ratio,
                        max_consecutive_failures=outcome.max_consecutive_failures,
                        max_consecutive_high_latency=outcome.max_consecutive_high_latency,
                        accepted=False,
                        reason="rf_whitelist_media_failed",
                        elapsed_seconds=outcome.elapsed_seconds,
                        early_stop=outcome.early_stop,
                    )
                )
            else:
                filtered_working.append(outcome)

        return sorted(filtered_working, key=self._working_priority_key), sorted(
            rejected,
            key=lambda item: (item.reason, outcome_sort_key(item)),
        )

    def _live_probe_loop(self) -> None:
        while not self.live_probe_stop.wait(timeout=5.0):
            if self.pool.count() <= 0:
                continue
            try:
                self._run_background_health_cycle()
            except Exception as exc:
                self._log(f"[live] probe loop error: {exc}")

    def _run_background_health_cycle(self) -> None:
        if not self._health_cycle_lock.acquire(blocking=False):
            return
        try:
            if self._refresh_in_progress.is_set():
                return
            pressure = self._active_media_transfer_pressure()
            if pressure["active_media"] > 0 or pressure["active_heavy"] > 0:
                return
            now = time.time()
            prefer_media = (
                pressure["active_media"] > 0
                or pressure["active_heavy"] > 0
                or (now - self._last_media_activity_at) <= 60.0
            )
            focused_interval = 35.0 if self.local_server.is_running() else 75.0
            if prefer_media and self.local_server.is_running():
                focused_interval = 24.0
            if pressure["active_heavy"] > 0:
                focused_interval = 12.0
            broad_interval = max(150.0, float(self.config.live_probe_interval_sec) * 6.0)
            media_interval = 900.0
            if prefer_media:
                media_interval = 180.0
            if pressure["active_heavy"] > 0:
                media_interval = 60.0

            if (now - self._last_focused_probe_at) >= focused_interval:
                self._run_live_probe_once(focused=True, prefer_media=prefer_media)
                self._last_focused_probe_at = now

            if (now - self._last_broad_probe_at) >= broad_interval:
                self._run_live_probe_once(
                    focused=False,
                    prefer_media=prefer_media and pressure["recent_media"] > 0,
                )
                self._last_broad_probe_at = now

            if (now - self._last_media_pulse_at) >= media_interval:
                self._run_background_media_pulse(limit=3 if prefer_media else 1, prefer_media=prefer_media)
                self._last_media_pulse_at = now
        finally:
            self._health_cycle_lock.release()

    def _run_live_probe_once(self, *, focused: bool, prefer_media: bool = False) -> None:
        if self._refresh_in_progress.is_set():
            return
        if focused:
            candidates = self.pool.select_monitor_targets(limit=3 if prefer_media else 2, prefer_media=prefer_media)
        elif prefer_media:
            candidates = self.pool.select_turbo_media_candidates(limit=max(2, min(5, self.config.live_probe_top_n)))
        else:
            candidates = self.pool.select_candidates(is_media=False, limit=max(1, min(4, self.config.live_probe_top_n)))
        if not candidates:
            return

        settings = ProbeSettings(
            duration=min(3.5, max(2.0, float(self.config.live_probe_duration_sec if not focused else 2.5))),
            interval=0.7,
            timeout=min(6.0, self.config.timeout),
            max_latency_ms=self.config.max_latency_ms,
            min_success_rate=0.34,
            max_high_latency_ratio=1.0,
            high_latency_streak=5,
            unreachable_failures=2,
        )
        outcomes = run_async(
            probe_all(
                proxies=[item.proxy for item in candidates],
                settings=settings,
                concurrency=max(1, min((3 if focused and prefer_media else 2 if focused else 4), len(candidates))),
                verbose=False,
                log_sink=self._log,
                event_sink=None,
            )
        )
        for outcome in outcomes:
            ok = outcome.successes > 0
            cooldown_reason = self.pool.update_live_probe(
                outcome.proxy.key,
                outcome.avg_latency_ms,
                ok,
                outcome.reason,
                max_latency_ms=float(self.config.max_latency_ms or 300.0),
                high_latency_streak_limit=1 if prefer_media and focused else 2 if focused else 3,
                failure_limit=1 if prefer_media and focused else 2 if focused else 3,
                cooldown_seconds=180.0 if focused else 120.0,
            )
            if cooldown_reason:
                self._log(f"[live] demoted {outcome.proxy.host}:{outcome.proxy.port} -> {cooldown_reason}")
                self._emit(
                    "proxy_cooldown",
                    host=outcome.proxy.host,
                    port=outcome.proxy.port,
                    reason=cooldown_reason,
                )
        self._emit("live_probe_updated", count=len(outcomes), focused=focused, prefer_media=prefer_media)

    def _run_background_media_pulse(self, *, limit: int = 1, prefer_media: bool = False) -> None:
        if self._refresh_in_progress.is_set() or not self.local_server.is_running():
            return
        if not self.auth_config.api_id or not self.auth_config.api_hash.strip():
            return
        candidates = self.pool.select_monitor_targets(limit=max(1, limit), prefer_media=prefer_media)
        if not candidates:
            return
        for target in candidates:
            try:
                with self.telegram_lock:
                    result = run_async(light_media_probe(target.proxy, self.auth_config))
            except Exception as exc:
                self._log(f"[media-bg] probe error for {target.proxy.host}:{target.proxy.port} -> {exc}")
                continue

            if result.note == "session_not_authorized":
                self._emit("telegram_auth_required", feature="background_media")
                self._log("[media-bg] skipped: telegram_session_not_authorized")
                return
            if result.note in {"no_media_samples_found", "no_video_samples_found"}:
                self.pool.update_deep_media_score(
                    result.proxy_key,
                    result.score,
                    result.note,
                    upload_kbps=result.upload_kbps,
                    download_kbps=result.download_kbps,
                    aux_kbps=result.aux_kbps,
                )
                self._log(f"[media-bg] {target.proxy.host}:{target.proxy.port} -> {result.note}")
                continue

            cooldown_reason = self.pool.update_background_media_probe(
                result.proxy_key,
                result.score,
                result.note,
                upload_kbps=result.upload_kbps,
                download_kbps=result.download_kbps,
                aux_kbps=result.aux_kbps,
                failure_score=0.7 if prefer_media else 0.6,
                cooldown_seconds=360.0 if prefer_media else 300.0,
            )
            self._log(
                f"[media-bg] {target.proxy.host}:{target.proxy.port} -> "
                f"{result.note} score={result.score if result.score is not None else 'n/a'}"
            )
            if cooldown_reason:
                self._emit(
                    "proxy_cooldown",
                    host=target.proxy.host,
                    port=target.proxy.port,
                    reason=cooldown_reason,
                )

    def _schedule_media_acceleration_probe(self, payload: dict[str, Any]) -> None:
        now = time.time()
        if (now - self._last_media_accel_probe_at) < 12.0:
            return
        self._last_media_accel_probe_at = now

        def _runner() -> None:
            if not self._health_cycle_lock.acquire(blocking=False):
                return
            try:
                host = str(payload.get("host") or "")
                port = payload.get("port")
                upload_kbps = payload.get("upload_kbps")
                label = f"{host}:{port}" if host and port else "media session"
                self._log(f"[media-boost] heavy upload detected on {label}, reprobe turbo shortlist ({upload_kbps} KB/s)")
                self._run_live_probe_once(focused=True, prefer_media=True)
                self._run_background_media_pulse(limit=3, prefer_media=True)
                stamp = time.time()
                self._last_focused_probe_at = stamp
                self._last_media_pulse_at = stamp
            finally:
                self._health_cycle_lock.release()

        threading.Thread(target=_runner, daemon=True, name="mtproxy-media-boost").start()

    def _handle_internal_event(self, event_name: str, payload: dict[str, Any]) -> None:
        now = time.time()
        if event_name == "local_upstream_selected" and bool(payload.get("is_media")):
            self._last_media_activity_at = now
            return
        if event_name == "local_media_activity":
            self._last_media_activity_at = now
            if bool(payload.get("heavy_upload")):
                self._last_heavy_upload_at = now
            return
        if event_name == "local_session_closed" and (bool(payload.get("is_media")) or bool(payload.get("heavy_upload"))):
            self._last_media_activity_at = now
            if bool(payload.get("heavy_upload")):
                self._last_heavy_upload_at = now

    def _export_combined_results(
        self,
        base_result: CollectorRunResult,
        all_outcomes: list[ProbeOutcome],
        working: list[ProbeOutcome],
        rejected: list[ProbeOutcome],
    ) -> None:
        out_dir = (self.install_dir / self.config.out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        all_txt_path = out_dir / ALL_FILE_NAME
        working_txt_path = out_dir / LIST_FILE_NAME
        fast_txt_path = out_dir / FAST_LIST_FILE_NAME
        rejected_txt_path = out_dir / REJECTED_FILE_NAME
        report_json_path = out_dir / REPORT_FILE_NAME
        source_audit_path = out_dir / SOURCE_AUDIT_FILE_NAME
        socks5_all_txt_path = out_dir / SOCKS5_FILE_NAME

        fast_urls = [item.proxy.url for item in self._select_fast_candidates(working)]
        self._write_url_list(all_txt_path, [item.proxy.url for item in all_outcomes])
        self._write_url_list(working_txt_path, [item.proxy.url for item in working])
        self._write_url_list(fast_txt_path, fast_urls)
        self._write_url_list(rejected_txt_path, [item.proxy.url for item in rejected])
        with contextlib.suppress(Exception):
            if socks5_all_txt_path.exists():
                socks5_all_txt_path.unlink()

        report = build_report(
            base_result.source_summaries,
            [item.proxy for item in all_outcomes],
            base_result.socks5,
            all_outcomes,
            base_result.config,
        )
        report["notes"].append("Local app runtime may further reprioritize proxies using live media/session telemetry.")
        report["telegram_sources_enabled"] = self.config.telegram_sources_enabled
        report["telegram_sources"] = list(self._collect_enabled_telegram_sources())
        report["telegram_api_proxy_url"] = self.config.telegram_api_proxy_url
        report["deep_media_enabled"] = self.config.deep_media_enabled
        report["rf_whitelist_check_enabled"] = self.config.rf_whitelist_check_enabled
        report["thread_source_enabled"] = self.config.thread_source_enabled
        report["thread_source_url"] = self.config.thread_source_url
        source_audit = self._build_source_audit(base_result.source_summaries, all_outcomes)
        report["source_audit"] = source_audit
        report["proxies"] = self._augment_report_proxy_rows(report["proxies"])
        self._write_json_file(report_json_path, report)
        self._atomic_write(source_audit_path, self._format_source_audit(source_audit))

        self.last_export = {
            "all_txt_path": str(all_txt_path),
            "working_txt_path": str(working_txt_path),
            "fast_txt_path": str(fast_txt_path),
            "rejected_txt_path": str(rejected_txt_path),
            "report_json_path": str(report_json_path),
            "source_audit_path": str(source_audit_path),
        }
        self._emit(
            "files_written",
            out_dir=str(out_dir),
            all_txt_path=str(all_txt_path),
            working_txt_path=str(working_txt_path),
            fast_txt_path=str(fast_txt_path),
            rejected_txt_path=str(rejected_txt_path),
            report_json_path=str(report_json_path),
            source_audit_path=str(source_audit_path),
        )

    def _build_source_audit(self, source_summaries: list[Any], outcomes: list[ProbeOutcome]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for summary in source_summaries:
            source_url = str(summary.source_url)
            source_outcomes = [item for item in outcomes if source_url in item.proxy.sources]
            reason_counts: dict[str, int] = {}
            for outcome in source_outcomes:
                reason_counts[outcome.reason] = reason_counts.get(outcome.reason, 0) + 1
            rows.append(
                {
                    "source_url": source_url,
                    "fetched_count": len(summary.fetched_urls),
                    "fetched_urls": list(summary.fetched_urls),
                    "errors": list(summary.errors),
                    "error_count": len(summary.errors),
                    "mtproxy_found": int(getattr(summary, "mtproxy_found", 0)),
                    "mtproxy_new": int(getattr(summary, "mtproxy_new", 0)),
                    "mtproxy_duplicate": int(getattr(summary, "mtproxy_duplicate", 0)),
                    "socks5_found": int(getattr(summary, "socks5_found", 0)),
                    "socks5_new": int(getattr(summary, "socks5_new", 0)),
                    "socks5_duplicate": int(getattr(summary, "socks5_duplicate", 0)),
                    "script_urls_found": int(getattr(summary, "script_urls_found", 0)),
                    "data_urls_found": int(getattr(summary, "data_urls_found", 0)),
                    "probed_unique": len(source_outcomes),
                    "working": sum(1 for item in source_outcomes if item.accepted),
                    "rejected": sum(1 for item in source_outcomes if not item.accepted),
                    "reasons": dict(sorted(reason_counts.items())),
                }
            )
        rows.sort(key=lambda item: (int(item["working"]), int(item["mtproxy_new"]), int(item["mtproxy_found"])), reverse=True)
        return rows

    @staticmethod
    def _format_source_audit(rows: list[dict[str, Any]]) -> str:
        lines = [
            "MTProxy AutoSwitch source audit",
            f"generated_at={time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        totals = {
            "found": sum(int(row.get("mtproxy_found") or 0) for row in rows),
            "new": sum(int(row.get("mtproxy_new") or 0) for row in rows),
            "duplicate": sum(int(row.get("mtproxy_duplicate") or 0) for row in rows),
            "probed": sum(int(row.get("probed_unique") or 0) for row in rows),
            "working": sum(int(row.get("working") or 0) for row in rows),
            "rejected": sum(int(row.get("rejected") or 0) for row in rows),
            "errors": sum(int(row.get("error_count") or 0) for row in rows),
        }
        lines.append(
            "TOTAL "
            f"found={totals['found']} new={totals['new']} duplicate={totals['duplicate']} "
            f"probed_refs={totals['probed']} working_refs={totals['working']} "
            f"rejected_refs={totals['rejected']} errors={totals['errors']}"
        )
        lines.append("")
        for index, row in enumerate(rows, start=1):
            reasons = ", ".join(f"{key}:{value}" for key, value in dict(row.get("reasons") or {}).items()) or "-"
            lines.append(f"[{index}] {row.get('source_url')}")
            lines.append(
                "    "
                f"fetched={row.get('fetched_count')} errors={row.get('error_count')} "
                f"mtproxy_found={row.get('mtproxy_found')} new={row.get('mtproxy_new')} "
                f"duplicate={row.get('mtproxy_duplicate')} probed_refs={row.get('probed_unique')} "
                f"working_refs={row.get('working')} rejected_refs={row.get('rejected')}"
            )
            lines.append(
                "    "
                f"socks5_found={row.get('socks5_found')} scripts={row.get('script_urls_found')} "
                f"data_urls={row.get('data_urls_found')} reasons={reasons}"
            )
            errors = list(row.get("errors") or [])
            if errors:
                for error in errors[:5]:
                    lines.append(f"    error: {error}")
                if len(errors) > 5:
                    lines.append(f"    ... {len(errors) - 5} more errors")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def _select_fast_candidates(self, working: list[ProbeOutcome]) -> list[ProbeOutcome]:
        limit = max(1, int(self.config.fast_list_limit or DEFAULT_FAST_LIST_LIMIT))
        if not working:
            return []
        ordered = sorted(working, key=self._working_priority_key)
        latency_cap = max(float(self.config.max_latency_ms or 300.0) * 0.85, 180.0)
        success_floor = max(float(self.config.min_success_rate or 0.7), 0.85)
        ratio_cap = min(float(self.config.max_high_latency_ratio or 0.6), 0.35)

        selected: list[ProbeOutcome] = []
        selected_keys: set[tuple[str, int, str]] = set()
        selected_hosts: set[str] = set()

        def try_append(outcome: ProbeOutcome, *, unique_host: bool) -> None:
            if len(selected) >= limit or outcome.proxy.key in selected_keys:
                return
            if unique_host and outcome.proxy.host in selected_hosts:
                return
            selected.append(outcome)
            selected_keys.add(outcome.proxy.key)
            selected_hosts.add(outcome.proxy.host)

        preferred = [
            outcome
            for outcome in ordered
            if outcome.success_rate >= success_floor
            and outcome.high_latency_ratio <= ratio_cap
            and (outcome.avg_latency_ms is None or outcome.avg_latency_ms <= latency_cap)
        ]
        for outcome in preferred:
            try_append(outcome, unique_host=True)
        for outcome in preferred:
            try_append(outcome, unique_host=False)
        for outcome in ordered:
            try_append(outcome, unique_host=True)
        for outcome in ordered:
            try_append(outcome, unique_host=False)
        return selected[:limit]

    def _augment_report_proxy_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pool_rows = {row["url"]: row for row in self.pool.snapshot()}
        for row in rows:
            extra = pool_rows.get(row["url"])
            if extra is None:
                continue
            row["live_latency_ms"] = extra["live_latency_ms"]
            row["media_score"] = extra["media_score"]
            row["deep_media_score"] = extra["deep_media_score"]
            row["deep_media_note"] = extra["deep_media_note"]
        return rows

    def _apply_latest_deep_media_scores(self) -> None:
        for proxy_key, result in self._latest_deep_media_scores.items():
            self.pool.update_deep_media_score(
                proxy_key,
                result.score,
                result.note,
                upload_kbps=result.upload_kbps,
                download_kbps=result.download_kbps,
                aux_kbps=result.aux_kbps,
            )

    def _apply_manual_override_from_config(self) -> None:
        raw_url = str(getattr(self.config, "manual_upstream_url", "") or "").strip()
        if not raw_url:
            self.pool.set_manual_override(None)
            return
        proxy = parse_proxy_link(raw_url, "config", "config")
        if proxy is None:
            self.pool.set_manual_override(None)
            return
        self.pool.set_manual_override(proxy.key)

    def select_manual_upstream(self, proxy_url: str) -> None:
        proxy = parse_proxy_link(str(proxy_url or "").strip(), "manual_select", "manual_select")
        if proxy is None:
            raise ValueError("invalid proxy url")
        if self.pool.snapshot_by_key(proxy.key) is None:
            raise ValueError("proxy not found in current pool")
        self.config.manual_upstream_url = proxy.url
        self.save_config()
        self._apply_manual_override_from_config()
        self._restart_local_server_if_running(reason="manual upstream selected")
        self._emit("manual_upstream_changed", url=self.config.manual_upstream_url)

    def clear_manual_upstream(self) -> None:
        if self.config.manual_upstream_url:
            self.config.manual_upstream_url = ""
            self.save_config()
        self.pool.set_manual_override(None)
        self._restart_local_server_if_running(reason="auto balance selected")
        self._emit("manual_upstream_changed", url="")

    def quick_probe_pool(self, *, limit: int = 8, reason: str = "manual") -> int:
        if self.pool.count() <= 0:
            return 0
        with self._health_cycle_lock:
            pressure = self._active_media_transfer_pressure()
            if pressure["active_media"] > 0 or pressure["active_heavy"] > 0:
                self._log(
                    f"[quick-probe] skipped during active media (reason={reason} "
                    f"active_media={pressure['active_media']} active_heavy={pressure['active_heavy']})"
                )
                self._emit("quick_probe_skipped", reason=reason, **pressure)
                return 0
            now = time.time()
            if reason == "startup" and (now - self._last_quick_probe_at) < 20.0:
                return 0
            candidates = self.pool.select_candidates(is_media=False, limit=max(1, min(limit, self.pool.count())))
            if not candidates:
                return 0
            self._emit("quick_probe_started", total=len(candidates), reason=reason)
            settings = ProbeSettings(
                duration=2.4 if reason == "startup" else 3.0,
                interval=0.6,
                timeout=min(5.5, max(3.0, float(self.config.timeout))),
                max_latency_ms=min(280.0, max(180.0, float(self.config.max_latency_ms or 300.0))),
                min_success_rate=0.34,
                max_high_latency_ratio=1.0,
                high_latency_streak=4,
                unreachable_failures=1,
            )
            outcomes = run_async(
                probe_all(
                    proxies=[item.proxy for item in candidates],
                    settings=settings,
                    concurrency=max(1, min(4, len(candidates))),
                    verbose=False,
                    log_sink=self._log,
                    event_sink=None,
                )
            )
            for outcome in outcomes:
                self.pool.update_live_probe(
                    outcome.proxy.key,
                    outcome.avg_latency_ms,
                    outcome.successes > 0,
                    outcome.reason,
                    max_latency_ms=float(self.config.max_latency_ms or 300.0),
                    high_latency_streak_limit=3,
                    failure_limit=2,
                    cooldown_seconds=240.0 if reason == "startup" else 180.0,
                )
            self._last_quick_probe_at = time.time()
            self._emit("quick_probe_finished", total=len(outcomes), reason=reason)
            return len(outcomes)

    def _configured_telegram_api_proxy(self) -> ProxyRecord | None:
        raw_url = str(getattr(self.config, "telegram_api_proxy_url", "") or "").strip()
        if not raw_url:
            return None
        proxy = parse_proxy_link(raw_url, "telegram_api_proxy", "telegram_api_proxy")
        if proxy is None:
            self._log("[telegram-api] configured proxy url is invalid; using runtime fallback")
        return proxy

    @staticmethod
    def _proxy_identity(proxy: ProxyRecord | None) -> tuple[str, int, str] | None:
        if proxy is None:
            return None
        return proxy.key

    def _telegram_api_proxy_candidates(
        self,
        *,
        preferred: ProxyRecord | None = None,
        include_direct: bool = True,
    ) -> list[ProxyRecord | None]:
        candidates: list[ProxyRecord | None] = []
        seen: set[tuple[str, int, str] | None] = set()

        def add(proxy: ProxyRecord | None, *, allow_none: bool = False) -> None:
            if proxy is None and not allow_none:
                return
            key = self._proxy_identity(proxy)
            if key in seen:
                return
            seen.add(key)
            candidates.append(proxy)

        if bool(getattr(self.config, "telegram_api_proxy_enabled", False)):
            add(self._configured_telegram_api_proxy())
        add(preferred)
        add(self._best_proxy())
        if include_direct:
            add(None, allow_none=True)
        return candidates

    @staticmethod
    def _telegram_proxy_label(proxy: ProxyRecord | None) -> str:
        if proxy is None:
            return "direct"
        return f"{proxy.host}:{proxy.port}"

    def _run_telegram_api_call(
        self,
        operation: str,
        factory: Any,
        *,
        preferred: ProxyRecord | None = None,
        include_direct: bool = True,
    ) -> Any:
        no_retry_errors = {
            "send_code_timeout",
            "sign_in_timeout",
            "password_sign_in_timeout",
            "qr_login_timeout",
            "qr_wait_timeout",
            "qr_password_timeout",
            "send_empty_timeout",
            "send_chunk_timeout",
        }
        last_exc: Exception | None = None
        for upstream in self._telegram_api_proxy_candidates(preferred=preferred, include_direct=include_direct):
            try:
                self._log(f"[telegram-api] {operation} via {self._telegram_proxy_label(upstream)}")
                return run_async(factory(upstream))
            except Exception as exc:
                text = str(exc)
                if text.startswith(TELEGRAM_USER_ERROR_PREFIX):
                    raise RuntimeError(text[len(TELEGRAM_USER_ERROR_PREFIX):]) from exc
                if text in no_retry_errors:
                    self._log(f"[telegram-api] {operation} failed via {self._telegram_proxy_label(upstream)} without retry: {exc}")
                    raise
                last_exc = exc
                self._log(f"[telegram-api] {operation} failed via {self._telegram_proxy_label(upstream)}: {exc}")
        if last_exc is not None:
            raise last_exc
        return run_async(factory(None))

    def _best_proxy(self):
        best = self.pool.best()
        if best is not None:
            return best.proxy
        if self.last_working:
            return self.last_working[0].proxy
        return None

    def _collect_enabled_telegram_sources(self) -> list[str]:
        if not bool(self.config.telegram_sources_enabled):
            return []
        merged: list[str] = []
        seen: set[str] = set()
        for raw_url in self.config.telegram_sources:
            url = str(raw_url).strip()
            if not url or url in seen:
                continue
            seen.add(url)
            merged.append(url)
        if not merged and bool(self.config.thread_source_enabled):
            legacy_url = str(self.config.thread_source_url).strip()
            if legacy_url:
                merged.append(legacy_url)
        return merged

    def _load_manual_list_proxies(self) -> list[ProxyRecord]:
        paths = [
            self.install_dir / self.config.out_dir / FAST_LIST_FILE_NAME,
            self.install_dir / self.config.out_dir / LIST_FILE_NAME,
            self.install_dir / LEGACY_OUT_DIR_NAME / LEGACY_WORKING_FILE_NAME,
        ]
        proxies: dict[tuple[str, int, str], ProxyRecord] = {}
        for path in paths:
            if not path.exists():
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except Exception as exc:
                self._log(f"[manual-list] failed to read {path.name}: {exc}")
                continue
            for raw_line in lines:
                line = raw_line.strip()
                if not line:
                    continue
                proxy = parse_proxy_link(line, str(path), str(path))
                if proxy is None:
                    continue
                proxy.sources.add(f"file:{path.name}")
                proxies[proxy.key] = proxy
        return list(proxies.values())

    def _load_known_working_proxy_records(self) -> list[ProxyRecord]:
        limit = max(48, min(96, int(self.config.max_proxies or 0) or 96))
        paths = [
            self.install_dir / self.config.out_dir / FAST_LIST_FILE_NAME,
            self.install_dir / self.config.out_dir / REPORT_FILE_NAME,
            self.install_dir / self.config.out_dir / LIST_FILE_NAME,
            self.install_dir / LEGACY_OUT_DIR_NAME / LEGACY_WORKING_FILE_NAME,
            self.install_dir / LEGACY_OUT_DIR_NAME / LEGACY_REPORT_FILE_NAME,
        ]
        if self.state_root != self.install_dir:
            paths.extend(
                [
                    self.state_root / self.config.out_dir / FAST_LIST_FILE_NAME,
                    self.state_root / self.config.out_dir / REPORT_FILE_NAME,
                    self.state_root / self.config.out_dir / LIST_FILE_NAME,
                    self.state_root / LEGACY_OUT_DIR_NAME / LEGACY_WORKING_FILE_NAME,
                    self.state_root / LEGACY_OUT_DIR_NAME / LEGACY_REPORT_FILE_NAME,
                ]
            )
        proxies: dict[tuple[str, int, str], ProxyRecord] = {}
        for path in paths:
            if len(proxies) >= limit:
                break
            if path.suffix.lower() == ".json":
                for outcome in self._load_seed_outcomes(path, source_name=f"known:{path.name}"):
                    if len(proxies) >= limit:
                        break
                    outcome.proxy.sources.add(f"known:{path.name}")
                    proxies.setdefault(outcome.proxy.key, outcome.proxy)
                continue
            for raw_url in self._read_url_list(path):
                if len(proxies) >= limit:
                    break
                proxy = parse_proxy_link(raw_url, f"known:{path.name}", str(path))
                if proxy is None:
                    continue
                proxy.sources.add(f"known:{path.name}")
                proxies.setdefault(proxy.key, proxy)
        return list(proxies.values())

    def _read_existing_proxy_list_urls(self) -> list[str]:
        candidates = [
            self.install_dir / self.config.out_dir / FAST_LIST_FILE_NAME,
            self.install_dir / self.config.out_dir / LIST_FILE_NAME,
            self.install_dir / LEGACY_OUT_DIR_NAME / LEGACY_WORKING_FILE_NAME,
        ]
        merged: list[str] = []
        seen: set[str] = set()
        for path in candidates:
            for url in self._read_url_list(path):
                if url in seen:
                    continue
                seen.add(url)
                merged.append(url)
        return merged

    def _merge_existing_proxy_list(self, existing_urls: list[str], fresh_urls: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for line in existing_urls:
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            merged.append(url)
        for line in fresh_urls:
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            merged.append(url)
        return merged

    def _read_url_list(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except Exception as exc:
            self._log(f"[manual-list] failed to read {path.name}: {exc}")
            return []

    def _write_url_list(self, path: Path, urls: list[str]) -> None:
        unique_urls = self._merge_existing_proxy_list([], urls)
        content = "\n".join(unique_urls)
        if content:
            content += "\n"
        self._atomic_write(path, content)

    def _write_json_file(self, path: Path, payload: dict[str, Any]) -> None:
        self._atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2))

    def _atomic_write(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(content, encoding="utf-8")
        temp_path.replace(path)

    def _load_initial_pool(self) -> None:
        report_candidates = [
            (self.install_dir / self.config.out_dir / FAST_LIST_FILE_NAME, "fast_list"),
            (self.install_dir / self.config.out_dir / LIST_FILE_NAME, "default_list"),
            (self.install_dir / LEGACY_OUT_DIR_NAME / LEGACY_WORKING_FILE_NAME, "legacy_working_list"),
            (self.install_dir / self.config.out_dir / REPORT_FILE_NAME, "cached_report"),
            (self.install_dir / LEGACY_OUT_DIR_NAME / LEGACY_REPORT_FILE_NAME, "legacy_cached_report"),
        ]
        for bundle_root in bundled_resource_roots():
            report_candidates.append((bundle_root / "mtproxy_seed.json", "bundled_seed"))

        for report_path, source_name in report_candidates:
            outcomes = self._load_seed_outcomes(report_path, source_name=source_name)
            if not outcomes:
                continue
            if source_name in {"cached_report", "legacy_cached_report"} and len(outcomes) < 3:
                self._log(f"[seed] skipped weak cache {report_path.name}: only {len(outcomes)} working proxies")
                continue

            self.last_outcomes = list(outcomes)
            self.last_working = sorted((item for item in outcomes if item.accepted), key=outcome_sort_key)
            self.last_rejected = sorted(
                (item for item in outcomes if not item.accepted),
                key=lambda item: (item.reason, outcome_sort_key(item)),
            )
            self.pool.replace_outcomes(self.last_working)
            self._apply_manual_override_from_config()
            self.seed_source = source_name
            self.seed_loaded_at = time.time()
            self._log(f"[seed] loaded {len(self.last_working)} working proxies from {report_path.name}")
            self._emit(
                "seed_loaded",
                source=source_name,
                count=len(self.last_working),
                path=str(report_path),
            )
            break

    def _load_seed_outcomes(self, report_path: Path, *, source_name: str) -> list[ProbeOutcome]:
        if not report_path.exists():
            return []

        if report_path.suffix.lower() == ".txt":
            return self._load_seed_outcomes_from_txt(report_path, source_name=source_name)

        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._log(f"[seed] failed to read {report_path.name}: {exc}")
            return []

        proxy_rows = payload.get("proxies")
        if not isinstance(proxy_rows, list):
            return []

        outcomes: list[ProbeOutcome] = []
        for row in proxy_rows:
            outcome = self._seed_row_to_outcome(row)
            if outcome is not None and outcome.accepted:
                outcomes.append(outcome)
        return outcomes

    def _load_seed_outcomes_from_txt(self, path: Path, *, source_name: str) -> list[ProbeOutcome]:
        outcomes: list[ProbeOutcome] = []
        seen: set[tuple[str, int, str]] = set()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            self._log(f"[seed] failed to read {path.name}: {exc}")
            return outcomes

        for index, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue
            proxy = parse_proxy_link(line, str(path), str(path))
            if proxy is None or proxy.key in seen:
                continue
            seen.add(proxy.key)
            outcomes.append(
                ProbeOutcome(
                    proxy=proxy,
                    attempts=1,
                    successes=1,
                    failures=0,
                    success_rate=1.0,
                    avg_latency_ms=float(index),
                    p95_latency_ms=float(index),
                    min_latency_ms=float(index),
                    max_latency_ms=float(index),
                    high_latency_ratio=0.0,
                    max_consecutive_failures=0,
                    max_consecutive_high_latency=0,
                    accepted=True,
                    reason=source_name,
                    elapsed_seconds=0.0,
                    early_stop="seed_list",
                )
            )
        return outcomes

    def _seed_row_to_outcome(self, row: dict[str, Any]) -> ProbeOutcome | None:
        try:
            proxy = ProxyRecord(
                host=str(row["host"]).strip().lower(),
                port=int(row["port"]),
                secret=str(row["secret"]).strip().lower(),
                sources=set(row.get("sources", []) or []),
                discovered_from=set(row.get("discovered_from", []) or []),
            )
            return ProbeOutcome(
                proxy=proxy,
                attempts=int(row.get("attempts") or 0),
                successes=int(row.get("successes") or 0),
                failures=int(row.get("failures") or 0),
                success_rate=float(row.get("success_rate") or 0.0),
                avg_latency_ms=_to_float(row.get("avg_latency_ms")),
                p95_latency_ms=_to_float(row.get("p95_latency_ms")),
                min_latency_ms=_to_float(row.get("min_latency_ms")),
                max_latency_ms=_to_float(row.get("max_latency_ms")),
                high_latency_ratio=float(row.get("high_latency_ratio") or 0.0),
                max_consecutive_failures=int(row.get("max_consecutive_failures") or 0),
                max_consecutive_high_latency=int(row.get("max_consecutive_high_latency") or 0),
                accepted=bool(row.get("accepted")),
                reason=str(row.get("reason") or "seed"),
                elapsed_seconds=float(row.get("elapsed_seconds") or 0.0),
                early_stop=row.get("early_stop"),
            )
        except Exception:
            return None

    def _load_config(self) -> AppConfig:
        legacy_paths = [
            self.state_root / CONFIG_FILE_NAME,
            self.state_root / "app_state" / CONFIG_FILE_NAME,
            self.install_dir / CONFIG_FILE_NAME,
            self.install_dir / "app_state" / CONFIG_FILE_NAME,
        ]
        if not self.config_path.exists():
            for legacy_path in legacy_paths:
                if not legacy_path.exists():
                    continue
                with contextlib.suppress(Exception):
                    self.config_path.write_text(legacy_path.read_text(encoding="utf-8"), encoding="utf-8")
                    break
        if not self.config_path.exists():
            config = AppConfig()
            self.config_path.write_text(
                json.dumps(self._config_payload(config), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return config
        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        normalized = False
        if data.get("out_dir") in ("", LEGACY_OUT_DIR_NAME, None):
            data["out_dir"] = LIST_DIR_NAME
            normalized = True
        if data.get("out_dir") == "list_test":
            data["out_dir"] = LIST_DIR_NAME
            normalized = True
        if data.get("appearance") not in {"auto", "light", "dark"}:
            data["appearance"] = "auto"
            normalized = True
        try:
            max_proxies = int(data.get("max_proxies") or 0)
        except (TypeError, ValueError):
            max_proxies = 0
        if "max_proxies" not in data or max_proxies <= 0:
            data["max_proxies"] = DEFAULT_MAX_PROXIES
            normalized = True
        if data.get("telegram_session_file") in (
            "",
            "app_state/telegram_user",
            "app_state/telegram_user.session",
            f"{DATA_DIR_NAME}/telegram_user.sec",
            None,
        ):
            data["telegram_session_file"] = "telegram_user.sec"
            normalized = True
        if "local_fake_tls_enabled" in data:
            data.pop("local_fake_tls_enabled", None)
            normalized = True
        if "local_fake_tls_domain" in data:
            data.pop("local_fake_tls_domain", None)
            normalized = True
        try:
            source_max_age_days = int(data.get("telegram_source_max_age_days") or 0)
        except (TypeError, ValueError):
            source_max_age_days = 0
        if "telegram_source_max_age_days" not in data or source_max_age_days <= 0:
            data["telegram_source_max_age_days"] = DEFAULT_SOURCE_MAX_AGE_DAYS
            normalized = True
        try:
            source_max_messages = int(data.get("telegram_source_max_messages") or 0)
        except (TypeError, ValueError):
            source_max_messages = 0
        if "telegram_source_max_messages" not in data or source_max_messages <= 0:
            data["telegram_source_max_messages"] = DEFAULT_SOURCE_MAX_MESSAGES
            normalized = True
        try:
            source_max_proxies = int(data.get("telegram_source_max_proxies") or 0)
        except (TypeError, ValueError):
            source_max_proxies = 0
        if "telegram_source_max_proxies" not in data or source_max_proxies <= 0:
            data["telegram_source_max_proxies"] = DEFAULT_SOURCE_MAX_PROXIES
            normalized = True
        if "rf_whitelist_check_enabled" not in data:
            data["rf_whitelist_check_enabled"] = False
            normalized = True
        try:
            deep_media_top_n = int(data.get("deep_media_top_n") or 0)
        except (TypeError, ValueError):
            deep_media_top_n = 0
        if "deep_media_top_n" not in data or deep_media_top_n < 0 or deep_media_top_n == 10:
            data["deep_media_top_n"] = DEFAULT_DEEP_MEDIA_TOP_N
            normalized = True
        if "auto_update_enabled" not in data:
            data["auto_update_enabled"] = True
            normalized = True
        if "telegram_api_proxy_url" not in data:
            data["telegram_api_proxy_url"] = DEFAULT_TELEGRAM_API_PROXY_URL
            normalized = True
        if "telegram_api_proxy_enabled" not in data:
            data["telegram_api_proxy_enabled"] = False
            normalized = True
        persistent_auth = self._load_persistent_telegram_auth() or self._load_legacy_telegram_auth(legacy_paths)
        if persistent_auth:
            for key, value in persistent_auth.items():
                if key == "telegram_api_id":
                    if int(data.get(key) or 0) <= 0 and int(value or 0) > 0:
                        data[key] = int(value)
                        normalized = True
                elif key in {"telegram_api_hash", "telegram_phone", "telegram_api_proxy_url", "telegram_session_file"}:
                    if not str(data.get(key) or "").strip() and str(value or "").strip():
                        data[key] = str(value).strip()
                        normalized = True
                elif key == "telegram_api_proxy_enabled":
                    if bool(data.get(key, False)) != bool(value):
                        data[key] = bool(value)
                        normalized = True
        if "telegram_sources_enabled" not in data:
            data["telegram_sources_enabled"] = bool(data.get("thread_source_enabled", False))
            normalized = True
        if "telegram_sources" not in data or not isinstance(data.get("telegram_sources"), list):
            legacy_url = str(data.get("thread_source_url") or "").strip()
            data["telegram_sources"] = [legacy_url] if legacy_url else list(DEFAULT_TELEGRAM_SOURCE_URLS)
            normalized = True
        if not data.get("thread_source_url"):
            telegram_sources = [str(item).strip() for item in data.get("telegram_sources", []) if str(item).strip()]
            if telegram_sources:
                data["thread_source_url"] = telegram_sources[0]
                normalized = True
        if "thread_source_enabled" not in data:
            data["thread_source_enabled"] = bool(data.get("telegram_sources_enabled", False))
            normalized = True
        sources = [
            str(item).strip()
            for item in data.get("sources", [])
            if str(item).strip() and str(item).strip() not in REMOVED_WEB_SOURCES
        ]
        if any(str(item).strip() in REMOVED_WEB_SOURCES for item in data.get("sources", [])):
            normalized = True
        for source in RECOMMENDED_WEB_SOURCE_ADDITIONS:
            if source not in sources:
                sources.append(source)
                normalized = True
        data["sources"] = sources
        telegram_sources = [str(item).strip() for item in data.get("telegram_sources", []) if str(item).strip()]
        for source in RECOMMENDED_TELEGRAM_SOURCE_ADDITIONS:
            if source not in telegram_sources:
                telegram_sources.append(source)
                normalized = True
        data["telegram_sources"] = telegram_sources
        if normalized:
            with contextlib.suppress(Exception):
                normalized_payload = self._config_payload(AppConfig(**(asdict(AppConfig()) | data)))
                self.config_path.write_text(json.dumps(normalized_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        defaults = asdict(AppConfig())
        defaults.update(data)
        config = AppConfig(**defaults)
        self._save_persistent_telegram_auth(self._config_payload(config))
        return config

    def _persistent_telegram_auth_path(self) -> Path:
        return self.state_dir / TELEGRAM_AUTH_STATE_FILE_NAME

    def _load_persistent_telegram_auth(self) -> dict[str, Any]:
        auth_path = self._persistent_telegram_auth_path()
        if not auth_path.exists():
            return {}
        try:
            payload = json.loads(auth_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(payload, dict):
            return {}
        allowed = {
            "telegram_api_id",
            "telegram_api_hash",
            "telegram_phone",
            "telegram_api_proxy_enabled",
            "telegram_api_proxy_url",
            "telegram_session_file",
        }
        return {key: payload[key] for key in allowed if key in payload}

    def _load_legacy_telegram_auth(self, config_paths: list[Path]) -> dict[str, Any]:
        for config_path in config_paths:
            if not config_path.exists():
                continue
            try:
                payload = json.loads(config_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            api_id = int(payload.get("telegram_api_id") or 0)
            api_hash = str(payload.get("telegram_api_hash") or "").strip()
            if api_id <= 0 or not api_hash:
                continue
            return {
                "telegram_api_id": api_id,
                "telegram_api_hash": api_hash,
                "telegram_phone": str(payload.get("telegram_phone") or "").strip(),
                "telegram_api_proxy_enabled": bool(payload.get("telegram_api_proxy_enabled", False)),
                "telegram_api_proxy_url": str(payload.get("telegram_api_proxy_url") or DEFAULT_TELEGRAM_API_PROXY_URL).strip(),
                "telegram_session_file": Path(str(payload.get("telegram_session_file") or "telegram_user.sec")).name,
            }
        return {}

    def _save_persistent_telegram_auth(self, payload: dict[str, Any]) -> None:
        auth_payload = {
            "telegram_api_id": int(payload.get("telegram_api_id") or 0),
            "telegram_api_hash": str(payload.get("telegram_api_hash") or "").strip(),
            "telegram_phone": str(payload.get("telegram_phone") or "").strip(),
            "telegram_api_proxy_enabled": bool(payload.get("telegram_api_proxy_enabled", False)),
            "telegram_api_proxy_url": str(payload.get("telegram_api_proxy_url") or DEFAULT_TELEGRAM_API_PROXY_URL).strip(),
            "telegram_session_file": Path(str(payload.get("telegram_session_file") or "telegram_user.sec")).name,
        }
        with contextlib.suppress(Exception):
            auth_path = self._persistent_telegram_auth_path()
            auth_path.parent.mkdir(parents=True, exist_ok=True)
            auth_path.write_text(json.dumps(auth_payload, ensure_ascii=False, indent=2), encoding="utf-8")
            _hide_windows_path(auth_path.parent)
            _hide_windows_path(auth_path)

    def _working_priority_key(self, outcome: ProbeOutcome) -> tuple[float, float, float, float, str]:
        latency = outcome.avg_latency_ms if outcome.avg_latency_ms is not None else 9_999.0
        pool_row = self.pool.snapshot_by_key(outcome.proxy.key)
        latest_media = self._latest_deep_media_scores.get(outcome.proxy.key)
        media_score = latest_media.score if latest_media is not None else None
        deep_download_kbps = latest_media.download_kbps if latest_media is not None else None
        deep_upload_kbps = latest_media.upload_kbps if latest_media is not None else None
        if media_score is None and pool_row:
            media_score = pool_row.get("deep_media_score")
        if deep_download_kbps is None and pool_row:
            deep_download_kbps = pool_row.get("deep_media_download_kbps")
        if deep_upload_kbps is None and pool_row:
            deep_upload_kbps = pool_row.get("deep_media_upload_kbps")
        media_penalty = -float(media_score) if media_score is not None else 0.0
        deep_download_penalty = -float(deep_download_kbps) if deep_download_kbps is not None else 0.0
        deep_upload_penalty = -float(deep_upload_kbps) if deep_upload_kbps is not None else 0.0
        return (
            deep_download_penalty,
            deep_upload_penalty,
            media_penalty,
            latency,
            -outcome.success_rate,
            outcome.high_latency_ratio,
            outcome.proxy.url,
        )

    def _log(self, message: str) -> None:
        if self.log_sink is not None:
            self.log_sink(message)

    def _emit(self, event_name: str, payload: dict[str, Any] | None = None, **kwargs: Any) -> None:
        merged = dict(payload or {})
        merged.update(kwargs)
        self._handle_internal_event(event_name, merged)
        if self.event_sink is not None:
            self.event_sink(event_name, merged)


def _to_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _hide_windows_path(path: Path) -> None:
    if sys.platform != "win32":
        return
    with contextlib.suppress(Exception):
        ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
