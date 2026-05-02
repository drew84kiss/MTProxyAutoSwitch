from __future__ import annotations

import contextlib
import ctypes
import plistlib
import sys
import threading
import time
import webbrowser
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None

from PySide6.QtCore import QEvent, QObject, QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QCloseEvent, QCursor, QDesktopServices, QIcon, QIntValidator, QPalette, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QAbstractSpinBox,
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from mtproxy_app_backend import (
    AppConfig,
    AppRuntime,
    BALANCER_STRATEGIES,
    DEFAULT_FAST_LIST_LIMIT,
    DEFAULT_LOCAL_SECRET,
    DEFAULT_TELEGRAM_API_PROXY_URL,
)
from mtproxy_collector import DEFAULT_SOURCES
from mtproxy_net import TELEGRAM_WEB_HOSTS_LINES
from mtproxy_telegram import DEFAULT_TELEGRAM_SOURCE_URLS, normalize_telegram_phone
from mtproxy_updater import (
    APP_PUBLIC_VERSION,
    fetch_latest_release,
    is_update_available,
    launch_prepared_update,
    prepare_update,
)


APP_NAME = "MTProxy AutoSwitch"
APP_ICON_PATH = Path(__file__).resolve().parent / "img" / "icon.ico"
SINGLE_INSTANCE_MUTEX_NAME = "Global\\MTProxyAutoSwitch.Singleton"
HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
HOSTS_BLOCK_BEGIN = "# MTProxy AutoSwitch Telegram Web Begin"
HOSTS_BLOCK_END = "# MTProxy AutoSwitch Telegram Web End"
AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_VALUE = "MTProxyAutoSwitch"

BALANCER_LABELS = {
    "round_robin": "Round robin",
    "consistent_hash": "Consistent hash",
    "sticky_session": "Sticky session",
}
BALANCER_BY_LABEL = {value: key for key, value in BALANCER_LABELS.items()}
APPEARANCE_LABELS = {
    "auto": "Авто",
    "light": "Светлая",
    "dark": "Темная",
}
APPEARANCE_BY_LABEL = {value: key for key, value in APPEARANCE_LABELS.items()}
CLOSE_LABELS = {
    "ask": "Всегда спрашивать",
    "tray": "Скрывать в трей",
    "exit": "Закрывать приложение",
}
CLOSE_BY_LABEL = {value: key for key, value in CLOSE_LABELS.items()}

BALANCER_HELP = (
    "Round robin: новые сессии идут по очереди между лучшими proxy.\n\n"
    "Consistent hash: один и тот же ключ сессии старается попадать на один и тот же proxy. "
    "Это стабильнее при нескольких клиентах.\n\n"
    "Sticky session: начатая сессия закрепляется за одним upstream и не прыгает между proxy. "
    "Это самый безопасный режим для длинных загрузок и выгрузок."
)

QSS = """
QWidget {
    background: #F3F0F8;
    color: #221D31;
    font-family: "Segoe UI";
    font-size: 12px;
}
QScrollArea {
    border: none;
    background: transparent;
}
QScrollArea > QWidget > QWidget {
    background: transparent;
}
QScrollBar:vertical {
    width: 0px;
    background: transparent;
    border: none;
}
QScrollBar:horizontal {
    height: 0px;
    background: transparent;
    border: none;
}
QLabel {
    background: transparent;
}
QFrame#card, QFrame#rowCard, QFrame#activeCard, QFrame#proxyRow, QFrame#aboutCard {
    background: #FAF8FD;
    border: 1px solid #D8D1E5;
    border-radius: 22px;
}
QFrame#fieldCard {
    background: #EEE8F5;
    border: 1px solid #D5CCE4;
    border-radius: 18px;
}
QFrame#activeCard:hover, QFrame#rowCard:hover {
    background: #F0ECFF;
    border: 1px solid #6158C7;
}
QPushButton {
    min-height: 34px;
    border-radius: 17px;
    padding: 0 14px;
    border: 1px solid #D5CCE4;
    background: #FAF8FD;
    color: #221D31;
    font-weight: 600;
}
QPushButton:hover {
    background: #E6DFF6;
    border: 1px solid #BFB3D5;
}
QPushButton:pressed {
    background: #D8CFF0;
    border: 1px solid #6158C7;
    padding-top: 1px;
    padding-left: 15px;
}
QPushButton:disabled {
    color: #B2A9C4;
    background: #EEE8F5;
    border: 1px solid #E1D9EC;
}
QPushButton#accent {
    background: #6158C7;
    color: #FFFFFF;
    border: 1px solid #6158C7;
}
QPushButton#accent:hover {
    background: #5148B8;
    border: 1px solid #5148B8;
}
QPushButton#accent:pressed {
    background: #443AA3;
    border: 1px solid #443AA3;
}
QPushButton#soft {
    background: #E6DFF6;
    color: #6158C7;
    border: 1px solid #E6DFF6;
}
QPushButton#soft:hover {
    background: #D9CEF3;
    color: #5148B8;
    border: 1px solid #BBAEE0;
}
QPushButton#soft:pressed {
    background: #C9BCEB;
    color: #443AA3;
    border: 1px solid #6158C7;
}
QPushButton#danger {
    background: #D95B75;
    color: #FFFFFF;
    border: 1px solid #D95B75;
}
QPushButton#danger:hover {
    background: #C94B66;
    border: 1px solid #C94B66;
}
QPushButton#danger:pressed {
    background: #B83D58;
    border: 1px solid #B83D58;
}
QPushButton#primary {
    background: #D95B75;
    color: #FFFFFF;
    border: none;
    font-size: 22px;
    font-weight: 700;
}
QPushButton#primary[started="false"] {
    background: #6158C7;
}
QProgressBar {
    height: 8px;
    border-radius: 4px;
    border: none;
    background: #D8D1E5;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    border-radius: 4px;
    background: #6158C7;
}
QLineEdit, QSpinBox, QComboBox, QTextEdit, QPlainTextEdit {
    background: #EEE8F5;
    border: 1px solid #D5CCE4;
    border-radius: 16px;
    padding: 6px 10px;
    color: #221D31;
}
QWidget#inlineRow, QWidget#transparentPanel {
    background: transparent;
}
QSpinBox::up-button, QSpinBox::down-button {
    width: 0px;
    border: none;
}
QComboBox {
    min-height: 28px;
}
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QCheckBox {
    background: transparent;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border-radius: 5px;
    border: 2px solid #6158C7;
    background: #FAF8FD;
}
QCheckBox::indicator:checked {
    background: #6158C7;
}
QCheckBox:disabled {
    color: #9A91AA;
}
QCheckBox::indicator:disabled {
    background: #E6DFF6;
    border: 2px solid #D8D1E5;
}
QCheckBox::indicator:checked:disabled {
    background: #CFC5E0;
    border: 2px solid #CFC5E0;
}
QListWidget#cardList {
    background: transparent;
    border: none;
    outline: none;
}
QListWidget#cardList::item {
    border: none;
    background: transparent;
    padding: 0;
    margin: 0;
}
"""

QSS_LIGHT = QSS
QSS_DARK = QSS_LIGHT
for _light, _dark in {
    "#F3F0F8": "#16131D",
    "#221D31": "#F5F0FF",
    "#FAF8FD": "#201B2A",
    "#D8D1E5": "#3A324A",
    "#EEE8F5": "#2A2435",
    "#D5CCE4": "#443A57",
    "#F0ECFF": "#2D2740",
    "#BFB3D5": "#5B4D72",
    "#D8CFF0": "#39304E",
    "#E1D9EC": "#3B334A",
    "#6158C7": "#9A90FF",
    "#5148B8": "#B0A7FF",
    "#443AA3": "#8176F0",
    "#E6DFF6": "#312A41",
    "#D9CEF3": "#3A3150",
    "#BBAEE0": "#675B82",
    "#C9BCEB": "#463A61",
    "#9A91AA": "#9487A8",
    "#CFC5E0": "#554B66",
}.items():
    QSS_DARK = QSS_DARK.replace(_light, _dark)

THEMES = {
    "light": {
        "qss": QSS_LIGHT,
        "text": "#221D31",
        "soft": "#6E667F",
        "badge_bg": "#E6DFF6",
        "badge_fg": "#6158C7",
        "status_on_bg": "#D7F0DE",
        "status_on_fg": "#1A7D55",
        "status_off_bg": "#E8E2F1",
        "status_off_fg": "#5E5670",
        "alert_bg": "#FAF8FD",
        "alert_border": "#D8D1E5",
        "primary_on": "#D95B75",
        "primary_on_hover": "#C94A67",
        "primary_off": "#6158C7",
        "primary_off_hover": "#5148B8",
        "proxy_selected_bg": "#EEE9FF",
        "proxy_active_bg": "#F7F4FB",
        "proxy_bg": "#FAF8FD",
        "proxy_selected_border": "#6158C7",
        "proxy_active_border": "#1A7D55",
        "proxy_border": "#D8D1E5",
    },
    "dark": {
        "qss": QSS_DARK,
        "text": "#F5F0FF",
        "soft": "#B8ACCB",
        "badge_bg": "#312A41",
        "badge_fg": "#B0A7FF",
        "status_on_bg": "#173826",
        "status_on_fg": "#6EE7B7",
        "status_off_bg": "#2A2435",
        "status_off_fg": "#B8ACCB",
        "alert_bg": "#201B2A",
        "alert_border": "#3A324A",
        "primary_on": "#D95B75",
        "primary_on_hover": "#E06B82",
        "primary_off": "#9A90FF",
        "primary_off_hover": "#B0A7FF",
        "proxy_selected_bg": "#2D2740",
        "proxy_active_bg": "#202C26",
        "proxy_bg": "#201B2A",
        "proxy_selected_border": "#9A90FF",
        "proxy_active_border": "#6EE7B7",
        "proxy_border": "#3A324A",
    },
}


def _asset_icon() -> QIcon:
    return QIcon(str(APP_ICON_PATH)) if APP_ICON_PATH.exists() else QIcon()


def _system_prefers_dark() -> bool:
    if sys.platform == "win32" and winreg is not None:
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                0,
                winreg.KEY_READ,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return int(value) == 0
        except Exception:
            return False
    app = QApplication.instance()
    if app is None:
        return False
    return app.palette().color(QPalette.Window).lightness() < 128


def _resolve_theme(appearance: str) -> str:
    if appearance == "dark":
        return "dark"
    if appearance == "light":
        return "light"
    return "dark" if _system_prefers_dark() else "light"


def _safe_float(value: object) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except Exception:
        return None


def _format_latency(value: object) -> str:
    number = _safe_float(value)
    if number is None or number <= 0:
        return "n/a"
    return f"{int(round(number))} ms"


def _format_rate(value: object) -> str:
    number = _safe_float(value)
    if number is None or number <= 0:
        return "n/a"
    if number >= 1024:
        return f"{number / 1024:.1f} MB/s"
    return f"{int(round(number))} KB/s"


def _trim_middle(text: str, limit: int = 56) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    left = max(8, (limit - 1) // 2)
    right = max(8, limit - left - 1)
    return f"{text[:left]}…{text[-right:]}"


def _telegram_web_hosts_block() -> str:
    return "\n".join([HOSTS_BLOCK_BEGIN, *TELEGRAM_WEB_HOSTS_LINES, HOSTS_BLOCK_END])


def _strip_hosts_block(text: str) -> str:
    start = text.find(HOSTS_BLOCK_BEGIN)
    if start < 0:
        return text
    end = text.find(HOSTS_BLOCK_END, start)
    if end < 0:
        return text[:start].rstrip() + "\n"
    end += len(HOSTS_BLOCK_END)
    stripped = (text[:start] + text[end:]).strip()
    return stripped + ("\n" if stripped else "")


def _autostart_command() -> str:
    target = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin":
            app_bundle = _macos_app_bundle_path(target)
            if app_bundle is not None:
                return f'/usr/bin/open -a "{app_bundle}"'
        return f'"{target}"'
    script = Path(__file__).resolve()
    return f'"{target}" "{script}"'


def _macos_app_bundle_path(target: Path | None = None) -> Path | None:
    executable_path = (target or Path(sys.executable)).resolve()
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


def _macos_launch_agent_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / "com.mtproxyautoswitch.plist"


def _macos_launch_agent_payload() -> dict[str, object]:
    target = Path(sys.executable).resolve()
    app_bundle = _macos_app_bundle_path(target)
    if app_bundle is not None:
        arguments = ["/usr/bin/open", "-a", str(app_bundle)]
        working_directory = str(app_bundle.parent)
    elif getattr(sys, "frozen", False):
        arguments = [str(target)]
        working_directory = str(target.parent)
    else:
        script = Path(__file__).resolve()
        arguments = [str(target), str(script)]
        working_directory = str(script.parent)
    return {
        "Label": _macos_launch_agent_path().stem,
        "ProgramArguments": arguments,
        "WorkingDirectory": working_directory,
        "RunAtLoad": True,
        "KeepAlive": False,
    }


def is_autostart_enabled() -> bool:
    if sys.platform == "darwin":
        path = _macos_launch_agent_path()
        if not path.exists():
            return False
        try:
            with path.open("rb") as handle:
                payload = plistlib.load(handle)
            return list(payload.get("ProgramArguments") or []) == _macos_launch_agent_payload()["ProgramArguments"]
        except Exception:
            return False
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, AUTOSTART_VALUE)
        return str(value).strip() == _autostart_command()
    except OSError:
        return False


def set_autostart_enabled(enabled: bool) -> None:
    if sys.platform == "darwin":
        path = _macos_launch_agent_path()
        if enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as handle:
                plistlib.dump(_macos_launch_agent_payload(), handle, sort_keys=False)
        else:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        return
    if winreg is None:
        if enabled:
            raise RuntimeError("autostart_is_not_supported")
        return
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY) as key:
        if enabled:
            winreg.SetValueEx(key, AUTOSTART_VALUE, 0, winreg.REG_SZ, _autostart_command())
        else:
            with contextlib.suppress(FileNotFoundError):
                winreg.DeleteValue(key, AUTOSTART_VALUE)


def _acquire_single_instance():
    if sys.platform != "win32":
        return object()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX_NAME)
    if not handle:
        return None
    if ctypes.get_last_error() == 183:
        kernel32.CloseHandle(handle)
        return None
    return handle


def _release_single_instance(handle) -> None:
    if sys.platform == "win32" and handle:
        with contextlib.suppress(Exception):
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)


class UiBridge(QObject):
    log = Signal(str)
    event = Signal(str, object)
    task_done = Signal(str, object)
    task_failed = Signal(str, str)


class ClickableFrame(QFrame):
    clicked = Signal()

    def mousePressEvent(self, event):  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
            event.accept()
            return
        super().mousePressEvent(event)


class DismissibleOverlay(QWidget):
    dismiss_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.card: QWidget | None = None

    def mousePressEvent(self, event):  # noqa: N802
        if event.button() == Qt.LeftButton:
            position = event.position().toPoint() if hasattr(event, "position") else event.pos()
            if self.card is None or not self.card.geometry().contains(position):
                self.dismiss_requested.emit()
                event.accept()
                return
        super().mousePressEvent(event)


class QuietSpinBox(QSpinBox):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.setFocusPolicy(Qt.StrongFocus)

    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


class LinkButton(QPushButton):
    def __init__(self, text: str, url: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.url = url
        self.setObjectName("soft")
        self.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.url)))


class QRDialog(QDialog):
    def __init__(self, parent: QWidget, url: str, on_password: Callable[[str], None]) -> None:
        super().__init__(parent)
        self.setWindowTitle("QR вход Telegram")
        self.setModal(False)
        self.on_password = on_password
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        title = QLabel("QR вход Telegram")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        layout.addWidget(title)
        hint = QLabel("Отсканируйте QR-код в Telegram. Если включена 2FA, введите пароль ниже.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #6E667F;")
        layout.addWidget(hint)

        image = QLabel()
        image.setAlignment(Qt.AlignCenter)
        pixmap = self._make_qr_pixmap(url)
        if not pixmap.isNull():
            image.setPixmap(pixmap.scaled(260, 260, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            image.setText(url)
            image.setWordWrap(True)
        layout.addWidget(image)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Пароль 2FA, если нужен")
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)
        row = QHBoxLayout()
        copy = QPushButton("Скопировать ссылку")
        copy.setObjectName("soft")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(url))
        submit = QPushButton("Продолжить")
        submit.setObjectName("accent")
        submit.clicked.connect(lambda: self.on_password(self.password.text()))
        row.addWidget(copy)
        row.addWidget(submit)
        layout.addLayout(row)
        self.resize(360, 470)

    @staticmethod
    def _make_qr_pixmap(url: str) -> QPixmap:
        try:
            import io
            import qrcode

            image = qrcode.make(url)
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            pixmap = QPixmap()
            pixmap.loadFromData(buffer.getvalue(), "PNG")
            return pixmap
        except Exception:
            return QPixmap()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(_asset_icon())
        self.resize(438, 720)
        self.setMinimumSize(438, 720)
        self.setMaximumSize(560, 860)
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, False)

        self.log_lines: list[str] = []
        self.task_callbacks: dict[str, tuple[Callable[[Any], None] | None, Callable[[str], None] | None]] = {}
        self.refresh_in_progress = False
        self.refresh_cancel_event = threading.Event()
        self.last_snapshot: dict[str, Any] = {}
        self.last_upload_kbps: float | None = None
        self.last_download_kbps: float | None = None
        self.update_release: Any | None = None
        self.qr_dialog: QRDialog | None = None
        self.alert_overlay: QWidget | None = None
        self._quitting = False
        self._telegram_auth_known = False
        self._telegram_authorized = False
        self._telegram_auth_stage = "start"
        self._telegram_auth_busy: str | None = None

        QApplication.instance().installEventFilter(self)
        self.bridge = UiBridge()
        self.bridge.log.connect(self._append_log)
        self.bridge.event.connect(self._handle_runtime_event)
        self.bridge.task_done.connect(self._on_task_done)
        self.bridge.task_failed.connect(self._on_task_failed)
        self.runtime = AppRuntime(log_sink=self._runtime_log, event_sink=self._runtime_event)
        self.runtime.config.autostart_enabled = is_autostart_enabled()
        self._theme_name = _resolve_theme(self.runtime.config.appearance)
        QApplication.instance().setStyleSheet(THEMES[self._theme_name]["qss"])

        self._build_ui()
        self._build_tray()
        self._refresh_settings_from_config()
        self._refresh_snapshot()

        self.snapshot_timer = QTimer(self)
        self.snapshot_timer.setInterval(1000)
        self.snapshot_timer.timeout.connect(self._refresh_snapshot)
        self.snapshot_timer.start()

        QTimer.singleShot(350, self.refresh_auth_status)
        QTimer.singleShot(900, self._auto_refresh_initial)
        if self.runtime.config.auto_update_enabled:
            QTimer.singleShot(1500, self.check_updates_silent)
        if self.runtime.config.start_minimized_to_tray:
            QTimer.singleShot(600, self.hide_to_tray)

    def _runtime_log(self, message: str) -> None:
        self.bridge.log.emit(str(message))

    def _runtime_event(self, event_name: str, payload: dict[str, object]) -> None:
        self.bridge.event.emit(str(event_name), dict(payload or {}))

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if event.type() == QEvent.KeyPress and isinstance(watched, QLineEdit):
            if self._handle_line_edit_shortcut(watched, event):
                return True
        return super().eventFilter(watched, event)

    def _handle_line_edit_shortcut(self, field: QLineEdit, event: QEvent) -> bool:
        modifiers = event.modifiers()
        native_key = int(event.nativeVirtualKey() or 0) if hasattr(event, "nativeVirtualKey") else 0
        key = int(event.key()) if hasattr(event, "key") else 0
        ctrl = bool(modifiers & Qt.ControlModifier)
        shift = bool(modifiers & Qt.ShiftModifier)
        alt = bool(modifiers & Qt.AltModifier)

        if ctrl and not alt:
            if native_key == 0x41 or key == Qt.Key_A:
                field.selectAll()
            elif native_key == 0x43 or key == Qt.Key_C:
                field.copy()
            elif native_key == 0x56 or key == Qt.Key_V:
                if not field.isReadOnly():
                    self._paste_into_line_edit(field)
            elif native_key == 0x58 or key == Qt.Key_X:
                if not field.isReadOnly():
                    field.cut()
            elif native_key == 0x5A or key == Qt.Key_Z:
                if not field.isReadOnly():
                    field.undo()
            elif native_key == 0x59 or key == Qt.Key_Y:
                if not field.isReadOnly():
                    field.redo()
            elif native_key == 0x2D or key == Qt.Key_Insert:
                field.copy()
            else:
                return False
            event.accept()
            return True

        if shift and not alt:
            if native_key == 0x2D or key == Qt.Key_Insert:
                if not field.isReadOnly():
                    self._paste_into_line_edit(field)
                event.accept()
                return True
            if native_key == 0x2E or key == Qt.Key_Delete:
                if not field.isReadOnly():
                    field.cut()
                event.accept()
                return True

        return False

    def _paste_into_line_edit(self, field: QLineEdit) -> None:
        if field is getattr(self, "telegram_api_id", None):
            text = "".join(ch for ch in QApplication.clipboard().text() if ch.isdigit())
            if text:
                field.insert(text)
            return
        if field is getattr(self, "telegram_api_hash", None):
            text = QApplication.clipboard().text().strip()
            if text:
                field.insert(text)
            return
        field.paste()

    def _build_ui(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.addStretch(1)
        self.stack = QStackedWidget()
        self.stack.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.stack.setFixedWidth(406)
        root.addWidget(self.stack)
        root.addStretch(1)
        self.setCentralWidget(central)

        self.main_page, self.main_layout = self._plain_page()
        self.settings_page = self._build_settings_page()
        self.proxies_page = self._build_proxies_page()
        self.stack.addWidget(self.main_page)
        self.stack.addWidget(self.settings_page)
        self.stack.addWidget(self.proxies_page)
        self._build_main_page(self.main_layout)

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        width = min(520, max(406, self.width() - 32))
        self.stack.setFixedWidth(width)
        self._refresh_wraps(width)
        self._refresh_main_density()
        if self.alert_overlay is not None:
            self.alert_overlay.setGeometry(self.centralWidget().rect())

    def _refresh_wraps(self, width: int | None = None) -> None:
        width = width or self.stack.width()
        wrap = max(250, width - 70)
        for label in getattr(self, "_wrapping_labels", []):
            label.setMaximumWidth(wrap)

    def _refresh_main_density(self) -> None:
        if not hasattr(self, "primary_button"):
            return
        height = max(540, int(self.height() or 720))
        if height < 620:
            primary_size = 138
            spacing = 4
            hero_margins = (10, 8, 10, 8)
            active_height = 92
            stat_height = 78
            show_thread = False
            show_active_hint = False
            show_footer = False
            show_hero_hint = False
        elif height < 760:
            primary_size = 198
            spacing = 6
            hero_margins = (14, 10, 14, 8)
            active_height = 116
            stat_height = 78
            show_thread = False
            show_active_hint = True
            show_footer = False
            show_hero_hint = True
        else:
            primary_size = 234
            spacing = 8
            hero_margins = (16, 12, 16, 10)
            active_height = 128
            stat_height = 90
            show_thread = True
            show_active_hint = True
            show_footer = False
            show_hero_hint = True
        self.main_layout.setSpacing(spacing)
        margin = 10 if height < 620 else 12 if height < 760 else 16
        self.main_layout.setContentsMargins(margin, margin, margin, margin)
        if hasattr(self, "thread_text"):
            self.thread_text.setVisible(show_thread)
        if hasattr(self, "active_hint"):
            self.active_hint.setVisible(show_active_hint)
        if hasattr(self, "primary_hint"):
            self.primary_hint.setVisible(show_hero_hint)
        if hasattr(self, "footer_info"):
            self.footer_info.setVisible(show_footer)
        self._primary_button_size = primary_size
        self.primary_button.setFixedSize(primary_size, primary_size)
        if hasattr(self, "hero_layout"):
            self.hero_layout.setContentsMargins(*hero_margins)
            self.hero_layout.setSpacing(max(6, spacing))
        if hasattr(self, "hero_card"):
            hero_height = primary_size + (108 if show_hero_hint else 70)
            self.hero_card.setFixedHeight(hero_height)
            self.hero_card.updateGeometry()
        for card in getattr(self, "_stat_cards", []):
            card.setFixedHeight(stat_height)
            card.updateGeometry()
        if hasattr(self, "active_card"):
            self.active_card.setFixedHeight(active_height)
            self.active_card.updateGeometry()
        self._apply_primary_style()
        self.main_layout.invalidate()
        self.main_layout.activate()

    def _apply_primary_style(self) -> None:
        if not hasattr(self, "primary_button"):
            return
        size = int(getattr(self, "_primary_button_size", 144))
        radius = size // 2
        running = bool(getattr(self, "_local_running", False))
        theme = THEMES[getattr(self, "_theme_name", "light")]
        color = theme["primary_on"] if running else theme["primary_off"]
        hover = theme["primary_on_hover"] if running else theme["primary_off_hover"]
        font_size = 20 if size < 150 else 24 if size < 210 else 28
        self.primary_button.setStyleSheet(
            f"QPushButton#primary {{"
            f"min-width:{size}px;max-width:{size}px;min-height:{size}px;max-height:{size}px;"
            f"border-radius:{radius}px;background:{color};color:#FFFFFF;border:none;"
            f"font-size:{font_size}px;font-weight:700;padding:0px;"
            f"}} QPushButton#primary:hover {{ background:{hover}; }}"
        )

    def _page(self) -> tuple[QWidget, QVBoxLayout]:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        scroll.setWidget(body)
        return scroll, layout

    def _plain_page(self) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        return page, layout

    def _label(self, text: str = "", *, size: int = 12, bold: bool = False, soft: bool = False) -> QLabel:
        label = QLabel(text)
        label.setWordWrap(True)
        label.setProperty("mtSoft", bool(soft))
        label.setProperty("mtSize", int(size))
        label.setProperty("mtBold", bool(bold))
        self._style_label(label)
        return label

    def _style_label(self, label: QLabel) -> None:
        theme = THEMES[getattr(self, "_theme_name", "light")]
        color = theme["soft"] if bool(label.property("mtSoft")) else theme["text"]
        size = int(label.property("mtSize") or 12)
        weight = "700" if bool(label.property("mtBold")) else "400"
        label.setStyleSheet(f"color: {color}; font-size: {size}px; font-weight: {weight};")

    def _refresh_themed_widgets(self) -> None:
        theme = THEMES[getattr(self, "_theme_name", "light")]
        for label in self.findChildren(QLabel):
            if label.property("mtSize") is not None:
                self._style_label(label)
        if hasattr(self, "version_badge"):
            self.version_badge.setStyleSheet(
                f"background:{theme['badge_bg']};color:{theme['badge_fg']};"
                "border-radius:12px;padding:4px 10px;font-weight:700;"
            )
        if hasattr(self, "status_chip"):
            self._refresh_snapshot()
        else:
            self._apply_primary_style()

    def apply_appearance(self, appearance: str | None = None) -> None:
        appearance = appearance or self.runtime.config.appearance
        self._theme_name = _resolve_theme(appearance)
        QApplication.instance().setStyleSheet(THEMES[self._theme_name]["qss"])
        self._refresh_themed_widgets()

    def _card(self, name: str = "card") -> QFrame:
        card = QFrame()
        card.setObjectName(name)
        return card

    def _button(self, text: str, *, accent: bool = False, soft: bool = False, danger: bool = False) -> QPushButton:
        button = QPushButton(text)
        button.setCursor(Qt.PointingHandCursor)
        if accent:
            button.setObjectName("accent")
        elif soft:
            button.setObjectName("soft")
        elif danger:
            button.setObjectName("danger")
        return button

    def _close_alert_overlay(self) -> None:
        if self.alert_overlay is None:
            return
        overlay = self.alert_overlay
        self.alert_overlay = None
        overlay.hide()
        overlay.deleteLater()

    def _show_in_app_dialog(
        self,
        title: str,
        message: str,
        *,
        kind: str = "info",
        buttons: list[tuple[str, str, Callable[[bool], None] | None]] | None = None,
        checkbox_text: str | None = None,
    ) -> None:
        self._close_alert_overlay()
        overlay = DismissibleOverlay(self.centralWidget())
        overlay.setObjectName("alertOverlay")
        overlay.setAttribute(Qt.WA_StyledBackground, True)
        overlay.setGeometry(self.centralWidget().rect())
        overlay.setStyleSheet("QWidget#alertOverlay { background: rgba(34, 29, 49, 82); }")
        overlay.dismiss_requested.connect(self._close_alert_overlay)

        shell = QVBoxLayout(overlay)
        shell.setContentsMargins(18, 18, 18, 18)
        shell.addStretch(1)

        card = QFrame()
        card.setObjectName("alertCard")
        theme = THEMES[getattr(self, "_theme_name", "light")]
        card.setStyleSheet(
            f"QFrame#alertCard {{ background:{theme['alert_bg']}; "
            f"border:1px solid {theme['alert_border']}; border-radius:22px; }}"
        )
        card_width = min(380, max(330, self.stack.width() - 40))
        card.setFixedWidth(card_width)
        card.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Minimum)
        body = QVBoxLayout(card)
        body.setContentsMargins(18, 18, 18, 18)
        body.setSpacing(12)

        title_label = self._label(title, size=17, bold=True)
        body.addWidget(title_label)
        text_label = self._label(message, soft=True)
        text_label.setMaximumWidth(card_width - 36)
        text_label.setMinimumHeight(text_label.sizeHint().height())
        text_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        body.addWidget(text_label)

        remember = QCheckBox(checkbox_text) if checkbox_text else None
        if remember is not None:
            body.addWidget(remember)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        dialog_buttons = buttons or [("Ок", "accent", None)]
        for label, style, callback in dialog_buttons:
            button = self._button(label, accent=style == "accent", soft=style == "soft", danger=style == "danger")

            def handle_click(
                _checked: bool = False,
                cb: Callable[[bool], None] | None = callback,
                remember_box: QCheckBox | None = remember,
            ) -> None:
                remember_value = bool(remember_box.isChecked()) if remember_box is not None else False
                self._close_alert_overlay()
                if cb is not None:
                    cb(remember_value)

            button.clicked.connect(handle_click)
            actions.addWidget(button)
        body.addLayout(actions)
        card.adjustSize()

        shell.addWidget(card, 0, Qt.AlignHCenter)
        shell.addStretch(1)
        overlay.card = card
        overlay.show()
        overlay.raise_()
        self.alert_overlay = overlay

    def show_info(self, title: str, message: str) -> None:
        self._show_in_app_dialog(title, message, kind="info")

    def show_warning(self, title: str, message: str) -> None:
        self._show_in_app_dialog(title, message, kind="warning")

    def show_error(self, title: str, message: str) -> None:
        self._show_in_app_dialog(title, message, kind="error")

    def show_confirm(
        self,
        title: str,
        message: str,
        *,
        yes_text: str = "Да",
        no_text: str = "Нет",
        on_yes: Callable[[bool], None] | None = None,
        on_no: Callable[[bool], None] | None = None,
        checkbox_text: str | None = None,
    ) -> None:
        self._show_in_app_dialog(
            title,
            message,
            kind="question",
            checkbox_text=checkbox_text,
            buttons=[(no_text, "soft", on_no), (yes_text, "accent", on_yes)],
        )

    def _build_main_page(self, layout: QVBoxLayout) -> None:
        header = QHBoxLayout()
        title_row = QHBoxLayout()
        title = self._label("MTProxy", size=24, bold=True)
        self.version_badge = QLabel(f"v{APP_PUBLIC_VERSION}")
        theme = THEMES[getattr(self, "_theme_name", "light")]
        self.version_badge.setStyleSheet(
            f"background:{theme['badge_bg']};color:{theme['badge_fg']};"
            "border-radius:12px;padding:4px 10px;font-weight:700;"
        )
        title_row.addWidget(title)
        title_row.addWidget(self.version_badge)
        title_row.addStretch(1)
        self.settings_button = self._button("Настройки")
        self.settings_button.clicked.connect(self.open_settings)
        header.addLayout(title_row, 1)
        header.addWidget(self.settings_button)
        layout.addLayout(header)

        self.status_chip = QLabel("Подготовка")
        self.status_chip.setStyleSheet(
            f"background:{theme['status_on_bg']};color:{theme['status_on_fg']};"
            "border-radius:16px;padding:8px 14px;font-weight:700;"
        )
        layout.addWidget(self.status_chip, 0, Qt.AlignLeft)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        self.progress_text = self._label("Готов к обновлению", soft=True)
        layout.addWidget(self.progress_text)
        self.thread_text = self._label("Telegram-источники еще не проверялись", size=11, soft=True)
        layout.addWidget(self.thread_text)

        hero = self._card()
        self.hero_card = hero
        hero.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        hero_layout = QVBoxLayout(hero)
        self.hero_layout = hero_layout
        hero_layout.setContentsMargins(16, 16, 16, 12)
        hero_layout.setSpacing(10)
        self.primary_button = QPushButton("Пуск")
        self.primary_button.setObjectName("primary")
        self.primary_button.setProperty("started", "false")
        self.primary_button.clicked.connect(self.primary_action)
        hero_layout.addWidget(self.primary_button, 0, Qt.AlignHCenter)
        self.primary_hint = self._label("Стартовый список загрузится сразу, полный refresh пройдет в фоне.", soft=True)
        self.primary_hint.setAlignment(Qt.AlignCenter)
        hero_layout.addWidget(self.primary_hint)
        hero_actions = QHBoxLayout()
        self.refresh_button = self._button("Обновить", soft=True)
        self.refresh_button.clicked.connect(self.start_refresh)
        self.open_list_button = self._button("Открыть list")
        self.open_list_button.clicked.connect(self.open_output_folder)
        hero_actions.addWidget(self.refresh_button)
        hero_actions.addWidget(self.open_list_button)
        hero_layout.addLayout(hero_actions)
        layout.addWidget(hero)

        connect_actions = QHBoxLayout()
        self.copy_button = self._button("Скопировать")
        self.copy_button.clicked.connect(self.copy_local_link)
        self.connect_button = self._button("Подключиться", accent=True)
        self.connect_button.clicked.connect(self.connect_local_proxy)
        connect_actions.addWidget(self.copy_button)
        connect_actions.addWidget(self.connect_button)
        layout.addLayout(connect_actions)

        stats = QGridLayout()
        stats.setSpacing(8)
        self._stat_cards: list[QFrame] = []
        self.pool_value = self._stat_card(stats, 0, "Рабочих")
        self.ping_value = self._stat_card(stats, 1, "Пинг")
        self.speed_value = self._stat_card(stats, 2, "Скорость", value_size=16)
        layout.addLayout(stats)

        self.active_card = ClickableFrame()
        self.active_card.setObjectName("activeCard")
        self.active_card.setCursor(QCursor(Qt.PointingHandCursor))
        self.active_card.clicked.connect(self.open_proxy_picker)
        active_layout = QVBoxLayout(self.active_card)
        active_layout.setContentsMargins(16, 14, 16, 14)
        top = QHBoxLayout()
        top.addWidget(self._label("Активный upstream", size=15, bold=True))
        top.addStretch(1)
        self.choose_proxy_button = self._button("Выбрать", soft=True)
        self.choose_proxy_button.clicked.connect(self.open_proxy_picker)
        top.addWidget(self.choose_proxy_button)
        active_layout.addLayout(top)
        self.active_proxy = self._label("Еще не выбран")
        active_layout.addWidget(self.active_proxy)
        self.active_hint = self._label("Нажмите, чтобы открыть пул и выбрать upstream", size=10, soft=True)
        active_layout.addWidget(self.active_hint)
        self.footer_info = self._label("Стартовая инициализация", size=11, soft=True)
        active_layout.addWidget(self.footer_info)
        layout.addWidget(self.active_card)
        layout.addStretch(1)

        self._wrapping_labels = [
            self.primary_hint,
            self.progress_text,
            self.thread_text,
            self.active_proxy,
            self.active_hint,
            self.footer_info,
        ]
        self._refresh_main_density()

    def _stat_card(self, grid: QGridLayout, column: int, title: str, *, value_size: int = 18) -> QLabel:
        card = self._card()
        self._stat_cards.append(card)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card.setMinimumHeight(86)
        card.setMaximumHeight(96)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 10, 12, 10)
        card_layout.addWidget(self._label(title, size=10, soft=True))
        value = self._label("n/a", size=value_size, bold=True)
        card_layout.addWidget(value)
        grid.addWidget(card, 0, column)
        return value

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        header = QHBoxLayout()
        self.settings_title = self._label("Настройки", size=24, bold=True)
        self.settings_back = self._button("Назад")
        self.settings_back.clicked.connect(self.settings_back_action)
        header.addWidget(self.settings_title, 1)
        header.addWidget(self.settings_back)
        layout.addLayout(header)

        self.settings_stack = QStackedWidget()
        self.settings_home = self._settings_home()
        self.settings_pages: dict[str, QWidget] = {
            "home": self.settings_home,
            "general": self._settings_general(),
            "routing": self._settings_routing(),
            "telegram": self._settings_telegram(),
            "sources": self._settings_sources(),
            "pool": self._settings_pool(),
            "logs": self._settings_logs(),
            "about": self._settings_about(),
        }
        for widget in self.settings_pages.values():
            self.settings_stack.addWidget(widget)
        layout.addWidget(self.settings_stack, 1)

        footer = QHBoxLayout()
        open_list = self._button("Открыть папку list")
        open_list.clicked.connect(self.open_output_folder)
        self.save_settings_button = self._button("Сохранить", accent=True)
        self.save_settings_button.clicked.connect(self.save_settings)
        footer.addWidget(open_list)
        footer.addWidget(self.save_settings_button)
        layout.addLayout(footer)
        return page

    def _settings_home(self) -> QWidget:
        page, layout = self._page()
        layout.setSpacing(8)
        for key, title, subtitle in [
            ("general", "Общие", "Приложение и обновления"),
            ("routing", "Маршрутизация", "Local frontend и balancer"),
            ("telegram", "Telegram", "Авторизация и Telegram-источники"),
            ("sources", "Источники", "Web-списки и проверка"),
            ("pool", "Пул", "Рабочие upstream"),
            ("logs", "Логи", "Последние события"),
            ("about", "О приложении", "Ссылки и информация"),
        ]:
            row = ClickableFrame()
            row.setObjectName("rowCard")
            row.setCursor(QCursor(Qt.PointingHandCursor))
            row.setFixedHeight(68)
            row.clicked.connect(lambda checked=False, page_key=key: self.show_settings_page(page_key))
            row_layout = QVBoxLayout(row)
            row_layout.setContentsMargins(16, 8, 16, 8)
            top = QHBoxLayout()
            top.addWidget(self._label(title, size=16, bold=True))
            top.addStretch(1)
            top.addWidget(self._label("›", size=22, soft=True))
            row_layout.addLayout(top)
            row_layout.addWidget(self._label(subtitle, size=11, soft=True))
            layout.addWidget(row)
        layout.addStretch(1)
        return page

    def _settings_general(self) -> QWidget:
        page, layout = self._page()
        card = self._card()
        form = QVBoxLayout(card)
        form.setContentsMargins(16, 16, 16, 16)
        form.addWidget(self._label("Поведение приложения", size=16, bold=True))
        self.autostart_check = QCheckBox("Запускать вместе с Windows")
        self.start_minimized_check = QCheckBox("Стартовать свернутым в трей")
        self.auto_start_local_check = QCheckBox("Автостарт локального proxy frontend")
        self.auto_update_check = QCheckBox("Проверять обновления при запуске")
        for widget in (self.autostart_check, self.start_minimized_check, self.auto_start_local_check, self.auto_update_check):
            form.addWidget(widget)
        self.appearance_combo = self._combo(list(APPEARANCE_LABELS.values()))
        self.appearance_combo.currentTextChanged.connect(
            lambda text: self.apply_appearance(APPEARANCE_BY_LABEL.get(text, "auto"))
        )
        self.close_combo = self._combo(list(CLOSE_LABELS.values()))
        form.addLayout(self._form_row("Тема", self.appearance_combo))
        form.addLayout(self._form_row("При закрытии окна", self.close_combo))
        self.update_status = self._label(f"Версия {APP_PUBLIC_VERSION}", size=11, soft=True)
        form.addWidget(self.update_status)
        row = QHBoxLayout()
        self.check_updates_button = self._button("Проверить", soft=True)
        self.check_updates_button.clicked.connect(self.check_updates)
        self.install_update_button = self._button("Установить", accent=True)
        self.install_update_button.clicked.connect(self.install_update)
        self.install_update_button.setEnabled(False)
        row.addWidget(self.check_updates_button)
        row.addWidget(self.install_update_button)
        form.addLayout(row)
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    def _settings_routing(self) -> QWidget:
        page, layout = self._page()
        card = self._card()
        form = QVBoxLayout(card)
        form.setContentsMargins(16, 16, 16, 16)
        form.addWidget(self._label("Локальный frontend", size=16, bold=True))
        self.local_host = QLineEdit()
        self.local_port = self._spin(1, 65535)
        self.local_secret = QLineEdit()
        form.addLayout(self._form_row("Host", self.local_host))
        form.addLayout(self._form_row("Port", self.local_port))
        self.local_secret.hide()
        form.addWidget(self._label("Secret используется внутренне и автоматически добавляется в ссылку подключения.", size=11, soft=True))
        strategy_row = QHBoxLayout()
        strategy_row.addWidget(self._label("Стратегия выбора upstream", size=16, bold=True), 1)
        help_btn = self._button("? ", soft=True)
        help_btn.setFixedWidth(42)
        help_btn.clicked.connect(lambda: self.show_info("Стратегии Balancer", BALANCER_HELP))
        strategy_row.addWidget(help_btn)
        form.addLayout(strategy_row)
        self.strategy_combo = self._combo([BALANCER_LABELS[key] for key in sorted(BALANCER_STRATEGIES)])
        form.addWidget(self.strategy_combo)
        note = self._label(
            "Файл list/fast_list.txt собирается автоматически из лучших proxy после обновления. "
            "При старте приложение сначала берет upstream именно оттуда.",
            soft=True,
        )
        form.addWidget(note)
        form.addWidget(self._label("Telegram Web", size=16, bold=True))
        web_note = self._label("Hosts-правила помогают Telegram Web и web-парсингу Telegram-доменов.", soft=True)
        form.addWidget(web_note)
        hosts_row = QHBoxLayout()
        copy_hosts = self._button("Копировать", soft=True)
        apply_hosts = self._button("Применить", soft=True)
        remove_hosts = self._button("Удалить", soft=True)
        copy_hosts.clicked.connect(self.copy_hosts_block)
        apply_hosts.clicked.connect(self.apply_hosts_block)
        remove_hosts.clicked.connect(self.remove_hosts_block)
        hosts_row.addWidget(copy_hosts)
        hosts_row.addWidget(apply_hosts)
        hosts_row.addWidget(remove_hosts)
        form.addLayout(hosts_row)
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    def _settings_telegram(self) -> QWidget:
        page, layout = self._page()
        auth = self._card()
        form = QVBoxLayout(auth)
        form.setContentsMargins(16, 16, 16, 16)
        form.setSpacing(10)
        form.addWidget(self._label("Авторизация Telegram", size=16, bold=True))
        intro = self._label("Для Telegram API нужны собственные API ID и API Hash. Сессия хранится только в AppData.", soft=True)
        form.addWidget(intro)
        self.telegram_api_id = QLineEdit()
        self.telegram_api_id.setValidator(QIntValidator(1, 2_147_483_647, self.telegram_api_id))
        self.telegram_api_id.setPlaceholderText("API ID")
        self.telegram_api_hash = QLineEdit()
        self.telegram_api_hash.setPlaceholderText("API Hash")
        self.telegram_api_proxy = QLineEdit()
        self.telegram_phone = QLineEdit()
        self.telegram_phone.setPlaceholderText("+79991234567")
        self.telegram_code = QLineEdit()
        self.telegram_code.setPlaceholderText("Код из Telegram")
        self.telegram_password = QLineEdit()
        self.telegram_password.setPlaceholderText("Пароль 2FA, если Telegram запросит")
        self.telegram_password.setEchoMode(QLineEdit.Password)
        self._telegram_password_visible = False

        self.telegram_setup_panel = QWidget()
        self.telegram_setup_panel.setObjectName("transparentPanel")
        setup_layout = QVBoxLayout(self.telegram_setup_panel)
        setup_layout.setContentsMargins(0, 0, 0, 0)
        setup_layout.setSpacing(8)
        for label, widget in [
            ("API ID", self.telegram_api_id),
            ("API Hash", self.telegram_api_hash),
        ]:
            setup_layout.addWidget(self._form_row_widget(label, widget))
        setup_layout.addWidget(LinkButton("Получить API ID и API Hash на my.telegram.org/apps", "https://my.telegram.org/apps"))

        setup_layout.addWidget(self._label("Вход по телефону", size=14, bold=True))
        setup_layout.addWidget(self._label("Телефон", soft=True))
        phone_row = QHBoxLayout()
        phone_row.setSpacing(8)
        phone_row.addWidget(self.telegram_phone, 1)
        self.auth_code_button = self._button("Запросить код", accent=True)
        self.auth_code_button.clicked.connect(self.request_auth_code)
        phone_row.addWidget(self.auth_code_button)
        setup_layout.addLayout(phone_row)

        self.telegram_code_panel = QWidget()
        self.telegram_code_panel.setObjectName("transparentPanel")
        code_layout = QVBoxLayout(self.telegram_code_panel)
        code_layout.setContentsMargins(0, 0, 0, 0)
        code_layout.setSpacing(8)
        code_layout.addWidget(self._label("Подтверждение входа", size=14, bold=True))
        code_layout.addWidget(self._form_row_widget("Код", self.telegram_code))
        password_row = QHBoxLayout()
        password_row.setSpacing(8)
        password_row.addWidget(self.telegram_password, 1)
        self.telegram_password_toggle = self._button("Показать", soft=True)
        self.telegram_password_toggle.setFixedWidth(92)
        self.telegram_password_toggle.clicked.connect(self.toggle_telegram_password)
        password_row.addWidget(self.telegram_password_toggle)
        code_layout.addWidget(self._label("Пароль 2FA", soft=True))
        code_layout.addLayout(password_row)
        self.telegram_code_actions = QWidget()
        self.telegram_code_actions.setObjectName("transparentPanel")
        code_buttons = QHBoxLayout(self.telegram_code_actions)
        code_buttons.setContentsMargins(0, 0, 0, 0)
        self.auth_login_button = self._button("Войти", accent=True)
        self.auth_login_button.clicked.connect(self.complete_auth)
        code_buttons.addWidget(self.auth_login_button)
        code_layout.addWidget(self.telegram_code_actions)
        setup_layout.addWidget(self.telegram_code_panel)

        self.telegram_api_proxy_enabled = QCheckBox("Использовать API proxy")
        self.telegram_api_proxy_enabled.toggled.connect(self._update_telegram_api_proxy_ui)
        setup_layout.addWidget(self.telegram_api_proxy_enabled)
        setup_layout.addWidget(self._label("Нужно только если авторизация Telegram плохо проходит напрямую.", size=11, soft=True))
        self.telegram_api_proxy_panel = QWidget()
        self.telegram_api_proxy_panel.setObjectName("transparentPanel")
        proxy_layout = QVBoxLayout(self.telegram_api_proxy_panel)
        proxy_layout.setContentsMargins(0, 0, 0, 0)
        proxy_layout.setSpacing(6)
        proxy_layout.addWidget(self._label("MTProxy для авторизации Telegram API. Обычно не нужен, включайте только если логин/QR не проходят напрямую.", size=11, soft=True))
        proxy_layout.addWidget(self._form_row_widget("API proxy", self.telegram_api_proxy))
        setup_layout.addWidget(self.telegram_api_proxy_panel)
        form.addWidget(self.telegram_setup_panel)

        self.auth_status = self._label("Статус авторизации не проверен", soft=True)
        form.addWidget(self.auth_status)

        self.telegram_alt_actions = QWidget()
        self.telegram_alt_actions.setObjectName("transparentPanel")
        alt_buttons = QGridLayout(self.telegram_alt_actions)
        alt_buttons.setContentsMargins(0, 0, 0, 0)
        self.auth_check_button = self._button("Проверить сессию", soft=True)
        self.auth_qr_button = self._button("QR вход", soft=True)
        self.auth_check_button.clicked.connect(self.refresh_auth_status)
        self.auth_qr_button.clicked.connect(self.start_qr_auth)
        alt_buttons.addWidget(self.auth_check_button, 0, 0)
        alt_buttons.addWidget(self.auth_qr_button, 0, 1)
        form.addWidget(self.telegram_alt_actions)

        self.telegram_authorized_actions = QWidget()
        self.telegram_authorized_actions.setObjectName("transparentPanel")
        authorized_buttons = QHBoxLayout(self.telegram_authorized_actions)
        authorized_buttons.setContentsMargins(0, 0, 0, 0)
        self.auth_send_button = self._button("Отправить список в Saved", soft=True)
        self.auth_logout_button = self._button("Выйти", danger=True)
        self.auth_send_button.clicked.connect(self.send_proxy_list_to_saved)
        self.auth_logout_button.clicked.connect(self.logout_auth)
        authorized_buttons.addWidget(self.auth_send_button)
        authorized_buttons.addWidget(self.auth_logout_button)
        form.addWidget(self.telegram_authorized_actions)
        layout.addWidget(auth)

        sources = self._card()
        src = QVBoxLayout(sources)
        src.setContentsMargins(16, 16, 16, 16)
        src.addWidget(self._label("Telegram-источники", size=16, bold=True))
        self.telegram_sources_enabled = QCheckBox("Использовать Telegram-источники")
        self.telegram_sources_enabled.toggled.connect(self._telegram_sources_toggled)
        src.addWidget(self.telegram_sources_enabled)
        self.telegram_sources_locked = self._label("Источники включаются только после успешной авторизации Telegram API.", soft=True)
        src.addWidget(self.telegram_sources_locked)
        self.telegram_source_checks: dict[str, QCheckBox] = {}
        for source in DEFAULT_TELEGRAM_SOURCE_URLS:
            check = QCheckBox(source)
            self.telegram_source_checks[source] = check
            src.addWidget(check)
        self.telegram_max_messages = self._spin(1, 5000)
        self.telegram_max_proxies = self._spin(1, 5000)
        src.addLayout(self._form_row("Сообщений на источник", self.telegram_max_messages))
        src.addLayout(self._form_row("Proxy из Telegram", self.telegram_max_proxies))
        layout.addWidget(sources)
        layout.addStretch(1)
        self._update_telegram_api_proxy_ui()
        self._update_telegram_auth_ui()
        return page

    def _settings_sources(self) -> QWidget:
        page, layout = self._page()
        card = self._card()
        form = QVBoxLayout(card)
        form.setContentsMargins(16, 16, 16, 16)
        form.addWidget(self._label("Web-источники", size=16, bold=True))
        enable_all = self._button("Включить все источники", soft=True)
        enable_all.clicked.connect(lambda: [check.setChecked(True) for check in self.source_checks.values()])
        form.addWidget(enable_all)
        self.source_checks: dict[str, QCheckBox] = {}
        for source in DEFAULT_SOURCES:
            check = QCheckBox(source)
            self.source_checks[source] = check
            form.addWidget(check)
        layout.addWidget(card)

        probe = self._card()
        p = QVBoxLayout(probe)
        p.setContentsMargins(16, 16, 16, 16)
        p.setSpacing(10)
        p.addWidget(self._label("Параметры проверки", size=16, bold=True))
        self.deep_media_enabled = QCheckBox("Deep media check через Telegram API")
        p.addWidget(self.deep_media_enabled)
        self.advanced_probe_enabled = QCheckBox("Показать параметры проверки")
        self.advanced_probe_enabled.toggled.connect(self._update_advanced_probe_ui)
        p.addWidget(self.advanced_probe_enabled)
        p.addWidget(self._label("Менять только при необходимости: неверные значения могут сильно замедлить refresh или ухудшить отбор.", size=11, soft=True))
        self.advanced_probe_panel = QWidget()
        self.advanced_probe_panel.setObjectName("transparentPanel")
        advanced_layout = QVBoxLayout(self.advanced_probe_panel)
        advanced_layout.setContentsMargins(0, 0, 0, 0)
        advanced_layout.setSpacing(8)
        self.duration = self._spin(3, 120)
        self.timeout = self._spin(2, 60)
        self.workers = self._spin(1, 200)
        self.max_latency = self._spin(50, 10000)
        self.live_probe_top_n = self._spin(1, 200)
        for label, widget in [
            ("Длительность, сек", self.duration),
            ("Timeout, сек", self.timeout),
            ("Параллельность", self.workers),
            ("Макс. latency, ms", self.max_latency),
            ("Быстрая проверка top N", self.live_probe_top_n),
        ]:
            advanced_layout.addWidget(self._form_row_widget(label, widget))
        p.addWidget(self.advanced_probe_panel)
        layout.addWidget(probe)
        layout.addStretch(1)
        self._update_advanced_probe_ui()
        return page

    def _settings_pool(self) -> QWidget:
        page, layout = self._page()
        self.pool_list = QListWidget()
        self.pool_list.setObjectName("cardList")
        self.pool_list.setSpacing(8)
        self.pool_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.pool_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        layout.addWidget(self.pool_list)
        row = QHBoxLayout()
        copy = self._button("Скопировать proxy_list", soft=True)
        copy.clicked.connect(self.copy_pool_to_clipboard)
        probe = self._button("Быстрая проверка", accent=True)
        probe.clicked.connect(self.quick_probe)
        row.addWidget(copy)
        row.addWidget(probe)
        layout.addLayout(row)
        return page

    def _settings_logs(self) -> QWidget:
        page, layout = self._page()
        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.logs.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        layout.addWidget(self.logs)
        copy = self._button("Копировать лог", soft=True)
        copy.clicked.connect(lambda: QApplication.clipboard().setText("\n".join(self.log_lines)))
        layout.addWidget(copy)
        return page

    def _settings_about(self) -> QWidget:
        page, layout = self._page()
        layout.addWidget(
            self._about_card(
                f"{APP_NAME} · v{APP_PUBLIC_VERSION}",
                "Приложение собирает MTProto-прокси, проверяет их доступность, выбирает быстрые upstream "
                "и держит локальный frontend для Telegram.",
                None,
                None,
            )
        )
        layout.addWidget(
            self._about_card(
                "Оригинальный проект Flowseal",
                "Базовый локальный MTProto frontend, на основе которого сделан этот форк.",
                "Открыть GitHub Flowseal",
                "https://github.com/Flowseal/tg-ws-proxy",
            )
        )
        layout.addWidget(
            self._about_card(
                "Telegram автора",
                "Если приложение оказалось полезным, подписка на канал будет большой поддержкой.",
                "Открыть Telegram автора",
                "https://t.me/peppe_poppo",
            )
        )
        layout.addWidget(
            self._about_card(
                "Репозиторий этого форка",
                "Здесь лежат исходники, публичные сборки, история изменений и задачи по развитию приложения.",
                "Открыть репозиторий",
                "https://github.com/pengvench/MTProxyAutoSwitch",
            )
        )
        layout.addStretch(1)
        return page

    def _about_card(self, title: str, body: str, button_text: str | None, url: str | None) -> QFrame:
        card = self._card("aboutCard")
        form = QVBoxLayout(card)
        form.setContentsMargins(16, 14, 16, 14)
        form.setSpacing(8)
        form.addWidget(self._label(title, size=15, bold=True))
        form.addWidget(self._label(body, soft=True))
        if button_text and url:
            form.addWidget(LinkButton(button_text, url))
        return card

    def _build_proxies_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        top = QHBoxLayout()
        back = self._button("Назад")
        back.clicked.connect(lambda: self.stack.setCurrentWidget(self.main_page))
        quick = self._button("Проверить", soft=True)
        quick.clicked.connect(self.quick_probe)
        top.addWidget(back)
        top.addStretch(1)
        top.addWidget(quick)
        layout.addLayout(top)
        layout.addWidget(self._label("Прокси", size=24, bold=True))
        self.proxy_mode_text = self._label("Режим: Auto balance", soft=True)
        layout.addWidget(self.proxy_mode_text)
        balancer_row = QHBoxLayout()
        balancer_row.addWidget(self._label("Balancer", soft=True))
        self.proxy_strategy_combo = self._combo([BALANCER_LABELS[key] for key in sorted(BALANCER_STRATEGIES)])
        self.proxy_strategy_combo.currentTextChanged.connect(self.change_strategy_from_proxy_page)
        help_btn = self._button("?", soft=True)
        help_btn.setFixedWidth(42)
        help_btn.clicked.connect(lambda: self.show_info("Стратегии Balancer", BALANCER_HELP))
        balancer_row.addWidget(self.proxy_strategy_combo, 1)
        balancer_row.addWidget(help_btn)
        layout.addLayout(balancer_row)
        self.proxy_count_text = self._label("В пуле 0 рабочих proxy", soft=True)
        layout.addWidget(self.proxy_count_text)
        self.proxy_list = QListWidget()
        self.proxy_list.setObjectName("cardList")
        self.proxy_list.setSpacing(8)
        self.proxy_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.proxy_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.proxy_list.itemClicked.connect(self.proxy_item_clicked)
        layout.addWidget(self.proxy_list, 1)
        self.proxy_footer = self._label("Текущий режим: Auto balance", size=11, soft=True)
        layout.addWidget(self.proxy_footer)
        return page

    def _combo(self, values: list[str]) -> QComboBox:
        combo = QComboBox()
        combo.addItems(values)
        return combo

    def _spin(self, minimum: int, maximum: int) -> QuietSpinBox:
        spin = QuietSpinBox()
        spin.setRange(minimum, maximum)
        return spin

    def _form_row(self, label: str, widget: QWidget) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addWidget(self._label(label, soft=True), 0)
        row.addWidget(widget, 1)
        return row

    def _form_row_widget(self, label: str, widget: QWidget) -> QWidget:
        holder = QWidget()
        holder.setObjectName("inlineRow")
        holder.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QHBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self._form_row(label, widget))
        return holder

    def _proxy_card_widget(
        self,
        *,
        badge: str,
        title: str,
        subtitle: str,
        metric: str,
        selected: bool = False,
        active: bool = False,
        on_click: Callable[[], None] | None = None,
    ) -> ClickableFrame:
        card = ClickableFrame()
        card.setObjectName("proxyRow")
        card.setCursor(QCursor(Qt.PointingHandCursor))
        if on_click is not None:
            card.clicked.connect(on_click)
        theme = THEMES[getattr(self, "_theme_name", "light")]
        bg = theme["proxy_selected_bg"] if selected else theme["proxy_active_bg"] if active else theme["proxy_bg"]
        border = (
            theme["proxy_selected_border"]
            if selected
            else theme["proxy_active_border"] if active else theme["proxy_border"]
        )
        card.setStyleSheet(
            f"QFrame#proxyRow {{ background:{bg}; border:1px solid {border}; border-radius:18px; }}"
        )
        layout = QHBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(10)
        avatar = QLabel(badge[:2].upper())
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setFixedSize(34, 34)
        avatar.setStyleSheet(
            f"background:{theme['proxy_selected_border']};color:#FFFFFF;"
            "border-radius:17px;font-weight:700;font-size:11px;"
            if selected or active
            else f"background:{theme['badge_bg']};color:{theme['badge_fg']};"
            "border-radius:17px;font-weight:700;font-size:11px;"
        )
        layout.addWidget(avatar)
        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        title_label = self._label(title, size=14, bold=True)
        title_label.setWordWrap(False)
        title_label.setToolTip(title)
        subtitle_label = self._label(subtitle, size=10, soft=True)
        subtitle_label.setWordWrap(False)
        subtitle_label.setToolTip(subtitle)
        text_col.addWidget(title_label)
        text_col.addWidget(subtitle_label)
        layout.addLayout(text_col, 1)
        metric_label = self._label(metric, size=13, bold=True, soft=False)
        metric_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(metric_label)
        return card

    def _add_card_item(self, list_widget: QListWidget, widget: QWidget, value: str = "") -> QListWidgetItem:
        item = QListWidgetItem()
        item.setData(Qt.UserRole, value)
        item.setSizeHint(QSize(1, max(62, widget.sizeHint().height() + 6)))
        list_widget.addItem(item)
        list_widget.setItemWidget(item, widget)
        return item

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(_asset_icon(), self)
        self.tray.setToolTip(APP_NAME)
        self.tray.activated.connect(self._tray_activated)
        self._refresh_tray_menu()
        self.tray.show()

    def _refresh_tray_menu(self) -> None:
        menu = QMenu()
        show_action = QAction("Открыть", self)
        show_action.triggered.connect(self.show_from_tray)
        menu.addAction(show_action)
        copy_action = QAction("Скопировать ссылку", self)
        copy_action.triggered.connect(self.copy_local_link)
        menu.addAction(copy_action)
        snapshot = self.runtime.snapshot()
        if snapshot.get("local_running"):
            action = QAction("Остановить", self)
            action.triggered.connect(self.stop_local_proxy)
        else:
            action = QAction("Запустить", self)
            action.triggered.connect(self.start_local_proxy)
        menu.addAction(action)
        if self.refresh_in_progress:
            refresh = QAction("Отменить обновление", self)
            refresh.triggered.connect(self.cancel_refresh)
        else:
            refresh = QAction("Обновить", self)
            refresh.triggered.connect(self.start_refresh)
        menu.addAction(refresh)
        quit_action = QAction("Выход", self)
        quit_action.triggered.connect(lambda: self.quit_application(force=True))
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.DoubleClick, QSystemTrayIcon.Trigger):
            self.show_from_tray()

    def open_settings(self) -> None:
        self._refresh_settings_from_config()
        self.show_settings_page("home")
        self.stack.setCurrentWidget(self.settings_page)

    def show_settings_page(self, key: str) -> None:
        widget = self.settings_pages.get(key, self.settings_home)
        self.settings_stack.setCurrentWidget(widget)
        titles = {
            "home": "Настройки",
            "general": "Общие",
            "routing": "Маршрутизация",
            "telegram": "Telegram",
            "sources": "Источники",
            "pool": "Пул",
            "logs": "Логи",
            "about": "О приложении",
        }
        self.settings_title.setText(titles.get(key, "Настройки"))
        self.settings_back.setText("Назад")
        if key == "pool":
            self._refresh_pool_table()
        elif key == "telegram":
            self._update_telegram_auth_ui()
            self.refresh_auth_status()

    def settings_back_action(self) -> None:
        if self.settings_stack.currentWidget() is self.settings_home:
            self.stack.setCurrentWidget(self.main_page)
        else:
            self.show_settings_page("home")

    def open_proxy_picker(self) -> None:
        self._refresh_proxy_page()
        self.stack.setCurrentWidget(self.proxies_page)

    def _refresh_settings_from_config(self) -> None:
        cfg = self.runtime.config
        self.autostart_check.setChecked(is_autostart_enabled())
        self.start_minimized_check.setChecked(bool(cfg.start_minimized_to_tray))
        self.auto_start_local_check.setChecked(bool(cfg.auto_start_local))
        self.auto_update_check.setChecked(bool(cfg.auto_update_enabled))
        self.appearance_combo.setCurrentText(APPEARANCE_LABELS.get(cfg.appearance, "Авто"))
        self.close_combo.setCurrentText(CLOSE_LABELS.get(cfg.close_behavior, "Всегда спрашивать"))
        self.local_host.setText(str(cfg.local_host))
        self.local_port.setValue(int(cfg.local_port))
        self.local_secret.setText(str(cfg.local_secret))
        self.strategy_combo.setCurrentText(BALANCER_LABELS.get(cfg.balancer_strategy, "Sticky session"))
        self.telegram_api_id.setText(str(cfg.telegram_api_id) if int(cfg.telegram_api_id or 0) > 0 else "")
        self.telegram_api_hash.setText(str(cfg.telegram_api_hash or ""))
        self.telegram_api_proxy_enabled.setChecked(bool(getattr(cfg, "telegram_api_proxy_enabled", False)))
        self.telegram_api_proxy.setText(str(cfg.telegram_api_proxy_url or DEFAULT_TELEGRAM_API_PROXY_URL))
        self.telegram_phone.setText(str(cfg.telegram_phone or ""))
        self.telegram_sources_enabled.blockSignals(True)
        self.telegram_sources_enabled.setChecked(
            bool(cfg.telegram_sources_enabled) and (not self._telegram_auth_known or self._telegram_authorized)
        )
        self.telegram_sources_enabled.blockSignals(False)
        active_sources = set(cfg.sources or [])
        for source, check in self.source_checks.items():
            check.setChecked(source in active_sources)
        active_tg = set(cfg.telegram_sources or [])
        for source, check in self.telegram_source_checks.items():
            check.setChecked(source in active_tg)
        self.telegram_max_messages.setValue(int(cfg.telegram_source_max_messages or 1))
        self.telegram_max_proxies.setValue(int(cfg.telegram_source_max_proxies or 1))
        self.duration.setValue(int(round(float(cfg.duration or 35))))
        self.timeout.setValue(int(round(float(cfg.timeout or 8))))
        self.workers.setValue(int(cfg.workers or 25))
        self.max_latency.setValue(int(round(float(cfg.max_latency_ms or 300))))
        self.live_probe_top_n.setValue(int(cfg.live_probe_top_n or 12))
        self.deep_media_enabled.setChecked(bool(cfg.deep_media_enabled))
        self.advanced_probe_enabled.setChecked(False)
        self._update_advanced_probe_ui()
        self._update_telegram_api_proxy_ui()
        self._update_telegram_auth_ui()
        self.apply_appearance(cfg.appearance)

    def _update_telegram_api_proxy_ui(self) -> None:
        if hasattr(self, "telegram_api_proxy_panel"):
            self.telegram_api_proxy_panel.setVisible(bool(self.telegram_api_proxy_enabled.isChecked()))

    def _update_advanced_probe_ui(self) -> None:
        if hasattr(self, "advanced_probe_panel"):
            self.advanced_probe_panel.setVisible(bool(self.advanced_probe_enabled.isChecked()))

    def _update_telegram_auth_ui(self) -> None:
        if not hasattr(self, "telegram_sources_enabled"):
            return
        authorized = bool(self._telegram_authorized)
        known = bool(self._telegram_auth_known)
        busy = str(getattr(self, "_telegram_auth_busy", "") or "")
        stage = self._telegram_auth_stage if not authorized else "authorized"
        waiting_for_code = stage == "code"

        self.telegram_setup_panel.setVisible(not authorized)
        self.telegram_code_panel.setVisible(waiting_for_code and not authorized)
        self.telegram_alt_actions.setVisible(not authorized)
        self.telegram_code_actions.setVisible(waiting_for_code and not authorized)
        self.telegram_authorized_actions.setVisible(authorized)

        self.telegram_sources_enabled.setEnabled(True)
        if known and not authorized:
            self.telegram_sources_enabled.blockSignals(True)
            self.telegram_sources_enabled.setChecked(False)
            self.telegram_sources_enabled.blockSignals(False)
        self.telegram_sources_locked.setVisible(not authorized)
        self.auth_code_button.setEnabled(not busy)
        self.auth_login_button.setEnabled(waiting_for_code and not busy)
        self.auth_check_button.setEnabled(not busy)
        self.auth_qr_button.setEnabled(not busy)
        self.auth_send_button.setEnabled(authorized and not busy)
        self.auth_logout_button.setEnabled(authorized and not busy)
        self.telegram_password_toggle.setEnabled(not busy)
        self.telegram_api_id.setEnabled(not busy)
        self.telegram_api_hash.setEnabled(not busy)
        self.telegram_api_proxy_enabled.setEnabled(not busy)
        self.telegram_api_proxy.setEnabled(not busy and self.telegram_api_proxy_enabled.isChecked())
        self.telegram_phone.setEnabled(not busy)
        self.telegram_code.setEnabled(waiting_for_code and not busy)
        self.telegram_password.setEnabled(waiting_for_code and not busy)
        self.auth_code_button.setText("Запрашиваем..." if busy == "request_code" else "Запросить код")
        self.auth_login_button.setText("Входим..." if busy == "complete_auth" else "Войти")
        self.auth_check_button.setText("Проверяем..." if busy == "auth_status" else "Проверить сессию")
        self.auth_qr_button.setText("Открываем QR..." if busy == "qr_auth" else "QR вход")
        self.auth_send_button.setText("Отправляем..." if busy == "send_saved" else "Отправить список в Saved")
        self.auth_logout_button.setText("Выходим..." if busy == "logout_auth" else "Выйти")
        self._update_telegram_sources_enabled()

    def _set_telegram_auth_busy(self, action: str | None, status: str | None = None) -> None:
        self._telegram_auth_busy = action
        if status is not None:
            self.auth_status.setText(status)
        self._update_telegram_auth_ui()

    def _telegram_auth_failed(self, error: str) -> None:
        message = self._format_telegram_error(error)
        self._set_telegram_auth_busy(None, f"Ошибка Telegram: {message}")
        self.show_error("Telegram", message)

    @staticmethod
    def _format_telegram_error(error: str) -> str:
        text = str(error or "").strip()
        messages = {
            "telegram_api_credentials_missing": "Укажите API ID и API Hash.",
            "phone_code_hash_missing": "Сначала запросите код Telegram.",
            "connect_timeout": "Не удалось подключиться к Telegram API: истекло время ожидания. Проверьте интернет или API proxy.",
            "send_code_timeout": "Telegram не ответил на запрос кода. Проверьте подключение или попробуйте другой API proxy.",
            "sign_in_timeout": "Telegram не ответил при проверке кода. Проверьте подключение или попробуйте еще раз.",
            "password_sign_in_timeout": "Telegram не ответил при проверке пароля 2FA. Проверьте подключение или попробуйте еще раз.",
            "auth_status_timeout": "Telegram не ответил на проверку сессии. Проверьте подключение или API proxy.",
            "qr_login_timeout": "Telegram не выдал QR-код вовремя. Проверьте подключение или API proxy.",
            "qr_wait_timeout": "QR-код истек. Запустите QR вход еще раз.",
            "qr_password_timeout": "Telegram не ответил при проверке пароля 2FA для QR входа.",
            "logout_timeout": "Telegram не ответил на запрос выхода. Проверьте подключение.",
            "send_empty_timeout": "Telegram не ответил при отправке сообщения в Saved.",
            "send_chunk_timeout": "Telegram не ответил при отправке списка в Saved.",
        }
        return messages.get(text, text or "Неизвестная ошибка")

    def _telegram_sources_toggled(self, checked: bool) -> None:
        if checked and not self._telegram_authorized:
            self.show_warning(
                "Telegram-источники",
                "Сначала авторизуйтесь в Telegram API. После успешного входа эти источники можно будет включить.",
            )
            self.telegram_sources_enabled.blockSignals(True)
            self.telegram_sources_enabled.setChecked(False)
            self.telegram_sources_enabled.blockSignals(False)
        self._update_telegram_sources_enabled()

    def _update_telegram_sources_enabled(self) -> None:
        if not hasattr(self, "telegram_sources_enabled"):
            return
        enabled = bool(self._telegram_authorized and self.telegram_sources_enabled.isChecked())
        for check in self.telegram_source_checks.values():
            check.setEnabled(True)
        for widget in (self.telegram_max_messages, self.telegram_max_proxies):
            widget.setEnabled(enabled)

    def _collect_config(self) -> AppConfig:
        payload = asdict(self.runtime.config)
        payload.update(
            {
                "autostart_enabled": bool(self.autostart_check.isChecked()),
                "start_minimized_to_tray": bool(self.start_minimized_check.isChecked()),
                "auto_start_local": bool(self.auto_start_local_check.isChecked()),
                "auto_update_enabled": bool(self.auto_update_check.isChecked()),
                "appearance": APPEARANCE_BY_LABEL.get(self.appearance_combo.currentText(), "auto"),
                "close_behavior": CLOSE_BY_LABEL.get(self.close_combo.currentText(), "ask"),
                "local_host": self.local_host.text().strip() or "127.0.0.1",
                "local_port": int(self.local_port.value()),
                "local_secret": self.local_secret.text().strip() or DEFAULT_LOCAL_SECRET,
                "balancer_strategy": BALANCER_BY_LABEL.get(self.strategy_combo.currentText(), "sticky_session"),
                "telegram_api_id": int(self.telegram_api_id.text().strip() or 0),
                "telegram_api_hash": self.telegram_api_hash.text().strip(),
                "telegram_api_proxy_enabled": bool(self.telegram_api_proxy_enabled.isChecked()),
                "telegram_api_proxy_url": self.telegram_api_proxy.text().strip() or DEFAULT_TELEGRAM_API_PROXY_URL,
                "telegram_phone": normalize_telegram_phone(self.telegram_phone.text().strip()) or self.telegram_phone.text().strip(),
                "telegram_sources_enabled": bool(self.telegram_sources_enabled.isChecked())
                and (not self._telegram_auth_known or self._telegram_authorized),
                "telegram_sources": [source for source, check in self.telegram_source_checks.items() if check.isChecked()],
                "sources": [source for source, check in self.source_checks.items() if check.isChecked()],
                "telegram_source_max_messages": int(self.telegram_max_messages.value()),
                "telegram_source_max_proxies": int(self.telegram_max_proxies.value()),
                "duration": float(self.duration.value()),
                "timeout": float(self.timeout.value()),
                "workers": int(self.workers.value()),
                "max_latency_ms": float(self.max_latency.value()),
                "live_probe_top_n": int(self.live_probe_top_n.value()),
                "deep_media_enabled": bool(self.deep_media_enabled.isChecked()),
                "rf_whitelist_check_enabled": False,
            }
        )
        return AppConfig(**payload)

    def save_settings(self) -> None:
        try:
            cfg = self._collect_config()
            set_autostart_enabled(bool(cfg.autostart_enabled))
        except Exception as exc:
            self.show_error("Настройки не сохранены", str(exc))
            return
        self.run_task(
            "save_settings",
            lambda: self.runtime.apply_config(cfg),
            on_success=lambda _result: self._settings_saved(),
        )

    def _settings_saved(self) -> None:
        self._refresh_settings_from_config()
        self._refresh_snapshot()
        self.show_info("Настройки", "Параметры сохранены")

    def toggle_telegram_password(self) -> None:
        self._telegram_password_visible = not bool(getattr(self, "_telegram_password_visible", False))
        self.telegram_password.setEchoMode(QLineEdit.Normal if self._telegram_password_visible else QLineEdit.Password)
        self.telegram_password_toggle.setText("Скрыть" if self._telegram_password_visible else "Показать")

    def run_task(
        self,
        name: str,
        func: Callable[[], Any],
        *,
        on_success: Callable[[Any], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        token = f"{name}:{time.monotonic_ns()}"
        self.task_callbacks[token] = (on_success, on_error)

        def worker() -> None:
            try:
                result = func()
                self.bridge.task_done.emit(token, result)
            except Exception as exc:
                self.bridge.task_failed.emit(token, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    def _on_task_done(self, token: str, result: object) -> None:
        callbacks = self.task_callbacks.pop(token, (None, None))
        if callbacks[0] is not None:
            callbacks[0](result)
        self._refresh_snapshot()

    def _on_task_failed(self, token: str, error: str) -> None:
        callbacks = self.task_callbacks.pop(token, (None, None))
        if callbacks[1] is not None:
            callbacks[1](error)
        else:
            self.show_error("Ошибка", error)
        self._refresh_snapshot()

    def primary_action(self) -> None:
        if self.runtime.snapshot().get("local_running"):
            self.stop_local_proxy()
        else:
            self.start_local_proxy()

    def start_local_proxy(self) -> None:
        self.run_task(
            "start_local",
            lambda: self.runtime.start_local_server(raise_on_verify_failure=True),
            on_error=lambda error: self.show_error("Запуск не выполнен", error),
        )

    def stop_local_proxy(self) -> None:
        self.run_task("stop_local", self.runtime.stop_local_server)

    def start_refresh(self) -> None:
        if self.refresh_in_progress:
            self.cancel_refresh()
            return
        self.refresh_in_progress = True
        self.refresh_cancel_event = threading.Event()
        self.progress.setValue(20)
        self.progress_text.setText("Подготовка к обновлению списка")
        self.refresh_button.setText("Отмена")
        self._refresh_tray_menu()

        def worker() -> None:
            try:
                self.runtime.run_refresh(cancel_event=self.refresh_cancel_event)
                self.bridge.task_done.emit("refresh", True)
            except Exception as exc:
                self.bridge.task_failed.emit("refresh", str(exc))

        self.task_callbacks["refresh"] = (lambda _result: self._refresh_finished(True), lambda error: self._refresh_failed(error))
        threading.Thread(target=worker, daemon=True).start()

    def cancel_refresh(self) -> None:
        if self.refresh_in_progress:
            self.refresh_cancel_event.set()
            self.progress_text.setText("Обновление отменяется...")

    def _refresh_finished(self, _ok: bool) -> None:
        self.refresh_in_progress = False
        self.refresh_button.setText("Обновить")
        self.progress.setValue(1000)
        self._refresh_tray_menu()
        self._refresh_snapshot()

    def _refresh_failed(self, error: str) -> None:
        self.refresh_in_progress = False
        self.refresh_button.setText("Обновить")
        if "cancel" in error.lower() or "refresh_cancelled" in error:
            self.progress_text.setText("Обновление отменено")
        else:
            self.progress_text.setText(f"Ошибка обновления: {error}")
            self.show_error("Обновление не выполнено", error)
        self._refresh_tray_menu()
        self._refresh_snapshot()

    def _auto_refresh_initial(self) -> None:
        snapshot = self.runtime.snapshot()
        if int(snapshot.get("working_count") or 0) <= 0 and not self.refresh_in_progress:
            self.start_refresh()
        elif self.runtime.config.auto_start_local and snapshot.get("pool_rows") and not snapshot.get("local_running"):
            self.start_local_proxy()

    def _refresh_snapshot(self) -> None:
        snapshot = self.runtime.snapshot()
        self.last_snapshot = snapshot
        rows = list(snapshot.get("pool_rows") or [])
        running = bool(snapshot.get("local_running"))
        self._local_running = running
        self.status_chip.setText("Локальный прокси активен" if running else "Локальный прокси остановлен")
        theme = THEMES[getattr(self, "_theme_name", "light")]
        self.status_chip.setStyleSheet(
            (
                f"background:{theme['status_on_bg']};color:{theme['status_on_fg']};"
                if running
                else f"background:{theme['status_off_bg']};color:{theme['status_off_fg']};"
            )
            + "border-radius:16px;padding:8px 14px;font-weight:700;"
        )
        self.primary_button.setText("Стоп" if running else "Пуск")
        self.primary_button.setProperty("started", "true" if running else "false")
        self._apply_primary_style()
        local_endpoint = f"{self.runtime.config.local_host}:{self.runtime.config.local_port}"
        self.primary_hint.setText(
            f"Локальный адрес для Telegram: {local_endpoint}"
            if running
            else "Нажмите Пуск, чтобы поднять локальный frontend."
        )
        self.pool_value.setText(str(len(rows)))
        best_row = rows[0] if rows else {}
        latency = best_row.get("live_latency_ms") or best_row.get("base_latency_ms") or best_row.get("connect_latency_ms")
        self.ping_value.setText(_format_latency(latency))
        upload = best_row.get("recent_media_upload_kbps") or best_row.get("deep_media_upload_kbps")
        download = best_row.get("recent_media_download_kbps") or best_row.get("deep_media_download_kbps")
        if _safe_float(upload):
            self.last_upload_kbps = _safe_float(upload)
        if _safe_float(download):
            self.last_download_kbps = _safe_float(download)
        self.speed_value.setText(f"↑ {_format_rate(self.last_upload_kbps)}\n↓ {_format_rate(self.last_download_kbps)}")
        active = snapshot.get("manual_upstream_url") or snapshot.get("best_proxy") or "Еще не выбран"
        self.active_proxy.setText(_trim_middle(str(active), 72))
        if not self.refresh_in_progress:
            self.progress_text.setText(
                f"Обновление завершено: {len(rows)} рабочих из {snapshot.get('unique_count', 0)}"
                if snapshot.get("last_refresh_finished_at")
                else "Готов к обновлению"
            )
        thread_status = str(snapshot.get("thread_status") or "disabled")
        if thread_status == "disabled":
            self.thread_text.setText("Telegram-источники выключены и ожидают следующего обновления")
        else:
            self.thread_text.setText(f"Загружено из Telegram-источников: {snapshot.get('thread_proxy_count', 0)}")
        self.footer_info.setText("Загружен стартовый пул. Полный refresh запустится автоматически." if rows else "Рабочий пул пока пуст.")
        self._refresh_proxy_page(only_if_visible=True)
        self._refresh_pool_table()
        self._refresh_tray_menu()

    def _handle_runtime_event(self, event_name: str, payload: object) -> None:
        payload = dict(payload or {})
        if event_name == "phase":
            phase = payload.get("phase")
            if phase == "scraping":
                total = int(payload.get("total_sources") or 0)
                self.progress.setValue(40)
                self.progress_text.setText(f"Сбор сайтов: 0/{total}")
            elif phase == "probing":
                total = int(payload.get("total_proxies") or 0)
                self.progress.setValue(380)
                self.progress_text.setText(f"Проверка прокси: 0/{total}")
        elif event_name == "source_started":
            total = max(1, int(payload.get("total") or 1))
            index = max(1, int(payload.get("index") or 1))
            self.progress.setValue(int(40 + ((index - 1) / total) * 300))
            self.progress_text.setText(f"Сбор сайтов: {index}/{total}")
        elif event_name == "probe_result":
            total = max(1, int(payload.get("total") or 1))
            completed = max(0, int(payload.get("completed") or 0))
            self.progress.setValue(int(380 + (completed / total) * 480))
            self.progress_text.setText(f"Проверка прокси: {completed}/{total}")
        elif event_name == "runtime_refresh_waiting":
            self.progress_text.setText("Ждем окончания пользовательской media-сессии Telegram")
        elif event_name == "runtime_refresh_complete":
            self.progress.setValue(1000)
            self.progress_text.setText(
                f"Обновление завершено: {payload.get('working', 0)} рабочих из {payload.get('unique', 0)}"
            )
        elif event_name == "local_server_state":
            self._refresh_snapshot()
        elif event_name == "telegram_qr_ready":
            url = str(payload.get("url") or "")
            if url:
                self.show_qr_dialog(url)

    def _append_log(self, message: str) -> None:
        line = str(message)
        self.log_lines.append(line)
        if len(self.log_lines) > 500:
            self.log_lines = self.log_lines[-500:]
        if hasattr(self, "logs"):
            self.logs.setPlainText("\n".join(self.log_lines))
            self.logs.verticalScrollBar().setValue(self.logs.verticalScrollBar().maximum())

    def _refresh_proxy_page(self, *, only_if_visible: bool = False) -> None:
        if only_if_visible and self.stack.currentWidget() is not self.proxies_page:
            return
        snapshot = self.runtime.snapshot()
        rows = list(snapshot.get("pool_rows") or [])
        strategy = str(snapshot.get("balancer_strategy") or "sticky_session")
        manual = str(snapshot.get("manual_upstream_url") or "")
        label = BALANCER_LABELS.get(strategy, strategy)
        self.proxy_strategy_combo.blockSignals(True)
        self.proxy_strategy_combo.setCurrentText(label)
        self.proxy_strategy_combo.blockSignals(False)
        self.proxy_mode_text.setText(f"Режим: {'Ручной upstream' if manual else f'Auto balance ({label})'}")
        self.proxy_count_text.setText(f"В пуле {len(rows)} рабочих proxy")
        self.proxy_footer.setText(f"Текущий upstream: {_trim_middle(manual, 72)}" if manual else f"Текущий режим: Auto balance · {label}")
        self.proxy_list.clear()

        auto_widget = self._proxy_card_widget(
            badge="B",
            title="balance",
            subtitle=f"Balancer ({label})",
            metric="AUTO",
            selected=not manual,
            on_click=lambda: self._apply_proxy_url(""),
        )
        self._add_card_item(self.proxy_list, auto_widget, "")
        for index, row in enumerate(rows):
            url = str(row.get("url") or "")
            host = f"{row.get('host')}:{row.get('port')}"
            latency = _format_latency(row.get("live_latency_ms") or row.get("base_latency_ms") or row.get("connect_latency_ms"))
            tag = "Manual" if url == manual else "Fast list" if index < DEFAULT_FAST_LIST_LIMIT else "Proxy"
            speed = ""
            up = _safe_float(row.get("recent_media_upload_kbps") or row.get("deep_media_upload_kbps"))
            down = _safe_float(row.get("recent_media_download_kbps") or row.get("deep_media_download_kbps"))
            if up or down:
                speed = f" ↑{_format_rate(up)} ↓{_format_rate(down)}"
            widget = self._proxy_card_widget(
                badge=str(index + 1),
                title=_trim_middle(host, 34),
                subtitle=f"{tag} | {row.get('reason', 'ready')}{speed}",
                metric=latency,
                selected=bool(manual and url == manual),
                active=bool(url and url == snapshot.get("best_proxy")),
                on_click=lambda proxy_url=url: self._apply_proxy_url(proxy_url),
            )
            self._add_card_item(self.proxy_list, widget, url)

    def proxy_item_clicked(self, item: QListWidgetItem) -> None:
        url = str(item.data(Qt.UserRole) or "")
        self._apply_proxy_url(url)

    def _apply_proxy_url(self, url: str) -> None:
        if url:
            self.run_task("manual_proxy", lambda: self.runtime.select_manual_upstream(url))
        else:
            self.run_task("auto_proxy", self.runtime.clear_manual_upstream)

    def change_strategy_from_proxy_page(self, label: str) -> None:
        strategy = BALANCER_BY_LABEL.get(label, "sticky_session")
        if strategy == self.runtime.config.balancer_strategy:
            return
        payload = asdict(self.runtime.config)
        payload["balancer_strategy"] = strategy
        config = AppConfig(**payload)
        self.strategy_combo.setCurrentText(BALANCER_LABELS.get(strategy, label))
        self.run_task("change_strategy", lambda: self.runtime.apply_config(config))

    def _refresh_pool_table(self) -> None:
        if not hasattr(self, "pool_list"):
            return
        rows = list(self.runtime.snapshot().get("pool_rows") or [])
        self.pool_list.clear()
        for index, row in enumerate(rows):
            host = f"{row.get('host')}:{row.get('port')}"
            latency = _format_latency(row.get("live_latency_ms") or row.get("base_latency_ms") or row.get("connect_latency_ms"))
            up = _format_rate(row.get("recent_media_upload_kbps") or row.get("deep_media_upload_kbps"))
            down = _format_rate(row.get("recent_media_download_kbps") or row.get("deep_media_download_kbps"))
            subtitle = f"{row.get('reason') or 'ready'} · ↑ {up} · ↓ {down}"
            widget = self._proxy_card_widget(
                badge=str(index + 1),
                title=_trim_middle(host, 34),
                subtitle=subtitle,
                metric=latency,
                selected=bool(row.get("manual_selected")),
            )
            self._add_card_item(self.pool_list, widget, str(row.get("url") or ""))

    def copy_pool_to_clipboard(self) -> None:
        rows = list(self.runtime.snapshot().get("pool_rows") or [])
        QApplication.clipboard().setText("\n".join(str(row.get("url") or "") for row in rows if row.get("url")))

    def quick_probe(self) -> None:
        self.run_task("quick_probe", lambda: self.runtime.quick_probe_pool(limit=self.runtime.config.live_probe_top_n, reason="manual"))

    def copy_local_link(self) -> None:
        snapshot = self.runtime.snapshot()
        url = str(snapshot.get("local_tg_url") or snapshot.get("local_url") or "")
        if not url:
            self.show_info("Нет ссылки", "Локальная ссылка еще не сформирована.")
            return
        QApplication.clipboard().setText(url)
        self.progress_text.setText("Ссылка подключения скопирована")

    def connect_local_proxy(self) -> None:
        snapshot = self.runtime.snapshot()
        url = str(snapshot.get("local_tg_url") or "")
        if not url:
            self.show_info("Нет ссылки", "Сначала запустите локальный proxy frontend.")
            return
        webbrowser.open(url)

    def open_output_folder(self) -> None:
        path = (self.runtime.install_dir / self.runtime.config.out_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def copy_hosts_block(self) -> None:
        QApplication.clipboard().setText(_telegram_web_hosts_block())
        self.show_info("Telegram Web", "Hosts-блок скопирован")

    def apply_hosts_block(self) -> None:
        try:
            current = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore") if HOSTS_PATH.exists() else ""
            updated = _strip_hosts_block(current).rstrip() + "\n\n" + _telegram_web_hosts_block() + "\n"
            HOSTS_PATH.write_text(updated, encoding="utf-8")
            self.show_info("Telegram Web", "Hosts-правила применены")
        except PermissionError:
            self.show_error("Telegram Web", "Нет доступа к hosts. Запустите приложение от имени администратора.")
        except Exception as exc:
            self.show_error("Telegram Web", str(exc))

    def remove_hosts_block(self) -> None:
        try:
            current = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
            HOSTS_PATH.write_text(_strip_hosts_block(current), encoding="utf-8")
            self.show_info("Telegram Web", "Hosts-правила удалены")
        except PermissionError:
            self.show_error("Telegram Web", "Нет доступа к hosts. Запустите приложение от имени администратора.")
        except Exception as exc:
            self.show_error("Telegram Web", str(exc))

    def refresh_auth_status(self) -> None:
        if getattr(self, "_telegram_auth_busy", None):
            return
        self._set_telegram_auth_busy("auth_status", "Проверяем авторизацию Telegram...")
        self.run_task(
            "auth_status",
            self.runtime.run_auth_status,
            on_success=lambda result: (self._set_telegram_auth_busy(None), self._auth_status_loaded(result)),
            on_error=lambda error: (self._set_telegram_auth_busy(None), self._auth_status_failed(error)),
        )

    def _auth_status_loaded(self, result: object) -> None:
        payload = dict(result or {})
        self._telegram_auth_known = True
        if payload.get("authorized"):
            self._telegram_authorized = True
            self._telegram_auth_stage = "authorized"
            display = payload.get("display") or payload.get("phone") or "Telegram"
            self.auth_status.setText(f"Авторизовано: {display}")
        elif payload.get("session_exists"):
            self._telegram_authorized = False
            self._telegram_auth_stage = "start"
            if not payload.get("credentials_configured", True):
                self.auth_status.setText("Сессия найдена. Укажите API ID и API Hash, чтобы проверить вход.")
            else:
                self.auth_status.setText("Сессия найдена, но Telegram ее не принял. Нужен повторный вход.")
        else:
            self._telegram_authorized = False
            self._telegram_auth_stage = "start"
            self.auth_status.setText("Telegram API не авторизован")
        self._update_telegram_auth_ui()

    def _auth_status_failed(self, error: str) -> None:
        self._telegram_auth_known = False
        self._telegram_authorized = False
        self.auth_status.setText(f"Ошибка проверки авторизации: {self._format_telegram_error(error)}")
        self._update_telegram_auth_ui()

    def _save_auth_config_inline(self) -> None:
        cfg = self._collect_config()
        set_autostart_enabled(bool(cfg.autostart_enabled))
        self.runtime.apply_config(cfg)

    def _normalized_telegram_phone_input(self) -> str:
        phone = normalize_telegram_phone(self.telegram_phone.text().strip())
        if phone:
            self.telegram_phone.setText(phone)
        return phone

    def request_auth_code(self) -> None:
        if getattr(self, "_telegram_auth_busy", None):
            return
        try:
            phone = self._normalized_telegram_phone_input()
            if not phone:
                raise RuntimeError("Введите телефон")
            self._save_auth_config_inline()
        except Exception as exc:
            self.show_error("Telegram", str(exc))
            return
        self._set_telegram_auth_busy("request_code", "Запрашиваем код Telegram...")
        self.run_task(
            "request_code",
            lambda: self.runtime.request_auth_code(phone),
            on_success=lambda result: (self._set_telegram_auth_busy(None), self._auth_code_requested(result)),
            on_error=self._telegram_auth_failed,
        )

    def _auth_code_requested(self, result: object) -> None:
        payload = dict(result or {})
        phone = str(payload.get("phone") or "")
        if phone:
            self.telegram_phone.setText(phone)
        self._telegram_auth_known = True
        self._telegram_authorized = False
        self._telegram_auth_stage = "code"
        self.auth_status.setText("Код отправлен. Введите код подтверждения.")
        self._update_telegram_auth_ui()
        self.show_info("Telegram", "Код отправлен")

    def complete_auth(self) -> None:
        if getattr(self, "_telegram_auth_busy", None):
            return
        try:
            phone = self._normalized_telegram_phone_input()
            code = self.telegram_code.text().strip()
            if not phone or not code:
                raise RuntimeError("Нужны телефон и код подтверждения")
            self._save_auth_config_inline()
        except Exception as exc:
            self.show_error("Telegram", str(exc))
            return
        self._set_telegram_auth_busy("complete_auth", "Входим в Telegram...")
        self.run_task(
            "complete_auth",
            lambda: self.runtime.complete_auth(phone, code, self.telegram_password.text()),
            on_success=lambda result: (self._set_telegram_auth_busy(None), self._auth_completed(result)),
            on_error=self._telegram_auth_failed,
        )

    def _auth_completed(self, result: object) -> None:
        payload = dict(result or {})
        if payload.get("password_required"):
            self._telegram_auth_known = True
            self._telegram_authorized = False
            self._telegram_auth_stage = "code"
            self.auth_status.setText("Telegram запросил пароль 2FA. Введите пароль и нажмите «Войти» еще раз.")
            self._update_telegram_auth_ui()
            return
        self._telegram_auth_known = True
        self._telegram_authorized = True
        self._telegram_auth_stage = "authorized"
        self._update_telegram_auth_ui()
        self.refresh_auth_status()
        self.show_info("Telegram", "Сессия авторизована")

    def logout_auth(self) -> None:
        if getattr(self, "_telegram_auth_busy", None):
            return
        self._set_telegram_auth_busy("logout_auth", "Выходим из Telegram...")
        self.run_task(
            "logout_auth",
            self.runtime.logout_auth,
            on_success=lambda result: (self._set_telegram_auth_busy(None), self._auth_logged_out(result)),
            on_error=self._telegram_auth_failed,
        )

    def _auth_logged_out(self, _result: object) -> None:
        self._telegram_auth_known = True
        self._telegram_authorized = False
        self._telegram_auth_stage = "start"
        self.telegram_sources_enabled.setChecked(False)
        self.auth_status.setText("Telegram API не авторизован")
        self._update_telegram_auth_ui()

    def start_qr_auth(self, password: str = "") -> None:
        if getattr(self, "_telegram_auth_busy", None):
            return
        try:
            self._save_auth_config_inline()
        except Exception as exc:
            self.show_error("Telegram", str(exc))
            return
        self._set_telegram_auth_busy("qr_auth", "Готовим QR вход Telegram...")
        self.run_task(
            "qr_auth",
            lambda: self.runtime.run_qr_login(password=password),
            on_success=self._qr_auth_completed,
            on_error=lambda error: (
                self._set_telegram_auth_busy(None, f"Ошибка QR входа: {self._format_telegram_error(error)}"),
                self.show_warning("Telegram", self._format_telegram_error(error)),
            ),
        )

    def _qr_auth_completed(self, result: object) -> None:
        payload = dict(result or {})
        self._set_telegram_auth_busy(None)
        if payload.get("password_required"):
            self.auth_status.setText("Telegram запросил пароль 2FA. Введите его в QR окне и продолжите.")
            return
        if payload.get("timeout"):
            self.auth_status.setText("QR код истек. Запустите QR вход еще раз.")
            return
        self.refresh_auth_status()

    def show_qr_dialog(self, url: str) -> None:
        if self.qr_dialog is not None:
            self.qr_dialog.close()
        self.qr_dialog = QRDialog(self, url, lambda password: self.start_qr_auth(password=password))
        self.qr_dialog.show()

    def send_proxy_list_to_saved(self) -> None:
        if getattr(self, "_telegram_auth_busy", None):
            return
        self._set_telegram_auth_busy("send_saved", "Отправляем список в Saved Messages...")
        self.run_task(
            "send_saved",
            self.runtime.send_working_proxies_to_saved_messages,
            on_success=lambda result: (
                self._set_telegram_auth_busy(None),
                self.show_info("Telegram", f"Отправлено: {dict(result or {}).get('sent', 0)}"),
            ),
            on_error=self._telegram_auth_failed,
        )

    def check_updates_silent(self) -> None:
        self.check_updates(show_dialog=False)

    def check_updates(self, *, show_dialog: bool = True) -> None:
        self.check_updates_button.setEnabled(False)
        self.update_status.setText("Проверяем обновления...")

        def loaded(release: object) -> None:
            self.update_release = release
            tag = str(getattr(release, "tag_name", "") or "")
            available = bool(tag and is_update_available(APP_PUBLIC_VERSION, release))
            self.install_update_button.setEnabled(available)
            self.check_updates_button.setEnabled(True)
            self.update_status.setText(f"Доступна версия {tag}" if available else f"Установлена актуальная версия {APP_PUBLIC_VERSION}")
            if show_dialog:
                if available:
                    self.show_info("Обновления", f"Доступна версия {tag}")
                else:
                    self.show_info("Обновления", "Новых версий не найдено")

        def failed(error: str) -> None:
            self.check_updates_button.setEnabled(True)
            self.install_update_button.setEnabled(False)
            self.update_status.setText(f"Ошибка проверки: {error}")
            if show_dialog:
                self.show_error("Обновления", error)

        self.run_task("check_updates", fetch_latest_release, on_success=loaded, on_error=failed)

    def install_update(self) -> None:
        release = self.update_release
        if release is None:
            return

        def prepared(result: object) -> None:
            def restart(_remember: bool = False) -> None:
                launch_prepared_update(result)
                self.quit_application(force=True)

            self.show_confirm(
                "Обновления",
                "Обновление загружено. Перезапустить приложение сейчас?",
                yes_text="Перезапустить",
                no_text="Позже",
                on_yes=restart,
            )

        self.run_task(
            "prepare_update",
            lambda: prepare_update(
                install_dir=self.runtime.install_dir,
                state_dir=self.runtime.state_dir,
                current_version=APP_PUBLIC_VERSION,
            ),
            on_success=prepared,
        )

    def hide_to_tray(self) -> None:
        self.hide()
        if self.tray.isVisible():
            self.tray.showMessage(APP_NAME, "Приложение продолжает работать в трее", QSystemTrayIcon.Information, 1800)

    def show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._quitting:
            event.accept()
            return
        behavior = self.runtime.config.close_behavior
        if behavior == "tray":
            event.ignore()
            self.hide_to_tray()
            return
        if behavior == "exit":
            self.quit_application(force=True)
            event.accept()
            return
        event.ignore()
        self.show_confirm(
            "Закрытие приложения",
            "Можно полностью закрыть приложение или убрать его в трей.",
            yes_text="Закрыть",
            no_text="В трей",
            checkbox_text="Запомнить выбор",
            on_yes=lambda remember: self._apply_close_choice("exit", remember),
            on_no=lambda remember: self._apply_close_choice("tray", remember),
        )

    def _apply_close_choice(self, choice: str, remember: bool) -> None:
        if remember:
            payload = asdict(self.runtime.config)
            payload["close_behavior"] = choice
            with contextlib.suppress(Exception):
                self.runtime.apply_config(AppConfig(**payload))
        if choice == "tray":
            self.hide_to_tray()
        else:
            self.quit_application(force=True)

    def quit_application(self, *, force: bool = False) -> None:
        self._quitting = True
        self.refresh_cancel_event.set()
        with contextlib.suppress(Exception):
            self.runtime.shutdown()
        with contextlib.suppress(Exception):
            self.tray.hide()
        QApplication.instance().quit()


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(_asset_icon())
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)

    single_instance_handle = _acquire_single_instance()
    if single_instance_handle is None:
        QMessageBox.warning(None, APP_NAME, "Приложение уже запущено.")
        return

    window = MainWindow()
    window.show()
    try:
        sys.exit(app.exec())
    finally:
        _release_single_instance(single_instance_handle)


if __name__ == "__main__":
    main()
