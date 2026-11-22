import base64
import ctypes
from ctypes import wintypes
import datetime
import hashlib
import hmac
import io
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import ntpath
import os
import shutil
import queue
import re
import select
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageGrab, ImageTk
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PORT = 47321
DISCOVERY_PORT = 47322
DISCOVERY_REQUEST = b"WASL/8/"
LEGACY_DISCOVERY = (b"WASL/7/", b"WASL/6/", b"WASL/5/", b"WASL/3/")
CONNECT_REQUEST = b"WASL/8/CONTROL"
DIRECT_REQUEST = b"WASL/8/DIRECT"
AUTO_ADAPTER = "تلقائي"
VERSION = "1.2.6"
LOG = logging.getLogger("WaslLAN")
INPUT_BLOCKED = b"!input-blocked"
INPUT_RESTORED = b"!input-restored"
INPUT_BLOCKED_LABEL = "رفض ويندوز أمر التحكم. للنوافذ المرتفعة شغّل وصل كمسؤول على جهاز الزبون."
DESKTOP_PAUSED_LABEL = "العرض متوقف مؤقتًا. أكمل مطالبة ويندوز على جهاز الزبون."
FILE_CHUNK = 256 * 1024
FILE_LIMIT = 512 * 1024 * 1024
NETWORKS = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
)))
USER32 = ctypes.WinDLL("user32", use_last_error=True)
try:
    USER32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except AttributeError:
    USER32.SetProcessDPIAware()


def configure_logging():
    if LOG.handlers:
        return
    folder = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "WaslLAN")
    try:
        folder.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(folder / "wasl.log", maxBytes=512 * 1024, backupCount=2, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        LOG.addHandler(handler)
        LOG.setLevel(logging.INFO)
    except OSError:
        LOG.addHandler(logging.NullHandler())


def normalize_wireguard_config(value):
    if len(value) > 64 * 1024:
        raise ValueError("حجم إعداد WireGuard أكبر من الحد المسموح.")
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    if "\\n" in value:
        value = value.replace("\\n", "\n")
    value = value.strip().lstrip("\ufeff")
    if "\n" not in value and "\\" in value:
        value = value.replace("\\", "\n")
    sections = []
    cleaned = []
    allowed = {"Interface": {"PrivateKey", "Address", "DNS", "ListenPort", "MTU", "Table"},
               "Peer": {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}}
    full_tunnel = False
    for line in value.splitlines():
        line = line.strip().removesuffix("\\").strip()
        if line.startswith("\\#"):
            line = line[1:]
        cleaned.append(line)
        if not line or line.startswith("#"):
            continue
        if line in ("[Interface]", "[Peer]"):
            sections.append((line[1:-1], set()))
            continue
        key, separator, setting = line.partition("=")
        key, setting = key.strip(), setting.split("#", 1)[0].strip()
        if not sections or not separator or not setting or key not in allowed[sections[-1][0]]:
            raise ValueError("الإعداد يتضمن سطرًا غير معروف. الصق ملف WireGuard الأصلي.")
        present = sections[-1][1]
        if key in present:
            raise ValueError("يوجد حقل مكرر داخل أحد أقسام الإعداد.")
        present.add(key)
        if key in ("PrivateKey", "PublicKey", "PresharedKey"):
            try:
                valid_key = len(base64.b64decode(setting, validate=True)) == 32
            except ValueError:
                valid_key = False
            if not valid_key:
                raise ValueError("يوجد مفتاح WireGuard بتنسيق غير صالح.")
        if key in ("Address", "AllowedIPs"):
            try:
                for value in setting.split(","):
                    address = ipaddress.ip_interface(value.strip())
                    full_tunnel |= key == "AllowedIPs" and address.network.prefixlen == 0
            except ValueError:
                raise ValueError("يوجد عنوان أو نطاق IP غير صالح في إعداد النفق.") from None
    if (len(sections) < 2 or sections[0][0] != "Interface" or "PrivateKey" not in sections[0][1]
            or any(section != "Peer" or "PublicKey" not in keys for section, keys in sections[1:])):
        raise ValueError("ألصق إعدادًا كاملًا يحتوي على [Interface] وقسم [Peer] واحد على الأقل.")
    return "\n".join(cleaned).strip() + "\n", full_tunnel


def valid_vpn_endpoint(endpoint):
    if not endpoint:
        return True
    match = re.fullmatch(r"([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::([0-9]{1,5}))?", endpoint)
    if not match or len(endpoint) > 120:
        return False
    hostname, port = match.groups()
    return ".." not in hostname and (port is None or 1 <= int(port) <= 65535)


def connection_profiles_path():
    return Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "WaslLAN", "connections.json")


def load_connection_profiles():
    try:
        path = connection_profiles_path()
        if path.stat().st_size > 256 * 1024:
            raise ValueError("connection profile size limit")
        rows = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            raise ValueError("invalid connection profile file")
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        LOG.warning("Could not load saved connections")
        return {}
    profiles = {}
    for item in rows[:128]:
        if not isinstance(item, dict):
            continue
        name, address, endpoint = (item.get(key) for key in ("name", "address", "endpoint"))
        if not all(isinstance(value, str) for value in (name, address, endpoint)):
            continue
        if not name or len(name) > 48 or not name.isprintable() or not valid_vpn_endpoint(endpoint):
            continue
        try:
            profiles[name] = (local_address(address), endpoint)
        except ValueError:
            continue
    return profiles


def save_connection_profiles(profiles):
    path = connection_profiles_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, mode="w", encoding="utf-8", delete=False) as handle:
            staging = Path(handle.name)
            rows = [{"name": name, "address": address, "endpoint": endpoint}
                    for name, (address, endpoint) in profiles.items()]
            json.dump(rows, handle, ensure_ascii=False, indent=2)
        staging.replace(path)
    finally:
        if staging:
            staging.unlink(missing_ok=True)


def local_address(value):
    address = ipaddress.IPv4Address(value)
    if not any(address in network for network in NETWORKS):
        raise ValueError("استخدم عنوان IPv4 محليًا.")
    return str(address)


def interface_networks():
    networks = {"127.0.0.1": ipaddress.IPv4Network("127.0.0.0/8")}
    table_size = wintypes.ULONG()
    get_table = ctypes.windll.iphlpapi.GetIpAddrTable
    if get_table(None, ctypes.byref(table_size), False) == 122:
        table = ctypes.create_string_buffer(table_size.value)
        if get_table(table, ctypes.byref(table_size), False) == 0:
            count, = struct.unpack_from("<I", table)
            for offset in range(4, 4 + min(count, (len(table) - 4) // 24) * 24, 24):
                raw_address = socket.inet_ntoa(table[offset:offset + 4])
                raw_mask = socket.inet_ntoa(table[offset + 8:offset + 12])
                try:
                    address = local_address(raw_address)
                    networks[address] = ipaddress.IPv4Network((address, raw_mask), strict=False)
                except ValueError:
                    continue
    if len(networks) == 1:
        try:
            records = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        except OSError:
            records = ()
        for record in records:
            try:
                address = local_address(record[4][0])
                networks.setdefault(address, ipaddress.IPv4Network((address, 32)))
            except ValueError:
                continue
    return dict(sorted(networks.items(), key=lambda item: (item[0].startswith("127."),
                                                           item[1].prefixlen == 32, item[0])))


def addresses():
    return list(interface_networks())


STREAM_LEVELS = (
    (640, 400, 40, 8),
    (960, 600, 52, 12),
    (1280, 800, 63, 16),
    (1600, 1000, 73, 20),
    (1920, 1200, 82, 24),
    (2560, 1600, 88, 24),
)


class StreamQuality:
    def __init__(self):
        self.level = 2
        self.fast_frames = 0

    def settings(self, mode):
        level = self.level if mode == "auto" else {"speed": 1, "detail": 5}[mode]
        return STREAM_LEVELS[level]

    def observe(self, elapsed):
        if elapsed > .14:
            self.level = max(0, self.level - (2 if elapsed > .35 else 1))
            self.fast_frames = 0
        elif elapsed < .055:
            self.fast_frames += 1
            if self.fast_frames >= 16:
                self.level = min(len(STREAM_LEVELS) - 1, self.level + 1)
                self.fast_frames = 0
        else:
            self.fast_frames = 0


USER32.OpenInputDesktop.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
USER32.OpenInputDesktop.restype = wintypes.HANDLE
USER32.GetUserObjectInformationW.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD))
USER32.GetUserObjectInformationW.restype = wintypes.BOOL
USER32.CloseDesktop.argtypes = (wintypes.HANDLE,)
USER32.CloseDesktop.restype = wintypes.BOOL


def normal_input_desktop():
    desktop = USER32.OpenInputDesktop(0, False, 0x0001)  # DESKTOP_READOBJECTS
    if not desktop:
        return False
    try:
        name = ctypes.create_unicode_buffer(128)
        return bool(USER32.GetUserObjectInformationW(desktop, 2, name, ctypes.sizeof(name), None)
                    and name.value.casefold() == "default")
    finally:
        USER32.CloseDesktop(desktop)


def monitor_rects():
    screens = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.HDC,
                                       ctypes.POINTER(wintypes.RECT), wintypes.LPARAM)

    @callback_type
    def collect(monitor, device, bounds, data):
        rect = bounds.contents
        screens.append((rect.left, rect.top, rect.right, rect.bottom))
        return True

    USER32.EnumDisplayMonitors(None, None, collect, 0)
    if not screens:
        screens.append((0, 0, USER32.GetSystemMetrics(0), USER32.GetSystemMetrics(1)))
    return sorted(screens, key=lambda r: (r[:2] != (0, 0), r[0], r[1]))[:8]


def verification_code(connection):
    binding = connection.get_channel_binding("tls-unique")
    if not binding:
        raise ValueError("تعذّر إنشاء رمز تحقق لهذه الجلسة.")
    digest = hashlib.sha256(binding).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1000000:06d}"


def discover(interfaces, stop=None):
    requests = {prefix + secrets.token_hex(12).encode("ascii"): prefix == DISCOVERY_REQUEST
                for prefix in (DISCOVERY_REQUEST, *LEGACY_DISCOVERY)}
    supported_nonces = {request.decode("ascii"): supported for request, supported in requests.items()}
    clients = []
    found = {}
    try:
        for address, network in interfaces.items():
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                client.bind((address, 0))
                targets = [address]
                if not address.startswith("127."):
                    if network.prefixlen < 31:
                        targets.append(str(network.broadcast_address))
                    targets.append("255.255.255.255")
                sent = False
                for target in targets:
                    for request in requests:
                        try:
                            client.sendto(request, (target, DISCOVERY_PORT))
                            sent = True
                        except OSError:
                            continue
                if sent:
                    clients.append(client)
                else:
                    client.close()
            except OSError:
                client.close()
        deadline = time.monotonic() + 0.9
        while clients and (remaining := deadline - time.monotonic()) > 0:
            if stop and stop.is_set():
                break
            ready, _, _ = select.select(clients, [], [], min(.2, remaining))
            for client in ready:
                try:
                    payload, peer = client.recvfrom(1024)
                    address = local_address(peer[0])
                    nonce, name, fingerprint, busy = json.loads(payload)
                    if (not isinstance(nonce, str) or nonce not in supported_nonces or not isinstance(name, str)
                            or not 1 <= len(name) <= 63 or not name.isprintable()
                            or not isinstance(fingerprint, str) or len(fingerprint) != 64
                            or len(bytes.fromhex(fingerprint)) != 32 or type(busy) is not bool):
                        continue
                    supported = supported_nonces[nonce]
                    if supported or address not in found:
                        found[address] = (name, fingerprint, busy, supported)
                except (OSError, ValueError, TypeError):
                    continue
        return found
    finally:
        for client in clients:
            client.close()


def advertise(host, receiver, name, fingerprint):
    try:
        while not host["stop"].is_set():
            try:
                payload, peer = receiver.recvfrom(128)
            except socket.timeout:
                continue
            except OSError as exc:
                if getattr(exc, "winerror", None) in (10040, 10054):
                    continue
                raise
            try:
                peer_address = ipaddress.IPv4Address(local_address(peer[0]))
            except ValueError:
                continue
            if len(payload) != len(DISCOVERY_REQUEST) + 24 or not payload.startswith(DISCOVERY_REQUEST):
                continue
            try:
                nonce = payload.decode("ascii")
            except UnicodeDecodeError:
                continue
            try:
                if any(peer_address in network for network in host["networks"]):
                    receiver.sendto(json.dumps([nonce, name, fingerprint, host["busy"].is_set()]).encode(), peer)
            except OSError:
                continue
    except (OSError, ValueError):
        pass
    finally:
        receiver.close()


def windows_admin():
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def launch_elevated_customer(executable):
    path = str(Path(executable).resolve())
    parameters = f"--customer --handoff-from {os.getpid()}"
    quoted_path = path.replace("'", "''")
    powershell = str(Path(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
    command = (
        f"Start-Process -FilePath '{quoted_path}' -ArgumentList '{parameters}' "
        "-Verb RunAs -ErrorAction Stop"
    )
    env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                            env=env, creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True, timeout=90)
    return result.returncode == 0


def wait_for_customer_handoff(options):
    if "--handoff-from" not in options:
        return True
    index = options.index("--handoff-from") + 1
    if index >= len(options) or not options[index].isascii() or not options[index].isdecimal():
        return False
    pid = int(options[index])
    if not 0 < pid <= 0xffffffff or pid == os.getpid():
        return False
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        return ctypes.get_last_error() == 87  # Process already exited.
    try:
        return kernel.WaitForSingleObject(handle, 12000) == 0
    finally:
        kernel.CloseHandle(handle)


def firewall_command(executable, elevated=False):
    powershell = str(Path(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
    safe_path = str(executable).replace("'", "''")
    identity = hashlib.sha256(str(executable).casefold().encode()).hexdigest()[:16]
    rules = []
    for protocol, port in (("TCP", PORT), ("UDP", DISCOVERY_PORT)):
        name = f"WaslLAN-{identity}-{protocol}"
        rules.append(
            f"if (-not (Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue)) {{ "
            f"New-NetFirewallRule -Name '{name}' -DisplayName 'WaslLAN {protocol} {port}' "
            f"-Direction Inbound -Action Allow -Program '{safe_path}' -Protocol {protocol} "
            f"-LocalPort {port} -RemoteAddress LocalSubnet4 -Profile Any | Out-Null "
            f"}} else {{ Enable-NetFirewallRule -Name '{name}' | Out-Null }}"
        )
    script = "$ErrorActionPreference='Stop'; try { " + "; ".join(rules) + "; exit 0 } catch { exit 1 }"
    payload = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    if elevated:
        return [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", payload]
    launch = (
        f"$p=Start-Process -FilePath '{powershell.replace(chr(39), chr(39)*2)}' -Verb RunAs "
        f"-ArgumentList '-NoProfile -NonInteractive -EncodedCommand {payload}' -Wait -PassThru "
        "-WindowStyle Hidden -ErrorAction Stop; exit $p.ExitCode"
    )
    return [powershell, "-NoProfile", "-NonInteractive", "-Command", launch]


def server_identity():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wasl LAN")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with tempfile.TemporaryDirectory() as folder:
        certificate, private_key = (Path(folder, name) for name in ("cert.pem", "key.pem"))
        certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private_key.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        context.load_cert_chain(certificate, private_key)
    return context, cert.fingerprint(hashes.SHA256()).hex()


def read_exact(connection, size, deadline):
    data = bytearray()
    while len(data) < size:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("frame deadline")
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def receive(connection, limit):
    timeout = connection.gettimeout()
    deadline = time.monotonic() + timeout if timeout is not None else None
    size, = struct.unpack("!I", read_exact(connection, 4, deadline))
    if not 0 < size <= limit:
        raise ValueError("حجم الرسالة غير صالح.")
    return read_exact(connection, size, deadline)


def send(connection, payload):
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def close(connection):
    if connection is not None:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()


class MouseInput(ctypes.Structure):
    _fields_ = (("dx", wintypes.LONG), ("dy", wintypes.LONG), ("data", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD), ("extra", ctypes.c_size_t))


class KeyboardInput(ctypes.Structure):
    _fields_ = (("key", wintypes.WORD), ("scan", wintypes.WORD), ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("extra", ctypes.c_size_t))


class InputData(ctypes.Union):
    _fields_ = (("mouse", MouseInput), ("keyboard", KeyboardInput))


class WindowsInput(ctypes.Structure):
    _fields_ = (("kind", wintypes.DWORD), ("data", InputData))


USER32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(WindowsInput), ctypes.c_int)
USER32.SendInput.restype = wintypes.UINT


class InputUnavailable(OSError):
    pass


class Input:
    BUTTON_FLAGS = {1: (0x02, 0x04), 2: (0x20, 0x40), 3: (0x08, 0x10)}
    EXTENDED_KEYS = {33, 34, 35, 36, 37, 38, 39, 40, 44, 45, 46, 91, 92, 93, 111, 144, 163, 165}

    def __init__(self):
        self.keys = set()
        self.buttons = set()
        self.origin = (0, 0)

    @staticmethod
    def inject(event):
        if USER32.SendInput(1, ctypes.byref(event), ctypes.sizeof(event)) != 1:
            raise InputUnavailable

    def key(self, key, down):
        if not down and key not in self.keys:
            return
        flags = int(key in self.EXTENDED_KEYS) | (0 if down else 0x02)
        data = InputData(keyboard=KeyboardInput(key, 0, flags, 0, 0))
        self.inject(WindowsInput(1, data))
        (self.keys.add if down else self.keys.discard)(key)

    def mouse(self, flags, data=0):
        self.inject(WindowsInput(0, InputData(mouse=MouseInput(0, 0, data, flags, 0, 0))))

    def button(self, button, down):
        if not down and button not in self.buttons:
            return
        self.mouse(self.BUTTON_FLAGS[button][0 if down else 1])
        (self.buttons.add if down else self.buttons.discard)(button)

    def release(self):
        successful = True
        for pressed, release in ((self.keys, self.key), (self.buttons, self.button)):
            for value in tuple(pressed):
                try:
                    release(value, False)
                except InputUnavailable:
                    successful = False
        return successful

    def apply(self, event, width, height):
        kind = event[0]
        if kind == "release":
            if not self.release():
                raise InputUnavailable
        elif kind in ("move", "button", "wheel"):
            x, y = event[1:3]
            if type(x) is not int or type(y) is not int or not (0 <= x <= 10000 and 0 <= y <= 10000):
                raise ValueError
            if not USER32.SetCursorPos(self.origin[0] + x * (width - 1) // 10000,
                                       self.origin[1] + y * (height - 1) // 10000):
                raise InputUnavailable
            if kind == "button" and event[3] in self.BUTTON_FLAGS and type(event[4]) is bool:
                self.button(event[3], event[4])
            if kind == "wheel" and event[3] in (-120, 120):
                self.mouse(0x0800, event[3] & 0xffffffff)
        elif kind == "key" and type(event[1]) is int and 8 <= event[1] <= 254 and type(event[2]) is bool:
            self.key(event[1], event[2])


class FileExchange:
    def __init__(self, session, jobs):
        self.session = session
        self.jobs = jobs
        self.source = None
        self.destination = None
        self.remaining = 0
        self.sending_remaining = 0
        self.received_name = None
        self.awaiting_ack = False
        self.ignored_receive = False
        self.responses = queue.SimpleQueue()

    def notify(self, kind, data):
        self.jobs.put((self.session, kind, data))

    def outgoing(self):
        try:
            return self.responses.get_nowait()
        except queue.Empty:
            pass
        if self.awaiting_ack:
            return b"-"
        if self.source is None:
            try:
                path = self.session["files"].get_nowait()
            except queue.Empty:
                return b"-"
            try:
                self.source = path.open("rb")
                size = os.fstat(self.source.fileno()).st_size
                self.sending_remaining = size
                if size > FILE_LIMIT:
                    raise ValueError
                return b"M" + json.dumps([path.name, size]).encode()
            except (OSError, ValueError):
                self.finish_source("تعذّر قراءة الملف أو تجاوز حجمه 512 ميغابايت.")
                return b"-"
        try:
            data = self.source.read(min(FILE_CHUNK, self.sending_remaining))
        except OSError:
            self.finish_source("تعذّرت قراءة الملف.")
            return b"X"
        if data:
            self.sending_remaining -= len(data)
            return b"D" + data
        if self.sending_remaining:
            self.finish_source("تغيّر حجم الملف أثناء الإرسال.")
            return b"X"
        self.source.close()
        self.source = None
        self.awaiting_ack = True
        return b"E"

    def finish_source(self, status):
        if self.source:
            self.source.close()
            self.source = None
        self.notify("sent", status)

    def incoming(self, packet):
        flag, data = packet[:1], packet[1:]
        if flag == b"-" and not data:
            return
        if packet == b"A" and self.awaiting_ack:
            self.awaiting_ack = False
            self.notify("sent", "استلم الطرف الآخر الملف.")
            return
        if packet == b"F":
            self.awaiting_ack = False
            self.finish_source("تعذّر استلام الملف لدى الطرف الآخر.")
            self.responses.put(b"X")
            return
        if flag == b"M" and len(data) <= 4096 and self.destination is None:
            name, size = json.loads(data)
            if (not isinstance(name, str) or not name or name != ntpath.basename(name)
                    or any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name)
                    or type(size) is not int or not 0 <= size <= FILE_LIMIT):
                raise ValueError
            self.ignored_receive = False
            self.received_name = name
            self.remaining = size
            folder = self.session["folder"]
            try:
                with self.session["storage_lock"]:
                    used = sum(path.stat().st_size for path in Path(folder).iterdir())
                if size + used > 2 * FILE_LIMIT or size + 32 * 1024 * 1024 > shutil.disk_usage(folder).free:
                    raise OSError("receive storage limit")
                self.destination = tempfile.NamedTemporaryFile(dir=folder, delete=False)
            except OSError:
                self.reject_destination()
                return
            self.notify("transfer", f"جارٍ استلام الملف {name}")
        elif self.ignored_receive and flag in (b"D", b"E"):
            return
        elif flag == b"D" and self.destination and 0 < len(data) <= self.remaining:
            try:
                self.destination.write(data)
                self.remaining -= len(data)
            except OSError:
                self.reject_destination()
        elif flag == b"E" and not data and self.destination and self.remaining == 0:
            path = Path(self.destination.name)
            try:
                self.destination.close()
            except OSError:
                self.reject_destination()
                return
            self.destination = None
            self.responses.put(b"A")
            self.notify("received", (self.received_name, path))
        elif flag == b"X" and not data:
            self.discard_destination()
            if not self.ignored_receive:
                self.notify("transfer", "توقّف إرسال الملف.")
            self.ignored_receive = False
        else:
            raise ValueError

    def reject_destination(self):
        self.discard_destination()
        self.ignored_receive = True
        self.responses.put(b"F")
        self.notify("transfer", "تعذّر حفظ الملف مؤقتًا. تحقق من المساحة المتاحة.")

    def discard_destination(self):
        if self.destination:
            path = Path(self.destination.name)
            try:
                self.destination.close()
            except OSError:
                LOG.warning("Temporary file close failed")
            self.destination = None
            try:
                with self.session["storage_lock"]:
                    path.unlink(missing_ok=True)
            except OSError:
                LOG.warning("Temporary file cleanup failed")

    def close(self):
        if self.source:
            self.source.close()
        self.discard_destination()


class Desk(tk.Tk):
    def __init__(self, role=None):
        super().__init__()
        self.title("وصل | التحكم عبر الشبكة المحلية")
        work_area = wintypes.RECT(0, 0, self.winfo_screenwidth(), self.winfo_screenheight())
        USER32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work_area), 0)
        available_width = work_area.right - work_area.left
        available_height = work_area.bottom - work_area.top
        width, height = min(900, available_width - 32), min(550, available_height - 54)
        left = work_area.left + (available_width - width) // 2
        top = work_area.top + max(8, (available_height - height - 38) // 2)
        self.geometry(f"{width}x{height}+{left}+{top}")
        self.minsize(min(740, width), min(450, height))
        self.configure(bg="#f4f7fc")
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.jobs = queue.Queue()
        self.frames = queue.Queue(maxsize=1)
        self.session = None
        self.availability = None
        self.devices = {}
        self.seen_devices = {}
        self.scanning = False
        self.discovery_count = None
        self.direct_address = tk.StringVar(self)
        self.saved_connections = {}
        self.wireguard_dialog = None
        self.closing = False
        self.close_event = threading.Event()
        self.workers = []
        self.firewall_pending = False
        self.elevation_pending = False
        self.admin_mode = windows_admin()
        self.fullscreen = False
        self.role = None
        self.pending_prompt = None
        self.image_rect = None
        self.photo = None
        self.status = tk.StringVar(self, value="جاهز")
        self.device_hint = tk.StringVar(self, value="جارٍ البحث في الشبكة…")
        self.available_label = tk.StringVar(self, value="هذا الجهاز غير متاح")
        self.control_status = tk.StringVar(self, value="")
        self.screen_title = tk.StringVar(self, value="سطح المكتب")
        self.screen_detail = tk.StringVar(self, value="اختر جهازًا من القائمة لبدء جلسة")
        self.adapter = tk.StringVar(self)
        self.host_address = tk.StringVar(self, value="")
        self.control = tk.BooleanVar(self, value=False)
        self.stream_mode = tk.StringVar(self, value="تلقائي")
        self.monitor_choice = tk.StringVar(self, value="الشاشة 1")
        self.stream_stats = tk.StringVar(self, value="")
        self.remote_screen = 0
        self.remote_topology = None
        self.paused_display = False
        self.file_status = tk.StringVar(self, value="اتصل بجهاز لإرسال الملفات واستلامها.")
        self.scale = tk.StringVar(self, value="ملاءمة النافذة")
        self.storage = None
        self.storage_lock = threading.Lock()
        self.saving = False
        self.pending_files = []
        self.last_move = 0
        self.configure_styles()
        if role:
            self.open_role(role)
        else:
            self.role_picker()

    def launch_worker(self, method, *args):
        self.workers = [worker for worker in self.workers if worker.is_alive()]
        worker = threading.Thread(target=method, args=args, daemon=True)
        self.workers.append(worker)
        worker.start()

    def configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10), foreground="#243652")
        style.configure("TButton", padding=(11, 6), background="#edf2fb", borderwidth=0, relief="flat")
        style.map("TButton", background=[("active", "#dfe9fb")])
        style.configure("Accent.TButton", background="#2853d3", foreground="white")
        style.map("Accent.TButton", background=[("disabled", "#b6c6ef"), ("active", "#1d42b6")],
                  foreground=[("disabled", "#f6f8ff")])
        style.configure("TFrame", background="#ffffff")
        style.configure("TLabel", background="#ffffff", foreground="#243652")
        style.configure("TCheckbutton", background="#ffffff")
        style.configure("Shell.TNotebook", background="#edf2f7", borderwidth=0, padding=0)
        style.layout("Shell.TNotebook.Tab", [])
        style.configure("Nav.TButton", background="#ffffff", foreground="#52647a", padding=(13, 6))
        style.map("Nav.TButton", background=[("active", "#eef4fb")])
        style.configure("Current.Nav.TButton", background="#e4efff", foreground="#1744a0",
                        font=("Segoe UI", 10, "bold"))
        style.map("Current.Nav.TButton", background=[("active", "#dceaff")])
        style.configure("Danger.TButton", background="#fceced", foreground="#a82536")
        style.map("Danger.TButton", background=[("disabled", "#edf1f6"), ("active", "#f8dce0")])
        style.configure("TEntry", padding=6, fieldbackground="#f6f8fc", bordercolor="#dbe4ef")
        style.configure("TCombobox", padding=4, fieldbackground="#f7f9fc", bordercolor="#dbe4ef")
        style.configure("TMenubutton", padding=(9, 5))
        style.configure("ExitFullscreen.TButton", background="#243b60", foreground="#ffffff", padding=(14, 7))
        style.map("ExitFullscreen.TButton", background=[("active", "#395781")])
        style.configure("Treeview", rowheight=33, font=("Segoe UI", 10), background="#ffffff",
                        fieldbackground="#ffffff", borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", background="#f0f4fc", relief="flat")
        style.map("Treeview", background=[("selected", "#dce8ff")], foreground=[("selected", "#193d9b")])
        style.configure("Role.TButton", font=("Segoe UI", 16, "bold"), padding=(24, 20),
                        background="#edf3ff", foreground="#2144a2")
        style.map("Role.TButton", background=[("active", "#dce8ff"), ("focus", "#e1ebff")])

    def role_picker(self):
        self.picker = tk.Frame(self, bg="#f4f7fc")
        self.picker.pack(fill="both", expand=True)
        panel = tk.Frame(self.picker, bg="white", highlightbackground="#e0e8f5", highlightthickness=1)
        panel.place(relx=.5, rely=.49, anchor="center", width=570, height=318)
        tk.Label(panel, text="وصل", font=("Segoe UI", 30, "bold"), foreground="#193c96",
                 background="white").pack(pady=(28, 0))
        tk.Label(panel, text="اختر وضع التشغيل", font=("Segoe UI", 15), foreground="#445c7d",
                 background="white").pack(pady=(0, 20))
        choices = ttk.Frame(panel, padding=(24, 0))
        choices.pack(fill="x", padx=14)
        for role, number, label, detail, side in (
            ("manager", "١", "المدير", "الاتصال بالأجهزة", "right"),
            ("customer", "٢", "الزبون", "إتاحة هذا الجهاز", "left"),
        ):
            card = ttk.Frame(choices)
            card.pack(side=side, fill="x", expand=True, padx=6)
            ttk.Button(card, text=f"{label}  {number}", style="Role.TButton",
                       command=lambda selected=role: self.open_role(selected)).pack(fill="x")
            ttk.Label(card, text=detail, anchor="center", foreground="#526782").pack(fill="x", pady=(8, 0))
        ttk.Button(self.picker, text="إعداد WireGuard", command=self.open_wireguard_settings).place(
            relx=0, rely=1, x=14, y=-14, anchor="sw")
        self.bind("<KeyPress>", self.role_key)
        self.after_idle(self.focus_set)

    def role_key(self, event):
        if self.wireguard_dialog:
            return
        if event.char in ("1", "١", "۱") or event.keysym in ("1", "KP_1"):
            self.open_role("manager")
        elif event.char in ("2", "٢", "۲") or event.keysym in ("2", "KP_2"):
            self.open_role("customer")

    def open_role(self, role):
        if self.role:
            return
        self.role = role
        if hasattr(self, "picker"):
            self.unbind("<KeyPress>")
            self.picker.destroy()
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.build()
        self.poll_timer = self.after(25, self.poll)
        if role == "customer":
            self.startup_timer = self.after(80, lambda: self.host(automatic=True))
            self.scan_timer = None
        else:
            self.startup_timer = self.after(100, self.scan)
            self.scan_timer = self.after(4000, self.autoscan)

    def build(self):
        self.header = header = tk.Frame(self, bg="#ffffff", highlightbackground="#dce5ef", highlightthickness=1)
        header.pack(fill="x", padx=14, pady=(10, 8))
        brand = tk.Frame(header, bg="#ffffff")
        brand.pack(side="right", padx=10, pady=7)
        tk.Label(brand, text="وصل", font=("Segoe UI", 15, "bold"), bg="#2853d3",
                 fg="#ffffff", padx=9, pady=4).pack(side="right")
        tk.Label(brand, text="المدير" if self.role == "manager" else "الزبون", font=("Segoe UI", 10, "bold"),
                 bg="#ffffff", fg="#526782").pack(side="right", padx=(8, 10))
        navigation = tk.Frame(header, bg="#ffffff")
        navigation.pack(side="right", padx=8)
        ttk.Button(header, text="WireGuard", command=self.open_wireguard_settings).pack(
            side="left", padx=8)
        self.footer = footer = tk.Frame(self, bg="#f4f7fc")
        footer.pack(side="bottom", fill="x", padx=14, pady=(6, 8))
        self.disconnect_button = ttk.Button(footer, text="قطع الجلسة", style="Danger.TButton", command=self.stop)
        self.disconnect_button.pack(side="left")
        self.disconnect_button.state(["disabled"])
        tk.Label(footer, text=VERSION, bg="#f4f7fc", fg="#526782", padx=8).pack(side="left")
        tk.Label(footer, textvariable=self.status, bg="#f4f7fc", fg="#445c7d", anchor="e").pack(
            side="right", fill="x", expand=True, padx=(12, 0))
        self.tabs = ttk.Notebook(self, style="Shell.TNotebook")
        self.tabs.pack(fill="both", expand=True, padx=14)
        self.live = ttk.Frame(self.tabs)
        settings = ttk.Frame(self.tabs)
        files = ttk.Frame(self.tabs, padding=20)
        pages = [(self.live, "الأجهزة" if self.role == "manager" else "حالة الجهاز")]
        if self.role == "manager":
            saved = ttk.Frame(self.tabs, padding=16)
            self.build_saved_connections(saved)
            pages.append((saved, "الاتصالات"))
        pages.extend(((files, "الملفات"), (settings, "الإعدادات")))
        self.navigation_buttons = []
        for page, title in pages:
            self.tabs.add(page, text=title)
            button = ttk.Button(navigation, text=title, style="Nav.TButton",
                                command=lambda target=page: self.tabs.select(target))
            button.pack(side="right", padx=2)
            self.navigation_buttons.append((str(page), button))
        self.tabs.bind("<<NotebookTabChanged>>", self.update_navigation)
        self.update_navigation()
        self.build_settings(settings)
        ttk.Label(files, text="نقل الملفات", font=("Segoe UI", 20, "bold")).pack(anchor="e")
        self.file_button = ttk.Button(files, text="اختيار ملف وإرساله", style="Accent.TButton", command=self.choose_file)
        self.file_button.pack(anchor="e", pady=12)
        self.file_button.state(["disabled"])
        ttk.Label(files, textvariable=self.file_status, wraplength=520).pack(anchor="e")
        self.received_list = tk.Listbox(files, font=("Segoe UI", 11), activestyle="none", relief="flat",
                                       bg="#f6f8fc", fg="#243652", selectbackground="#dce8ff",
                                       selectforeground="#193d9b", highlightthickness=1,
                                       highlightbackground="#dce5ef", exportselection=False)
        self.received_list.pack(fill="both", expand=True, pady=10)
        self.save_button = ttk.Button(files, text="حفظ الملف المحدد", command=self.save_file)
        self.save_button.pack(anchor="e")
        self.received_list.bind("<<ListboxSelect>>", self.update_save_button)
        self.update_save_button()
        self.adapter.set(AUTO_ADAPTER)
        self.control.set(True)

        self.devices_panel = tk.Frame(self.live, bg="#ffffff", width=246, highlightthickness=1,
                                      highlightbackground="#e2eaf6")
        self.devices_panel.pack(side="right", fill="y", padx=(8, 0))
        self.devices_panel.pack_propagate(False)
        ttk.Label(self.devices_panel, text="الأجهزة على الشبكة", font=("Segoe UI", 13, "bold")).pack(
            anchor="e", padx=11, pady=(10, 4))
        ttk.Label(self.devices_panel, textvariable=self.device_hint, wraplength=215, justify="right").pack(
            anchor="e", padx=11, pady=(0, 7))
        self.device_list = ttk.Treeview(self.devices_panel, columns=("ip", "name"), show="headings",
                                        selectmode="browse", height=6)
        self.device_list.heading("ip", text="العنوان")
        self.device_list.heading("name", text="الجهاز", anchor="e")
        self.device_list.column("ip", width=97, anchor="center", stretch=False)
        self.device_list.column("name", width=120, anchor="e")
        self.device_list.bind("<<TreeviewSelect>>", lambda event: self.update_connect())
        self.device_list.bind("<Double-1>", self.open_device_row)
        self.device_list.bind("<Return>", lambda event: self.join())
        self.device_list.tag_configure("idle", foreground="#243652")
        self.device_list.tag_configure("busy", foreground="#67788f")
        actions = ttk.Frame(self.devices_panel, padding=(9, 6, 9, 8))
        actions.pack(side="bottom", fill="x")
        self.connect_button = ttk.Button(actions, text="تحكم", style="Accent.TButton", command=self.join)
        self.connect_button.pack(side="right", fill="x", expand=True)
        self.connect_button.state(["disabled"])
        ttk.Button(actions, text="تحديث", command=self.scan).pack(side="left", padx=(0, 6))
        direct = ttk.Frame(self.devices_panel, padding=(9, 4, 9, 2))
        direct.pack(side="bottom", fill="x")
        ttk.Label(direct, text="عنوان الزبون", anchor="e").pack(fill="x", pady=(0, 3))
        self.direct_entry = ttk.Entry(direct, textvariable=self.direct_address, justify="left")
        self.direct_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.direct_entry.bind("<Return>", lambda event: self.join_by_address())
        self.direct_button = ttk.Button(direct, text="اتصال", command=self.join_by_address)
        self.direct_button.pack(side="right")
        self.device_list.pack(fill="both", expand=True, padx=9)

        self.workspace = tk.Frame(self, bg="#132443")
        self.workspace.pack(in_=self.live, side="left", fill="both", expand=True)
        self.toolbar = tk.Frame(self.workspace, bg="#203557")
        self.toolbar.pack(fill="x")
        tk.Label(self.toolbar, textvariable=self.screen_title, bg="#203557", fg="#f3f7ff",
                 font=("Segoe UI", 10, "bold")).pack(side="right", padx=14, pady=10)
        tk.Label(self.toolbar, textvariable=self.control_status, bg="#203557", fg="#b8d1ff",
                 font=("Segoe UI", 10)).pack(side="right", padx=6)
        self.fullscreen_button = ttk.Button(self.toolbar, text="تكبير الشاشة", command=self.toggle_fullscreen)
        self.stream_bar = stream_bar = tk.Frame(self.workspace, bg="#edf3ff")
        self.monitor_box = ttk.Combobox(stream_bar, state="disabled", width=10, textvariable=self.monitor_choice)
        self.monitor_box.pack(side="right", padx=(4, 8), pady=5)
        self.monitor_box.bind("<<ComboboxSelected>>", self.stream_options)
        self.quality_box = ttk.Combobox(stream_bar, state="disabled", width=9, textvariable=self.stream_mode,
                                        values=("تلقائي", "سرعة", "وضوح"))
        self.quality_box.pack(side="right", padx=4, pady=5)
        self.quality_box.bind("<<ComboboxSelected>>", self.stream_options)
        self.maintenance = ttk.Menubutton(stream_bar, text="الصيانة", state="disabled")
        menu = tk.Menu(self.maintenance, tearoff=False)
        for label, keys in (
            ("إدارة المهام", (162, 160, 27)), ("مستكشف الملفات", (91, 69)),
            ("نافذة تشغيل", (91, 82)), ("إظهار سطح المكتب", (91, 68)),
        ):
            menu.add_command(label=label, command=lambda shortcut=keys: self.remote_shortcut(shortcut))
        self.maintenance.configure(menu=menu)
        self.maintenance.pack(side="right", padx=4, pady=5)
        tk.Label(stream_bar, textvariable=self.stream_stats, bg="#edf3ff", fg="#34507a",
                 font=("Segoe UI", 9)).pack(side="left", padx=8)
        self.canvas = tk.Canvas(self.workspace, bg="#132443", highlightthickness=0, takefocus=True)
        self.canvas.pack(fill="both", expand=True)
        self.fullscreen_actions = ttk.Frame(self.workspace)
        self.exit_fullscreen_button = ttk.Button(self.fullscreen_actions, text="تصغير العرض   Esc",
                                                 style="ExitFullscreen.TButton", command=self.toggle_fullscreen)
        self.exit_fullscreen_button.pack(side="right")
        ttk.Button(self.fullscreen_actions, text="WireGuard", style="ExitFullscreen.TButton",
                   command=self.open_wireguard_settings).pack(side="right")
        self.bind("<Escape>", self.exit_fullscreen_key)
        self.canvas.bind("<Configure>", lambda event: self.placeholder() if self.photo is None else None)
        self.canvas.bind("<Motion>", lambda event: self.pointer(event, "move"))
        self.canvas.bind("<MouseWheel>", lambda event: self.pointer(event, "wheel", 120 if event.delta > 0 else -120))
        for button in (1, 2, 3):
            self.canvas.bind(f"<ButtonPress-{button}>", lambda event, b=button: self.pointer(event, "button", b, True))
            self.canvas.bind(f"<ButtonRelease-{button}>", lambda event, b=button: self.pointer(event, "button", b, False))
        self.canvas.bind("<KeyPress>", lambda event: self.handle_key(event, True))
        self.canvas.bind("<KeyRelease>", lambda event: self.handle_key(event, False))
        self.canvas.bind("<FocusOut>", lambda event: self.emit(["release"]))
        if self.role == "customer":
            self.devices_panel.pack_forget()
            self.workspace.pack_forget()
            self.customer_view()

    def open_wireguard_settings(self):
        if self.wireguard_dialog:
            self.wireguard_dialog.lift()
            return
        dialog = self.wireguard_dialog = tk.Toplevel(self)
        dialog.title("إعداد WireGuard")
        dialog.transient(self)
        dialog.minsize(450, 330)
        dialog.geometry("560x405")
        if self.fullscreen:
            dialog.attributes("-topmost", True)
        panel = ttk.Frame(dialog, padding=14)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text="الصق إعداد WireGuard الكامل", font=("Segoe UI", 13, "bold")).pack(anchor="e")
        ttk.Label(panel, text="احفظه بصيغة .conf، ثم استورده وفعّله في WireGuard.",
                  anchor="e").pack(fill="x", pady=(3, 8))
        editor = tk.Text(panel, wrap="none", height=9, font=("Consolas", 10), undo=False,
                         exportselection=False, highlightthickness=1)
        editor.pack(fill="both", expand=True)
        status = tk.StringVar(dialog)
        ttk.Label(panel, textvariable=status, wraplength=480, anchor="e", justify="right").pack(
            fill="x", pady=(5, 3))
        buttons = ttk.Frame(panel)
        buttons.pack(fill="x")

        def close_dialog():
            self.wireguard_dialog = None
            dialog.destroy()

        def export():
            try:
                config, full_tunnel = normalize_wireguard_config(editor.get("1.0", "end-1c"))
            except ValueError as exc:
                status.set(str(exc))
                return
            if full_tunnel and not messagebox.askokcancel(
                    "نفق كامل", "هذا الإعداد يمرّر حركة الإنترنت عبر النفق عند تفعيله. هل تريد حفظه؟",
                    parent=dialog):
                return
            path = filedialog.asksaveasfilename(parent=dialog, title="حفظ ملف WireGuard",
                                                initialfile="Wasl.conf", defaultextension=".conf",
                                                confirmoverwrite=False, filetypes=[("WireGuard", "*.conf")])
            if not path:
                return
            if Path(path).suffix.lower() != ".conf":
                status.set("اختر اسم ملف ينتهي بـ .conf.")
                return
            try:
                with Path(path).open("x", encoding="utf-8", newline="\n") as output:
                    output.write(config)
            except FileExistsError:
                status.set("الملف موجود. اختر اسمًا جديدًا.")
                return
            except OSError:
                status.set("تعذّر حفظ الملف. اختر مجلدًا آخر.")
                return
            editor.delete("1.0", "end")
            status.set("تم الحفظ. استورد الملف في WireGuard. يحتوي الملف على مفتاح خاص؛ احفظه في مكان آمن.")

        def open_client():
            folder = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
            executable = Path(folder, "WireGuard", "wireguard.exe") if folder else None
            if not executable or not executable.is_file():
                status.set("ثبّت تطبيق WireGuard الرسمي لويندوز أولًا.")
                return
            try:
                os.startfile(executable)
            except OSError:
                status.set("تعذّر فتح تطبيق WireGuard.")

        dialog.protocol("WM_DELETE_WINDOW", close_dialog)
        dialog.bind("<Escape>", lambda event: close_dialog())
        ttk.Button(buttons, text="حفظ للاستيراد", style="Accent.TButton", command=export).pack(side="right")
        ttk.Button(buttons, text="فتح WireGuard", command=open_client).pack(side="right", padx=6)
        ttk.Button(buttons, text="إغلاق", command=close_dialog).pack(side="left")
        editor.focus_set()

    def build_saved_connections(self, parent):
        self.saved_connections = load_connection_profiles()
        self.profile_selected = None
        self.profile_name = tk.StringVar(self)
        self.profile_address = tk.StringVar(self)
        self.profile_endpoint = tk.StringVar(self)
        self.profile_status = tk.StringVar(self, value="")
        parent.columnconfigure(0, weight=3)
        parent.columnconfigure(1, weight=2)
        parent.rowconfigure(1, weight=1)
        ttk.Label(parent, text="الاتصالات المحفوظة", font=("Segoe UI", 15, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="e", pady=(0, 12))
        form = ttk.Frame(parent, padding=(8, 0, 14, 0))
        form.grid(row=1, column=0, sticky="nsew")
        for label, value in (("اسم الجهاز", self.profile_name), ("عنوان الزبون الداخلي", self.profile_address),
                             ("خادم WireGuard · اختياري", self.profile_endpoint)):
            ttk.Label(form, text=label, anchor="e").pack(fill="x", pady=(0, 3))
            ttk.Entry(form, textvariable=value, justify="right" if value is self.profile_name else "left").pack(
                fill="x", pady=(0, 7))
        actions = ttk.Frame(form)
        actions.pack(fill="x", pady=(4, 0))
        ttk.Button(actions, text="حفظ", style="Accent.TButton", command=self.save_profile).pack(side="right")
        ttk.Button(actions, text="جديد", command=self.clear_profile).pack(side="right", padx=5)
        ttk.Button(actions, text="حذف", style="Danger.TButton", command=self.delete_profile).pack(side="left")
        ttk.Label(form, textvariable=self.profile_status, anchor="e", wraplength=280, justify="right").pack(
            fill="x", pady=8)

        listing = ttk.Frame(parent)
        listing.grid(row=1, column=1, sticky="nsew")
        self.profile_list = ttk.Treeview(listing, columns=("address", "name"), show="headings",
                                         selectmode="browse", height=4)
        self.profile_list.heading("address", text="العنوان")
        self.profile_list.heading("name", text="الجهاز", anchor="e")
        self.profile_list.column("address", width=106, minwidth=86, anchor="center")
        self.profile_list.column("name", width=124, minwidth=85, anchor="e")
        self.profile_list.pack(fill="both", expand=True)
        self.profile_list.bind("<<TreeviewSelect>>", self.select_profile)
        self.profile_list.bind("<Double-1>", self.open_profile_row)
        self.profile_list.bind("<Return>", lambda event: self.connect_profile())
        self.profile_connect_button = ttk.Button(listing, text="اتصال", command=self.connect_profile,
                                                 style="Accent.TButton")
        self.profile_connect_button.pack(fill="x", pady=(7, 0))
        self.refresh_profiles()

    def refresh_profiles(self, selected=None):
        self.profile_list.delete(*self.profile_list.get_children())
        self.profile_rows = sorted(self.saved_connections, key=str.casefold)
        for index, name in enumerate(self.profile_rows):
            self.profile_list.insert("", "end", iid=str(index), values=(self.saved_connections[name][0], name))
        if selected in self.profile_rows:
            self.profile_list.selection_set(str(self.profile_rows.index(selected)))
        self.update_profile_connect()

    def update_profile_connect(self):
        enabled = self.profile_selected in self.saved_connections and not self.session
        self.profile_connect_button.state(["!disabled" if enabled else "disabled"])

    def select_profile(self, event=None):
        selected = self.profile_list.selection()
        if not selected:
            self.update_profile_connect()
            return
        name = self.profile_rows[int(selected[0])]
        address, endpoint = self.saved_connections[name]
        if self.profile_selected != name:
            self.profile_status.set("")
        self.profile_selected = name
        self.profile_name.set(name)
        self.profile_address.set(address)
        self.profile_endpoint.set(endpoint)
        self.update_profile_connect()

    def clear_profile(self):
        self.profile_selected = None
        self.profile_list.selection_remove(self.profile_list.selection())
        for value in (self.profile_name, self.profile_address, self.profile_endpoint, self.profile_status):
            value.set("")
        self.update_profile_connect()

    def save_profile(self):
        name = self.profile_name.get().strip()
        endpoint = self.profile_endpoint.get().strip()
        if not name or len(name) > 48 or not name.isprintable():
            self.profile_status.set("أدخل اسمًا للجهاز حتى 48 حرفًا.")
            return
        try:
            address = local_address(self.profile_address.get().strip())
        except ValueError:
            self.profile_status.set("أدخل عنوان IPv4 داخليًا صالحًا.")
            return
        if not valid_vpn_endpoint(endpoint):
            self.profile_status.set("أدخل اسم خادم WireGuard أو عنوانه، مثل vpn.example.com:51820.")
            return
        if name in self.saved_connections and name != self.profile_selected:
            self.profile_status.set("هذا الاسم مستخدم. اختر الجهاز من القائمة لتحريره.")
            return
        if len(self.saved_connections) >= 128 and self.profile_selected is None:
            self.profile_status.set("وصلت إلى الحد الأقصى للاتصالات المحفوظة.")
            return
        updated = self.saved_connections.copy()
        if self.profile_selected is not None:
            updated.pop(self.profile_selected, None)
        updated[name] = (address, endpoint)
        if self.commit_profiles(updated):
            self.profile_selected = name
            self.refresh_profiles(name)
            self.profile_status.set("تم حفظ الاتصال.")

    def delete_profile(self):
        name = self.profile_selected
        if name not in self.saved_connections:
            return
        if not messagebox.askyesno("حذف اتصال", f"حذف الاتصال المحفوظ «{name}»؟", parent=self):
            return
        updated = self.saved_connections.copy()
        del updated[name]
        if self.commit_profiles(updated):
            self.clear_profile()
            self.refresh_profiles()
            self.profile_status.set("تم حذف الاتصال.")

    def commit_profiles(self, updated):
        try:
            save_connection_profiles(updated)
        except OSError:
            LOG.warning("Could not save connection profiles", exc_info=True)
            self.profile_status.set("تعذّر حفظ بيانات الاتصال على هذا الجهاز.")
            return False
        self.saved_connections = updated
        return True

    def open_profile_row(self, event):
        row = self.profile_list.identify_row(event.y)
        if row:
            self.profile_list.selection_set(row)
            self.select_profile()
            self.connect_profile()

    def connect_profile(self):
        if self.session or self.profile_selected not in self.saved_connections:
            return
        name = self.profile_selected
        address, _ = self.saved_connections[name]
        self.direct_address.set(address)
        self.connect_to(address, name, None)

    def update_navigation(self, event=None):
        selected = self.tabs.select()
        for page, button in self.navigation_buttons:
            button.configure(style="Current.Nav.TButton" if page == selected else "Nav.TButton")

    def request_admin_mode(self, from_approval=False):
        if self.role != "customer" or self.admin_mode or self.elevation_pending or self.firewall_pending:
            return
        if not getattr(sys, "frozen", False):
            messagebox.showinfo("صلاحيات المسؤول", "استخدم WaslLAN.exe لتشغيل وضع المسؤول.", parent=self)
            return
        if (self.session and not from_approval) or self.saving or self.pending_files:
            messagebox.showinfo("صلاحيات المسؤول", "أنه الجلسة واحفظ الملفات المستلمة قبل إعادة التشغيل.", parent=self)
            return
        if not messagebox.askokcancel(
                "تشغيل وصل كمسؤول",
                "سيُعاد فتح وصل بصلاحيات المسؤول على جهاز الزبون. بعد ذلك، يمكنك السماح للمدير بالتحكم في النوافذ المرتفعة.",
                parent=self):
            return
        self.elevation_pending = True
        if from_approval and self.pending_prompt:
            self.pending_prompt(False, elevating=True)
        self.status.set("بانتظار موافقة ويندوز على صلاحيات المسؤول…")

        def restart():
            try:
                launched = launch_elevated_customer(sys.executable)
            except (OSError, subprocess.TimeoutExpired):
                launched = False
            self.jobs.put((None, "elevation_result", launched))

        self.launch_worker(restart)

    def allow_firewall(self):
        if self.firewall_pending or self.elevation_pending:
            return
        if not getattr(sys, "frozen", False):
            messagebox.showinfo("إذن الشبكة", "شغّل WaslLAN.exe لمنح الإذن لهذا التطبيق وحده.", parent=self)
            return
        if not messagebox.askokcancel(
                "إذن الشبكة", "السماح لوصل باستقبال الاتصال من الشبكة المحلية؟ ستطلب ويندوز موافقة المسؤول.",
                parent=self):
            return
        self.firewall_pending = True
        self.status.set("بانتظار موافقة ويندوز على إذن الشبكة…")

        def apply_firewall():
            try:
                result = subprocess.run(firewall_command(Path(sys.executable).resolve(),
                                                         bool(ctypes.windll.shell32.IsUserAnAdmin())),
                                        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=90)
                ok = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                ok = False
            self.jobs.put((None, "firewall_result", ok))

        self.launch_worker(apply_firewall)

    def update_save_button(self, event=None):
        self.save_button.state(["!disabled" if self.received_list.curselection() and not self.saving else "disabled"])

    def open_device_row(self, event):
        row = self.device_list.identify_row(event.y)
        if row:
            self.device_list.selection_set(row)
            self.join()

    def customer_view(self):
        surface = tk.Frame(self.live, bg="#edf3ff")
        surface.pack(fill="both", expand=True)
        card = tk.Frame(surface, bg="white", highlightbackground="#dbe6fd", highlightthickness=1)
        card.place(relx=.5, rely=.50, anchor="center", width=374, height=216)
        indicator = tk.Label(card, text="●", bg="white", fg="#67788f", font=("Segoe UI", 20))
        indicator.pack(pady=(10, 0))
        def refresh_indicator(*args):
            active = self.session and self.session["role"] == "host"
            indicator.configure(fg="#2853d3" if active else "#168361" if self.availability else "#67788f")
        self.available_label.trace_add("write", refresh_indicator)
        tk.Label(card, text=socket.gethostname(), bg="white", fg="#172e54",
                 font=("Segoe UI", 17, "bold")).pack(pady=(2, 4))
        tk.Label(card, textvariable=self.available_label, bg="white", fg="#43618a",
                 font=("Segoe UI", 13)).pack()
        if self.admin_mode:
            ttk.Label(card, text="صلاحيات المسؤول", foreground="#1744a0").pack()
        tk.Label(card, textvariable=self.host_address, bg="white", fg="#526782", wraplength=320,
                 font=("Segoe UI", 11)).pack(pady=5)
        buttons = ttk.Frame(card, padding=(8, 4))
        buttons.pack()
        self.server_button = ttk.Button(buttons, text="إتاحة هذا الجهاز", command=self.host)
        self.server_button.pack(side="right", padx=4)
        ttk.Button(buttons, text="نسخ العنوان", command=self.copy_host_address).pack(side="right", padx=4)

    def build_settings(self, parent):
        sidebar = tk.Frame(parent, bg="#173344", width=160)
        sidebar.pack(side="right", fill="y")
        sidebar.pack_propagate(False)
        content = ttk.Frame(parent, padding=24)
        content.pack(fill="both", expand=True)

        def show(section):
            for widget in content.winfo_children():
                widget.destroy()
            ttk.Label(content, text=section, font=("Segoe UI", 22, "bold")).pack(anchor="e", pady=(0, 16))
            ttk.Separator(content).pack(fill="x", pady=(0, 16))
            if section == "الاتصال":
                if self.role == "customer":
                    ttk.Label(content, text="بطاقة الشبكة").pack(anchor="e")
                    ttk.Combobox(content, state="readonly", values=(AUTO_ADAPTER, *addresses()), textvariable=self.adapter).pack(
                        anchor="e", pady=8)
                    if self.admin_mode:
                        ttk.Label(content, text="وصل يعمل بصلاحيات المسؤول").pack(anchor="e", pady=6)
                    else:
                        ttk.Button(content, text="تشغيل وصل كمسؤول", style="Accent.TButton",
                                   command=self.request_admin_mode).pack(anchor="e", pady=6)
                ttk.Label(content, text=f"TCP {PORT}   ·   UDP {DISCOVERY_PORT}").pack(anchor="e")
                ttk.Button(content, text="السماح في جدار الحماية", command=self.allow_firewall).pack(
                    anchor="e", pady=10)
                ttk.Label(content, text="إذا اختفى الزبون، تحقّق من الإذن على جهازه أولًا.",
                          wraplength=330).pack(anchor="e")
            elif section == "الأذونات":
                ttk.Checkbutton(content, text="إظهار خيار التحكم عند الموافقة على الطلب",
                                variable=self.control).pack(anchor="e")
                ttk.Label(content, text="يمكنك اختيار العرض فقط عند قبول أي طلب.").pack(anchor="e", pady=8)
            elif section == "العرض":
                ttk.Label(content, text="حجم الشاشة عند المشاهدة").pack(anchor="e")
                ttk.Combobox(content, state="readonly", values=("ملاءمة النافذة", "الحجم الفعلي"),
                             textvariable=self.scale).pack(anchor="e", pady=8)
            else:
                ttk.Label(content, text="لغة الواجهة").pack(anchor="e")
                ttk.Label(content, text="العربية").pack(anchor="e", pady=8)
                ttk.Label(content, text="وصل لسطح مكتب ويندوز").pack(anchor="e", pady=8)

        sections = ("عام", "الاتصال", "الأذونات") if self.role == "customer" else ("عام", "الاتصال", "العرض")
        for section in sections:
            tk.Button(sidebar, text=section, command=lambda name=section: show(name),
                      bg="#173344", fg="#ffffff", activebackground="#009582", activeforeground="#ffffff",
                      font=("Segoe UI", 12), relief="flat", anchor="e", padx=18).pack(fill="x", ipady=7)
        show("عام")

    def choose_file(self):
        session = self.session
        if not session:
            return
        selection = filedialog.askopenfilename(parent=self, title="اختر ملفًا لإرساله")
        if not selection or session is not self.session:
            return
        session["files"].put_nowait(Path(selection))
        self.file_button.state(["disabled"])
        self.file_status.set("جارٍ إرسال الملف…")

    def save_file(self):
        selected = self.received_list.curselection()
        if not selected or self.saving:
            return
        file = self.pending_files[selected[0]]
        name, source = file
        target = filedialog.asksaveasfilename(parent=self, initialfile=name, title="حفظ الملف المستلم")
        if not target:
            return
        self.saving = True
        self.update_save_button()
        self.file_status.set(f"جارٍ حفظ {name}…")

        def write_file():
            staging = None
            error = None
            try:
                with tempfile.NamedTemporaryFile(dir=Path(target).parent, delete=False) as temporary:
                    staging = Path(temporary.name)
                    with source.open("rb") as incoming:
                        shutil.copyfileobj(incoming, temporary, FILE_CHUNK)
                staging.replace(target)
                with self.storage_lock:
                    source.unlink(missing_ok=True)
            except OSError as exc:
                error = exc
                LOG.warning("File save failed (%s)", type(exc).__name__)
            finally:
                if staging:
                    try:
                        staging.unlink(missing_ok=True)
                    except OSError:
                        LOG.warning("Save staging cleanup failed")
                self.jobs.put((None, "save_result", (file, error)))

        self.launch_worker(write_file)

    def report_callback_exception(self, exc_type, exc_value, traceback):
        LOG.error("UI callback failed", exc_info=(exc_type, exc_value, traceback))
        self.status.set("حدث خطأ غير متوقع. أعد المحاولة.")

    def placeholder(self):
        self.canvas.delete("all")
        x, y = self.canvas.winfo_width() // 2, self.canvas.winfo_height() // 2
        self.canvas.create_rectangle(x - 26, y - 59, x + 26, y - 25, outline="#7fa6fc", width=2)
        self.canvas.create_line(x, y - 25, x, y - 17, x - 12, y - 17, fill="#7fa6fc", width=2)
        self.canvas.create_line(x, y - 17, x + 12, y - 17, fill="#7fa6fc", width=2)
        self.canvas.create_text(x, y + 15, text=self.screen_detail.get(), fill="#dce8ff",
                                font=("Segoe UI", 13), width=max(200, self.canvas.winfo_width() - 40))

    def toggle_fullscreen(self):
        if not self.fullscreen and not (self.session and self.session["role"] == "viewer" and self.photo):
            return
        self.fullscreen = not self.fullscreen
        self.workspace.pack_forget()
        if self.fullscreen:
            self.header.pack_forget()
            self.footer.pack_forget()
            self.tabs.pack_forget()
            self.toolbar.pack_forget()
            self.stream_bar.pack_forget()
            self.workspace.configure(bg="#000000")
            self.canvas.configure(bg="#000000")
            self.workspace.pack(fill="both", expand=True)
            self.fullscreen_actions.place(relx=1, x=-14, y=14, anchor="ne")
            self.fullscreen_actions.lift()
        else:
            self.fullscreen_actions.place_forget()
            self.workspace.configure(bg="#132443")
            self.canvas.configure(bg="#132443")
            self.header.pack(fill="x", padx=14, pady=(10, 8))
            self.footer.pack(side="bottom", fill="x", padx=14, pady=(6, 8))
            self.tabs.pack(fill="both", expand=True, padx=14)
            self.toolbar.pack(fill="x", before=self.canvas)
            if self.session:
                self.stream_bar.pack(fill="x", before=self.canvas)
            self.workspace.pack(in_=self.live, side="left", fill="both", expand=True)
        self.image_rect = None
        self.attributes("-fullscreen", self.fullscreen)
        self.canvas.focus_set()

    def exit_fullscreen_key(self, event=None):
        if self.fullscreen:
            self.toggle_fullscreen()
            return "break"
        return None

    def copy_host_address(self):
        if self.availability:
            self.clipboard_clear()
            self.clipboard_append(self.availability["addresses"][0])
            self.status.set("نُسخ عنوان الجهاز.")

    def scan(self, show_progress=True):
        if self.role != "manager" or self.scanning or self.closing:
            return
        self.scanning = True
        if show_progress and not self.devices:
            self.device_hint.set("جارٍ البحث في الشبكة…")

        def scan_network():
            try:
                found = discover(interface_networks(), self.close_event)
            except (OSError, ValueError):
                LOG.exception("Discovery scan failed")
                found = {}
            self.jobs.put((None, "devices", found))

        self.launch_worker(scan_network)

    def autoscan(self):
        self.scan(show_progress=False)
        self.scan_timer = self.after(4000, self.autoscan)

    def show_devices(self, devices):
        self.scanning = False
        now = time.monotonic()
        self.seen_devices.update((address, (device, now)) for address, device in devices.items())
        self.seen_devices = {address: (device, seen) for address, (device, seen) in self.seen_devices.items()
                             if now - seen < 7}
        devices = {address: device for address, (device, _) in self.seen_devices.items()}
        previous = self.device_list.selection()
        by_identity = {}
        for address in sorted(devices, key=lambda value: (value.startswith("127."), value)):
            by_identity.setdefault(devices[address][1], address)
        devices = {address: devices[address] for address in by_identity.values()}
        self.devices = devices
        if len(devices) != self.discovery_count:
            self.discovery_count = len(devices)
            LOG.info("Discovery found %d device(s)", self.discovery_count)
        existing = set(self.device_list.get_children())
        removed = existing - devices.keys()
        if removed:
            self.device_list.delete(*removed)
        for index, (address, device) in enumerate(sorted(devices.items(), key=lambda item: item[1][0].casefold())):
            name, _, busy, supported = device
            label = f"{name} · تحديث مطلوب" if not supported else f"{name} · مشغول" if busy else name
            values = (address, label)
            tags = ("busy" if busy or not supported else "idle",)
            if address in existing:
                if tuple(self.device_list.item(address, "values")) != values:
                    self.device_list.item(address, values=values, tags=tags)
                if self.device_list.index(address) != index:
                    self.device_list.move(address, "", index)
            else:
                self.device_list.insert("", index, iid=address, values=values, tags=tags)
        if not (previous and previous[0] in devices) and len(devices) == 1:
            self.device_list.selection_set(next(iter(devices)))
        compatible = sum(device[3] for device in devices.values())
        if devices and not compatible:
            hint = "ظهر الزبون بإصدار أقدم. حدّثه ثم اضغط تحديث."
        elif devices:
            hint = f"الأجهزة الظاهرة: {len(devices)}"
        else:
            hint = "القائمة فارغة. تأكّد من وضع ٢ أو أدخل عنوان الزبون."
        self.device_hint.set(hint)
        self.update_connect()

    def update_connect(self):
        selected = self.device_list.selection()
        device = self.devices.get(selected[0]) if selected else None
        reachable = device and device[3] and not device[2]
        self.connect_button.state(["!disabled" if not self.session and reachable else "disabled"])
        state = "disabled" if self.session else "!disabled"
        self.direct_button.state([state])
        self.direct_entry.state([state])
        if self.role == "manager":
            self.update_profile_connect()

    def host(self, automatic=False):
        if self.role != "customer":
            return
        if self.availability:
            if automatic:
                return
            if self.session and self.session["role"] == "host":
                self.stop()
            self.stop_host()
            return
        listeners, receiver = [], None
        networks = interface_networks()
        selection = self.adapter.get()
        if selection != AUTO_ADAPTER:
            networks = {selection: networks[selection]} if selection in networks else {}
        bound_addresses = []
        try:
            context, fingerprint = server_identity()
            for address in networks:
                listener = socket.socket(socket.AF_INET)
                try:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    listener.bind((address, PORT))
                    listener.listen(1)
                    listener.setblocking(False)
                except OSError:
                    listener.close()
                    continue
                listeners.append(listener)
                bound_addresses.append(address)
            if not listeners:
                raise OSError("تعذّر فتح منفذ الاتصال. أغلق أي نسخة أخرى من وصل على جهاز الزبون.")
        except (OSError, ValueError) as exc:
            for channel in listeners:
                close(channel)
            self.available_label.set("تعذّرت إتاحة الجهاز")
            self.status.set(str(exc))
            if not automatic:
                messagebox.showerror("تعذّرت إتاحة الجهاز", str(exc), parent=self)
            return
        try:
            receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            receiver.bind(("", DISCOVERY_PORT))
            receiver.settimeout(1)
        except OSError:
            close(receiver)
            receiver = None
        host = {"addresses": bound_addresses, "listeners": listeners, "networks": [networks[address] for address in bound_addresses],
                "receiver": receiver,
                "stop": threading.Event(), "busy": threading.Event(), "socket": None}
        self.availability = host
        LOG.info("Host started with %d TCP interface(s); UDP discovery %s",
                 len(bound_addresses), "active" if receiver else "unavailable")
        self.server_button.configure(text="إيقاف إتاحة الجهاز")
        self.available_label.set("متاح للاتصال" if receiver else "متاح بالعنوان فقط")
        displayed = [address for address in bound_addresses if not address.startswith("127.")] or bound_addresses
        self.host_address.set("  /  ".join(displayed))
        self.status.set("يمكن إرسال طلب اتصال." if receiver else "تعذّر تشغيل الاكتشاف. اتصل بعنوان الجهاز.")
        name = socket.gethostname()[:63]
        if receiver:
            self.launch_worker(advertise, host, receiver, name, fingerprint)
        self.launch_worker(self.serve, host, context)

    def stop_host(self):
        host, self.availability = self.availability, None
        if host:
            host["stop"].set()
            for channel in [*host["listeners"], host["receiver"], host["socket"]]:
                close(channel)
        if self.role == "customer":
            self.server_button.configure(text="إتاحة هذا الجهاز")
        self.available_label.set("الإتاحة متوقفة")
        self.host_address.set("")

    def join(self):
        selected = self.device_list.selection()
        if self.session or not selected or selected[0] not in self.devices:
            return
        address = selected[0]
        name, fingerprint, busy, supported = self.devices[address]
        if not supported:
            self.status.set("حدّث وصل على جهاز الزبون قبل بدء الجلسة.")
        elif not busy:
            self.connect_to(address, name, fingerprint)

    def join_by_address(self):
        if self.session:
            return
        address = self.direct_address.get().strip()
        if not address:
            self.status.set("أدخل عنوان IPv4 الظاهر على شاشة الزبون.")
            self.direct_entry.focus_set()
            return
        try:
            address = local_address(address)
        except ValueError:
            self.status.set("عنوان غير صالح. مثال: 192.168.1.10")
            self.direct_entry.focus_set()
            self.direct_entry.selection_range(0, "end")
            return
        self.connect_to(address, address, None)

    def connect_to(self, address, name, fingerprint):
        self.tabs.select(self.live)
        self.screen_title.set(name)
        self.screen_detail.set("بانتظار الموافقة على الجهاز البعيد…")
        self.placeholder()
        session = self.start("viewer", "جارٍ الاتصال. بانتظار موافقة الجهاز البعيد.")
        if session:
            self.launch_worker(self.watch, session, address, PORT, fingerprint)
        else:
            self.screen_detail.set(self.status.get())
            self.placeholder()

    def start(self, role, status):
        if self.storage is None:
            try:
                self.storage = tempfile.TemporaryDirectory(prefix="WaslLAN-", ignore_cleanup_errors=True)
            except OSError:
                self.status.set("تعذّر إنشاء مساحة العمل المؤقتة.")
                LOG.warning("Session workspace could not be created")
                return None
        session = {"folder": self.storage.name, "storage_lock": self.storage_lock, "files": queue.Queue(maxsize=1),
                   "stream_options": ("auto", 0), "frame_view": (0, 0), "remote_paused": False,
                   "role": role, "stop": threading.Event(), "socket": None, "input": False,
                   "outbox": queue.Queue(maxsize=128)}
        self.session = session
        self.update_connect()
        self.disconnect_button.state(["!disabled"])
        if self.availability:
            self.availability["busy"].set()
        self.status.set(status)
        return session

    def stop(self, status="تم إيقاف الجلسة."):
        session, self.session = self.session, None
        if session:
            session["stop"].set()
            close(session["socket"])
        if self.pending_prompt:
            self.pending_prompt(False, False)
        self.attributes("-topmost", False)
        self.file_button.state(["disabled"])
        self.file_status.set("اتصل بجهاز لإرسال الملفات واستلامها.")
        self.disconnect_button.state(["disabled"])
        self.fullscreen_button.pack_forget()
        self.stream_bar.pack_forget()
        self.quality_box.configure(state="disabled")
        self.monitor_box.configure(state="disabled")
        self.maintenance.configure(state="disabled")
        self.stream_stats.set("")
        self.monitor_choice.set("الشاشة 1")
        self.remote_topology = None
        self.paused_display = False
        self.stream_mode.set("تلقائي")
        if self.fullscreen:
            self.toggle_fullscreen()
        if self.availability:
            self.available_label.set("متاح للاتصال" if self.availability["receiver"] else "متاح بالعنوان فقط")
            if not session or session["role"] != "host":
                self.availability["busy"].clear()
        self.control_status.set("")
        self.screen_title.set("سطح المكتب")
        self.screen_detail.set("اختر جهازًا من القائمة لبدء جلسة")
        self.update_connect()
        self.scan()
        self.photo = self.image_rect = None
        self.placeholder()
        self.status.set(status)

    def quit_app(self):
        if self.elevation_pending:
            self.status.set("أكمل مطالبة ويندوز أو ألغها لإغلاق التطبيق.")
            return
        if self.role is None:
            self.destroy()
            return
        if self.saving:
            self.status.set("انتظر حتى يكتمل حفظ الملف.")
            return
        if self.closing:
            return
        self.closing = True
        self.close_event.set()
        for timer in (self.poll_timer, self.startup_timer, self.scan_timer):
            if timer:
                self.after_cancel(timer)
        self.stop()
        self.stop_host()
        self.status.set("جارٍ إغلاق اتصالات الشبكة…")
        self.finish_shutdown(time.monotonic() + 2)

    def finish_shutdown(self, deadline):
        if time.monotonic() < deadline and any(worker.is_alive() for worker in self.workers):
            self.after(35, self.finish_shutdown, deadline)
            return
        if self.storage:
            self.storage.cleanup()
        self.destroy()

    def approve(self, session, address, answer, code=None):
        prompt = tk.Toplevel(self)
        prompt.title("طلب مشاركة الشاشة")
        prompt.transient(self)
        prompt.attributes("-topmost", True)
        prompt.grab_set()
        ttk.Label(prompt, padding=16, text=f"طلب اتصال وارد من {address}").pack()
        if code:
            ttk.Label(prompt, padding=(16, 0, 16, 8),
                      text=f"رمز التحقق {code} · وافق بعد مطابقته مع المدير.").pack()
        if self.admin_mode:
            ttk.Label(prompt, padding=(16, 0, 16, 8),
                      text="وصل يعمل كمسؤول. للتحكم العادي، افتحه دون صلاحيات المسؤول.").pack()
        controls = ttk.Frame(prompt, padding=10)
        controls.pack(fill="x")

        def finish(accepted, control=False, *, elevating=False):
            if elevating:
                mode = b"elevating"
            elif not accepted:
                mode = b"denied"
            elif not control:
                mode = b"view"
            elif self.admin_mode:
                mode = b"admin"
            else:
                mode = b"control"
            self.pending_prompt = None
            prompt.destroy()
            answer.put((session, mode))

        self.pending_prompt = finish
        prompt.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        ttk.Button(controls, text="مشاهدة", command=lambda: finish(True)).pack(side="right", padx=4)
        ordinary = ttk.Button(controls, text="تحكم عادي", command=lambda: finish(True, True))
        ordinary.pack(side="right", padx=4)
        administrator = ttk.Button(controls, text="تحكم مسؤول", style="Accent.TButton",
                                   command=lambda: finish(True, True) if self.admin_mode else self.request_admin_mode(True))
        administrator.pack(side="right", padx=4)
        if self.admin_mode or not self.control.get():
            ordinary.state(["disabled"])
        if not self.control.get():
            administrator.state(["disabled"])
        ttk.Button(controls, text="رفض", style="Danger.TButton", command=lambda: finish(False)).pack(
            side="right", padx=4)
        prompt.focus_force()

    def serve(self, host, context):
        while not host["stop"].is_set():
            try:
                ready, _, _ = select.select(host["listeners"], [], [], 1)
                if not ready:
                    continue
                raw, peer = ready[0].accept()
            except BlockingIOError:
                continue
            except (OSError, ValueError):
                return
            connection = raw
            host["socket"] = raw
            session = None
            try:
                if host["stop"].is_set():
                    return
                local_address(peer[0])
                raw.settimeout(5)
                connection = context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
                host["socket"] = connection
                if host["stop"].is_set():
                    return
                connection.do_handshake()
                request = receive(connection, 64)
                if request not in (CONNECT_REQUEST, DIRECT_REQUEST):
                    continue
                code = verification_code(connection) if request == DIRECT_REQUEST else None
                answer = queue.Queue()
                self.jobs.put((host, "incoming", (peer[0], answer, connection, code)))
                deadline = time.monotonic() + 50
                mode = b"denied"
                while not host["stop"].is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.jobs.put((host, "approval_ended", (answer, "انتهت مهلة الموافقة.")))
                        break
                    try:
                        session, mode = answer.get(timeout=min(.2, remaining))
                        break
                    except queue.Empty:
                        readable, _, _ = select.select([connection], [], [], 0)
                        if readable:
                            self.jobs.put((host, "approval_ended", (answer, "أغلق المدير طلب الاتصال.")))
                            break
                        continue
                if host["stop"].is_set():
                    return
                send(connection, mode)
                if mode in (b"view", b"control", b"admin") and session and not session["stop"].is_set():
                    connection.settimeout(6)
                    self.jobs.put((session, "hosting", (peer[0], mode)))
                    self.host_session(session, connection, mode != b"view")
            except (OSError, EOFError, ValueError, IndexError, TypeError) as exc:
                if not host["stop"].is_set() and not (session and session["stop"].is_set()):
                    LOG.info("Host connection ended (%s)", type(exc).__name__)
            finally:
                close(connection)
                host["socket"] = None
                if session:
                    host["busy"].clear()
                    self.jobs.put((session, "end", "انتهت الجلسة. ما زال الجهاز متاحًا للاتصال."))

    def host_session(self, session, connection, control):
        transfer = FileExchange(session, self.jobs)
        input_state = Input()
        blocked = False
        notice = None
        quality = StreamQuality()
        mode, monitor = "auto", 0
        topology = [(0, 0, 640, 360)]
        revision = 0
        paused = False
        last_topology = float("-inf")
        with Image.new("RGB", (640, 360), "#132443") as blank, io.BytesIO() as buffer:
            blank.save(buffer, "JPEG", quality=45)
            pause_frame = buffer.getvalue()
        try:
            while not session["stop"].is_set():
                started = time.monotonic()
                frame = None
                fps = 3
                if normal_input_desktop():
                    if paused or started - last_topology >= 1:
                        current = monitor_rects()
                        if current != topology:
                            topology = current
                            revision += 1
                            input_state.release()
                        last_topology = started
                    monitor = min(monitor, len(topology) - 1)
                    bounds = topology[monitor]
                    width, height = bounds[2] - bounds[0], bounds[3] - bounds[1]
                    input_state.origin = bounds[:2]
                    max_width, max_height, jpeg, fps = quality.settings(mode)
                    try:
                        with ImageGrab.grab(bbox=bounds, all_screens=True) as screen, io.BytesIO() as buffer:
                            screen.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
                            screen.save(buffer, "JPEG", quality=jpeg, subsampling=0 if jpeg >= 73 else 2)
                            frame = buffer.getvalue()
                    except OSError:
                        if not paused:
                            LOG.info("Screen capture paused while Windows desktop is unavailable")
                if frame is None:
                    frame = pause_frame
                    fps = 3
                    if not paused:
                        LOG.info("Desktop unavailable; keeping remote session open")
                now_paused = frame is pause_frame
                if now_paused != paused:
                    paused = now_paused
                    blocked = False
                    revision += 1
                    input_state.release()
                    self.jobs.put((session, "desktop_pause", paused))
                send(connection, json.dumps([monitor, len(topology), revision, paused]).encode("ascii"))
                send(connection, frame)
                send(connection, notice if notice else transfer.outgoing())
                notice = None
                incoming = receive(connection, 16384)
                delivered = time.monotonic() - started
                mode_requested, monitor_requested, generation, viewed_monitor, events = json.loads(incoming)
                if (mode_requested not in ("auto", "speed", "detail") or type(monitor_requested) is not int
                        or not 0 <= monitor_requested < 8 or not isinstance(events, list) or len(events) > 128):
                    raise ValueError
                next_monitor = min(monitor_requested, len(topology) - 1)
                mode = mode_requested
                if mode == "auto" and not paused:
                    quality.observe(delivered)
                if (control and not paused and not session["stop"].is_set() and normal_input_desktop()
                        and generation == revision and viewed_monitor == monitor):
                    failed = False
                    attempted = False
                    for event in events:
                        if session["stop"].is_set():
                            break
                        if not isinstance(event, list) or not event:
                            raise ValueError
                        attempted |= event[0] in ("key", "button", "wheel")
                        try:
                            input_state.apply(event, width, height)
                        except InputUnavailable:
                            failed = True
                    if failed and not blocked:
                        blocked = True
                        notice = INPUT_BLOCKED
                        self.jobs.put((session, "input_error", True))
                    elif blocked and attempted and not failed:
                        blocked = False
                        notice = INPUT_RESTORED
                        self.jobs.put((session, "input_error", False))
                transfer.incoming(receive(connection, FILE_CHUNK + 1))
                if next_monitor != monitor:
                    input_state.release()
                monitor = next_monitor
                session["stop"].wait(max(0, 1 / fps - (time.monotonic() - started)))
        finally:
            input_state.release()
            transfer.close()

    def watch(self, session, address, port, fingerprint):
        connection = None
        transfer = FileExchange(session, self.jobs)
        failure = "تعذّر بدء الاتصال بجهاز الزبون."
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET)
            session["socket"] = raw
            connection = raw
            if session["stop"].is_set():
                return
            raw.settimeout(5)
            failure = "لم يرد جهاز الزبون. تحقق من العنوان واتصال الجهازين بالشبكة."
            try:
                raw.connect((address, port))
            except ConnectionRefusedError:
                failure = "جهاز الزبون رفض الاتصال. افتح وضع ٢ وتأكد من ظهور «متاح للاتصال»."
                raise
            failure = "تعذّر بدء الاتصال الآمن. استخدم النسخة نفسها على الجهازين."
            connection = context.wrap_socket(raw, server_hostname=address, do_handshake_on_connect=False)
            session["socket"] = connection
            if session["stop"].is_set():
                return
            connection.do_handshake()
            digest = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
            if fingerprint is not None and not hmac.compare_digest(fingerprint, digest):
                raise ValueError("تغيّرت هوية الجهاز منذ آخر بحث. حدّث قائمة الأجهزة.")
            if fingerprint is None:
                code = verification_code(connection)
                self.jobs.put((session, "verify", code))
                send(connection, DIRECT_REQUEST)
            else:
                send(connection, CONNECT_REQUEST)
            connection.settimeout(55)
            failure = "انتهى الاتصال قبل موافقة جهاز الزبون."
            try:
                mode = receive(connection, 32)
            except EOFError:
                failure = "أغلق الزبون الطلب قبل الموافقة. تحقّق من تطابق الإصدار وحالة الإتاحة."
                raise
            if mode == b"elevating":
                raise ValueError("وافق الزبون على طلب صلاحيات المسؤول. أعد الاتصال بعد أن يصبح متاحًا.")
            if mode not in (b"view", b"control", b"admin"):
                raise ValueError("لم يوافق الزبون على الاتصال.")
            connection.settimeout(6)
            failure = "انقطعت الجلسة مع جهاز الزبون."
            session["input"] = mode in (b"control", b"admin")
            session["admin_control"] = mode == b"admin"
            self.jobs.put((session, "viewing", session["input"]))
            frame_count = byte_count = 0
            stats_at = time.monotonic()
            while not session["stop"].is_set():
                monitor, monitor_count, revision, paused = json.loads(receive(connection, 128))
                if (type(monitor) is not int or type(monitor_count) is not int or type(revision) is not int
                        or type(paused) is not bool or not 0 <= monitor < monitor_count <= 8):
                    raise ValueError("بيانات الشاشة غير صالحة.")
                session["remote_paused"] = paused
                payload = receive(connection, 8 * 1024 * 1024)
                with Image.open(io.BytesIO(payload), formats=["JPEG"]) as frame:
                    if frame.width > 2560 or frame.height > 1600:
                        raise ValueError("أبعاد الصورة غير صالحة.")
                    image = frame.convert("RGB")
                try:
                    self.frames.get_nowait()
                except queue.Empty:
                    pass
                self.frames.put_nowait((session, image, monitor, monitor_count, revision, paused))
                frame_count += 1
                byte_count += len(payload)
                elapsed = time.monotonic() - stats_at
                if elapsed >= 1:
                    size = f"{image.width}×{image.height}"
                    self.jobs.put((session, "stream_stats", (size, round(frame_count / elapsed),
                                                            byte_count * 8 / elapsed / 1_000_000)))
                    frame_count = byte_count = 0
                    stats_at = time.monotonic()
                packet = receive(connection, FILE_CHUNK + 1)
                if packet in (INPUT_BLOCKED, INPUT_RESTORED):
                    self.jobs.put((session, "input_error", packet == INPUT_BLOCKED))
                else:
                    transfer.incoming(packet)
                events = []
                mode, requested_monitor = session["stream_options"]
                generation, viewed_monitor = session["frame_view"]
                for _ in range(128):
                    try:
                        view, event = session["outbox"].get_nowait()
                    except queue.Empty:
                        break
                    if view == (generation, viewed_monitor) or event[0] == "release":
                        events.append(event)
                send(connection, json.dumps([mode, requested_monitor, generation, viewed_monitor, events]).encode("ascii"))
                send(connection, transfer.outgoing())
        except (OSError, EOFError, ValueError, TypeError, queue.Full) as exc:
            if not session["stop"].is_set():
                status = str(exc) if isinstance(exc, ValueError) else failure
                LOG.info("Viewer connection ended (%s, Windows code %s)", type(exc).__name__, getattr(exc, "winerror", None))
                self.jobs.put((session, "end", status))
        finally:
            close(connection)
            transfer.close()

    def stream_options(self, event=None):
        if self.session and self.session["role"] == "viewer":
            mode = {"تلقائي": "auto", "سرعة": "speed", "وضوح": "detail"}[self.stream_mode.get()]
            self.session["stream_options"] = (mode, max(0, self.monitor_box.current()))

    def remote_shortcut(self, keys):
        self.canvas.focus_set()
        for key in keys:
            self.emit(["key", key, True])
        for key in reversed(keys):
            self.emit(["key", key, False])

    def emit(self, event):
        session = self.session
        if session and session["role"] == "viewer" and session["input"] and not session["remote_paused"]:
            try:
                session["outbox"].put_nowait((session["frame_view"], event))
            except queue.Full:
                self.stop("انقطع التحكم بسبب ازدحام الاتصال.")
            return "break"
        return None

    def handle_key(self, event, down):
        if event.keysym == "Escape" and (self.fullscreen or getattr(self, "suppress_escape_release", False)):
            if down:
                self.suppress_escape_release = True
                self.exit_fullscreen_key()
            else:
                self.suppress_escape_release = False
            return "break"
        modifiers = {"Shift_L": 160, "Shift_R": 161, "Control_L": 162, "Control_R": 163,
                     "Alt_L": 164, "Alt_R": 165}
        return self.emit(["key", modifiers.get(event.keysym, event.keycode), down])

    def pointer(self, event, kind, *args):
        if not self.image_rect:
            return
        if kind == "move":
            now = time.monotonic()
            if now - self.last_move < 0.035:
                return
            self.last_move = now
        left, top, width, height = self.image_rect
        x, y = event.x - left, event.y - top
        if not (0 <= x < width and 0 <= y < height) and not (kind == "button" and not args[1]):
            return
        if kind == "button" and args[1] and self.session and self.session["input"]:
            self.canvas.focus_set()
        x = max(0, min(10000, x * 10000 // max(1, width - 1)))
        y = max(0, min(10000, y * 10000 // max(1, height - 1)))
        return self.emit([kind, x, y, *args])

    def poll(self):
        while True:
            try:
                session, kind, data = self.jobs.get_nowait()
            except queue.Empty:
                break
            if kind == "elevation_result":
                self.elevation_pending = False
                if data:
                    self.quit_app()
                    return
                self.status.set("أُلغي طلب صلاحيات المسؤول أو تعذّر تشغيله.")
                continue
            if kind == "firewall_result":
                self.firewall_pending = False
                self.status.set("تم السماح في جدار الحماية للشبكة المحلية." if data else
                                "تعذّر منح إذن الشبكة. قد تحتاج موافقة مسؤول الجهاز.")
                continue
            if kind == "save_result":
                file, error = data
                self.saving = False
                if error:
                    self.file_status.set("تعذّر الحفظ. اختر موقعًا آخر.")
                else:
                    index = self.pending_files.index(file)
                    self.pending_files.pop(index)
                    self.received_list.delete(index)
                    self.file_status.set(f"تم حفظ {file[0]}")
                self.update_save_button()
                continue
            if kind == "devices":
                self.show_devices(data)
                continue
            if kind == "incoming":
                address, answer, connection, code = data
                if session is not self.availability or self.session or self.elevation_pending:
                    answer.put((None, b"denied"))
                else:
                    incoming = self.start("host", f"طلب اتصال وارد من {address}")
                    if incoming is None:
                        answer.put((None, b"denied"))
                        continue
                    incoming["socket"] = connection
                    incoming["answer"] = answer
                    self.approve(incoming, address, answer, code)
                continue
            if kind == "approval_ended":
                answer, reason = data
                if self.session and self.session.get("answer") is answer:
                    self.stop(f"{reason} ما زال الجهاز متاحًا.")
                    session["busy"].clear()
                continue
            if kind == "received":
                name, path = data
                self.pending_files.append((name, path))
                self.received_list.insert("end", name)
                self.file_status.set(f"اكتمل استلام {name}. اختره من القائمة لحفظه.")
            if self.session is not session:
                continue
            if kind == "sent":
                self.file_button.state(["!disabled"])
                self.file_status.set(data)
            elif kind == "transfer":
                self.file_status.set(data)
            if kind == "hosting":
                address, permission = data
                mode = {b"view": "مشاهدة", b"control": "تحكم عادي", b"admin": "تحكم مسؤول"}[permission]
                self.status.set(f"مشاركة نشطة مع {address} | {mode}")
                self.available_label.set(f"جلسة نشطة · {mode}")
                self.file_button.state(["!disabled"])
                self.file_status.set("اختر ملفًا لإرساله إلى الجهاز المتصل.")
            elif kind == "viewing":
                self.control_status.set("تحكم مسؤول" if session.get("admin_control") else
                                        "تحكم عادي" if data else "مشاهدة")
                self.status.set("انقر داخل الشاشة لإرسال لوحة المفاتيح." if data else
                                "لتمكين التحكم، أعد الاتصال واختر «السماح بالتحكم» على جهاز الزبون.")
                self.quality_box.configure(state="readonly")
                self.maintenance.configure(state="normal" if data else "disabled")
                if data:
                    self.canvas.focus_set()
                self.file_button.state(["!disabled"])
                self.file_status.set("اختر ملفًا لإرساله إلى الجهاز المتصل.")
            elif kind == "stream_stats":
                size, fps, mbps = data
                stats = f"{size} · {fps} FPS"
                if self.workspace.winfo_width() >= 520:
                    stats += f" · {mbps:.1f} Mb/s"
                self.stream_stats.set(stats)
            elif kind == "verify":
                self.screen_detail.set(f"رمز التحقق {data} · طابقه مع جهاز الزبون")
                self.placeholder()
            elif kind == "desktop_pause":
                self.status.set(DESKTOP_PAUSED_LABEL if data else "عاد بث سطح المكتب.")
            elif kind == "input_error":
                self.status.set(INPUT_BLOCKED_LABEL if data else "عاد التحكم بالماوس ولوحة المفاتيح.")
                if session["role"] == "viewer":
                    self.control_status.set("تعذّر التحكم" if data else
                                            "تحكم مسؤول" if session.get("admin_control") else "تحكم عادي")
            elif kind == "end":
                self.stop(data)
        try:
            session, frame, monitor, count, revision, paused = self.frames.get_nowait()
        except queue.Empty:
            pass
        else:
            if session is self.session:
                if not self.fullscreen and not self.fullscreen_button.winfo_manager():
                    self.fullscreen_button.pack(side="left", padx=6, pady=4)
                    self.stream_bar.pack(fill="x", before=self.canvas)
                    self.workspace.update_idletasks()
                if self.remote_topology != (count, revision):
                    self.remote_topology = (count, revision)
                    self.monitor_box.configure(state="readonly", values=[f"الشاشة {i+1}" for i in range(count)])
                    self.monitor_box.current(min(session["stream_options"][1], count - 1))
                    self.stream_options()
                session["frame_view"] = (revision, monitor)
                if self.fullscreen or self.scale.get() == "ملاءمة النافذة":
                    scale = min(max(1, self.canvas.winfo_width()) / frame.width,
                                max(1, self.canvas.winfo_height()) / frame.height)
                    frame = frame.resize((max(1, round(frame.width * scale)), max(1, round(frame.height * scale))),
                                         Image.Resampling.BILINEAR)
                left = (self.canvas.winfo_width() - frame.width) // 2
                top = (self.canvas.winfo_height() - frame.height) // 2
                self.image_rect = (left, top, frame.width, frame.height)
                self.photo = ImageTk.PhotoImage(frame, master=self)
                self.canvas.delete("all")
                self.canvas.create_image(left, top, anchor="nw", image=self.photo)
                if paused:
                    self.image_rect = None
                    self.canvas.create_text(self.canvas.winfo_width() // 2, self.canvas.winfo_height() // 2,
                                            text=DESKTOP_PAUSED_LABEL, width=max(180, self.canvas.winfo_width() - 72),
                                            fill="#ffffff", font=("Segoe UI", 14, "bold"), justify="center")
                if paused != self.paused_display:
                    self.paused_display = paused
                    self.maintenance.configure(state="disabled" if paused or not session["input"] else "normal")
                    self.control_status.set("بانتظار ويندوز" if paused else
                                            "تحكم مسؤول" if session.get("admin_control") else
                                            "تحكم عادي" if session["input"] else "مشاهدة")
                    self.status.set(DESKTOP_PAUSED_LABEL if paused else "عاد بث سطح المكتب.")

        self.poll_timer = self.after(25, self.poll)


if __name__ == "__main__":
    configure_logging()
    LOG.info("WaslLAN %s started", VERSION)
    options = sys.argv[1:]
    role = "manager" if "--manager" in options else "customer" if "--customer" in options else None
    if wait_for_customer_handoff(options):
        Desk(role=role).mainloop()
    else:
        LOG.warning("Administrator handoff timed out or was invalid")
        dialog = tk.Tk()
        dialog.withdraw()
        messagebox.showerror("تعذّر إعادة تشغيل وصل", "أغلق النسخة السابقة، ثم افتح وصل كمسؤول.", parent=dialog)
        dialog.destroy()
