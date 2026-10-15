#!/usr/bin/env python3
"""
server-status: a one-file web dashboard for a Linux server's resources.

Uses only the Python 3 standard library (3.6+), so it runs without a venv or
pip packages on Debian, Ubuntu, Raspberry Pi OS and other Debian variants,
from a Raspberry Pi up to large servers. Optional cards (temperatures, RAID,
ZFS, Docker, GPU, apt updates, ...) only appear when the machine has them.

Quick start:
    python3 server.py               # listen on port 9808
    python3 server.py 9888          # listen on port 9888
    python3 server.py --help        # all options

To start at boot, see README.md, or print a ready-made systemd unit with:
    python3 server.py --print-systemd-unit

You do NOT need to run it as root.
"""

import argparse
import base64
import getpass
import glob
import hmac
import http.client
import json
import os
import platform
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from collections import deque
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

try:
    import fcntl
except ImportError:  # not available on non-Unix systems
    fcntl = None

try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python < 3.7 (Ubuntu 18.04, Debian 9)
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True


VERSION = "2.0"
DEFAULT_PORT = 9808
DEFAULT_SERVICES = ["HTTP:80", "SSH:22", "Samba:139"]
HISTORY_SECONDS = 15 * 60
DOCKER_SOCKET = "/var/run/docker.sock"
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

# Filesystems that hold real data. Pseudo filesystems (proc, tmpfs, squashfs
# snaps, overlay layers, ...) are skipped.
DISK_FS_TYPES = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "bcachefs", "zfs", "f2fs", "jfs", "reiserfs",
    "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "hfsplus",
    "nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "fuse.mergerfs", "fuse.rclone",
}
# Network filesystems can hang when the remote end disappears, so they are
# checked with a timeout.
NETWORK_FS_TYPES = {"nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "fuse.rclone"}
SKIP_MOUNT_PREFIXES = ("/snap/", "/var/lib/docker/", "/var/lib/containers/", "/var/lib/kubelet/")
SKIP_DISK_PREFIXES = ("loop", "ram", "zram", "dm-", "sr", "fd", "nbd")
SKIP_NET_PREFIXES = ("veth", "br-", "docker", "virbr", "vnet", "cali", "flannel", "cni", "kube-")
THROTTLE_FLAGS = [(0, "Under-voltage"), (1, "Frequency capped"), (2, "Throttled"), (3, "Soft temperature limit")]
# 64-bit ARM kernels don't put a model name in /proc/cpuinfo, only "CPU implementer" / "CPU part" codes.
ARM_VENDORS = {"0x41": "ARM", "0x42": "Broadcom", "0x43": "Cavium", "0x46": "Fujitsu", "0x48": "HiSilicon",
               "0x4e": "NVIDIA", "0x50": "Applied Micro", "0x51": "Qualcomm", "0x53": "Samsung",
               "0x61": "Apple", "0xc0": "Ampere"}
ARM_CORES = {  # implementer 0x41
    "0xb76": "ARM1176", "0xc07": "Cortex-A7", "0xc08": "Cortex-A8", "0xc09": "Cortex-A9", "0xc0f": "Cortex-A15",
    "0xd03": "Cortex-A53", "0xd04": "Cortex-A35", "0xd05": "Cortex-A55", "0xd07": "Cortex-A57",
    "0xd08": "Cortex-A72", "0xd09": "Cortex-A73", "0xd0a": "Cortex-A75", "0xd0b": "Cortex-A76",
    "0xd0c": "Neoverse-N1", "0xd0d": "Cortex-A77", "0xd40": "Neoverse-V1", "0xd41": "Cortex-A78",
    "0xd44": "Cortex-X1", "0xd46": "Cortex-A510", "0xd47": "Cortex-A710", "0xd48": "Cortex-X2",
    "0xd49": "Neoverse-N2", "0xd4b": "Cortex-A78C", "0xd4f": "Neoverse-V2", "0xd80": "Cortex-A520",
    "0xd81": "Cortex-A720",
}


# --- helpers ---

def read_file(path, default=None):
    """Return the text of a file, or `default` if it cannot be read."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def read_int(path):
    try:
        return int(read_file(path, "").strip())
    except ValueError:
        return None


def run_cmd(args, timeout=5, allow_error=False):
    """Run a command and return its stdout, or None if it is missing, fails or times out."""
    env = dict(os.environ, LC_ALL="C")
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                universal_newlines=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 and not allow_error:
        return None
    return result.stdout


def call_with_timeout(fn, timeout, *args):
    """Run fn(*args) in a thread; return its result, or None if it raised or took too long."""
    result = []

    def target():
        try:
            result.append(fn(*args))
        except OSError:
            pass

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    return result[0] if result else None


def to_float(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def natural_key(text):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", text)]


# --- static system information ---

def get_os_name():
    data = read_file("/etc/os-release") or read_file("/usr/lib/os-release") or ""
    fields = {}
    for line in data.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip().strip("\"'")
    if fields.get("PRETTY_NAME"):
        return fields["PRETTY_NAME"]
    if fields.get("NAME"):
        return (fields["NAME"] + " " + fields.get("VERSION", "")).strip()
    return platform.system() or "Unknown"


def arm_cores(cpuinfo):
    """(core names, vendor names) from the CPU implementer / part codes, e.g. (["Cortex-A55", "Cortex-A76"], ["ARM"])."""
    cores, vendors, implementer = [], [], None
    for line in cpuinfo.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip().lower()
        if key == "cpu implementer":
            implementer = value
            vendor = ARM_VENDORS.get(value)
            if vendor and vendor not in vendors:
                vendors.append(vendor)
        elif key == "cpu part":
            core = ARM_CORES.get(value) if implementer == "0x41" else None
            if core is None:
                cores.append(None)  # unknown part: let lscpu name it
            elif core not in cores:
                cores.append(core)
    return cores, vendors


def get_cpu_model():
    cpuinfo = read_file("/proc/cpuinfo") or ""
    fields = {}
    for line in cpuinfo.splitlines():
        key, sep, value = line.partition(":")
        if sep and value.strip():
            fields.setdefault(key.strip().lower(), value.strip())
    if "model name" in fields:  # x86 and 32-bit ARM
        return fields["model name"]
    cores, vendors = arm_cores(cpuinfo)
    if cores and None not in cores:  # 64-bit ARM, e.g. "Cortex-A72" or "Cortex-A55 + Cortex-A76"
        return " + ".join(cores)
    for line in (run_cmd(["lscpu"]) or "").splitlines():
        key, sep, value = line.partition(":")
        if key.strip() == "Model name" and value.strip() not in ("", "-"):
            return value.strip()
    for key in ("hardware", "cpu model", "processor"):  # older ARM kernels, MIPS
        if key in fields and not fields[key].isdigit():
            return fields[key]
    if vendors:
        return " + ".join(vendors) + " " + platform.machine()
    return platform.machine() or "Unknown"


def get_device_model():
    """Board name on ARM (e.g. "Raspberry Pi 4 Model B"), vendor + product on x86."""
    model = read_file("/sys/firmware/devicetree/base/model") or read_file("/proc/device-tree/model")
    if model:
        return model.strip("\x00 \n")
    placeholders = {"", "To Be Filled By O.E.M.", "System manufacturer", "System Product Name",
                    "Default string", "Not Specified", "Not Applicable"}
    parts = []
    for name in ("sys_vendor", "product_name"):
        value = (read_file("/sys/class/dmi/id/" + name) or "").strip()
        if value not in placeholders:
            parts.append(value)
    return " ".join(parts) or None


def get_static_info():
    return {
        "os": get_os_name(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": get_cpu_model(),
        "cpu_count": os.cpu_count(),
        "device": get_device_model(),
        "python": platform.python_version(),
    }


# --- network addresses ---

def get_primary_ip():
    """Address of the interface holding the default route (no packets are sent)."""
    for family, target in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((target, 1))
                return s.getsockname()[0]
        except OSError:
            continue
    return "127.0.0.1"


def get_ipv4(ifname):
    if fcntl is None:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            packed = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", ifname[:15].encode()))  # SIOCGIFADDR
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None


def get_ipv6_addresses():
    """Global-scope IPv6 addresses per interface."""
    result = {}
    for line in (read_file("/proc/net/if_inet6") or "").splitlines():
        parts = line.split()
        if len(parts) != 6 or parts[3] != "00":
            continue
        raw = ":".join(parts[0][i:i + 4] for i in range(0, 32, 4))
        try:
            address = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, raw))
        except (OSError, ValueError):
            continue
        result.setdefault(parts[5], []).append(address)
    return result


# --- live samples ---

def get_uptime():
    try:
        return float(read_file("/proc/uptime", "").split()[0])
    except (IndexError, ValueError):
        return None


def get_load():
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except (OSError, AttributeError):
        return None


def read_cpu_times():
    """{'cpu': (busy, total), 'cpu0': ...} in jiffies since boot."""
    times = {}
    for line in (read_file("/proc/stat") or "").splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        values = [int(v) for v in parts[1:9]]  # user nice system idle iowait irq softirq steal
        values += [0] * (8 - len(values))
        idle = values[3] + values[4]
        total = sum(values)
        times[parts[0]] = (total - idle, total)
    return times


def cpu_usage(before, after):
    if not after:
        return None

    def percent(name):
        if not before or name not in before:
            return None
        busy = after[name][0] - before[name][0]
        total = after[name][1] - before[name][1]
        return round(100.0 * busy / total, 1) if total > 0 else 0.0

    return {"total": percent("cpu"), "cores": [percent(name) for name in after if name != "cpu"]}


def get_memory():
    info = {}
    for line in (read_file("/proc/meminfo") or "").splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            info[key] = int(parts[0]) * 1024
    total = info.get("MemTotal")
    if not total:
        return None
    free = info.get("MemFree", 0)
    cache = info.get("Buffers", 0) + info.get("Cached", 0) + info.get("SReclaimable", 0)
    swap_total = info.get("SwapTotal", 0)
    return {
        "total": total,
        "used": max(total - free - cache, 0),  # same as the "used" column of `free`
        "cache": cache,
        "available": info.get("MemAvailable", free + cache),  # MemAvailable needs kernel 3.14+
        "swap_total": swap_total,
        "swap_used": swap_total - info.get("SwapFree", 0),
    }


def get_temperatures():
    sensors = []
    for hwmon in sorted(glob.glob("/sys/class/hwmon/hwmon*"), key=natural_key):
        chip = (read_file(hwmon + "/name") or "sensor").strip()
        for path in sorted(glob.glob(hwmon + "/temp*_input"), key=natural_key):
            value = read_int(path)
            if value is not None:
                label = (read_file(path.replace("_input", "_label")) or "").strip()
                sensors.append([chip + (" " + label if label else ""), value / 1000.0])
    if not sensors:  # older kernels / boards that only expose thermal zones
        for zone in sorted(glob.glob("/sys/class/thermal/thermal_zone*"), key=natural_key):
            value = read_int(zone + "/temp")
            if value is not None:
                sensors.append([(read_file(zone + "/type") or "zone").strip(), value / 1000.0])
    sensors = [s for s in sensors if -40 < s[1] < 150]  # drop disconnected / bogus sensors
    if not sensors:
        return None
    seen = {}
    for sensor in sensors:  # make names unique, e.g. two NVMe drives
        seen[sensor[0]] = seen.get(sensor[0], 0) + 1
        if seen[sensor[0]] > 1:
            sensor[0] += " #%d" % seen[sensor[0]]
    return {
        "max": round(max(s[1] for s in sensors), 1),
        "count": len(sensors),
        "sensors": [{"name": name, "celsius": round(value, 1)} for name, value in sensors[:16]],
    }


def unescape_mount(path):
    """/proc/mounts writes spaces etc. as octal escapes, e.g. "\\040"."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def list_mounts():
    mounts, seen = [], set()
    for line in (read_file("/proc/self/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        device, mount, fstype = unescape_mount(parts[0]), unescape_mount(parts[1]), parts[2]
        if fstype not in DISK_FS_TYPES and not (fstype == "overlay" and mount == "/"):
            continue
        if mount.startswith(SKIP_MOUNT_PREFIXES) or device in seen:  # bind mounts, btrfs subvolumes
            continue
        if fstype not in NETWORK_FS_TYPES and not os.path.isdir(mount):  # bind-mounted files, e.g. /etc/hostname in containers
            continue
        seen.add(device)
        mounts.append((device, mount, fstype))
    return mounts


def disk_usage(mount):
    st = os.statvfs(mount)
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    percent = round(100.0 * used / (used + free), 1) if used + free else 0.0  # same as `df`
    return {"total": total, "used": used, "free": free, "percent": percent}


def read_disk_io():
    """{'sda': (bytes_read, bytes_written)} for whole physical disks."""
    stats = {}
    for line in (read_file("/proc/diskstats") or "").splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        name = parts[2]
        if name.startswith(SKIP_DISK_PREFIXES) or not os.path.exists("/sys/block/" + name.replace("/", "!")):
            continue  # partitions and virtual devices
        stats[name] = (int(parts[5]) * 512, int(parts[9]) * 512)  # always 512-byte sectors
    return stats


def read_net_io():
    """{'eth0': (bytes_received, bytes_sent)} for interfaces that are up."""
    stats = {}
    for line in (read_file("/proc/net/dev") or "").splitlines()[2:]:
        name, _, rest = line.partition(":")
        name, parts = name.strip(), rest.split()
        if len(parts) < 9 or name == "lo" or name.startswith(SKIP_NET_PREFIXES):
            continue
        state = (read_file("/sys/class/net/%s/operstate" % name) or "").strip()
        if state in ("up", "unknown", ""):  # VPN tunnels report "unknown"
            stats[name] = (int(parts[0]), int(parts[8]))
    return stats


def rates(before, after, dt):
    """Per-second rates between two {name: (counter, ...)} samples."""
    result = []
    for name, values in after.items():
        old = before.get(name) if before and dt > 0 else None
        if old is None:
            result.append((name, (None,) * len(values)))
        else:
            result.append((name, tuple(round(max(0, (v - o) / dt)) for v, o in zip(values, old))))
    return result


def read_processes():
    """{pid: (name, cpu_ticks, rss_bytes)} for every process."""
    try:
        pids = [pid for pid in os.listdir("/proc") if pid.isdigit()]
    except OSError:
        return {}
    procs = {}
    for pid in pids:
        stat = read_file("/proc/%s/stat" % pid)
        if not stat:
            continue
        lparen, rparen = stat.find("("), stat.rfind(")")  # the name may contain spaces or ")"
        fields = stat[rparen + 2:].split()
        try:
            procs[int(pid)] = (stat[lparen + 1:rparen], int(fields[11]) + int(fields[12]), int(fields[21]) * PAGE_SIZE)
        except (IndexError, ValueError):
            continue
    return procs


def top_processes(before, after, dt, count=5):
    if not after:
        return None
    usage = []
    for pid, (name, ticks, rss) in after.items():
        old = before.get(pid) if before and dt > 0 else None
        cpu = round(100.0 * (ticks - old[1]) / CLK_TCK / dt, 1) if old and old[0] == name else None
        usage.append({"pid": pid, "name": name, "cpu": cpu, "rss": rss})
    return {
        "count": len(after),
        "by_cpu": sorted((u for u in usage if u["cpu"]), key=lambda u: u["cpu"], reverse=True)[:count],
        "by_memory": sorted(usage, key=lambda u: u["rss"], reverse=True)[:count],
    }


def port_open(port, hosts):
    for host in hosts:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    return True
        except OSError:
            continue
    return False


def get_raid():
    data = read_file("/proc/mdstat")
    if not data:
        return None
    arrays, lines = [], data.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("md") or ":" not in line:
            continue
        name, _, rest = line.partition(":")
        tokens = [t for t in rest.split() if not t.startswith("(")]  # drop "(auto-read-only)"
        state = tokens[0] if tokens else "unknown"
        level = tokens[1] if len(tokens) > 1 and "[" not in tokens[1] else None
        detail = lines[i + 1] if i + 1 < len(lines) else ""
        health = re.search(r"\[([U_]+)\]", detail)
        progress = re.search(r"(recovery|resync|reshape|check)\s*=\s*([\d.]+%)", lines[i + 2]) if i + 2 < len(lines) else None
        arrays.append({
            "name": name.strip(),
            "level": level,
            "state": state,
            "devices": [re.sub(r"\[\d+\].*", "", t) for t in tokens if "[" in t],
            "health": health.group(1) if health else None,
            "degraded": state != "active" or bool(health and "_" in health.group(1)),
            "progress": progress.group(1) + " " + progress.group(2) if progress else None,
        })
    return arrays or None


def get_reboot_required():
    if not os.path.exists("/var/run/reboot-required"):
        return {"required": False, "packages": []}
    packages = (read_file("/var/run/reboot-required.pkgs") or "").split()
    return {"required": True, "packages": sorted(set(packages))}


# --- slower, optional checks (run in their own threads) ---

def get_pi_throttling():
    out = run_cmd(["vcgencmd", "get_throttled"])
    if not out or "=" not in out:
        return None
    try:
        value = int(out.split("=", 1)[1].strip(), 16)
    except ValueError:
        return None
    return {
        "now": [name for bit, name in THROTTLE_FLAGS if value & (1 << bit)],
        "since_boot": [name for bit, name in THROTTLE_FLAGS if value & (1 << (bit + 16))],
    }


def get_pending_updates():
    """Count upgradable packages from the last `apt update` (no root needed)."""
    cmd = ["apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"]
    if shutil.which("nice"):
        cmd = ["nice", "-n", "19"] + cmd
    out = run_cmd(cmd, timeout=180)
    if out is None:
        return None
    packages = [line for line in out.splitlines() if line.startswith("Inst ")]
    return {"total": len(packages), "security": sum(1 for line in packages if "-security" in line)}


def get_zfs_pools():
    out = run_cmd(["zpool", "list", "-Hp", "-o", "name,health,size,alloc"])
    pools = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            pools.append({"name": parts[0], "health": parts[1], "size": to_float(parts[2]), "alloc": to_float(parts[3])})
    return pools or None


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path, timeout=3):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def get_docker_containers():
    conn = UnixHTTPConnection(DOCKER_SOCKET)
    try:
        conn.request("GET", "/containers/json?all=1")
        response = conn.getresponse()
        if response.status != 200:
            return None
        containers = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        conn.close()
    result = [{
        "name": (c.get("Names") or ["?"])[0].lstrip("/"),
        "image": c.get("Image", ""),
        "state": c.get("State", ""),
        "status": c.get("Status", ""),
    } for c in containers]
    return sorted(result, key=lambda c: (c["state"] != "running", c["name"]))


def get_nvidia_gpus():
    out = run_cmd(["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                   "--format=csv,noheader,nounits"])
    gpus = []
    for line in (out or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 5:
            used, total = to_float(parts[2]), to_float(parts[3])
            gpus.append({
                "name": parts[0],
                "util": to_float(parts[1]),
                "mem_used": used * 1048576 if used is not None else None,
                "mem_total": total * 1048576 if total is not None else None,
                "temp": to_float(parts[4]),
            })
    return gpus or None


def get_unit_states(units):
    out = run_cmd(["systemctl", "is-active"] + units, allow_error=True)  # exits non-zero if any unit is down
    states = (out or "").split()
    return {unit: i < len(states) and states[i] == "active" for i, unit in enumerate(units)}


# --- collector ---

class Collector:
    """Samples the system in background threads; HTTP requests only read the latest results."""

    def __init__(self, services, interval, check_updates=True):
        self.services = services
        self.interval = interval
        self.check_updates = check_updates
        self.static = get_static_info()
        self.history = deque(maxlen=max(2, int(HISTORY_SECONDS / interval)))
        self._lock = threading.Lock()
        self._latest = {}
        self._slow = {}
        self._stale_mounts = {}
        self._prev = None

    def start(self):
        self._sample()
        self._spawn(self._sample_loop)
        units = [s["unit"] for s in self.services if s["unit"]]
        tasks = [
            ("throttling", get_pi_throttling, 30, shutil.which("vcgencmd")),
            ("zfs", get_zfs_pools, 60, shutil.which("zpool")),
            ("docker", get_docker_containers, 10, os.access(DOCKER_SOCKET, os.R_OK | os.W_OK)),
            ("gpus", get_nvidia_gpus, 5, shutil.which("nvidia-smi")),
            ("updates", get_pending_updates, 3600, self.check_updates and shutil.which("apt-get")),
            ("_units", lambda: get_unit_states(units), 5, units),
        ]
        for key, fn, every, available in tasks:
            if available:
                self._spawn(self._repeat, key, fn, every)

    def snapshot(self):
        with self._lock:
            data = dict(self._latest)
            data.update((k, v) for k, v in self._slow.items() if not k.startswith("_"))
        data["system"] = dict(self.static, hostname=socket.gethostname(), ip=get_primary_ip())
        return data

    def history_points(self):
        with self._lock:
            return {"length": self.history.maxlen, "interval": self.interval, "points": list(self.history)}

    def _spawn(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    def _sample_loop(self):
        while True:
            time.sleep(self.interval)
            try:
                self._sample()
            except Exception:
                traceback.print_exc()

    def _repeat(self, key, fn, every):
        while True:
            try:
                value = fn()
            except Exception:
                traceback.print_exc()
                value = None
            with self._lock:
                self._slow[key] = value
            time.sleep(every)

    def _sample(self):
        now = time.monotonic()
        current = {"cpu": read_cpu_times(), "net": read_net_io(), "disk": read_disk_io(), "procs": read_processes()}
        prev, self._prev = self._prev, (now, current)
        dt = now - prev[0] if prev else 0
        before = prev[1] if prev else {}

        ipv6 = get_ipv6_addresses()
        network = [{"name": name, "rx": rx, "tx": tx, "ipv4": get_ipv4(name), "ipv6": ipv6.get(name, [])}
                   for name, (rx, tx) in rates(before.get("net"), current["net"], dt)]
        memory = get_memory()
        cpu = cpu_usage(before.get("cpu"), current["cpu"])
        data = {
            "time": round(time.time(), 3),
            "uptime": get_uptime(),
            "load": get_load(),
            "cpu": cpu,
            "memory": memory,
            "temperatures": get_temperatures(),
            "disks": self._disks(),
            "disk_io": [{"name": name, "read": r, "write": w}
                        for name, (r, w) in rates(before.get("disk"), current["disk"], dt)],
            "network": network,
            "processes": top_processes(before.get("procs"), current["procs"], dt),
            "raid": get_raid(),
            "reboot": get_reboot_required(),
            "services": self._services(),
        }
        # Same point the browser builds from each /api response (see pushHistory in the page).
        mem_pct = round(100.0 * (memory["total"] - memory["available"]) / memory["total"], 1) if memory else None
        rx = sum(n["rx"] for n in network) if network and network[0]["rx"] is not None else None
        tx = sum(n["tx"] for n in network) if network and network[0]["tx"] is not None else None
        point = [data["time"], cpu["total"] if cpu else None, mem_pct, rx, tx]
        with self._lock:
            self._latest = data
            self.history.append(point)

    def _disks(self):
        disks, now = [], time.monotonic()
        for device, mount, fstype in list_mounts():
            entry = {"device": device, "mount": mount, "type": fstype}
            if fstype in NETWORK_FS_TYPES:
                usage = None
                if self._stale_mounts.get(mount, 0) < now:
                    usage = call_with_timeout(disk_usage, 2, mount)
                    if usage is None:
                        self._stale_mounts[mount] = now + 60  # don't pile up hung threads
                if usage is None:
                    entry["stale"] = True
                    disks.append(entry)
                    continue
            else:
                try:
                    usage = disk_usage(mount)
                except OSError:
                    continue
            if usage["total"]:
                entry.update(usage)
                disks.append(entry)
        return disks

    def _services(self):
        hosts = ["127.0.0.1", "::1"]
        primary = get_primary_ip()
        if primary not in hosts:
            hosts.append(primary)  # services bound to the LAN address only
        with self._lock:
            units = self._slow.get("_units") or {}
        result = []
        for service in self.services:
            if service["port"]:
                up, target = port_open(service["port"], hosts), "port %d" % service["port"]
            else:
                up, target = units.get(service["unit"], False), service["unit"]
            result.append({"name": service["name"], "target": target, "up": up})
        return result


# --- /health and /metrics ---

def health_warnings(data):
    warnings = []
    for disk in data.get("disks") or []:
        if disk.get("stale"):
            warnings.append("filesystem %s is not responding" % disk["mount"])
        elif disk["percent"] >= 90:
            warnings.append("filesystem %s is %.0f%% full" % (disk["mount"], disk["percent"]))
    memory = data.get("memory")
    if memory and memory["available"] < memory["total"] * 0.1:
        warnings.append("less than 10% of memory available")
    for array in data.get("raid") or []:
        if array["degraded"]:
            warnings.append("RAID array %s is degraded" % array["name"])
    for pool in data.get("zfs") or []:
        if pool["health"] != "ONLINE":
            warnings.append("ZFS pool %s is %s" % (pool["name"], pool["health"]))
    for service in data.get("services") or []:
        if not service["up"]:
            warnings.append("service %s (%s) is down" % (service["name"], service["target"]))
    throttling = data.get("throttling")
    if throttling and throttling["now"]:
        warnings.append("Raspberry Pi: " + ", ".join(throttling["now"]).lower())
    return warnings


def escape_label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def prometheus_metrics(data):
    families = {}

    def add(name, help_text, value, **labels):
        if value is not None:
            families.setdefault(name, (help_text, []))[1].append((labels, value))

    add("uptime_seconds", "Seconds since boot.", data.get("uptime"))
    for minutes, value in zip((1, 5, 15), data.get("load") or []):
        add("load_average", "System load average.", value, minutes=minutes)
    cpu = data.get("cpu") or {}
    add("cpu_usage_percent", "Overall CPU usage.", cpu.get("total"))
    for core, value in enumerate(cpu.get("cores") or []):
        add("cpu_core_usage_percent", "Per-core CPU usage.", value, core=core)
    memory = data.get("memory") or {}
    for key in ("total", "used", "cache", "available", "swap_total", "swap_used"):
        add("memory_%s_bytes" % key, "Memory: %s." % key.replace("_", " "), memory.get(key))
    for disk in data.get("disks") or []:
        labels = {"mount": disk["mount"], "device": disk["device"], "fstype": disk["type"]}
        add("filesystem_responding", "1 if the filesystem answered in time.", 0 if disk.get("stale") else 1, **labels)
        for key in ("total", "used", "free"):
            add("filesystem_%s_bytes" % key, "Filesystem space: %s." % key, disk.get(key), **labels)
    for io in data.get("disk_io") or []:
        add("disk_read_bytes_per_second", "Disk read rate.", io["read"], device=io["name"])
        add("disk_write_bytes_per_second", "Disk write rate.", io["write"], device=io["name"])
    for net in data.get("network") or []:
        add("network_receive_bytes_per_second", "Network receive rate.", net["rx"], interface=net["name"])
        add("network_transmit_bytes_per_second", "Network transmit rate.", net["tx"], interface=net["name"])
    for sensor in (data.get("temperatures") or {}).get("sensors", []):
        add("temperature_celsius", "Hardware temperature sensor.", sensor["celsius"], sensor=sensor["name"])
    for service in data.get("services") or []:
        add("service_up", "1 if the service is reachable / active.", int(service["up"]),
            service=service["name"], target=service["target"])
    for array in data.get("raid") or []:
        add("raid_degraded", "1 if the md RAID array is degraded.", int(array["degraded"]), array=array["name"])
    for pool in data.get("zfs") or []:
        add("zfs_pool_online", "1 if the ZFS pool health is ONLINE.", int(pool["health"] == "ONLINE"), pool=pool["name"])
        add("zfs_pool_size_bytes", "ZFS pool size.", pool["size"], pool=pool["name"])
        add("zfs_pool_allocated_bytes", "ZFS pool allocated space.", pool["alloc"], pool=pool["name"])
    add("reboot_required", "1 if a reboot is required.", int(bool((data.get("reboot") or {}).get("required"))))
    updates = data.get("updates")
    if updates:
        add("updates_pending", "Upgradable apt packages.", updates["total"])
        add("updates_security", "Upgradable apt packages from security repositories.", updates["security"])
    states = {}
    for container in data.get("docker") or []:
        states[container["state"]] = states.get(container["state"], 0) + 1
    for state, count in states.items():
        add("docker_containers", "Docker containers by state.", count, state=state)
    for index, gpu in enumerate(data.get("gpus") or []):
        add("gpu_utilization_percent", "GPU utilization.", gpu["util"], gpu=index, name=gpu["name"])
        add("gpu_memory_used_bytes", "GPU memory used.", gpu["mem_used"], gpu=index, name=gpu["name"])
        add("gpu_temperature_celsius", "GPU temperature.", gpu["temp"], gpu=index, name=gpu["name"])
    add("processes", "Number of processes.", (data.get("processes") or {}).get("count"))

    lines = []
    for name, (help_text, samples) in families.items():
        metric = "server_status_" + name
        lines += ["# HELP %s %s" % (metric, help_text), "# TYPE %s gauge" % metric]
        for labels, value in samples:
            text = ",".join('%s="%s"' % (k, escape_label(v)) for k, v in sorted(labels.items()))
            lines.append("%s%s %s" % (metric, "{" + text + "}" if text else "", float(value)))
    return "\n".join(lines) + "\n"


# --- web server ---

class StatusHandler(BaseHTTPRequestHandler):
    server_version = "server-status/" + VERSION
    collector = None
    auth = None
    verbose = False
    page = b""

    def do_GET(self):
        self._route(send_body=True)

    def do_HEAD(self):
        self._route(send_body=False)

    def _route(self, send_body):
        url = urlsplit(self.path)
        path = url.path.rstrip("/") or "/"
        if path == "/favicon.ico":
            return self._send(200, "image/x-icon", FAVICON, send_body)
        if self.auth and not self._authorized():
            return self._send(401, "text/plain; charset=utf-8", b"Authentication required\n", send_body,
                              {"WWW-Authenticate": 'Basic realm="server status", charset="UTF-8"'})
        if path == "/":
            self._send(200, "text/html; charset=utf-8", self.page, send_body)
        elif path == "/api":
            self._send_json(200, self.collector.snapshot(), send_body)
        elif path == "/api/history":
            self._send_json(200, self.collector.history_points(), send_body)
        elif path == "/health":
            warnings = health_warnings(self.collector.snapshot())
            strict = "strict" in parse_qs(url.query, keep_blank_values=True)
            status = 503 if warnings and strict else 200
            self._send_json(status, {"status": "warning" if warnings else "ok", "warnings": warnings}, send_body)
        elif path == "/metrics":
            body = prometheus_metrics(self.collector.snapshot()).encode("utf-8")
            self._send(200, "text/plain; version=0.0.4; charset=utf-8", body, send_body)
        else:
            self._send(404, "text/plain; charset=utf-8", b"Not found\n", send_body)

    def _authorized(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            supplied = base64.b64decode(header[6:].strip())
        except ValueError:
            return False
        return hmac.compare_digest(supplied, self.auth.encode("utf-8"))

    def _send_json(self, status, data, send_body):
        self._send(status, "application/json", json.dumps(data).encode("utf-8"), send_body)

    def _send(self, status, content_type, body, send_body=True, headers=None):
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if send_body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the browser went away mid-response

    def log_message(self, format, *args):
        # The page polls every few seconds, so access logs are off unless --verbose.
        if self.verbose:
            super().log_message(format, *args)

    def log_error(self, format, *args):
        super().log_message(format, *args)


def make_server(bind, port):
    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET
        daemon_threads = True

    return Server((bind, port), StatusHandler)


# --- command line ---

def parse_service(spec):
    name, sep, target = (part.strip() for part in spec.partition(":"))
    if not sep:
        target = name  # "nginx" means the systemd unit nginx
    if not name or not target:
        raise argparse.ArgumentTypeError("expected NAME:PORT or NAME:UNIT, got %r" % spec)
    if target.isdigit():
        port = int(target)
        if not 0 < port < 65536:
            raise argparse.ArgumentTypeError("port out of range in %r" % spec)
        return {"name": name, "port": port, "unit": None}
    return {"name": name, "port": None, "unit": target}


def parse_args():
    parser = argparse.ArgumentParser(description="One-file web dashboard for a Linux server's resources.")
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT,
                        help="port to listen on [default: %d]" % DEFAULT_PORT)
    parser.add_argument("--bind", "-b", default="", metavar="ADDRESS",
                        help="address to listen on, e.g. 127.0.0.1 or :: [default: all IPv4 interfaces]")
    parser.add_argument("--service", "-s", action="append", type=parse_service, metavar="NAME:PORT|NAME:UNIT",
                        help="service to show in the sidebar; checks a local TCP port, or a systemd unit "
                             "if the target is not a number. Repeatable; replaces the defaults (%s)"
                             % ", ".join(DEFAULT_SERVICES))
    parser.add_argument("--auth", metavar="USER:PASSWORD",
                        help="require HTTP Basic auth (or set SERVER_STATUS_AUTH to keep it out of `ps`)")
    parser.add_argument("--interval", type=float, default=2.0, metavar="SECONDS",
                        help="how often to sample and refresh the page [default: 2]")
    parser.add_argument("--no-updates", action="store_true", help="don't count pending apt updates")
    parser.add_argument("--verbose", "-v", action="store_true", help="log every HTTP request")
    parser.add_argument("--print-systemd-unit", action="store_true",
                        help="print a systemd unit that runs this script with the same options, then exit")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    args.auth = args.auth or os.environ.get("SERVER_STATUS_AUTH")
    if args.auth and ":" not in args.auth:
        parser.error("--auth must look like USER:PASSWORD")
    args.service = args.service or [parse_service(s) for s in DEFAULT_SERVICES]
    return args


def systemd_unit():
    options, skip = [], False
    for arg in sys.argv[1:]:
        if skip:
            skip = False
        elif arg == "--auth":
            skip = True  # never write the password into a world-readable unit file
        elif arg != "--print-systemd-unit" and not arg.startswith("--auth="):
            options.append(arg)
    command = " ".join(shlex.quote(a) for a in [sys.executable, os.path.abspath(__file__)] + options)
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    return """[Unit]
Description=Server status web dashboard
After=network-online.target
Wants=network-online.target

[Service]
User={user}
ExecStart={command}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
# Optional Basic auth: create /etc/server-status.env (chmod 600) containing
#   SERVER_STATUS_AUTH=user:password
# and uncomment:
#EnvironmentFile=/etc/server-status.env

[Install]
WantedBy=multi-user.target
""".format(user=user, command=command)


def main():
    args = parse_args()
    if args.print_systemd_unit:
        print(systemd_unit(), end="")
        return

    collector = Collector(args.service, args.interval, check_updates=not args.no_updates)
    collector.start()
    StatusHandler.collector = collector
    StatusHandler.auth = args.auth
    StatusHandler.verbose = args.verbose
    StatusHandler.page = HTML_PAGE.replace("__INTERVAL_MS__", str(int(args.interval * 1000))).encode("utf-8")

    try:
        server = make_server(args.bind, args.port)
    except OSError as e:
        print("Could not listen on %s:%d: %s" % (args.bind or "*", args.port, e.strerror or e), file=sys.stderr)
        sys.exit(1)

    host = args.bind if args.bind not in ("", "0.0.0.0", "::") else get_primary_ip()
    print("Server started http://%s:%d" % ("[%s]" % host if ":" in host else host, args.port), flush=True)

    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))  # clean stop under systemd
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
        print("Server stopped.", flush=True)


# --- page ---

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Server status</title>
<style>
	:root {
		--bg: #eeeeee; --card: #ffffff; --text: #555555; --muted: #8a8a8a; --accent: #0a9ee0;
		--border: #e4e4e4; --track: #e6e6e6; --ok: #5cb85c; --cache: #5bc0de; --warn: #f0ad4e; --crit: #d9534f;
		--side-bg: #222222; --side-item: #292929; --side-text: #eeeeee; --side-border: #333333;
		--online: #90c95f; --offline: #fe3d1d; --shadow: 0 5px 5px -5px #bbbbbb;
	}
	@media (prefers-color-scheme: dark) {
		:root {
			--bg: #151515; --card: #1f1f1f; --text: #cfcfcf; --muted: #8f8f8f; --accent: #3db8f5;
			--border: #2e2e2e; --track: #333333; --side-bg: #0d0d0d; --side-item: #161616;
			--side-border: #262626; --shadow: none;
		}
	}
	* { box-sizing: border-box; margin: 0; padding: 0; }
	body { font: 15px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background: var(--bg); color: var(--text); }
	a { color: inherit; }

	#sidebar { position: fixed; top: 0; left: 0; bottom: 0; width: 170px; padding-top: 12px; background: var(--side-bg); overflow-y: auto; }
	#sidebar .title { color: var(--side-text); }
	#services { list-style: none; }
	#services li { padding: 10px; background: var(--side-item); color: var(--offline); border-bottom: 1px solid var(--side-border); overflow-wrap: anywhere; }
	#services li:first-child { border-top: 1px solid var(--side-border); }
	#services li.online { color: var(--online); border-right: 3px solid var(--online); }
	#services li small { display: block; color: var(--muted); font-size: 11px; }

	#main { margin-left: 170px; padding: 12px; }
	#grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(340px, 100%), 1fr)); gap: 12px; align-items: start; }
	#banner { margin-bottom: 12px; padding: 8px 12px; background: var(--crit); color: #fff; border-radius: 4px; }
	#footer { margin-top: 12px; text-align: center; font-size: 12px; color: var(--muted); }

	.card { background: var(--card); padding: 12px; box-shadow: var(--shadow); border-radius: 4px; min-width: 0; }
	.card[hidden] { display: none; }
	.title { margin: 0 5px 8px; text-transform: uppercase; text-align: center; font-size: 12px; letter-spacing: .04em; color: var(--muted); }
	.value { color: var(--accent); }
	.muted { color: var(--muted); font-size: 12px; }
	.uptime { color: var(--accent); margin-bottom: 8px; text-align: center; }
	.row { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; margin: 8px 0 3px; }
	.row > :last-child { text-align: right; white-space: nowrap; }
	.row > :first-child { min-width: 0; overflow-wrap: anywhere; }
	.hot { color: var(--crit); }
	.warm { color: var(--warn); }

	.bar { display: flex; height: 16px; background: var(--track); border-radius: 8px; overflow: hidden; }
	.bar > span { height: 100%; background: var(--ok); transition: width .4s; }
	.bar > span.cache { background: var(--cache); }
	.bar > span.warn, .cell.warn i { background: var(--warn); }
	.bar > span.crit, .cell.crit i { background: var(--crit); }

	.cores { display: grid; grid-template-columns: repeat(auto-fill, minmax(14px, 1fr)); gap: 3px; margin-top: 4px; }
	.cell { height: 22px; background: var(--track); border-radius: 2px; display: flex; align-items: flex-end; overflow: hidden; }
	.cell i { display: block; width: 100%; background: var(--ok); }

	.kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; font-size: 13px; }
	.kv dt { color: var(--muted); }
	.kv dd { overflow-wrap: anywhere; }

	.badge { display: inline-block; white-space: nowrap; padding: 0 7px; border-radius: 10px; font-size: 12px; color: #fff; background: var(--muted); }
	.badge.ok { background: var(--ok); }
	.badge.warn { background: var(--warn); }
	.badge.crit { background: var(--crit); }
	.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; background: var(--muted); }
	.dot.ok { background: var(--ok); }
	.dot.warn { background: var(--warn); }

	table { width: 100%; border-collapse: collapse; font-size: 13px; }
	th, td { padding: 4px 6px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; overflow-wrap: break-word; word-break: break-word; }
	th { color: var(--muted); font-weight: normal; font-size: 12px; }
	.num { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
	.scroll { max-height: 320px; overflow-y: auto; }
	.split { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 6px; }
	.split h4 { font-size: 12px; font-weight: normal; color: var(--muted); margin-bottom: 2px; }

	details { margin-top: 8px; font-size: 13px; }
	summary { cursor: pointer; }
	details table { margin-top: 4px; }

	.spark { display: block; width: 100%; height: 40px; margin-top: 10px; }
	.spark path { fill: none; stroke-width: 1.5; vector-effect: non-scaling-stroke; }
	.spark .s1 { stroke: var(--accent); }
	.spark .s2 { stroke: var(--warn); }
	.key-s1 { color: var(--accent); }
	.key-s2 { color: var(--warn); }

	@media (max-width: 700px) {
		#sidebar { position: static; width: auto; padding: 10px 12px; }
		#services { display: flex; flex-wrap: wrap; gap: 6px; }
		#services li, #services li:first-child { border: 1px solid var(--side-border); border-radius: 4px; padding: 6px 10px; }
		#services li.online { border-right: 3px solid var(--online); }
		#main { margin-left: 0; }
	}
</style>
</head>
<body>
<nav id="sidebar">
	<div class="title">services</div>
	<ul id="services"></ul>
</nav>
<main id="main">
	<div id="banner" hidden>Connection to the server lost, retrying&hellip;</div>
	<div id="grid">
		<section class="card" id="card-system"><div class="title">system</div><div id="system"></div></section>
		<section class="card" id="card-cpu"><div class="title">cpu</div><div id="cpu"></div></section>
		<section class="card" id="card-memory"><div class="title">memory</div><div id="memory"></div></section>
		<section class="card" id="card-disks"><div class="title">disk space</div><div id="disks"></div></section>
		<section class="card" id="card-storage" hidden><div class="title">storage health</div><div id="storage"></div></section>
		<section class="card" id="card-network" hidden><div class="title">network</div><div id="network"></div></section>
		<section class="card" id="card-diskio" hidden><div class="title">disk i/o</div><div id="diskio"></div></section>
		<section class="card" id="card-gpu" hidden><div class="title">gpu</div><div id="gpu"></div></section>
		<section class="card" id="card-processes" hidden><div class="title">processes</div><div id="processes"></div></section>
		<section class="card" id="card-docker" hidden><div class="title">docker</div><div id="docker"></div></section>
	</div>
	<footer id="footer"><a href="https://somik.org/">Powered by Somik.org</a></footer>
</main>
<script>
(function () {
	'use strict';
	const INTERVAL = __INTERVAL_MS__;
	const NS = 'http://www.w3.org/2000/svg';
	const $ = (id) => document.getElementById(id);
	const openDetails = {};
	let history = [], historyLen = 450, uptime = null;

	// --- DOM helpers (all text goes through textContent, never innerHTML) ---
	function el(tag, cls, text) {
		const node = document.createElement(tag);
		if (cls) node.className = cls;
		if (text != null) node.textContent = text;
		return node;
	}
	function append(parent, ...children) {
		for (const child of children) {
			if (child == null) continue;
			parent.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
		}
		return parent;
	}
	function fill(id, ...children) { const node = $(id); node.textContent = ''; return append(node, ...children); }
	function show(id, visible) { $(id).hidden = !visible; }

	function fmtBytes(n) {
		if (n == null) return '–';
		const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
		let i = 0;
		while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
		return (i === 0 ? n.toFixed(0) : n.toFixed(n < 10 ? 2 : 1)) + ' ' + units[i];
	}
	const fmtRate = (n) => n == null ? '–' : fmtBytes(n) + '/s';
	const fmtPct = (n) => n == null ? '–' : n.toFixed(1) + '%';
	const level = (pct) => pct >= 90 ? 'crit' : pct >= 80 ? 'warn' : '';
	const col = (i) => history.map((p) => p[i]);

	function row(left, right) {
		const wrap = (x) => typeof x === 'object' ? x : el('span', null, x);
		return append(el('div', 'row'), wrap(left), wrap(right));
	}
	function bar(parts) {
		const node = el('div', 'bar');
		for (const [pct, cls, title] of parts) {
			const seg = el('span', cls);
			seg.style.width = Math.max(0, Math.min(100, pct || 0)) + '%';
			if (title) seg.title = title;
			node.appendChild(seg);
		}
		return node;
	}
	function badge(text, cls) { return el('span', 'badge ' + (cls || ''), text); }
	function table(headers, rows, numCols) {
		numCols = numCols || [];
		const t = el('table'), head = el('tr');
		headers.forEach((h, i) => head.appendChild(el('th', numCols.includes(i) ? 'num' : null, h)));
		t.appendChild(head);
		for (const r of rows) {
			const tr = el('tr');
			r.forEach((cell, i) => tr.appendChild(append(el('td', numCols.includes(i) ? 'num' : null), cell == null ? '–' : cell)));
			t.appendChild(tr);
		}
		return t;
	}
	function details(key, summary, body) {
		const node = el('details');
		node.open = !!openDetails[key];  // survive the re-render every few seconds
		node.addEventListener('toggle', () => { openDetails[key] = node.open; });
		node.appendChild(append(el('summary'), ...[].concat(summary)));
		node.appendChild(body);
		return node;
	}
	function sparkline(series, max) {
		const W = 300, H = 40, svg = document.createElementNS(NS, 'svg');
		svg.setAttribute('class', 'spark');
		svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
		svg.setAttribute('preserveAspectRatio', 'none');
		if (!max) {
			max = 1;
			for (const s of series) for (const v of s.values) if (v != null && v > max) max = v;
		}
		for (const s of series) {
			const offset = historyLen - s.values.length;  // newest point at the right edge
			let d = '', pen = false;
			s.values.forEach((v, i) => {
				if (v == null) { pen = false; return; }
				const x = (offset + i) / (historyLen - 1) * W, y = H - 1 - Math.min(v / max, 1) * (H - 2);
				d += (pen ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1);
				pen = true;
			});
			if (d) {
				const path = document.createElementNS(NS, 'path');
				path.setAttribute('d', d);
				path.setAttribute('class', s.cls);
				svg.appendChild(path);
			}
		}
		return svg;
	}
	const historyLabel = () => 'last ' + Math.round(historyLen * INTERVAL / 60000) + ' minutes';

	// --- cards ---
	function renderServices(d) {
		const ul = $('services');
		ul.textContent = '';
		for (const s of d.services || []) {
			ul.appendChild(append(el('li', s.up ? 'online' : null, s.name), el('small', null, s.target)));
		}
	}

	function tickUptime() {
		const node = $('uptime');
		if (!node || !uptime) return;
		let t = Math.floor(uptime.base + (Date.now() - uptime.at) / 1000);
		const days = Math.floor(t / 86400); t %= 86400;
		const hours = Math.floor(t / 3600); t %= 3600;
		const minutes = Math.floor(t / 60), seconds = t % 60;
		const unit = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');
		node.textContent = 'Up ' + unit(days, 'day') + ', ' + unit(hours, 'hour') + ', ' +
			unit(minutes, 'minute') + ' and ' + unit(seconds, 'second');
	}

	function renderSystem(d) {
		const s = d.system, kv = el('dl', 'kv');
		const add = (key, value) => {
			if (value == null || value === '') return;
			append(kv, el('dt', null, key), append(el('dd'), value));
		};
		const cores = d.cpu && d.cpu.cores.length ? d.cpu.cores.length : s.cpu_count;
		add('Hostname', s.hostname);
		add('IP address', s.ip);
		add('OS', s.os);
		add('Kernel', s.kernel + ' (' + s.arch + ')');
		add('Device', s.device);
		add('CPU', s.cpu_model + (cores ? ' · ' + cores + (cores === 1 ? ' core' : ' cores') : ''));
		if (d.reboot && d.reboot.required) {
			add('Reboot', badge('required' + (d.reboot.packages.length ? ' by ' + d.reboot.packages.join(', ') : ''), 'warn'));
		}
		if (d.updates) {
			const u = d.updates;
			add('Updates', u.total
				? badge(u.total + ' pending' + (u.security ? ', ' + u.security + ' security' : ''), u.security ? 'crit' : 'warn')
				: badge('up to date', 'ok'));
		}
		const up = el('div', 'uptime');
		up.id = 'uptime';
		fill('system', d.uptime != null ? up : null, kv);
		tickUptime();
	}

	function renderCPU(d) {
		const c = d.cpu, node = fill('cpu');
		if (c && c.total != null) {
			append(node, row('Usage', fmtPct(c.total)), bar([[c.total, level(c.total)]]));
		} else {
			node.appendChild(el('div', 'muted', c ? 'Measuring…' : 'Not available'));
		}
		if (d.load) {
			const cores = (c && c.cores.length) || d.system.cpu_count || 1;
			const cls = d.load[0] > cores ? 'hot' : d.load[0] > cores * 0.8 ? 'warm' : 'value';
			node.appendChild(row('Load average (1 / 5 / 15 min)',
				el('span', cls, d.load.map((v) => v.toFixed(2)).join(' / '))));
		}
		if (c && c.cores.length > 1) {
			const grid = el('div', 'cores');
			c.cores.forEach((v, i) => {
				const cell = el('div', 'cell ' + level(v || 0)), bit = el('i');
				cell.title = 'CPU ' + i + ': ' + fmtPct(v);
				bit.style.height = (v || 0) + '%';
				grid.appendChild(append(cell, bit));
			});
			append(node, el('div', 'muted', 'Per core'), grid);
		}
		const t = d.temperatures;
		if (t) {
			const cls = t.max >= 85 ? 'hot' : t.max >= 75 ? 'warm' : 'value';
			node.appendChild(details('temps',
				['Temperature ', el('span', cls, t.max.toFixed(1) + ' °C'), el('span', 'muted', t.count > 1 ? ' hottest of ' + t.count + ' sensors' : '')],
				table(['Sensor', '°C'], t.sensors.map((s) => [s.name, s.celsius.toFixed(1)]), [1])));
		}
		const th = d.throttling;
		if (th && (th.now.length || th.since_boot.length)) {
			const line = el('div', 'row');
			append(line, el('span', null, 'Raspberry Pi'),
				append(el('span'), th.now.length ? badge(th.now.join(', ') + ' now', 'crit') : null, ' ',
					th.since_boot.length ? badge(th.since_boot.join(', ') + ' since boot', 'warn') : null));
			node.appendChild(line);
		}
		append(node, sparkline([{ values: col(1), cls: 's1' }], 100), el('div', 'muted', 'CPU usage, ' + historyLabel()));
	}

	function renderMemory(d) {
		const m = d.memory, node = fill('memory');
		if (!m) { node.appendChild(el('div', 'muted', 'Not available')); return; }
		const usedPct = 100 - m.available / m.total * 100;
		append(node,
			row('Used ' + fmtBytes(m.used) + ' · Cache ' + fmtBytes(m.cache), fmtBytes(m.total) + ' total'),
			bar([[m.used / m.total * 100, level(usedPct), 'Used'], [m.cache / m.total * 100, 'cache', 'Cache / buffers']]),
			el('div', 'muted', fmtBytes(m.available) + ' available'));
		if (m.swap_total > 0) {
			const p = m.swap_used / m.swap_total * 100;
			append(node, row('Swap ' + fmtBytes(m.swap_used), fmtBytes(m.swap_total) + ' total'), bar([[p, level(p)]]));
		}
		append(node, sparkline([{ values: col(2), cls: 's1' }], 100), el('div', 'muted', 'Memory in use, ' + historyLabel()));
	}

	function renderDisks(d) {
		const node = fill('disks');
		const disks = d.disks || [];
		if (!disks.length) node.appendChild(el('div', 'muted', 'No filesystems found'));
		for (const disk of disks) {
			const label = append(el('span'), el('strong', null, disk.mount), el('span', 'muted', ' ' + disk.device + ' · ' + disk.type));
			if (disk.stale) { node.appendChild(row(label, badge('not responding', 'crit'))); continue; }
			append(node,
				row(label, fmtBytes(disk.used) + ' / ' + fmtBytes(disk.total) + ' (' + disk.percent.toFixed(0) + '%)'),
				bar([[disk.percent, level(disk.percent)]]));
		}
	}

	function renderStorage(d) {
		const raid = d.raid || [], zfs = d.zfs || [];
		show('card-storage', raid.length || zfs.length);
		if (!raid.length && !zfs.length) return;
		const rows = raid.map((a) => [
			a.name, a.level || '–',
			badge(a.degraded ? 'degraded' : 'healthy', a.degraded ? 'crit' : 'ok'),
			[a.health ? '[' + a.health + ']' : '', a.progress || '', a.devices.join(' ')].filter(Boolean).join(' · '),
		]).concat(zfs.map((p) => [
			p.name, 'zfs', badge(p.health, p.health === 'ONLINE' ? 'ok' : 'crit'),
			fmtBytes(p.alloc) + ' / ' + fmtBytes(p.size),
		]));
		fill('storage', table(['Array / pool', 'Type', 'Status', 'Details'], rows));
	}

	function renderNetwork(d) {
		const ifaces = d.network || [];
		show('card-network', ifaces.length);
		if (!ifaces.length) return;
		const rows = ifaces.map((i) => {
			const addrs = el('div');
			[i.ipv4].concat(i.ipv6).filter(Boolean).forEach((a) => addrs.appendChild(el('div', null, a)));
			return [i.name, addrs.childNodes.length ? addrs : null, fmtRate(i.rx), fmtRate(i.tx)];
		});
		const rx = col(3), tx = col(4);
		const peak = Math.max(0, ...rx.filter((v) => v != null), ...tx.filter((v) => v != null));
		fill('network',
			table(['Interface', 'Address', '↓ In', '↑ Out'], rows, [2, 3]),
			sparkline([{ values: rx, cls: 's1' }, { values: tx, cls: 's2' }]),
			append(el('div', 'muted'), el('span', 'key-s1', '↓ in'), ' / ', el('span', 'key-s2', '↑ out'),
				', ' + historyLabel() + ' (peak ' + fmtRate(peak) + ')'));
	}

	function renderDiskIO(d) {
		const io = d.disk_io || [];
		show('card-diskio', io.length);
		if (io.length) fill('diskio', table(['Disk', 'Read', 'Write'], io.map((x) => [x.name, fmtRate(x.read), fmtRate(x.write)]), [1, 2]));
	}

	function renderGPU(d) {
		const gpus = d.gpus || [];
		show('card-gpu', gpus.length);
		const node = fill('gpu');
		for (const g of gpus) {
			append(node, row(el('strong', null, g.name), g.temp != null ? g.temp + ' °C' : ''),
				row('Utilization', fmtPct(g.util)), bar([[g.util, level(g.util)]]));
			if (g.mem_total) {
				const p = g.mem_used / g.mem_total * 100;
				append(node, row('Memory', fmtBytes(g.mem_used) + ' / ' + fmtBytes(g.mem_total)), bar([[p, level(p)]]));
			}
		}
	}

	function renderProcesses(d) {
		const p = d.processes;
		show('card-processes', p);
		if (!p) return;
		const cpu = append(el('div'), el('h4', null, 'Top CPU'),
			table(['Name', 'CPU'], p.by_cpu.map((x) => [x.name, fmtPct(x.cpu)]), [1]));
		const mem = append(el('div'), el('h4', null, 'Top memory'),
			table(['Name', 'RSS'], p.by_memory.map((x) => [x.name, fmtBytes(x.rss)]), [1]));
		fill('processes', el('div', 'muted', p.count + ' processes'), append(el('div', 'split'), cpu, mem));
	}

	function renderDocker(d) {
		const list = d.docker;
		show('card-docker', Array.isArray(list));
		if (!Array.isArray(list)) return;
		const running = list.filter((c) => c.state === 'running').length;
		const rows = list.map((c) => [
			append(el('span'), el('span', 'dot ' + (c.state === 'running' ? 'ok' : c.state === 'exited' ? '' : 'warn')), c.name),
			c.image, c.status,
		]);
		fill('docker', el('div', 'muted', running + ' running / ' + list.length + ' total'),
			append(el('div', 'scroll'), table(['Container', 'Image', 'Status'], rows)));
	}

	// --- data loop ---
	function pushHistory(d) {
		if (history.length && history[history.length - 1][0] >= d.time) return;
		const m = d.memory, net = d.network || [];
		const sum = (key) => net.length && net[0][key] != null ? net.reduce((a, n) => a + n[key], 0) : null;
		history.push([d.time, d.cpu ? d.cpu.total : null,
			m ? Math.round((m.total - m.available) / m.total * 1000) / 10 : null, sum('rx'), sum('tx')]);
		while (history.length > historyLen) history.shift();
	}

	function render(d) {
		if (d.uptime != null) uptime = { base: d.uptime, at: Date.now() };
		pushHistory(d);
		document.title = d.system.hostname + ' · status';
		const renderers = [renderServices, renderSystem, renderCPU, renderMemory, renderDisks, renderStorage,
			renderNetwork, renderDiskIO, renderGPU, renderProcesses, renderDocker];
		for (const fn of renderers) {
			try { fn(d); } catch (e) { console.error(fn.name, e); }
		}
	}

	async function refresh() {
		try {
			const res = await fetch('api', { cache: 'no-store' });
			if (!res.ok) throw new Error('HTTP ' + res.status);
			render(await res.json());
			$('banner').hidden = true;
		} catch (e) {
			$('banner').hidden = false;
		} finally {
			setTimeout(refresh, INTERVAL);
		}
	}

	fetch('api/history', { cache: 'no-store' })
		.then((res) => res.ok ? res.json() : null)
		.then((h) => { if (h) { history = h.points; historyLen = h.length; } })
		.catch(() => {})
		.finally(refresh);
	setInterval(tickUptime, 1000);
})();
</script>
</body>
</html>
"""

FAVICON_ICO = "AAABAAMAEBAAAAEAIABoBAAANgAAACAgAAABACAAKBEAAJ4EAAAwMAAAAQAgAGgmAADGFQAAKAAAABAAAAAgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXQAAAGYAAABmAAAAZgAAAGYAAABmAAAAZgAAAF0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFwAAABlAAAApQAAAN8AAADfAAAApQAAAGUAAABcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB3AAAAyAAAAMoAAADKAAAAygAAAMoAAADKAAAAygAAAMoAAADKAAAAygAAAMoAAADIAAAAeAAAAAAAAAAkAAAAugAAAAYAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAwAAAK0AAAAlAAAAMgAAAJkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACYAAAAMwAAADIAAACZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADSAAAAXgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmAAAADMAAAAyAAAAmQAAAEAAAAB6AAAAegAAACUAAAA/AAAAtQAAAL4AAAAAAAAAQQAAAHoAAAB6AAAAQAAAAJgAAAAzAAAAMgAAAJkAAAAnAAAAUAAAAGUAAACwAAAAqwAAADEAAACxAAAAKAAAAMMAAABwAAAAUAAAACcAAACYAAAAMwAAADIAAACZAAAAAAAAAAAAAAAAAAAAsAAAAL8AAAAAAAAATgAAAJwAAADnAAAAAwAAAAAAAAAAAAAAmAAAADMAAAAyAAAAmQAAAAAAAAAAAAAAAAAAACQAAAAxAAAAAAAAAAQAAADjAAAAqAAAAAAAAAAAAAAAAAAAAJgAAAAzAAAAMgAAAJkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQAAAE4AAAAAAAAAAAAAAAAAAACYAAAAMwAAADEAAACaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmQAAADMAAAAQAAAA0QAAAGwAAABmAAAAZgAAAGYAAABmAAAAZgAAAGYAAABmAAAAZgAAAGYAAABmAAAAawAAANAAAAAQAAAAAAAAACEAAABjAAAAZQAAAGUAAABlAAAAZQAAAGUAAABlAAAAZQAAAGUAAABlAAAAZQAAAGMAAAAiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAACAAAABAAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAApwAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAqAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAClAAAAywAAAMsAAADLAAAA1AAAAP4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAANUAAADLAAAAywAAAMsAAACmAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAsgAAAMAAAADAAAAAwAAAAMAAAACyAAAAEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAE0AAACRAAAAmgAAAJoAAACaAAAAmgAAAJoAAACaAAAAmgAAAJoAAACaAAAAmgAAAJoAAACaAAAAmgAAAJoAAACaAAAAmgAAAJoAAACaAAAAmgAAAJoAAACaAAAAmgAAAJIAAABOAAAAAQAAAAAAAAAAAAAAAAAAAAAAAACSAAAA/gAAAPwAAAD6AAAA+gAAAPoAAAD6AAAA+gAAAPoAAAD6AAAA+gAAAPoAAAD6AAAA+gAAAPoAAAD6AAAA+gAAAPoAAAD6AAAA+gAAAPoAAAD6AAAA+gAAAPoAAAD6AAAA+gAAAP4AAACTAAAAAAAAAAAAAAAAAAAALwAAAP0AAACvAAAAFgAAAAMAAAADAAAAAwAAAAMAAAADAAAAAwAAAAMAAAADAAAAAwAAAAMAAAADAAAAAwAAAAMAAAADAAAAAwAAAAMAAAADAAAAAwAAAAMAAAADAAAAAwAAAAMAAAALAAAAhQAAAP0AAAAxAAAAAAAAAAAAAABhAAAA/wAAAD4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1AAAA/wAAAGMAAAAAAAAAAAAAAGQAAAD/AAAAMwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEAAAD/AAAAZwAAAAAAAAAAAAAAZAAAAP8AAAAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAChAAAAJwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQAAAP8AAABnAAAAAAAAAAAAAABkAAAA/wAAADMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcQAAAP8AAACNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxAAAA/wAAAGcAAAAAAAAAAAAAAGQAAAD/AAAAMwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAADZAAAA/wAAAOcAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEAAAD/AAAAZwAAAAAAAAAAAAAAZAAAAP8AAAAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAASgAAAP4AAADJAAAA/gAAAFQAAAAAAAAAAAAAAAAAAAAGAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQAAAP8AAABnAAAAAAAAAAAAAABkAAAA/wAAADMAAAAaAAAA5gAAAPUAAAD1AAAA9QAAAPUAAACXAAAAAAAAAAAAAAC1AAAA8QAAAB8AAADvAAAAtwAAAAAAAAAAAAAAGQAAAOgAAAD1AAAA9QAAAPUAAAD1AAAA5wAAABsAAAAxAAAA/wAAAGcAAAAAAAAAAAAAAGQAAAD/AAAAMwAAAAoAAACTAAAAoQAAAKEAAAChAAAAzQAAAPoAAAApAAAAJgAAAPsAAACXAAAAAAAAAJkAAAD6AAAAIQAAAAAAAABjAAAA/wAAANAAAAChAAAAoQAAAKEAAACTAAAACwAAADEAAAD/AAAAZwAAAAAAAAAAAAAAZAAAAP8AAAAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAA+gAAAKMAAACPAAAA/AAAAC4AAAAAAAAANQAAAP4AAACAAAAAAAAAAKwAAAD/AAAATwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQAAAP8AAABnAAAAAAAAAAAAAABkAAAA/wAAADMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkAAAA+gAAAPEAAAC+AAAAAAAAAAAAAAABAAAAzgAAAN8AAAAMAAAA7QAAAPYAAAAPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxAAAA/wAAAGcAAAAAAAAAAAAAAGQAAAD/AAAAMwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkAAAD6AAAA/gAAAFIAAAAAAAAAAAAAAAAAAABrAAAA/wAAAIgAAAD+AAAAvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEAAAD/AAAAZwAAAAAAAAAAAAAAZAAAAP8AAAAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJEAAAC/AAAABQAAAAAAAAAAAAAAAAAAABMAAAD0AAAA+gAAAP8AAAB1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQAAAP8AAABnAAAAAAAAAAAAAABkAAAA/wAAADMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKIAAAD/AAAA/gAAAC4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxAAAA/wAAAGcAAAAAAAAAAAAAAGQAAAD/AAAAMwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAP4AAADhAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEAAAD/AAAAZwAAAAAAAAAAAAAAZAAAAP8AAAAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAlQAAAFcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQAAAP8AAABnAAAAAAAAAAAAAABkAAAA/wAAADMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxAAAA/wAAAGcAAAAAAAAAAAAAAGMAAAD/AAAAOQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADYAAAD/AAAAZgAAAAAAAAAAAAAAPgAAAP4AAACQAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAjAAAAP4AAABAAAAAAAAAAAAAAAACAAAAuAAAAP4AAADhAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAM0AAADNAAAAzQAAAN8AAAD+AAAAugAAAAIAAAAAAAAAAAAAAAAAAAAKAAAAfQAAAMMAAADLAAAAywAAAMsAAADLAAAAywAAAMsAAADLAAAAywAAAMsAAADLAAAAywAAAMsAAADLAAAAywAAAMsAAADLAAAAywAAAMsAAADLAAAAywAAAMsAAADLAAAAwwAAAH4AAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAADAAAABgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB8AAABLAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABLAAAAIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAMkAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAAzgAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAL0AAADqAAAA6wAAAOsAAADrAAAA6wAAAOwAAAD4AAAA/gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD5AAAA7AAAAOsAAADrAAAA6wAAAOsAAADqAAAAwwAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0AAABJAAAASwAAAEsAAABLAAAASwAAAFEAAAC9AAAA/gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP4AAAC/AAAAVQAAAEsAAABLAAAASwAAAEsAAABJAAAAIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAA3AAAAhwAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAIoAAAA3AAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAJQAAAEsAAABZAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABaAAAAWgAAAFoAAABZAAAATQAAACcAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAACDAAAA3QAAAPoAAAD+AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD+AAAA+gAAAOEAAACEAAAAFQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJIAAAD5AAAA/gAAAPsAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA9gAAAPYAAAD2AAAA+AAAAP4AAAD5AAAAmwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANgAAAPkAAAD7AAAAtQAAADUAAAAKAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAFAAAABQAAAAUAAAAHAAAAGAAAAHAAAAD0AAAA+gAAAD4AAAAAAAAAAAAAAAAAAAAAAAAAhQAAAP8AAADbAAAAKwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAADGAAAA/wAAAJMAAAAAAAAAAAAAAAAAAAAAAAAAoQAAAP8AAAC3AAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACyAAAA/wAAALIAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAAAAKAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAACPAAAA5wAAAHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0AAADcAAAA/wAAAM4AAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGkAAAD8AAAA/wAAAO0AAAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAANsAAAD/AAAA/wAAAPwAAACCAAAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXAAAAP4AAADzAAAA4QAAAP4AAADCAAAAGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAEAAAAxAAAAcAAAAHYAAAB2AAAAdgAAAHYAAAB2AAAAdgAAAFYAAAAFAAAAAAAAAAAAAAAPAAAAvAAAAP4AAAC6AAAAZgAAAPwAAADzAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAfAAAAHcAAAB2AAAAdgAAAHYAAAB2AAAAdgAAAHIAAAAyAAAAAQAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAkAAAChAAAA+gAAAPwAAAD8AAAA/AAAAPwAAAD8AAAA/AAAAOcAAAA9AAAAAAAAAAAAAABKAAAA6gAAAPkAAABvAAAACQAAANIAAAD+AAAAqgAAAAAAAAAAAAAAAAAAAAoAAACjAAAA+wAAAPwAAAD8AAAA/AAAAPwAAAD8AAAA/AAAAPsAAACjAAAADwAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAQAAABzAAAA1gAAANsAAADbAAAA2wAAANsAAADcAAAA9QAAAP0AAACPAAAACQAAAAUAAACRAAAA/AAAAOUAAAArAAAAAAAAAGsAAAD8AAAA8wAAACMAAAAAAAAAAAAAABcAAADXAAAA/wAAAPgAAADdAAAA2wAAANsAAADbAAAA2wAAANgAAAB1AAAABgAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAIAAAAHgAAACEAAAAhAAAAIQAAACEAAAAkAAAAngAAAP8AAADcAAAALQAAABkAAADVAAAA/gAAAKMAAAAEAAAAAAAAACEAAADgAAAA/gAAAIcAAAABAAAAAAAAADsAAAD3AAAA/wAAAMMAAAAlAAAAIQAAACEAAAAhAAAAIQAAAB8AAAAIAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIQAAAO8AAAD9AAAAkQAAAGMAAAD8AAAA+AAAAC8AAAAAAAAAAAAAAAgAAAChAAAA/gAAANwAAAAYAAAAAAAAAIcAAAD+AAAA/wAAAHMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIUAAAD9AAAA8gAAANkAAAD+AAAAsQAAAAAAAAAAAAAAAAAAAAAAAABgAAAA8gAAAPQAAABVAAAABgAAANMAAAD/AAAA+AAAACYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMAAADcAAAA/gAAAP4AAADzAAAATAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAA1QAAAP0AAACXAAAAOgAAAPoAAAD/AAAAywAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAACMAAAA/AAAAP4AAAC9AAAAGAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAjgAAAP8AAADaAAAAoAAAAP4AAAD+AAAAfgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AAAA1wAAAO8AAABvAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALgAAAPYAAAD9AAAA9QAAAP8AAADzAAAAPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAARgAAAFsAAAATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAALIAAAD/AAAA/wAAAP8AAADQAAAAHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEQAAAD5AAAA/wAAAP4AAACfAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMAAADOAAAA/gAAAPoAAABvAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAACOAAAA+gAAAOcAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbAAAAaAAAAD4AAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAowAAAP8AAACzAAAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACxAAAA/wAAALUAAAAAAAAAAAAAAAAAAAAAAAAAnwAAAP8AAAC9AAAAFwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAC5AAAA/wAAALAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAP4AAADlAAAAPAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAC4AAADjAAAA/gAAAIYAAAAAAAAAAAAAAAAAAAAAAAAAJwAAAOgAAAD+AAAAyQAAAG4AAABRAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABNAAAATQAAAE0AAABQAAAAagAAAMIAAAD+AAAA6wAAACwAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAFgAAADzAAAA/gAAAPkAAADzAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADyAAAA8gAAAPIAAADzAAAA+QAAAP4AAAD0AAAAZAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAABfAAAAywAAAOYAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA6wAAAOsAAADrAAAA5wAAAM8AAABgAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAFwAAAD4AAABKAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABLAAAASwAAAEsAAABKAAAAPwAAABoAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
FAVICON = base64.b64decode(FAVICON_ICO)


if __name__ == "__main__":
    main()
