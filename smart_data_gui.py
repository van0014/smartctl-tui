#!/usr/bin/env python3
"""
Disk SMART Dashboard, Direct I/O Benchmark & Partition Manager for Linux  (v2)

* SMART analytics (ATA + NVMe) with a real health verdict, worst-to-best sorting.
* O_DIRECT sequential + random-4K benchmark (page cache genuinely bypassed).
* Partition manager with a staged operation queue, a real pre-flight check
  (no fake dry-run), typed confirmation, and ONE privilege prompt per batch.

All privileged work goes through a small allow-listed runner that is passed to
`python -c` via sudo -n / pkexec - nothing is written to disk, nothing is run by shell.

Resize / format / clone paths are written to spec but should be rehearsed on a
loop device before you trust them with real data (see end of file).
"""
from __future__ import annotations

import json
import mmap
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRectF
from PyQt6.QtGui import QFont, QColor, QPainter, QBrush, QPen, QFontDatabase
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem,
    QTabWidget, QLabel, QPushButton, QComboBox, QProgressBar,
    QHeaderView, QMessageBox, QFrame, QSplitter, QScrollArea,
    QMenu, QInputDialog, QDialog, QFormLayout, QDialogButtonBox,
    QPlainTextEdit, QSpinBox, QFileDialog, QAbstractItemView,
)

KIB = 1024
MIB = KIB * 1024
GIB = MIB * 1024
MIN_FREE_GAP = 8 * MIB          # smaller gaps are alignment slack, not "free space"
SBIN_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PROTECTED_MOUNTPOINTS = {"/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/etc"}
BOOT_PARTTYPES = {"c12a7328-f81f-11d2-ba4b-00a0c93ec93b",   # EFI System
                  "21686148-6449-6e6f-744e-656564454649",   # BIOS boot
                  "0xef"}                                    # MBR ESP


def ui_font(pt: int = 9, bold: bool = False) -> QFont:
    f = QFont(QApplication.font())
    f.setPointSize(pt)
    f.setBold(bold)
    return f


def mono_font() -> QFont:
    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)


def fmt_size(n: Optional[float]) -> str:
    if n is None:
        return "N/A"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return str(n)


def which(exe: str) -> Optional[str]:
    return shutil.which(exe) or shutil.which(exe, path=SBIN_PATH)


# =====================================================================
# 0. PRIVILEGE HANDLING
# =====================================================================

def privilege_prefix() -> List[str]:
    """root -> nothing; passwordless/cached sudo -> 'sudo -n' (never hangs on a
    prompt); otherwise pkexec. Re-evaluated each call because sudo creds expire."""
    if os.geteuid() == 0:
        return []
    if which("sudo"):
        try:
            r = subprocess.run(["sudo", "-n", "true"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if r.returncode == 0:
                return ["sudo", "-n"]
        except Exception:
            pass
    if which("pkexec"):
        return ["pkexec"]
    raise RuntimeError("Root access is required but neither passwordless sudo nor pkexec "
                       "(polkit) is available. Install polkit or run this app as root.")


def privileged_python_cmd(snippet: str, *args: str) -> List[str]:
    return privilege_prefix() + [sys.executable, "-c", snippet, *args]


SMART_SNIPPET = r'''
import json, os, subprocess
os.environ["PATH"] = "/usr/local/sbin:/usr/sbin:/sbin:" + os.environ.get("PATH", "")

def run(argv):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

out = {"error": "", "devices": []}
devices = []
try:
    scan = run(["smartctl", "--scan-open", "-j"])
    devices = json.loads(scan.stdout or "{}").get("devices", [])
    if not devices:
        out["error"] = "smartctl found no devices. " + (scan.stderr or "").strip()
except FileNotFoundError:
    out["error"] = "smartctl is not installed (package: smartmontools)."
except ValueError:
    out["error"] = "Could not parse smartctl scan output."

for dev in devices:
    argv = ["smartctl", "-a", "-j"]
    if dev.get("type"):
        argv += ["-d", dev["type"]]
    argv.append(dev.get("name", ""))
    p = run(argv)
    try:
        data = json.loads(p.stdout)
    except ValueError:
        data = None
    out["devices"].append({"scan": dev, "data": data, "stderr": p.stderr.strip()})
print(json.dumps(out))
'''

RUNNER_SNIPPET = r'''
import json, os, re, shutil, subprocess, sys, time

SBIN = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ALLOWED = {"umount", "swapoff", "mount", "mkdir", "parted", "udevadm", "e2fsck",
           "resize2fs", "ntfsresize", "ntfsfix", "mkswap", "wipefs", "smartctl", "lsblk"}


def emit(**kw):
    sys.stdout.write(json.dumps(kw) + "\n")
    sys.stdout.flush()


def real(p):
    try:
        return os.path.realpath(p)
    except Exception:
        return p


def unescape(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def mount_table():
    table = {}
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("/"):
                    table.setdefault(real(unescape(parts[0])), []).append(unescape(parts[1]))
    except OSError:
        pass
    return table


def active_swaps():
    out = set()
    try:
        with open("/proc/swaps") as f:
            for line in list(f)[1:]:
                parts = line.split()
                if parts:
                    out.add(real(unescape(parts[0])))
    except OSError:
        pass
    return out


def list_parts(disk):
    p = subprocess.run([shutil.which("lsblk", path=SBIN) or "lsblk", "-nrpo", "PATH,TYPE", disk],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
    found = set()
    for line in p.stdout.splitlines():
        bits = line.split()
        if len(bits) == 2 and bits[1] == "part":
            found.add(bits[0])
    return found


def settle():
    exe = shutil.which("udevadm", path=SBIN)
    if exe:
        subprocess.run([exe, "settle", "--timeout=15"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def device_size(path):
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        return f.tell()


def do_clone(src, dst, oi):
    total = device_size(src)
    if device_size(dst) < total:
        return False, "Target is smaller than the source - refusing to clone."
    done = 0
    last = 0.0
    with open(src, "rb", buffering=0) as s, open(dst, "r+b", buffering=0) as d:
        while True:
            chunk = s.read(4 * 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                n = d.write(view)
                view = view[n:]
            done += len(chunk)
            now = time.time()
            if now - last > 0.4:
                emit(event="progress", op=oi, done=done, total=total)
                last = now
        d.flush()
        os.fsync(d.fileno())
    emit(event="progress", op=oi, done=total, total=total)
    settle()
    return True, ""


def run_step(step, ctx, oi):
    builtin = step.get("builtin")
    label = step.get("label") or builtin or " ".join(step.get("argv", []))
    try:
        if builtin == "assert_unmounted":
            path = step["path"]
            where = mount_table().get(real(path), [])
            if where or real(path) in active_swaps():
                return False, "%s is still in use (%s)." % (path, ", ".join(where) or "active swap")
            return True, ""
        if builtin == "remember_mount":
            where = mount_table().get(real(step["path"]), [])
            ctx["remembered"][step["path"]] = where[0] if where else None
            return True, ""
        if builtin == "restore_mount":
            mp = ctx["remembered"].get(step["path"])
            if mp:
                p = subprocess.run([shutil.which("mount", path=SBIN) or "mount", step["path"], mp],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                emit(event="step", op=oi, label="Remount %s on %s" % (step["path"], mp),
                     rc=p.returncode, out=(p.stdout or "")[-2000:])
            return True, ""
        if builtin == "clone":
            ok, err = do_clone(step["src"], step["dst"], oi)
            if ok:
                emit(event="step", op=oi, label=label, rc=0, out="")
            return ok, err

        argv = [ctx["new_part"] if a == "{NEW_PART}" else a for a in step["argv"]]
        if None in argv:
            return False, "Internal error: new partition path unknown."
        if step.get("only_if_mounted") and real(step["only_if_mounted"]) not in mount_table():
            return True, ""
        name = os.path.basename(argv[0])
        if not (name in ALLOWED or name.startswith("mkfs.") or name.startswith("fsck.")):
            return False, "Refusing to run a program that is not on the allow-list: %s" % argv[0]
        exe = shutil.which(argv[0], path=SBIN)
        if not exe:
            return False, "Required tool not found: %s" % argv[0]
        disk = step.get("capture_disk")
        before = list_parts(disk) if disk else None
        p = subprocess.run([exe] + argv[1:], input=step.get("stdin"), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True)
        out = (p.stdout or "")[-4000:]
        emit(event="step", op=oi, label=label, rc=p.returncode, out=out)
        if not (step.get("any_rc") or step.get("ignore_fail") or p.returncode in step.get("ok_codes", [0])):
            return False, "%s failed (exit %d): %s" % (label, p.returncode, out.strip()[-600:])
        if disk:
            settle()
            new = set()
            for _ in range(20):
                new = list_parts(disk) - before
                if new:
                    break
                time.sleep(0.5)
            if len(new) != 1:
                return False, "Could not identify the newly created partition."
            ctx["new_part"] = new.pop()
        return True, ""
    except Exception as exc:
        return False, "%s: %s" % (label, exc)


def main():
    spec = json.loads(sys.argv[1])
    for oi, op in enumerate(spec["ops"]):
        emit(event="op_start", op=oi, description=op.get("description", ""))
        ctx = {"remembered": {}, "new_part": None}
        ok, err = True, ""
        for step in op["steps"]:
            ok, err = run_step(step, ctx, oi)
            if not ok:
                break
        emit(event="op_done", op=oi, ok=ok, error=err)
        if not ok:
            sys.exit(1)
    emit(event="all_done")


main()
'''


# =====================================================================
# 1. SMART ANALYTICS
# =====================================================================

CRITICAL_HARDWARE_IDS = {5, 187, 196, 197, 198}
INTERFACE_ERROR_IDS = {188, 199}
INTERFACE_RAW_FLAG_IDS = {199}               # 188's raw is a vendor composite; don't flag on it
LIFE_REMAINING_IDS = {169, 177, 202, 231, 232, 233}   # normalised value == % life left
TEMPERATURE_IDS = {190, 194}
VENDOR_SCALED_IDS = {1, 7, 195}              # log-scaled / vendor-encoded; informational only
CRITICAL_RAW_PENALTY = 15

DEJARGONED_DESCRIPTIONS = {
    "01": "Read Error Rate (vendor-scaled, informational)",
    "05": "Physical Storage Blocks (Reallocated Sectors Surface Health)",
    "07": "Seek Error Rate (vendor-scaled, informational)",
    "09": "Operational Lifespan Accumulation (Total Power-On Hours)",
    "12": "Hardware Power Interventions (Total Drive Boot Cycles)",
    "177": "SSD Wear-Leveling Life Remaining",
    "187": "Data Read Consistency (Uncorrectable Sector Verification Failures)",
    "188": "Controller Instruction Integrity (Command Processing Timeouts)",
    "190": "Airflow Temperature",
    "194": "Thermal Enclosure Regulation (Internal Core Drive Temperature)",
    "196": "Emergency Storage Re-routing (Sector Reallocation Event Records)",
    "197": "Unstable Storage Sectors (Current Pending Bad Block Remap Queue)",
    "198": "Damaged Media Boundaries (Uncorrectable Platter Sector Counts)",
    "199": "SATA Motherboard Interface Pipeline (Data Transmission CRC Errors)",
    "231": "SSD Life Left",
    "232": "Available Reserved Space (SSD spare blocks)",
    "233": "Media Wear-Out Indicator",
    "241": "Total Data Written (LBAs)",
    "242": "Total Data Read (LBAs)",
    "NVMe": "Solid-State Silicon Drive Wear-Leveling Lifespan Remaining",
}

FRIENDLY_STATUS = {
    "FAILING": "DANGER: Active hardware degradation detected",
    "WARNING": "WEAR: Early warning signs or wear threshold reached",
    "INTERFACE ERR": "CABLE NOISE: Glitches from hotplugging or faulty cable",
    "HEALTHY": "PERFECT: Parameter operating within safe limits",
    "INFO": "INFO: Informational counter, not used for the verdict",
}
STATUS_ICONS = {"FAILING": "🔴", "WARNING": "🟡", "INTERFACE ERR": "🔀", "HEALTHY": "🟢", "INFO": "⚪"}
OVERALL_ICONS = {"CRITICAL": "🔴", "WARNING": "🟡", "UNKNOWN": "⚪", "INTF_WARN": "🟡", "HEALTHY": "🟢"}
OVERALL_PRIORITY = {"CRITICAL": 0, "WARNING": 1, "UNKNOWN": 2, "INTF_WARN": 3, "HEALTHY": 4}


def make_metric(jargon_id, jargon_name, clean_name, status, margin, current, thresh, raw,
                intf=False, critical=False) -> Dict[str, Any]:
    if status == "FAILING":
        score = -1.0 + (margin or 0.0) / 1000.0
    elif margin is None:
        score = 300.0
    else:
        score = margin + (0 if (critical or intf) else 100)
    return {
        "jargon_id": jargon_id, "jargon_name": jargon_name, "clean_name": clean_name,
        "status": status, "icon": STATUS_ICONS[status],
        "friendly_status": FRIENDLY_STATUS.get(status, status),
        "margin": "n/a" if margin is None else f"{margin:.1f}%", "margin_val": margin,
        "current": str(current), "thresh": str(thresh), "raw": str(raw),
        "_intf": intf, "_critical": critical, "_score": score,
    }


def score_ata_attribute(attr: Dict[str, Any]) -> Dict[str, Any]:
    aid = attr["id"]
    cur = attr.get("value", 0)
    worst = attr.get("worst", cur)
    thresh = attr.get("thresh", 0)
    raw = attr.get("raw", {})
    raw_val = raw.get("value", 0) or 0
    raw_str = raw.get("string", str(raw_val))
    when_failed = (attr.get("when_failed") or "").lower()
    is_critical = aid in CRITICAL_HARDWARE_IDS
    is_intf = aid in INTERFACE_ERROR_IDS

    margin: Optional[float] = None
    if aid in LIFE_REMAINING_IDS:
        margin = float(max(0, min(100, cur)))
    elif aid in TEMPERATURE_IDS or aid in VENDOR_SCALED_IDS:
        margin = None
    elif is_critical or is_intf or thresh > 0:
        # Distance to threshold relative to the best value this drive has ever shown.
        # (The old baseline jumped 100% -> 49% between value 100 and 101.)
        ref = max(100, worst, cur)
        denom = ref - thresh
        margin = 100.0 if denom <= 0 else (cur - thresh) / denom * 100.0
        margin = max(0.0, min(100.0, margin))
        if is_critical and raw_val > 0:
            margin = max(0.0, margin - raw_val * CRITICAL_RAW_PENALTY)

    if aid in TEMPERATURE_IDS:
        status = "WARNING" if (raw_val & 0xFF) >= 60 else "INFO"
    elif aid in LIFE_REMAINING_IDS:
        status = "FAILING" if margin <= 5 else "WARNING" if margin < 20 else "HEALTHY"
    elif margin is None:
        status = "FAILING" if (thresh > 0 and cur <= thresh) else "INFO"
    elif margin <= 0 or (thresh > 0 and cur <= thresh):
        status = "FAILING"
    elif margin < 40 or (is_critical and raw_val > 0):
        status = "WARNING"
    else:
        status = "HEALTHY"

    if when_failed == "now":
        status = "FAILING"
    elif when_failed == "past" and status in ("HEALTHY", "INFO"):
        status = "WARNING"

    if is_intf:
        if status == "FAILING" or status == "WARNING" or (aid in INTERFACE_RAW_FLAG_IDS and raw_val > 0):
            status = "INTERFACE ERR"

    str_id = f"{aid:02d}"
    return make_metric(str_id, attr.get("name", str_id), DEJARGONED_DESCRIPTIONS.get(str_id, attr.get("name", str_id)),
                       status, margin, cur, thresh, raw_str, intf=is_intf, critical=is_critical)


def analyze_nvme(log: Dict[str, Any]) -> List[Dict[str, Any]]:
    m: List[Dict[str, Any]] = []
    used = log.get("percentage_used", 0) or 0
    life = max(0.0, 100.0 - used)
    st = "HEALTHY" if life > 20 else "WARNING" if life > 5 else "FAILING"
    m.append(make_metric("NVMe", "percentage_used", DEJARGONED_DESCRIPTIONS["NVMe"], st, life,
                         100 - used, 0, f"{used}% used", critical=True))
    spare, sth = log.get("available_spare"), log.get("available_spare_threshold")
    if spare is not None:
        if sth is not None and spare <= sth:
            st = "FAILING"
        elif (sth is not None and spare <= sth + 10) or spare < 20:
            st = "WARNING"
        else:
            st = "HEALTHY"
        m.append(make_metric("SPARE", "available_spare", "Spare Blocks Remaining", st, float(spare),
                             spare, sth if sth is not None else "-", f"{spare}% (threshold {sth}%)", critical=True))
    cw = log.get("critical_warning", 0) or 0
    m.append(make_metric("CRIT", "critical_warning", "Controller Critical-Warning Flags",
                         "FAILING" if cw else "HEALTHY", 0.0 if cw else 100.0, cw, 0,
                         f"0x{cw:02x}" if cw else "none", critical=True))
    me = log.get("media_errors", 0) or 0
    m.append(make_metric("MEDIA", "media_errors", "Media / Data-Integrity Errors",
                         "WARNING" if me else "HEALTHY", 50.0 if me else 100.0, me, 0, str(me), critical=True))
    temp = log.get("temperature")
    if temp is not None:
        m.append(make_metric("TEMP", "temperature", "Composite Temperature (°C)",
                             "WARNING" if temp >= 70 else "INFO", None, temp, "-", f"{temp} °C"))
    if "power_on_hours" in log:
        m.append(make_metric("POH", "power_on_hours", "Total Power-On Hours", "INFO", None,
                             log["power_on_hours"], "-", f"{log['power_on_hours']:,} h"))
    if "data_units_written" in log:
        tb = log["data_units_written"] * 512000 / 1e12
        m.append(make_metric("WRITTEN", "data_units_written", "Total Data Written", "INFO", None,
                             log["data_units_written"], "-", f"{tb:.2f} TB"))
    if "unsafe_shutdowns" in log:
        m.append(make_metric("UNSAFE", "unsafe_shutdowns", "Unsafe Power-Offs", "INFO", None,
                             log["unsafe_shutdowns"], "-", str(log["unsafe_shutdowns"])))
    return m


def analyze_smart_json(dev_path: str, scan: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
    metrics: List[Dict[str, Any]] = []
    if "ata_smart_attributes" in d:
        metrics = [score_ata_attribute(a) for a in d["ata_smart_attributes"].get("table", [])]
    elif "nvme_smart_health_information_log" in d:
        metrics = analyze_nvme(d["nvme_smart_health_information_log"])

    passed = (d.get("smart_status") or {}).get("passed")
    critical_failure = any(x["status"] == "FAILING" and not x["_intf"] for x in metrics)
    has_warning = any(x["status"] == "WARNING" for x in metrics)
    has_intf = any(x["status"] == "INTERFACE ERR" for x in metrics)
    margins = [x["margin_val"] for x in metrics if x["margin_val"] is not None and not x["_intf"]]
    worst = min(margins) if margins else 100.0

    if not metrics and passed is None:
        overall = "UNKNOWN"          # never show green for a drive we couldn't read
    elif passed is False or critical_failure or worst == 0:
        overall = "CRITICAL"
    elif has_warning or worst < 50:
        overall = "WARNING"
    elif has_intf:
        overall = "INTF_WARN"
    else:
        overall = "HEALTHY"

    metrics.sort(key=lambda x: x["_score"])
    rot = d.get("rotation_rate")
    proto = (d.get("device") or {}).get("protocol", "")
    kind = "NVMe SSD" if proto.lower() == "nvme" else ("SSD" if rot == 0 else f"HDD {rot} rpm" if rot else "drive")
    tests = ((d.get("ata_smart_self_test_log") or {}).get("standard") or {}).get("table") or []
    last_test = "none logged"
    if tests:
        t = tests[0]
        last_test = f"{(t.get('type') or {}).get('string', 'test')}: {(t.get('status') or {}).get('string', '?')} @ {t.get('lifetime_hours', '?')} h"

    return {
        "path": dev_path,
        "dev_type": scan.get("type") or (d.get("device") or {}).get("type"),
        "model": d.get("model_name") or scan.get("info_name") or "Unknown Drive",
        "serial": d.get("serial_number", "N/A"),
        "firmware": d.get("firmware_version", "?"),
        "capacity": (d.get("user_capacity") or {}).get("bytes"),
        "kind": kind,
        "temperature": (d.get("temperature") or {}).get("current"),
        "power_on_hours": (d.get("power_on_time") or {}).get("hours"),
        "smart_passed": passed,
        "last_selftest": last_test,
        "status": overall, "icon": OVERALL_ICONS[overall], "metrics": metrics,
        "sort_key": (OVERALL_PRIORITY[overall], worst),
    }


def unreadable_drive(path: str, scan: Dict[str, Any], why: str) -> Dict[str, Any]:
    return {"path": path, "dev_type": scan.get("type"), "model": scan.get("info_name") or "Unreadable",
            "serial": "N/A", "firmware": "?", "capacity": None, "kind": "drive", "temperature": None,
            "power_on_hours": None, "smart_passed": None, "last_selftest": why or "no data",
            "status": "UNKNOWN", "icon": "⚪", "metrics": [], "sort_key": (2, 0.0)}


def analyze_system_drives() -> Tuple[List[Dict[str, Any]], str]:
    try:
        cmd = privileged_python_cmd(SMART_SNIPPET)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                           stdin=subprocess.DEVNULL, timeout=300)
    except Exception as e:
        return [], str(e)
    lines = [l for l in p.stdout.strip().splitlines() if l.strip()]
    if not lines:
        if p.returncode in (126, 127):
            return [], "Authentication was cancelled or denied."
        return [], (p.stderr.strip() or "No output from privileged SMART scan.")[:500]
    try:
        raw = json.loads(lines[-1])
    except ValueError:
        return [], ("Unexpected output: " + p.stdout + p.stderr)[:500]
    drives = []
    for entry in raw.get("devices", []):
        scan = entry.get("scan") or {}
        path = scan.get("name") or "?"
        if entry.get("data"):
            drives.append(analyze_smart_json(path, scan, entry["data"]))
        else:
            drives.append(unreadable_drive(path, scan, entry.get("stderr", "")))
    return sorted(drives, key=lambda x: x["sort_key"]), raw.get("error", "")


def drive_report_text(drive: Dict[str, Any]) -> str:
    lines = [f"Drive:        {drive['path']}  ({drive['kind']})",
             f"Model/Serial: {drive['model']} / {drive['serial']}  FW {drive['firmware']}",
             f"Capacity:     {fmt_size(drive['capacity'])}",
             f"Verdict:      {drive['status']}   (SMART self-assessment passed: {drive['smart_passed']})",
             f"Temperature:  {drive['temperature']} C   Power-on: {drive['power_on_hours']} h",
             f"Last test:    {drive['last_selftest']}", "",
             f"{'ID':<7}{'STATUS':<15}{'MARGIN':<9}{'CUR/THR':<10}{'RAW':<28}NAME"]
    for m in drive["metrics"]:
        lines.append(f"{m['jargon_id']:<7}{m['status']:<15}{m['margin']:<9}{m['current'] + '/' + m['thresh']:<10}"
                     f"{m['raw'][:26]:<28}{m['clean_name']}")
    return "\n".join(lines)


# =====================================================================
# 2. BLOCK DEVICES, LAYOUT, MOUNTS, SAFETY
# =====================================================================

LSBLK_TIERS = [
    "NAME,PATH,TYPE,FSTYPE,SIZE,FSAVAIL,FSUSED,MOUNTPOINT,MODEL,UUID,PTTYPE,PARTTYPE,PKNAME,LABEL",
    "NAME,PATH,TYPE,FSTYPE,SIZE,FSAVAIL,MOUNTPOINT,MODEL,UUID,PTTYPE,PARTTYPE,PKNAME,LABEL",
    "NAME,PATH,TYPE,FSTYPE,SIZE,MOUNTPOINT,MODEL,UUID",
]


def _normalize(dev: Dict[str, Any]) -> Dict[str, Any]:
    for k in ("size", "fsavail", "fsused"):
        v = dev.get(k)
        try:
            dev[k] = int(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            dev[k] = None
    if dev.get("fsused") is None and dev.get("size") and dev.get("fsavail") is not None:
        dev["fsused"] = max(0, dev["size"] - dev["fsavail"])
    dev["model"] = (dev.get("model") or "").strip()          # lsblk emits null, not ""
    dev["path"] = dev.get("path") or f"/dev/{dev.get('name', '')}"
    dev["fstype"] = dev.get("fstype") or ""
    dev["children"] = [_normalize(c) for c in (dev.get("children") or [])]
    return dev


def get_block_devices() -> List[Dict[str, Any]]:
    for cols in LSBLK_TIERS:       # older util-linux rejects unknown columns -> fall back
        try:
            res = subprocess.run(["lsblk", "-J", "-b", "-o", cols], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, check=True)
            return [_normalize(d) for d in json.loads(res.stdout).get("blockdevices", [])]
        except Exception:
            continue
    return []


def index_devices(devs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}

    def walk(dev, parent, disk):
        dev["_parent"] = parent["path"] if parent else None
        dev["_disk"] = disk or dev["path"]
        idx[dev["path"]] = dev
        for ch in dev["children"]:
            walk(ch, dev, disk or dev["path"])
    for d in devs:
        walk(d, None, None)
    return idx


def _sysfs_int(path: str) -> Optional[int]:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def part_geometry(name: str) -> Optional[Tuple[int, int]]:
    base = f"/sys/class/block/{name}"
    s, z = _sysfs_int(base + "/start"), _sysfs_int(base + "/size")
    return None if s is None or z is None else (s * 512, z * 512)


def partition_number(name: str) -> Optional[int]:
    return _sysfs_int(f"/sys/class/block/{name}/partition")


def whole_disk_in_use(disk: Dict[str, Any]) -> bool:
    return not disk.get("pttype") and bool(disk.get("fstype") or disk["children"])


def compute_layout(disk: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Ordered partitions plus real unallocated gaps, from sysfs start/size."""
    if whole_disk_in_use(disk):
        return []
    segs = []
    for ch in disk["children"]:
        if ch.get("type") != "part":
            continue
        geo = part_geometry(ch["name"])
        if geo:
            segs.append({"kind": "part", "start": geo[0], "size": geo[1], "dev": ch})
    segs.sort(key=lambda s: s["start"])
    out: List[Dict[str, Any]] = []
    cursor = MIB
    limit = (disk.get("size") or 0) - MIB
    for s in segs:
        if s["start"] - cursor >= MIN_FREE_GAP:
            out.append({"kind": "free", "start": cursor, "size": s["start"] - cursor})
        out.append(s)
        cursor = max(cursor, s["start"] + s["size"])
    if limit - cursor >= MIN_FREE_GAP:
        out.append({"kind": "free", "start": cursor, "size": limit - cursor})
    return out


def _unescape_mount(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def read_mount_table() -> List[Dict[str, str]]:
    rows = []
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[0].startswith("/"):
                    rows.append({"source": _unescape_mount(p[0]), "mountpoint": _unescape_mount(p[1]), "fstype": p[2]})
    except OSError:
        pass
    return rows


def read_mounts() -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for r in read_mount_table():
        out.setdefault(os.path.realpath(r["source"]), []).append(r["mountpoint"])
    try:
        with open("/proc/swaps") as f:
            for line in list(f)[1:]:
                p = line.split()
                if p:
                    out.setdefault(os.path.realpath(_unescape_mount(p[0])), []).append("[SWAP]")
    except OSError:
        pass
    return out


def compute_system_paths(idx: Dict[str, Dict[str, Any]]) -> Tuple[Set[str], Set[str]]:
    """Devices that back /, /boot, ... (including LVM/LUKS parents) plus ESP/BIOS-boot
    partitions on those disks. Returns (protected realpaths, system disk paths)."""
    real_idx = {os.path.realpath(p): d for p, d in idx.items()}
    protected: Set[str] = set()
    for r in read_mount_table():
        if r["mountpoint"] in PROTECTED_MOUNTPOINTS:
            dev = real_idx.get(os.path.realpath(r["source"]))
            while dev:
                protected.add(os.path.realpath(dev["path"]))
                dev = idx.get(dev["_parent"]) if dev.get("_parent") else None
    sys_disks = {d["path"] for d in idx.values() if d.get("type") == "disk" and os.path.realpath(d["path"]) in protected}
    for d in idx.values():
        if d.get("type") == "part" and d["_disk"] in sys_disks and (d.get("parttype") or "").lower() in BOOT_PARTTYPES:
            protected.add(os.path.realpath(d["path"]))
    return protected, sys_disks


# =====================================================================
# 3. OPERATION BUILDERS + PRE-FLIGHT
# =====================================================================

FS_CHOICES = ["ext4", "btrfs", "xfs", "ntfs", "vfat", "exfat", "swap"]
PARTED_FS = {"ext4": "ext4", "btrfs": "btrfs", "xfs": "xfs", "ntfs": "ntfs",
             "vfat": "fat32", "exfat": "ntfs", "swap": "linux-swap"}
TOOL_HINTS = {"parted": "parted", "wipefs": "util-linux", "mkswap": "util-linux", "mkfs.ext4": "e2fsprogs",
              "e2fsck": "e2fsprogs", "resize2fs": "e2fsprogs", "mkfs.ntfs": "ntfs-3g", "ntfsresize": "ntfs-3g",
              "ntfsfix": "ntfs-3g", "mkfs.vfat": "dosfstools", "mkfs.xfs": "xfsprogs",
              "mkfs.btrfs": "btrfs-progs", "mkfs.exfat": "exfatprogs", "smartctl": "smartmontools"}


def mkfs_argv(fstype: str, dev: str) -> List[str]:
    return {"ext4": ["mkfs.ext4", "-F", dev], "btrfs": ["mkfs.btrfs", "-f", dev],
            "xfs": ["mkfs.xfs", "-f", dev], "ntfs": ["mkfs.ntfs", "-f", dev],
            "vfat": ["mkfs.vfat", "-F", "32", dev], "exfat": ["mkfs.exfat", dev],
            "swap": ["mkswap", dev]}[fstype]


def _settle_step() -> Dict[str, Any]:
    return {"label": "Wait for udev", "argv": ["udevadm", "settle"], "ignore_fail": True}


def build_delete_op(dev: Dict[str, Any]) -> Dict[str, Any]:
    path, num = dev["path"], partition_number(dev["name"])
    if num is None:
        raise ValueError(f"Cannot determine the partition number of {path}.")
    disk = dev["_disk"]
    steps: List[Dict[str, Any]] = [
        {"label": f"Unmount {path}", "argv": ["umount", path], "only_if_mounted": path}]
    if dev.get("fstype") == "swap":
        steps.append({"label": f"swapoff {path}", "argv": ["swapoff", path], "ignore_fail": True})
    steps += [{"builtin": "assert_unmounted", "path": path},
              {"label": f"Delete partition {num} on {disk}", "argv": ["parted", "-s", disk, "rm", str(num)]},
              _settle_step()]
    return {"type": "DELETE", "description": f"Delete partition {path}", "device": path, "disk": disk,
            "targets": [path], "sources": [], "destructive": True, "steps": steps}


def build_create_op(disk: Dict[str, Any], seg: Dict[str, Any], size_mb: int, fstype: str) -> Dict[str, Any]:
    start_b = -(-seg["start"] // MIB) * MIB
    end_limit = ((seg["start"] + seg["size"]) // MIB) * MIB
    end_b = min(start_b + size_mb * MIB, end_limit)
    if end_b - start_b < MIB:
        raise ValueError("Selected region is too small.")
    dpath, pttype = disk["path"], disk.get("pttype") or ""
    needs_label = not pttype
    token = "primary" if pttype == "dos" else "data"
    steps: List[Dict[str, Any]] = []
    if needs_label:
        steps.append({"label": f"Write new GPT table on {dpath}", "argv": ["parted", "-s", dpath, "mklabel", "gpt"]})
        token = "data"
    steps += [
        {"label": f"Create partition on {dpath}",
         "argv": ["parted", "-s", "-a", "optimal", dpath, "mkpart", token, PARTED_FS[fstype],
                  f"{start_b // MIB}MiB", f"{end_b // MIB}MiB"], "capture_disk": dpath},
        {"label": "Wipe stale signatures", "argv": ["wipefs", "-a", "{NEW_PART}"]},
        {"label": f"Format new partition as {fstype}", "argv": mkfs_argv(fstype, "{NEW_PART}")},
    ]
    return {"type": "CREATE", "description": f"Create {(end_b - start_b) // MIB} MiB ({fstype}) partition on {dpath}",
            "disk": dpath, "start_b": start_b, "end_b": end_b, "fstype": fstype, "needs_label": needs_label,
            "targets": [], "sources": [], "destructive": True, "steps": steps}


def build_resize_op(dev: Dict[str, Any], seg: Dict[str, Any], new_mb: int) -> Dict[str, Any]:
    path, fs, disk = dev["path"], dev["fstype"], dev["_disk"]
    num = partition_number(dev["name"])
    if num is None:
        raise ValueError(f"Cannot determine the partition number of {path}.")
    cur_mb = seg["size"] // MIB
    new_bytes = new_mb * MIB
    end_sector = (seg["start"] + new_bytes) // 512 - 1          # inclusive last sector
    grow = new_mb > cur_mb
    resizepart = {"label": f"Resize partition {num} to {new_mb} MiB",
                  "argv": ["parted", "-s", disk, "resizepart", str(num), f"{end_sector}s"], "stdin": "Yes\n"}
    steps: List[Dict[str, Any]] = [
        {"label": f"Unmount {path}", "argv": ["umount", path], "only_if_mounted": path},
        {"builtin": "assert_unmounted", "path": path}]
    if fs in ("ext2", "ext3", "ext4"):
        fsck = {"label": "Check filesystem (required before resize)", "argv": ["e2fsck", "-f", "-p", path], "ok_codes": [0, 1]}
        if grow:
            steps += [resizepart, fsck, {"label": "Grow filesystem", "argv": ["resize2fs", path]}]
        else:
            steps += [fsck, {"label": f"Shrink filesystem to {new_mb} MiB", "argv": ["resize2fs", path, f"{new_mb}M"]}, resizepart]
    elif fs == "ntfs":
        if grow:
            steps += [resizepart, {"label": "Grow NTFS", "argv": ["ntfsresize", "-f", "-P", path], "stdin": "y\n"}]
        else:
            steps += [{"label": f"Shrink NTFS to {new_mb} MiB", "argv": ["ntfsresize", "-f", "-P", "-s", str(new_bytes), path], "stdin": "y\n"}, resizepart]
    else:
        raise ValueError(f"Resizing '{fs or 'unknown'}' filesystems is not supported (ext2/3/4 and NTFS only).")
    steps.append(_settle_step())
    return {"type": "RESIZE", "description": f"Resize {path} ({fs}) {cur_mb} -> {new_mb} MiB", "device": path,
            "disk": disk, "new_mb": new_mb, "cur_mb": cur_mb, "fstype": fs,
            "targets": [path], "sources": [], "destructive": True, "steps": steps}


def build_clone_op(src: str, dst: str) -> Dict[str, Any]:
    steps = [{"label": f"Unmount {p}", "argv": ["umount", p], "only_if_mounted": p} for p in (src, dst)]
    steps += [{"builtin": "assert_unmounted", "path": src}, {"builtin": "assert_unmounted", "path": dst},
              {"builtin": "clone", "src": src, "dst": dst, "label": f"Block-copy {src} -> {dst}"}, _settle_step()]
    return {"type": "CLONE", "description": f"Clone {src} -> {dst} (overwrites target)", "src": src, "dst": dst,
            "targets": [dst], "sources": [src], "destructive": True, "steps": steps}


def build_mount_op(path: str, target: str) -> Dict[str, Any]:
    return {"type": "MOUNT", "description": f"Mount {path} on {target}", "targets": [], "sources": [path],
            "destructive": False, "steps": [{"label": f"Create {target}", "argv": ["mkdir", "-p", target]},
                                           {"label": f"Mount {path}", "argv": ["mount", path, target]}]}


def build_check_op(dev: Dict[str, Any], repair: bool) -> Dict[str, Any]:
    path, fs = dev["path"], dev["fstype"]
    if fs == "ntfs":
        check = {"label": "ntfsfix (no-action check)", "argv": ["ntfsfix", "-n", path], "any_rc": True}
    elif fs in ("ext2", "ext3", "ext4"):
        argv = ["e2fsck", "-f", "-y" if repair else "-n", path]
        check = {"label": "e2fsck " + ("repair" if repair else "read-only check"), "argv": argv,
                 "ok_codes": [0, 1, 2] if repair else [0], "any_rc": not repair}
    else:
        raise ValueError(f"No checker wired up for '{fs}'.")
    steps = [{"builtin": "remember_mount", "path": path},
             {"label": f"Unmount {path}", "argv": ["umount", path], "only_if_mounted": path},
             {"builtin": "assert_unmounted", "path": path}, check,
             {"builtin": "restore_mount", "path": path}]
    return {"type": "CHECK", "description": f"Check {path} ({fs})", "targets": [path], "sources": [],
            "destructive": repair, "steps": steps}


def build_selftest_op(drive: Dict[str, Any]) -> Dict[str, Any]:
    argv = ["smartctl", "-t", "short"] + (["-d", drive["dev_type"]] if drive.get("dev_type") else []) + [drive["path"]]
    return {"type": "SELFTEST", "description": f"Start SMART short self-test on {drive['path']}",
            "targets": [], "sources": [], "destructive": False,
            "steps": [{"label": "smartctl -t short", "argv": argv, "any_rc": True}]}


def describe_steps(op: Dict[str, Any]) -> List[str]:
    out = []
    for s in op["steps"]:
        b = s.get("builtin")
        if b == "clone":
            out.append(f"[builtin] block-copy {s['src']} -> {s['dst']} (4 MiB chunks, fsync)")
        elif b:
            out.append(f"[builtin] {b} {s.get('path', '')}")
        else:
            out.append(("(if mounted) " if s.get("only_if_mounted") else "") + shlex.join(s["argv"]))
    return out


def preflight(ops: List[Dict[str, Any]], idx: Dict[str, Dict[str, Any]], protected: Set[str]) -> List[Tuple[str, str]]:
    """Real checks against the live system. Returns [(level, message)], level in ok/warn/error."""
    issues: List[Tuple[str, str]] = []
    mounts = read_mounts()
    removed: Set[str] = set()
    claims: Dict[str, List[Tuple[int, int]]] = {}

    def add(level, msg):
        issues.append((level, msg))

    for n, op in enumerate(ops, 1):
        tag = f"[{n}] {op['description']}"
        errors_before = sum(1 for l, _ in issues if l == "error")
        for p in op.get("targets", []) + op.get("sources", []):
            if not os.path.exists(p):
                add("error", f"{tag}: {p} does not exist.")
            elif p in removed:
                add("error", f"{tag}: {p} is removed by an earlier queued operation.")
        for p in op.get("targets", []):
            rp = os.path.realpath(p)
            if rp in protected:
                add("error", f"{tag}: {p} backs the running system (root/boot/ESP) - blocked. Use live media.")
            elif mounts.get(rp):
                add("warn", f"{tag}: {p} is mounted at {', '.join(mounts[rp])}; it will be unmounted first.")
        if op["type"] == "CLONE":
            src, dst = op["src"], op["dst"]
            if os.path.realpath(src) == os.path.realpath(dst):
                add("error", f"{tag}: source and target are the same device.")
            if os.path.realpath(src) in protected:
                add("error", f"{tag}: cloning the live system partition would give an inconsistent copy.")
            s, d = idx.get(src), idx.get(dst)
            if s and d and s.get("size") and d.get("size") and d["size"] < s["size"]:
                add("error", f"{tag}: target ({fmt_size(d['size'])}) is smaller than source ({fmt_size(s['size'])}).")
            if d and d.get("fstype"):
                add("warn", f"{tag}: existing {d['fstype']} filesystem on the target will be destroyed.")
            add("warn", f"{tag}: the clone keeps the source UUID/label - never leave both mounted/listed in fstab.")
        elif op["type"] == "DELETE":
            d = idx.get(op["device"])
            if d and d["children"]:
                add("error", f"{tag}: partition has active children (LVM/LUKS/RAID) - tear those down first.")
            if d and d.get("fstype") in ("LVM2_member", "crypto_LUKS", "linux_raid_member"):
                add("warn", f"{tag}: partition is a {d['fstype']} member.")
        elif op["type"] == "CREATE":
            disk = idx.get(op["disk"])
            if not disk:
                add("error", f"{tag}: disk not found.")
            else:
                if whole_disk_in_use(disk):
                    add("error", f"{tag}: disk holds a filesystem/volume directly with no partition table.")
                fits = any(s["kind"] == "free" and s["start"] <= op["start_b"] and op["end_b"] <= s["start"] + s["size"]
                           for s in compute_layout(disk))
                if not fits:
                    add("error", f"{tag}: region is no longer free on {op['disk']}.")
                for a, b in claims.get(op["disk"], []):
                    if op["start_b"] < b and a < op["end_b"]:
                        add("error", f"{tag}: overlaps another queued partition.")
                claims.setdefault(op["disk"], []).append((op["start_b"], op["end_b"]))
                nparts = sum(1 for c in disk["children"] if c.get("type") == "part") + len(claims[op["disk"]]) - 1
                if disk.get("pttype") == "dos" and nparts >= 4:
                    add("error", f"{tag}: MBR disks allow only 4 primary partitions.")
                if op["needs_label"]:
                    add("warn", f"{tag}: the disk has no partition table - a new GPT will be written.")
                if op["fstype"] == "vfat" and op["end_b"] - op["start_b"] < 64 * MIB:
                    add("warn", f"{tag}: FAT32 needs roughly >= 36 MiB; mkfs may refuse.")
                if op["disk"] in {d["path"] for d in idx.values() if os.path.realpath(d["path"]) in protected}:
                    add("warn", f"{tag}: this is a system disk (existing partitions are untouched).")
        elif op["type"] == "RESIZE":
            d = idx.get(op["device"])
            if d and d.get("fsused") and op["new_mb"] * MIB < d["fsused"] * 1.05:
                add("error", f"{tag}: new size is below the data currently in use ({fmt_size(d['fsused'])}).")
            if op["new_mb"] < op["cur_mb"]:
                add("warn", f"{tag}: shrinking is the riskiest operation here - have a backup.")
        elif op["type"] == "MOUNT":
            rp = os.path.realpath(op["sources"][0])
            if mounts.get(rp):
                add("error", f"{tag}: already mounted at {', '.join(mounts[rp])}.")

        for s in op["steps"]:
            if s.get("argv"):
                exe = s["argv"][0]
                if not which(exe):
                    add("error", f"{tag}: required tool '{exe}' not found (package: {TOOL_HINTS.get(exe, exe)}).")
        if sum(1 for l, _ in issues if l == "error") == errors_before:
            add("ok", f"{tag}: checks passed.")
        if op["type"] == "DELETE":
            removed.add(op["device"])
    return issues


def format_preflight(ops: List[Dict[str, Any]], issues: List[Tuple[str, str]]) -> str:
    mark = {"ok": "✔", "warn": "⚠", "error": "✖"}
    out = ["PRE-FLIGHT CHECK (real checks: devices, mounts, protected system paths, tools, free space, overlaps)", ""]
    out += [f"{mark[l]} {m}" for l, m in issues]
    out += ["", "PLANNED STEPS (executed in order, stop at first failure):"]
    for n, op in enumerate(ops, 1):
        out.append(f"\n[{n}] {op['description']}")
        out += [f"      {line}" for line in describe_steps(op)]
    out += ["", "Note: partitioning tools have no true dry-run mode; this validates preconditions, it cannot",
            "predict a tool failing midway."]
    return "\n".join(out)


# =====================================================================
# 4. WORKERS
# =====================================================================

class DriveScanWorker(QThread):
    scanned = pyqtSignal(list, str)

    def run(self):
        drives, err = analyze_system_drives()
        self.scanned.emit(drives, err)


class RootOpsWorker(QThread):
    """Runs a batch of ops through the allow-listed runner with a single auth prompt."""
    op_started = pyqtSignal(int, str)
    progress = pyqtSignal(int, int)
    completed = pyqtSignal(list, bool, str)      # done op indices, all ok, log text

    def __init__(self, ops: List[Dict[str, Any]]):
        super().__init__()
        self.ops = ops

    def run(self):
        spec = json.dumps({"ops": [{"description": o["description"], "steps": o["steps"]} for o in self.ops]})
        try:
            cmd = privileged_python_cmd(RUNNER_SNIPPET, spec)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, text=True)
        except Exception as e:
            self.completed.emit([], False, f"Could not start privileged runner: {e}")
            return
        log: List[str] = []
        done: List[int] = []
        saw_event = False
        for line in proc.stdout:
            line = line.rstrip("\n")
            try:
                ev = json.loads(line)
            except ValueError:
                if line.strip():
                    log.append(line)
                continue
            saw_event = True
            kind = ev.get("event")
            if kind == "op_start":
                log.append(f"\n=== [{ev['op'] + 1}] {ev['description']}")
                self.op_started.emit(ev["op"], ev["description"])
            elif kind == "step":
                tag = "ok " if ev["rc"] == 0 else f"rc={ev['rc']}"
                log.append(f"  [{tag}] {ev['label']}")
                if ev.get("out", "").strip():
                    log += ["      " + l for l in ev["out"].strip().splitlines()[-40:]]
            elif kind == "progress":
                self.progress.emit(ev["done"], ev["total"])
            elif kind == "op_done":
                if ev["ok"]:
                    done.append(ev["op"])
                    log.append("  -> SUCCESS")
                else:
                    log.append(f"  -> FAILED: {ev['error']}")
        rc = proc.wait()
        if not saw_event and rc in (126, 127):
            log.append("Authentication was cancelled or denied - nothing was changed.")
        elif rc != 0 and not any("FAILED" in l for l in log):
            log.append(f"Runner exited with code {rc}.")
        self.completed.emit(done, rc == 0 and len(done) == len(self.ops), "\n".join(log).strip())


class DirectIOBenchmarkWorker(QThread):
    # step, total, label, write MB/s, read MB/s, write IOPS, read IOPS
    progress = pyqtSignal(int, int, str, float, float, float, float)
    mode_detected = pyqtSignal(str)
    done = pyqtSignal()                 # (don't shadow QThread.finished)
    error = pyqtSignal(str)

    SEQ_STEPS = [(4096, "4 KB"), (16384, "16 KB"), (65536, "64 KB"), (262144, "256 KB"),
                 (1048576, "1 MB"), (4194304, "4 MB"), (16777216, "16 MB")]

    def __init__(self, target_path: str, file_size_mb: int = 128):
        super().__init__()
        self.target_path = target_path
        self.file_size_mb = file_size_mb
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    @staticmethod
    def _buf(size: int, fill: bool) -> mmap.mmap:
        mm = mmap.mmap(-1, size)              # anonymous mmap => page-aligned, as O_DIRECT needs
        if fill:
            mm.write(os.urandom(size))        # incompressible, unlike b'X' * n
        return mm

    def _flags(self, direct: bool) -> int:
        return os.O_DIRECT if direct else 0

    def _probe_direct(self, path: str) -> bool:
        o_direct = getattr(os, "O_DIRECT", 0)
        if not o_direct:
            return False
        buf = self._buf(4096, True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | o_direct, 0o600)
            try:
                os.write(fd, buf)
            finally:
                os.close(fd)
            return True
        except OSError:
            return False                      # tmpfs, some FUSE/ZFS: EINVAL
        finally:
            buf.close()

    def _seq(self, path: str, bs: int, total: int, direct: bool) -> Optional[Tuple[float, float]]:
        n = total // bs
        buf = self._buf(bs, True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | self._flags(direct), 0o600)
            try:
                t0 = time.perf_counter()
                for _ in range(n):
                    if self._is_cancelled:
                        return None
                    if os.write(fd, buf) != bs:
                        raise OSError("short write")
                os.fsync(fd)
                w = (n * bs / MIB) / max(time.perf_counter() - t0, 1e-9)
            finally:
                os.close(fd)
            fd = os.open(path, os.O_RDONLY | self._flags(direct))
            try:
                if not direct:
                    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                t0 = time.perf_counter()
                got = 0
                while not self._is_cancelled:
                    k = os.readv(fd, [buf])
                    if not k:
                        break
                    got += k
                if self._is_cancelled:
                    return None
                r = (got / MIB) / max(time.perf_counter() - t0, 1e-9)
            finally:
                os.close(fd)
            return w, r
        finally:
            buf.close()

    def _random(self, path: str, total: int, direct: bool, seconds: float = 2.0):
        bs = 4096
        blocks = total // bs
        buf = self._buf(bs, True)
        try:
            wflags = os.O_WRONLY | self._flags(direct) | (0 if direct else os.O_DSYNC)
            fd = os.open(path, wflags)
            try:
                ops, t0 = 0, time.perf_counter()
                while time.perf_counter() - t0 < seconds and not self._is_cancelled:
                    os.pwrite(fd, buf, random.randrange(blocks) * bs)
                    ops += 1
                w_iops = ops / max(time.perf_counter() - t0, 1e-9)
            finally:
                os.close(fd)
            fd = os.open(path, os.O_RDONLY | self._flags(direct))
            try:
                if not direct:
                    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                ops, t0 = 0, time.perf_counter()
                while time.perf_counter() - t0 < seconds and not self._is_cancelled:
                    os.preadv(fd, [buf], random.randrange(blocks) * bs)
                    ops += 1
                r_iops = ops / max(time.perf_counter() - t0, 1e-9)
            finally:
                os.close(fd)
            return w_iops, r_iops
        finally:
            buf.close()

    def run(self):
        path = os.path.join(self.target_path, f".smart_bench_{os.getpid()}.tmp")
        total = self.file_size_mb * MIB
        try:
            if not os.access(self.target_path, os.W_OK):
                raise PermissionError(f"{self.target_path} is not writable by your user - pick another mount point.")
            if shutil.disk_usage(self.target_path).free < total * 1.1 + 64 * MIB:
                raise OSError("Not enough free space for the selected workload size.")
            direct = self._probe_direct(path)
            self.mode_detected.emit("O_DIRECT (page cache bypassed)" if direct else
                                    "Buffered + fsync + cache eviction (O_DIRECT unsupported on this filesystem)")
            steps = len(self.SEQ_STEPS) + 1
            for idx, (bs, label) in enumerate(self.SEQ_STEPS):
                if self._is_cancelled:
                    break
                res = self._seq(path, bs, total, direct)
                if res is None:
                    break
                self.progress.emit(idx + 1, steps, label + " seq", res[0], res[1], 0.0, 0.0)
            if not self._is_cancelled:
                w_iops, r_iops = self._random(path, total, direct)
                if not self._is_cancelled:
                    self.progress.emit(steps, steps, "4 KB rnd QD1", w_iops * 4096 / MIB, r_iops * 4096 / MIB, w_iops, r_iops)
        except Exception as err:
            self.error.emit(str(err))
        finally:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass
            self.done.emit()


# =====================================================================
# 5. WIDGETS & DIALOGS
# =====================================================================

class SpeedBarCanvas(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.results: List[Dict[str, Any]] = []
        self.setMinimumHeight(320)

    def set_results(self, results: List[Dict[str, Any]]):
        self.results = results
        self.setMinimumHeight(max(320, 45 + len(results) * 42))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#1a1b26"))
        p.fillRect(0, 0, w, 32, QColor("#1f2335"))
        p.setPen(QColor("#7aa2f7"))
        p.setFont(ui_font(9, True))
        p.drawText(15, 0, 160, 32, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "📊 Throughput (MB/s):")
        for x, col, txt in ((180, "#f97316", "Write"), (270, "#38bdf8", "Read")):
            p.setBrush(QBrush(QColor(col)))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(x, 11, 12, 12, 2, 2)
            p.setPen(QColor("#c0caf5"))
            p.drawText(x + 18, 0, 70, 32, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, txt)
        if not self.results:
            p.setPen(QColor("#565f89"))
            p.setFont(ui_font(11, True))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "⚡ Select a target mount point and click 'Start Benchmark'.")
            return
        max_speed = max([max(r["write"], r["read"]) for r in self.results] + [100.0])
        ml, mr = 90, 210
        cw = max(100, w - ml - mr)
        row_h, y0 = 40, 45
        p.setPen(QPen(QColor("#414868"), 1))
        p.drawLine(ml, 40, ml + cw, 40)
        p.setFont(ui_font(8))
        for i in range(5):
            tx = ml + int(i / 4.0 * cw)
            p.setPen(QColor("#565f89"))
            p.drawLine(tx, 36, tx, 40)
            p.drawText(tx - 28, 22, 56, 14, Qt.AlignmentFlag.AlignCenter, f"{max_speed * i / 4:.0f} MB/s")
        bh = 7
        for i, res in enumerate(self.results):
            y = y0 + i * row_h
            p.setPen(QColor("#c0caf5"))
            p.setFont(ui_font(9, True))
            p.drawText(5, y, ml - 12, row_h, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, res["label"])
            for key, col, off, iops_key, pre in (("write", "#f97316", 4, "w_iops", "W"), ("read", "#38bdf8", bh + 8, "r_iops", "R")):
                length = int(res[key] / max_speed * cw)
                if length <= 0:
                    continue
                p.setBrush(QBrush(QColor(col)))
                p.setPen(Qt.PenStyle.NoPen)
                p.drawRoundedRect(QRectF(ml, y + off, length, bh), 2, 2)
                p.setPen(QColor(col))
                p.setFont(ui_font(8, True))
                text = f"{pre}: {res[key]:.1f}" + (f"  ({res[iops_key]:,.0f} IOPS)" if res.get(iops_key) else "")
                p.drawText(ml + length + 6, y + off - 3, mr - 10, bh + 8,
                           Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, text)
            p.setPen(QPen(QColor("#24283b"), 1))
            p.drawLine(ml, y + row_h - 2, ml + cw, y + row_h - 2)


class ResizeTrackWidget(QWidget):
    """Draggable partition bar. Right edge resizes; body / left edge MOVES the block without
    changing its size (only when max_offset_mb > 0, i.e. when creating). All values live in one
    invariant, enforced in _clamp():  0 <= offset,  min <= size,  offset + size <= max."""
    sizeChanged = pyqtSignal(int, int)      # (size_mb, offset_mb)
    PAD = 10

    def __init__(self, min_mb, max_mb, current_mb, original_mb=None, offset_mb=0, max_offset_mb=0, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(75)
        self.min_mb, self.max_mb = min_mb, max(max_mb, 1)
        self.max_offset_mb = max_offset_mb
        self.original_mb = original_mb
        self.offset_mb = offset_mb
        self.current_mb = current_mb
        self.dragging: Optional[str] = None
        self.drag_anchor_mb = 0
        self._clamp()

    def offset_limit(self) -> int:
        return min(self.max_offset_mb, self.max_mb - self.min_mb) if self.max_offset_mb > 0 else 0

    def _clamp(self):
        self.offset_mb = max(0, min(self.offset_limit(), self.offset_mb))
        self.current_mb = max(self.min_mb, min(self.max_mb - self.offset_mb, self.current_mb))

    def set_values(self, mb: int, offset: Optional[int] = None):
        if offset is not None:
            self.offset_mb = offset
        self.current_mb = mb
        self._clamp()                       # a larger offset shrinks the size so it never overflows the gap
        self.update()

    def _x(self, mb):
        return self.PAD + (self.width() - 2 * self.PAD) * mb / self.max_mb

    def _mb(self, x):
        usable = max(1, self.width() - 2 * self.PAD)
        return int(round(max(0.0, min(1.0, (x - self.PAD) / usable)) * self.max_mb))

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        p.fillRect(self.PAD, 20, w - 2 * self.PAD, 35, QColor("#16161e"))
        p.setPen(QPen(QColor("#414868"), 1))
        p.drawRoundedRect(self.PAD, 20, w - 2 * self.PAD, 35, 4, 4)
        ox, fx = int(self._x(self.offset_mb)), int(self._x(self.offset_mb + self.current_mb))
        p.fillRect(ox, 20, max(2, fx - ox), 35, QColor("#7aa2f7"))
        if self.original_mb:
            tx = int(self._x(self.original_mb))
            p.setPen(QPen(QColor("#e0af68"), 2))
            p.drawLine(tx, 14, tx, 61)
        p.setPen(QPen(QColor("#bb9af7"), 2))
        p.drawRect(ox, 20, max(2, fx - ox), 35)
        p.setPen(QPen(QColor("#1a1b26"), 2))
        p.drawLine(fx - 6, 28, fx - 6, 47)
        p.drawLine(fx - 2, 28, fx - 2, 47)
        p.setPen(QColor("#1a1b26"))
        p.setFont(ui_font(9, True))
        txt = f"{self.current_mb / 1024:.2f} GiB" if self.current_mb >= 1024 else f"{self.current_mb} MiB"
        p.drawText(ox, 20, max(10, fx - ox - 12), 35, Qt.AlignmentFlag.AlignCenter, txt)

    def mousePressEvent(self, e):
        if e.button() != Qt.MouseButton.LeftButton:
            return
        x = e.position().x()
        ox, fx = self._x(self.offset_mb), self._x(self.offset_mb + self.current_mb)
        movable = self.offset_limit() > 0
        if movable and abs(x - fx) > 12 and (ox - 12 <= x <= fx):
            self.dragging = "move"
            self.drag_anchor_mb = self._mb(x) - self.offset_mb
        else:
            self.dragging = "resize"
        self.setCursor(Qt.CursorShape.SizeHorCursor)
        self._apply(x)

    def mouseMoveEvent(self, e):
        if self.dragging:
            self._apply(e.position().x())

    def mouseReleaseEvent(self, e):
        self.dragging = None
        self.setCursor(Qt.CursorShape.ArrowCursor)

    def _apply(self, x):
        mb = self._mb(x)
        if self.dragging == "move":
            limit = min(self.offset_limit(), self.max_mb - self.current_mb)     # size stays constant
            self.offset_mb = max(0, min(limit, mb - self.drag_anchor_mb))
        elif self.dragging == "resize":
            self.current_mb = mb - self.offset_mb
            self._clamp()
        self.update()
        self.sizeChanged.emit(self.current_mb, self.offset_mb)


class SizeDialog(QDialog):
    """Track + spin boxes (+ optional offset and filesystem). Spin ranges follow the invariant,
    so the dialog can never hand back a region larger than the free gap."""

    def __init__(self, title, info_html, min_mb, max_mb, start_mb, original_mb=None,
                 max_offset_mb=0, with_fs=False, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(540)
        self.min_mb, self.max_mb = min_mb, max_mb
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        info = QLabel(info_html)
        info.setStyleSheet("color: #7aa2f7;")
        lay.addWidget(info)
        self.track = ResizeTrackWidget(min_mb, max_mb, start_mb, original_mb, max_offset_mb=max_offset_mb, parent=self)
        lay.addWidget(self.track)
        form = QFormLayout()
        self.spin_size = QSpinBox()
        self.spin_size.setSuffix(" MiB")
        self.spin_size.setGroupSeparatorShown(True)
        form.addRow("Size:", self.spin_size)
        self.spin_offset: Optional[QSpinBox] = None
        if self.track.offset_limit() > 0:
            self.spin_offset = QSpinBox()
            self.spin_offset.setSuffix(" MiB")
            self.spin_offset.setGroupSeparatorShown(True)
            form.addRow("Offset from start of gap:", self.spin_offset)
        self.combo_fs: Optional[QComboBox] = None
        if with_fs:
            self.combo_fs = QComboBox()
            self.combo_fs.addItems(FS_CHOICES)
            form.addRow("Filesystem:", self.combo_fs)
        lay.addLayout(form)
        self._update_spins()
        self.track.sizeChanged.connect(lambda *_: self._update_spins())
        self.spin_size.valueChanged.connect(lambda v: self._from_spins(v, None))
        if self.spin_offset:
            self.spin_offset.valueChanged.connect(lambda v: self._from_spins(None, v))
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _from_spins(self, size: Optional[int], offset: Optional[int]):
        self.track.set_values(self.track.current_mb if size is None else size, offset)
        self._update_spins()

    def _update_spins(self):
        t = self.track
        for spin, lo, hi, val in ((self.spin_size, self.min_mb, max(self.min_mb, self.max_mb - t.offset_mb), t.current_mb),
                                  (self.spin_offset, 0, t.offset_limit(), t.offset_mb)):
            if spin is None:
                continue
            spin.blockSignals(True)
            spin.setRange(lo, hi)
            spin.setValue(val)
            spin.blockSignals(False)

    def size_mb(self) -> int:
        return self.track.current_mb

    def offset_mb(self) -> int:
        return self.track.offset_mb

    def fstype(self) -> str:
        return self.combo_fs.currentText() if self.combo_fs else ""


class LogDialog(QDialog):
    def __init__(self, title: str, text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(820, 540)
        lay = QVBoxLayout(self)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFont(mono_font())
        view.setPlainText(text)
        lay.addWidget(view)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)


class BusyDialog(QDialog):
    """Modal progress that cannot be dismissed while privileged work runs."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(480)
        lay = QVBoxLayout(self)
        self.label = QLabel("Waiting for authentication...")
        self.label.setWordWrap(True)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        lay.addWidget(self.label)
        lay.addWidget(self.bar)
        note = QLabel("<i>Do not power off or close the app - interrupting disk operations can destroy data.</i>")
        note.setStyleSheet("color: #e0af68;")
        lay.addWidget(note)

    def set_text(self, t):
        self.label.setText(t)

    def set_progress(self, done, total):
        self.bar.setRange(0, 100)
        self.bar.setValue(int(done * 100 / total) if total else 0)

    def reject(self):
        pass

    def closeEvent(self, e):
        e.ignore()

    def finish(self):
        self.accept()


class PartitionMapWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(85)
        self.setMaximumHeight(105)
        self.items: List[Dict[str, Any]] = []

    def set_data(self, items: List[Dict[str, Any]]):
        self.items = items
        self.update()

    FS_COLORS = {"ext4": "#7aa2f7", "ext3": "#3d59a1", "ext2": "#2ac3de", "ntfs": "#9ece6a", "vfat": "#e0af68",
                 "exfat": "#c3e88d", "swap": "#bb9af7", "LVM2_member": "#ff9e64", "btrfs": "#73daca",
                 "xfs": "#f7768e", "crypto_LUKS": "#ff757f"}

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#16161e"))
        p.setPen(QPen(QColor("#414868"), 1))
        p.drawRoundedRect(0, 0, w - 1, h - 1, 6, 6)
        total = sum(i["size"] for i in self.items)
        if not self.items or total <= 0:
            p.setPen(QColor("#565f89"))
            p.setFont(ui_font(9))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No partition layout to display for this drive.")
            return
        bar_w, bar_h, bar_y = w - 12, h - 30, 8
        widths = [max(6.0, i["size"] / total * bar_w) for i in self.items]
        scale = min(1.0, bar_w / sum(widths))
        x = 6.0
        for item, wd in zip(self.items, widths):
            wd *= scale
            rect = QRectF(x, bar_y, wd, bar_h)
            if item.get("free"):
                p.setBrush(QBrush(QColor("#24283b"), Qt.BrushStyle.BDiagPattern))
                p.setPen(QPen(QColor("#565f89"), 1, Qt.PenStyle.DashLine))
            else:
                p.setBrush(QBrush(QColor(self.FS_COLORS.get(item["fstype"], "#565f89"))))
                p.setPen(QPen(QColor("#f7768e" if item.get("pending_delete") else "#1a1b26"), 2 if item.get("pending_delete") else 1))
            p.drawRect(rect)
            if wd > 40:
                p.setPen(QColor("#1a1b26" if not item.get("free") else "#a9b1d6"))
                p.setFont(ui_font(8, True))
                p.drawText(rect, Qt.AlignmentFlag.AlignCenter, item["name"])
                p.setPen(QColor("#a9b1d6"))
                p.setFont(ui_font(7))
                p.drawText(QRectF(x, bar_y + bar_h + 3, wd, 16), Qt.AlignmentFlag.AlignCenter, fmt_size(item["size"]))
            x += wd


# =====================================================================
# 6. MAIN WINDOW
# =====================================================================

class SmartDataGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Disk SMART, Benchmark & Partition Dashboard")
        self.resize(1280, 880)
        self.drives: List[Dict[str, Any]] = []
        self.block_devices: List[Dict[str, Any]] = []
        self.dev_index: Dict[str, Dict[str, Any]] = {}
        self.protected: Set[str] = set()
        self.system_disks: Set[str] = set()
        self.bench_results: List[Dict[str, Any]] = []
        self.pending_operations: List[Dict[str, Any]] = []
        self.clone_source_path: Optional[str] = None
        self.bench_worker: Optional[DirectIOBenchmarkWorker] = None
        self.scan_worker: Optional[DriveScanWorker] = None
        self.root_worker: Optional[RootOpsWorker] = None
        self.busy: Optional[BusyDialog] = None

        self.init_ui()
        self.apply_dark_theme()
        self.refresh_drives()
        self.populate_partition_manager()

    # ------------------------------------------------------------- UI
    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        main.setContentsMargins(12, 12, 12, 12)

        header = QFrame()
        header.setObjectName("HeaderFrame")
        header.setMaximumHeight(50)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(12, 8, 12, 8)
        title = QLabel("💾 Disk SMART, Benchmark & Partition Dashboard")
        title.setFont(ui_font(14, True))
        title.setStyleSheet("color: #7aa2f7;")
        self.btn_rescan = QPushButton("🔄 Rescan Disks")
        self.btn_rescan.clicked.connect(self.refresh_drives)
        hl.addWidget(title)
        hl.addStretch()
        hl.addWidget(self.btn_rescan)
        main.addWidget(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        side = QWidget()
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 0)
        side_lbl = QLabel("Storage Drives (Worst ➜ Best)")
        side_lbl.setFont(ui_font(10, True))
        side_lbl.setStyleSheet("color: #bb9af7;")
        self.drive_list_widget = QListWidget()
        self.drive_list_widget.currentRowChanged.connect(self.on_drive_selected)
        sl.addWidget(side_lbl)
        sl.addWidget(self.drive_list_widget)
        splitter.addWidget(side)

        tabs = QTabWidget()
        tabs.addTab(self._build_smart_tab(), "📊 SMART Analytics")
        tabs.addTab(self._build_bench_tab(), "⚡ Direct I/O Performance")
        tabs.addTab(self._build_parts_tab(), "🗂️ Partition Manager")
        splitter.addWidget(tabs)
        splitter.setSizes([300, 880])
        main.addWidget(splitter)

    def _readonly_table(self, headers: List[str]) -> QTableWidget:
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)   # cells used to be editable -> path spoofing
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.verticalHeader().setVisible(False)
        return t

    def _build_smart_tab(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        self.lbl_drive_banner = QLabel("Select a drive to view SMART metrics")
        self.lbl_drive_banner.setFont(ui_font(11, True))
        self.lbl_drive_banner.setWordWrap(True)
        self.lbl_drive_banner.setStyleSheet("color: #7dcfff; padding: 6px; background: #1f2335; border-radius: 6px;")
        self.lbl_drive_details = QLabel("")
        self.lbl_drive_details.setWordWrap(True)
        self.lbl_drive_details.setStyleSheet("color: #a9b1d6; padding: 4px 6px;")
        self.table_smart = self._readonly_table(["ID", "Clean Parameter Name", "Status", "Safety Margin", "Current/Thresh", "RAW"])
        self.table_smart.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        row = QHBoxLayout()
        self.btn_selftest = QPushButton("🧪 Run Short Self-Test")
        self.btn_selftest.clicked.connect(self.run_selftest)
        self.btn_export = QPushButton("📄 Export Report…")
        self.btn_export.clicked.connect(self.export_report)
        row.addWidget(self.btn_selftest)
        row.addWidget(self.btn_export)
        row.addStretch()
        lay.addWidget(self.lbl_drive_banner)
        lay.addWidget(self.lbl_drive_details)
        lay.addWidget(self.table_smart)
        lay.addLayout(row)
        return tab

    def _build_bench_tab(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Target Mount Point:"))
        self.combo_mounts = QComboBox()
        self.combo_mounts.setMinimumWidth(280)
        self.populate_mount_points()
        ctrl.addWidget(self.combo_mounts)
        ctrl.addWidget(QLabel("Workload Size:"))
        self.combo_size = QComboBox()
        self.combo_size.addItems(["64 MB", "128 MB", "256 MB", "512 MB"])
        self.combo_size.setCurrentText("128 MB")
        ctrl.addWidget(self.combo_size)
        self.btn_start_bench = QPushButton("▶ Start Benchmark")
        self.btn_start_bench.setStyleSheet("background-color: #10b981; color: white; font-weight: bold;")
        self.btn_start_bench.clicked.connect(self.start_benchmark)
        self.btn_stop_bench = QPushButton("⏹ Stop")
        self.btn_stop_bench.setEnabled(False)
        self.btn_stop_bench.clicked.connect(self.stop_benchmark)
        ctrl.addWidget(self.btn_start_bench)
        ctrl.addWidget(self.btn_stop_bench)
        lay.addLayout(ctrl)
        self.lbl_bench_mode = QLabel("Mode: -")
        self.lbl_bench_mode.setStyleSheet("color: #bb9af7;")
        lay.addWidget(self.lbl_bench_mode)
        self.bench_progress = QProgressBar()
        lay.addWidget(self.bench_progress)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.speed_canvas = SpeedBarCanvas()
        scroll.setWidget(self.speed_canvas)
        lay.addWidget(scroll)
        return tab

    def _build_parts_tab(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        sel = QHBoxLayout()
        lbl = QLabel("Select Target Disk:")
        lbl.setFont(ui_font(9, True))
        self.combo_disk_selector = QComboBox()
        self.combo_disk_selector.currentIndexChanged.connect(self.on_disk_dropdown_changed)
        btn = QPushButton("🔄 Refresh Layout")
        btn.clicked.connect(self.populate_partition_manager)
        sel.addWidget(lbl)
        sel.addWidget(self.combo_disk_selector, stretch=1)
        sel.addWidget(btn)
        lay.addLayout(sel)
        self.lbl_disk_info = QLabel("")
        self.lbl_disk_info.setStyleSheet("color: #7aa2f7;")
        lay.addWidget(self.lbl_disk_info)
        self.partition_map = PartitionMapWidget()
        lay.addWidget(self.partition_map)
        self.table_partitions = self._readonly_table(["Partition", "Type", "Filesystem", "Size", "Used", "Mount Point", "Device Path"])
        hdr = self.table_partitions.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)   # Mount Point
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)            # Device Path takes the rest
        self.table_partitions.setColumnWidth(0, 190)
        self.table_partitions.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_partitions.customContextMenuRequested.connect(self.show_partition_context_menu)
        lay.addWidget(self.table_partitions)

        self.list_pending = QListWidget()
        self.list_pending.setMaximumHeight(110)
        self.list_pending.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.list_pending.customContextMenuRequested.connect(self.pending_context_menu)
        lay.addWidget(self.list_pending)
        bar = QHBoxLayout()
        self.lbl_pending_count = QLabel("")
        self.lbl_pending_count.setStyleSheet("color: #e0af68; font-weight: bold;")
        self.btn_simulate_ops = QPushButton("🧪 Pre-flight Check")
        self.btn_simulate_ops.clicked.connect(self.simulate_pending_queue)
        self.btn_commit_ops = QPushButton("✔ Apply / Commit Changes")
        self.btn_commit_ops.setStyleSheet("background-color: #10b981; color: white; font-weight: bold; padding: 6px 16px;")
        self.btn_commit_ops.clicked.connect(self.commit_pending_queue)
        self.btn_clear_ops = QPushButton("❌ Clear Queue")
        self.btn_clear_ops.setStyleSheet("background-color: #f7768e; color: #1a1b26;")
        self.btn_clear_ops.clicked.connect(self.clear_pending_queue)
        bar.addWidget(self.lbl_pending_count)
        bar.addStretch()
        for b in (self.btn_simulate_ops, self.btn_commit_ops, self.btn_clear_ops):
            bar.addWidget(b)
        lay.addLayout(bar)
        hint = QLabel("Right-click a disk, partition or unallocated row. Right-click a queued operation to remove it.")
        hint.setStyleSheet("color: #bb9af7; background: #1f2335; padding: 8px; border-radius: 6px;")
        lay.addWidget(hint)
        self.update_pending_ui()
        return tab

    def apply_dark_theme(self):
        qss = """
        QMainWindow, QDialog, QMessageBox, QInputDialog { background-color: #1a1b26; }
        QWidget { color: #a9b1d6; }
        #HeaderFrame { background-color: #1f2335; border-bottom: 1px solid #414868; }
        QListWidget { background-color: #16161e; border: 1px solid #414868; border-radius: 6px; font-size: 13px; }
        QListWidget::item:selected { background-color: #283451; border-radius: 4px; }
        QTableWidget { background-color: #16161e; border: 1px solid #414868; gridline-color: #24283b; font-size: 12px; }
        QTableWidget::item:selected { background-color: #283451; }
        QHeaderView::section { background-color: #1f2335; color: #7aa2f7; font-weight: bold; padding: 4px; border: 1px solid #414868; }
        QTabWidget::pane { border: 1px solid #414868; background-color: #1a1b26; }
        QTabBar::tab { background: #1f2335; color: #a9b1d6; padding: 8px 16px; font-weight: bold; border-top-left-radius: 4px; border-top-right-radius: 4px; }
        QTabBar::tab:selected { background: #24283b; color: #7aa2f7; border-bottom: 2px solid #7aa2f7; }
        QPushButton { background-color: #24283b; color: #c0caf5; border: 1px solid #414868; border-radius: 4px; padding: 6px 14px; font-weight: bold; }
        QPushButton:hover { background-color: #3b4261; }
        QPushButton:disabled { color: #565f89; }
        QComboBox, QSpinBox, QLineEdit { background-color: #1f2335; border: 1px solid #414868; border-radius: 4px; padding: 4px; color: #c0caf5; }
        QComboBox QAbstractItemView { background-color: #1f2335; selection-background-color: #283451; }
        QPlainTextEdit { background-color: #16161e; border: 1px solid #414868; color: #c0caf5; }
        QProgressBar { border: 1px solid #414868; border-radius: 4px; text-align: center; background: #16161e; }
        QProgressBar::chunk { background-color: #7aa2f7; }
        QMenu { background-color: #1f2335; color: #c0caf5; border: 1px solid #414868; padding: 4px; }
        QMenu::item { padding: 6px 24px; border-radius: 4px; }
        QMenu::item:selected { background-color: #3b4261; color: #7aa2f7; }
        QMenu::item:disabled { color: #565f89; }
        QToolTip { background-color: #1f2335; color: #c0caf5; border: 1px solid #414868; }
        """
        QApplication.instance().setStyleSheet(qss)

    # --------------------------------------------------------- lifecycle
    def closeEvent(self, event):
        if self.root_worker and self.root_worker.isRunning():
            QMessageBox.warning(self, "Operation in progress",
                                "Disk operations are still running. Closing now could leave the disk half-modified.")
            event.ignore()
            return
        if self.bench_worker and self.bench_worker.isRunning():
            self.bench_worker.cancel()
            self.bench_worker.wait(5000)
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.wait(3000)
        event.accept()

    # ------------------------------------------------------------ SMART
    def refresh_drives(self):
        self.btn_rescan.setEnabled(False)
        self.btn_rescan.setText("⏳ Scanning...")
        self.scan_worker = DriveScanWorker()
        self.scan_worker.scanned.connect(self.on_drives_scanned)
        self.scan_worker.start()

    def on_drives_scanned(self, drives: List[Dict[str, Any]], err: str):
        self.drives = drives
        self.btn_rescan.setEnabled(True)
        self.btn_rescan.setText("🔄 Rescan Disks")
        self.drive_list_widget.clear()
        self.table_smart.setRowCount(0)
        if not drives:
            self.lbl_drive_banner.setText("No SMART drives available")
            QMessageBox.warning(self, "No Storage Drives", err or "No SMART storage drives detected.")
            return
        if err:
            self.lbl_drive_details.setText(f"⚠ {err}")
        colors = {"CRITICAL": "#f7768e", "WARNING": "#e0af68", "INTF_WARN": "#e0af68", "UNKNOWN": "#565f89"}
        for d in drives:
            item = QListWidgetItem(f"{d['icon']}  {d['path']} ({d['model'][:16]})")
            item.setForeground(QColor(colors.get(d["status"], "#9ece6a")))
            item.setToolTip(f"{d['kind']} - verdict: {d['status']}")
            self.drive_list_widget.addItem(item)
        self.drive_list_widget.setCurrentRow(0)

    def on_drive_selected(self, row: int):
        if row < 0 or row >= len(self.drives):
            return
        d = self.drives[row]
        self.lbl_drive_banner.setText(f"{d['icon']} {d['path']} | {d['model']} | S/N {d['serial']} | verdict: {d['status']}")
        temp = f"{d['temperature']} °C" if d["temperature"] is not None else "n/a"
        poh = f"{d['power_on_hours']:,} h" if d["power_on_hours"] is not None else "n/a"
        self.lbl_drive_details.setText(
            f"{d['kind']} · {fmt_size(d['capacity'])} · FW {d['firmware']} · temp {temp} · power-on {poh} · "
            f"SMART self-assessment: {'PASSED' if d['smart_passed'] else 'FAILED' if d['smart_passed'] is False else 'n/a'} · "
            f"last self-test: {d['last_selftest']}")
        self.table_smart.setRowCount(0)
        colors = {"FAILING": "#f7768e", "WARNING": "#e0af68", "INTERFACE ERR": "#e0af68", "INFO": "#7a88b8"}
        for m in d["metrics"]:
            r = self.table_smart.rowCount()
            self.table_smart.insertRow(r)
            id_item = QTableWidgetItem(m["jargon_id"])
            id_item.setToolTip(m["jargon_name"])
            st = QTableWidgetItem(f"{m['icon']} {m['status']}")
            st.setForeground(QColor(colors.get(m["status"], "#9ece6a")))
            st.setToolTip(m["friendly_status"])
            for c, it in enumerate((id_item, QTableWidgetItem(m["clean_name"]), st, QTableWidgetItem(m["margin"]),
                                    QTableWidgetItem(f"{m['current']} / {m['thresh']}"), QTableWidgetItem(m["raw"]))):
                self.table_smart.setItem(r, c, it)

    def current_drive(self) -> Optional[Dict[str, Any]]:
        row = self.drive_list_widget.currentRow()
        return self.drives[row] if 0 <= row < len(self.drives) else None

    def run_selftest(self):
        d = self.current_drive()
        if not d:
            return
        self.run_root_ops([build_selftest_op(d)], "Starting self-test", self._after_selftest)

    def _after_selftest(self, done, ok, log):
        LogDialog("Self-test", log + "\n\nThe test runs inside the drive; rescan in a few minutes to see the result.", self).exec()

    def export_report(self):
        d = self.current_drive()
        if not d:
            return
        name, _ = QFileDialog.getSaveFileName(self, "Export SMART report", f"smart_{os.path.basename(d['path'])}.txt", "Text (*.txt)")
        if name:
            try:
                with open(name, "w") as f:
                    f.write(drive_report_text(d) + "\n")
            except OSError as e:
                QMessageBox.critical(self, "Export failed", str(e))

    # -------------------------------------------------------- benchmark
    def populate_mount_points(self):
        self.combo_mounts.clear()
        home = os.path.expanduser("~")
        try:
            home_dev = os.stat(home).st_dev
        except OSError:
            home_dev = None
        seen = set()
        for r in read_mount_table():
            src, mp = r["source"], r["mountpoint"]
            if not src.startswith("/dev/") or src.startswith("/dev/loop") or r["fstype"] in ("squashfs", "iso9660"):
                continue
            target, note = mp, ""
            if not os.access(mp, os.W_OK):
                try:
                    if home_dev is not None and os.stat(mp).st_dev == home_dev:
                        target, note = home, " (via home dir)"
                    else:
                        continue
                except OSError:
                    continue
            if (src, target) in seen:
                continue
            seen.add((src, target))
            try:
                size = fmt_size(shutil.disk_usage(mp).total)
            except OSError:
                size = "?"
            self.combo_mounts.addItem(f"{mp}{note} ({src} - {size}, {r['fstype']})", target)
        if self.combo_mounts.count() == 0:
            self.combo_mounts.addItem(f"Home ({home})", home)

    def start_benchmark(self):
        mount_path = self.combo_mounts.currentData() or os.path.expanduser("~")
        size_mb = int(self.combo_size.currentText().split()[0])
        self.bench_results.clear()
        self.speed_canvas.set_results([])
        self.bench_progress.setValue(0)
        self.lbl_bench_mode.setText("Mode: probing...")
        self.btn_start_bench.setEnabled(False)
        self.btn_stop_bench.setEnabled(True)
        self.bench_worker = DirectIOBenchmarkWorker(mount_path, size_mb)
        self.bench_worker.progress.connect(self.on_bench_progress)
        self.bench_worker.mode_detected.connect(lambda m: self.lbl_bench_mode.setText(f"Mode: {m}"))
        self.bench_worker.done.connect(self.on_bench_finished)
        self.bench_worker.error.connect(lambda e: QMessageBox.critical(self, "Benchmark Error", e))
        self.bench_worker.start()

    def stop_benchmark(self):
        if self.bench_worker:
            self.bench_worker.cancel()

    def on_bench_progress(self, step, total, label, w, r, wi, ri):
        self.bench_progress.setValue(int(step * 100 / total))
        self.bench_results.append({"label": label, "write": w, "read": r, "w_iops": wi, "r_iops": ri})
        self.speed_canvas.set_results(self.bench_results)

    def on_bench_finished(self):
        self.btn_start_bench.setEnabled(True)
        self.btn_stop_bench.setEnabled(False)

    # ---------------------------------------------------- privileged ops
    def run_root_ops(self, ops: List[Dict[str, Any]], title: str, on_done):
        issues = preflight(ops, self.dev_index, self.protected) if any(o["type"] != "SELFTEST" for o in ops) else []
        errors = [m for l, m in issues if l == "error"]
        if errors:
            LogDialog("Blocked by pre-flight check", "\n".join(errors), self).exec()
            return
        self.busy = BusyDialog(title, self)
        self.root_worker = RootOpsWorker(ops)
        self.root_worker.op_started.connect(lambda i, d: self.busy.set_text(f"({i + 1}/{len(ops)}) {d}"))
        self.root_worker.progress.connect(lambda d, t: self.busy.set_progress(d, t))

        def finished(done, ok, log):
            self.busy.finish()
            self.busy = None
            on_done(done, ok, log)
        self.root_worker.completed.connect(finished)
        self.root_worker.start()
        self.busy.exec()

    def _after_immediate(self, done, ok, log):
        LogDialog("Result" if ok else "Operation failed", log, self).exec()
        self.populate_partition_manager()
        self.populate_mount_points()

    # -------------------------------------------------- partition manager
    def populate_partition_manager(self):
        self.block_devices = get_block_devices()
        self.dev_index = index_devices(self.block_devices)
        self.protected, self.system_disks = compute_system_paths(self.dev_index)
        previous = self.combo_disk_selector.currentData()
        prev_path = previous["path"] if previous else None
        self.combo_disk_selector.blockSignals(True)
        self.combo_disk_selector.clear()
        for disk in self.block_devices:
            if disk.get("type") == "disk":
                label = f"{disk['path']} — {disk['model'] or 'Storage Drive'} ({fmt_size(disk['size'])})"
                if disk["path"] in self.system_disks:
                    label += "  [system disk]"
                self.combo_disk_selector.addItem(label, disk)
        self.combo_disk_selector.blockSignals(False)
        if self.combo_disk_selector.count():
            idx = next((i for i in range(self.combo_disk_selector.count())
                        if self.combo_disk_selector.itemData(i)["path"] == prev_path), 0)
            self.combo_disk_selector.setCurrentIndex(idx)
            self.on_disk_dropdown_changed(idx)
        else:
            self.on_disk_dropdown_changed(-1)

    def _pending_deletes(self) -> Set[str]:
        return {o["device"] for o in self.pending_operations if o["type"] == "DELETE"}

    def on_disk_dropdown_changed(self, index: int):
        disk = self.combo_disk_selector.currentData()
        self.table_partitions.setRowCount(0)
        if not disk:
            self.partition_map.set_data([])
            self.lbl_disk_info.setText("")
            return
        layout = compute_layout(disk)
        pttype = disk.get("pttype") or ("none" if not whole_disk_in_use(disk) else "none (whole-disk use)")
        self.lbl_disk_info.setText(f"Partition table: {pttype.upper()}" +
                                   ("  ·  ⚠ system disk" if disk["path"] in self.system_disks else ""))
        doomed = self._pending_deletes()
        items = []
        if whole_disk_in_use(disk) or not layout:
            items.append({"name": disk["fstype"] or disk["name"], "size": disk["size"] or 0,
                          "fstype": disk["fstype"], "free": not disk["children"] and not disk["fstype"]})
        for seg in layout:
            if seg["kind"] == "free":
                items.append({"name": "Unallocated", "size": seg["size"], "fstype": "", "free": True})
            else:
                dev = seg["dev"]
                items.append({"name": dev["name"], "size": seg["size"], "fstype": dev["fstype"], "free": False,
                              "pending_delete": dev["path"] in doomed})
        self.partition_map.set_data(items)

        def add_row(payload, name, typ, fs, size, used, mount, path, bold=False, color=None, strike=False):
            r = self.table_partitions.rowCount()
            self.table_partitions.insertRow(r)
            for c, text in enumerate((name, typ, fs, size, used, mount, path)):
                it = QTableWidgetItem(text)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, payload)
                if color or bold or strike:
                    f = ui_font(9, bold)
                    f.setStrikeOut(strike)
                    it.setFont(f)
                    if color:
                        it.setForeground(QColor(color))
                self.table_partitions.setItem(r, c, it)

        def add_dev(dev, seg, depth):
            mp = dev.get("mountpoint") or "-"
            used = "-"
            if dev.get("fsused") is not None and dev.get("size"):
                used = f"{fmt_size(dev['fsused'])} ({dev['fsused'] * 100 // dev['size']}%)"
            pend = dev["path"] in doomed
            add_row({"kind": "part" if dev.get("type") == "part" else "nested", "dev": dev, "seg": seg, "layout": layout, "disk": disk},
                    "    " * depth + dev["name"] + ("  (pending delete)" if pend else ""), dev.get("type", ""),
                    dev["fstype"] or "-", fmt_size(dev["size"]), used, mp, dev["path"],
                    color="#f7768e" if pend else None, strike=pend)
            for ch in dev["children"]:
                add_dev(ch, None, depth + 1)

        add_row({"kind": "disk", "dev": disk, "layout": layout, "disk": disk}, disk["name"], "disk", disk["fstype"] or "-",
                fmt_size(disk["size"]), "-", disk.get("mountpoint") or "-", disk["path"], bold=True, color="#7aa2f7")
        if layout:
            for seg in layout:
                if seg["kind"] == "free":
                    add_row({"kind": "free", "seg": seg, "layout": layout, "disk": disk}, "    (unallocated)", "free", "-",
                            fmt_size(seg["size"]), "-", "-", f"@ {fmt_size(seg['start'])}", color="#565f89")
                else:
                    add_dev(seg["dev"], seg, 1)
        else:
            for ch in disk["children"]:
                add_dev(ch, None, 1)

    def show_partition_context_menu(self, pos):
        item = self.table_partitions.itemAt(pos)
        if item is None:
            return
        payload = self.table_partitions.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        if not payload:
            return
        menu = QMenu(self)
        kind = payload["kind"]
        dev = payload.get("dev")
        if kind in ("disk", "free"):
            a = menu.addAction("➕ Create Partition..." if kind == "disk" else "➕ Create Partition Here...")
            a.triggered.connect(lambda _=False, p=payload: self.action_create_partition(p))
            if kind == "disk" and not any(s["kind"] == "free" for s in payload["layout"]):
                a.setEnabled(False)
                a.setToolTip("No unallocated space on this disk.")
        elif dev:
            mounted = bool(dev.get("mountpoint"))
            if not mounted and dev["fstype"] and dev["fstype"] != "swap":
                a = menu.addAction("📂 Mount...")
                a.triggered.connect(lambda _=False, d=dev: self.execute_mount(d["path"]))
            if kind == "part":
                a = menu.addAction("📐 Stage Resize...")
                a.triggered.connect(lambda _=False, p=payload: self.action_resize_partition(p))
                a = menu.addAction("🗑️ Stage Partition Deletion")
                a.triggered.connect(lambda _=False, d=dev: self.action_delete_partition(d))
                menu.addSeparator()
                a = menu.addAction("📋 Copy Partition (Clone Source)")
                a.triggered.connect(lambda _=False, d=dev: self.set_copy_source(d["path"]))
                if self.clone_source_path and self.clone_source_path != dev["path"]:
                    a = menu.addAction(f"📥 Stage Clone: {self.clone_source_path} → here")
                    a.triggered.connect(lambda _=False, d=dev: self.stage_clone(d["path"]))
            if dev["fstype"] == "ntfs":
                a = menu.addAction("🔧 NTFS Check (read-only)")
                a.triggered.connect(lambda _=False, d=dev: self.execute_check(d, False))
            elif dev["fstype"] in ("ext2", "ext3", "ext4"):
                a = menu.addAction("🔧 Filesystem Check (read-only)")
                a.triggered.connect(lambda _=False, d=dev: self.execute_check(d, False))
                a = menu.addAction("🛠 Check && Repair (fsck -y)")
                a.triggered.connect(lambda _=False, d=dev: self.execute_check(d, True))
        if menu.actions():
            menu.exec(self.table_partitions.viewport().mapToGlobal(pos))

    def pending_context_menu(self, pos):
        row = self.list_pending.row(self.list_pending.itemAt(pos)) if self.list_pending.itemAt(pos) else -1
        if row < 0:
            return
        menu = QMenu(self)
        a = menu.addAction("Remove from queue")
        if menu.exec(self.list_pending.viewport().mapToGlobal(pos)) == a:
            del self.pending_operations[row]
            self.update_pending_ui()

    # ---- staging actions
    def _queue(self, op: Dict[str, Any]):
        self.pending_operations.append(op)
        self.update_pending_ui()

    def action_create_partition(self, payload):
        disk = payload["disk"]
        frees = [s for s in payload["layout"] if s["kind"] == "free"]
        if whole_disk_in_use(disk):
            QMessageBox.warning(self, "Cannot create partition",
                                "This disk holds a filesystem/volume directly (no partition table). Wipe it first.")
            return
        seg = payload.get("seg") if payload["kind"] == "free" else max(frees, key=lambda s: s["size"], default=None)
        if not seg:
            return
        max_mb = (seg["size"] - 0) // MIB - 1
        if max_mb < 1:
            QMessageBox.information(self, "No space", "Not enough unallocated space.")
            return
        note = "<br><b>No partition table found - a new GPT will be written.</b>" if not disk.get("pttype") else ""
        dlg = SizeDialog(f"Create Partition on {disk['path']}",
                         f"<b>Free region:</b> {fmt_size(seg['size'])} at {fmt_size(seg['start'])}{note}<br>"
                         "<i>Drag the right edge to resize, drag the body to move. Shrink first if the block fills the gap.</i>",
                         1, max_mb, max_mb, max_offset_mb=max_mb - 1, with_fs=True, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            try:
                off = dlg.offset_mb() * MIB
                placed = dict(seg, start=seg["start"] + off, size=seg["size"] - off)   # remaining gap after the offset
                self._queue(build_create_op(disk, placed, dlg.size_mb(), dlg.fstype()))
            except ValueError as e:
                QMessageBox.warning(self, "Cannot stage", str(e))

    def action_delete_partition(self, dev):
        if os.path.realpath(dev["path"]) in self.protected:
            QMessageBox.critical(self, "Safety Violation", f"{dev['path']} backs the running system (root/boot/ESP) and cannot be staged for deletion.")
            return
        if QMessageBox.warning(self, "Confirm Stage Deletion", f"Stage deletion of {dev['path']}?\n\nNothing happens until you click 'Apply'.",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            try:
                self._queue(build_delete_op(dev))
            except ValueError as e:
                QMessageBox.warning(self, "Cannot stage", str(e))

    def action_resize_partition(self, payload):
        dev, seg, layout = payload["dev"], payload["seg"], payload["layout"]
        if not seg:
            return
        cur_mb = seg["size"] // MIB
        end = seg["start"] + seg["size"]
        free_after = next((s for s in layout if s["kind"] == "free" and abs(s["start"] - end) <= MIB), None)
        max_mb = cur_mb + (free_after["size"] // MIB - 1 if free_after else 0)
        used = dev.get("fsused")
        min_mb = max(16, int(used * 1.1 / MIB) + 64) if used else 16
        min_mb = min(min_mb, cur_mb)
        if max_mb <= min_mb:
            QMessageBox.information(self, "Nothing to change", "No room to grow, and the data in use prevents shrinking.")
            return
        dlg = SizeDialog(f"Resize {dev['path']}", f"<b>Current:</b> {fmt_size(seg['size'])} · yellow tick = current size"
                         f"<br>Range: {min_mb} – {max_mb} MiB", min_mb, max_mb, cur_mb, original_mb=cur_mb, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.size_mb() != cur_mb:
            try:
                self._queue(build_resize_op(dev, seg, dlg.size_mb()))
            except ValueError as e:
                QMessageBox.warning(self, "Cannot stage", str(e))

    def set_copy_source(self, path):
        self.clone_source_path = path
        QMessageBox.information(self, "Clone source", f"{path} selected as clone source.\nRight-click a destination partition to stage the clone.")

    def stage_clone(self, dst):
        self._queue(build_clone_op(self.clone_source_path, dst))

    # ---- immediate privileged actions
    def execute_mount(self, path):
        target, ok = QInputDialog.getText(self, "Mount Partition", "Target mount directory (e.g. /mnt/data):")
        if ok and target.strip():
            self.run_root_ops([build_mount_op(path, target.strip())], "Mounting", self._after_immediate)

    def execute_check(self, dev, repair):
        if repair and QMessageBox.question(self, "Repair", f"Run a repairing fsck on {dev['path']}? This modifies the filesystem.",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            op = build_check_op(dev, repair)
        except ValueError as e:
            QMessageBox.warning(self, "Cannot check", str(e))
            return
        self.run_root_ops([op], "Checking filesystem", self._after_immediate)

    # ---- queue UI / preflight / commit
    def update_pending_ui(self):
        self.list_pending.clear()
        for i, op in enumerate(self.pending_operations, 1):
            it = QListWidgetItem(f"{i}. {op['description']}")
            it.setToolTip("\n".join(describe_steps(op)))
            self.list_pending.addItem(it)
        n = len(self.pending_operations)
        self.lbl_pending_count.setText(f"Pending Operations Queue: {n} operation{'s' if n != 1 else ''}")
        for b in (self.btn_simulate_ops, self.btn_commit_ops, self.btn_clear_ops):
            b.setEnabled(n > 0)
        if hasattr(self, "table_partitions"):
            self.on_disk_dropdown_changed(self.combo_disk_selector.currentIndex())

    def clear_pending_queue(self):
        self.pending_operations.clear()
        self.update_pending_ui()

    def simulate_pending_queue(self):
        if not self.pending_operations:
            return
        issues = preflight(self.pending_operations, self.dev_index, self.protected)
        LogDialog("Pre-flight check", format_preflight(self.pending_operations, issues), self).exec()

    def commit_pending_queue(self):
        ops = list(self.pending_operations)
        if not ops:
            return
        self.populate_partition_manager()           # re-read reality before judging the queue
        issues = preflight(ops, self.dev_index, self.protected)
        if any(l == "error" for l, _ in issues):
            LogDialog("Blocked by pre-flight check", format_preflight(ops, issues), self).exec()
            return
        summary = "\n".join(f"  • {o['description']}" for o in ops)
        warns = "\n".join(f"  ⚠ {m}" for l, m in issues if l == "warn")
        text, ok = QInputDialog.getText(
            self, "Final confirmation",
            f"These operations will be executed on real disks:\n\n{summary}\n\n{warns}\n\nType APPLY to continue:")
        if not ok or text.strip() != "APPLY":
            return
        self.run_root_ops(ops, "Applying changes", self.on_commit_finished)

    def on_commit_finished(self, done: List[int], ok: bool, log: str):
        # Only completed ops leave the queue: a failure keeps the failed op and everything after it.
        remaining = [o for i, o in enumerate(self.pending_operations) if i not in set(done)]
        self.pending_operations = remaining
        self.update_pending_ui()
        self.populate_partition_manager()
        self.populate_mount_points()
        LogDialog("All operations completed" if ok else "Operations stopped - see log (unfinished ops stay queued)", log, self).exec()


def main():
    if not sys.platform.startswith("linux"):
        print("This tool is Linux-only.")
        return 1
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SmartDataGUI()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

# ---------------------------------------------------------------------
# Rehearsing the destructive paths safely (no real disk involved):
#   truncate -s 2G /tmp/t.img && sudo losetup -fP --show /tmp/t.img   # -> /dev/loopN
# lsblk lists loop devices as type "loop" (this UI shows type "disk" only); to rehearse in the
# GUI, temporarily allow "loop" in populate_partition_manager(), create/resize/delete/clone
# there, then `sudo losetup -d /dev/loopN`.
# ---------------------------------------------------------------------
