#!/usr/bin/env python3
"""
Disk SMART data & Direct I/O Benchmark Dashboard for Linux
Combines Worst-to-Best SMART Analytics with Real-Time Direct I/O Benchmarking
"""

import sys
import os
import json
import time
import subprocess
from typing import List, Dict, Any, Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRectF
from PyQt6.QtGui import QFont, QColor, QPainter, QBrush, QPen
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem,
    QTabWidget, QLabel, QPushButton, QComboBox, QProgressBar,
    QHeaderView, QMessageBox, QFrame, QSplitter, QScrollArea
)

# =====================================================================
# 1. SMART ANALYTICS ENGINE (Retained & Adapted from drives.py)
# =====================================================================

CRITICAL_HARDWARE_IDS = {5, 187, 196, 197, 198}
INTERFACE_ERROR_IDS = {188, 199}

DEJARGONED_DESCRIPTIONS = {
    "05": "Physical Storage Blocks (Reallocated Sectors Surface Health)",
    "09": "Operational Lifespan Accumulation (Total Power-On Hours)",
    "12": "Hardware Power Interventions (Total Drive Boot Cycles)",
    "187": "Data Read Consistency (Uncorrectable Sector Verification Failures)",
    "188": "Controller Instruction Integrity (Command Processing Timeouts)",
    "194": "Thermal Enclosure Regulation (Internal Core Drive Temperature)",
    "196": "Emergency Storage Re-routing (Sector Reallocation Event Records)",
    "197": "Unstable Storage Sectors (Current Pending Bad Block Remap Queue)",
    "198": "Damaged Media Boundaries (Uncorrectable Platter Sector Counts)",
    "199": "SATA Motherboard Interface Pipeline (Data Transmission CRC Errors)",
    "NVMe": "Solid-State Silicon Drive Wear-Leveling Lifespan Remaining",
}

FRIENDLY_STATUS = {
    "FAILING": "DANGER: Active hardware degradation detected",
    "WARNING": "WEAR: Early warning signs or wear threshold reached",
    "INTERFACE ERR": "CABLE NOISE: Glitches from hotplugging or faulty cable",
    "HEALTHY": "PERFECT: Parameter operating within safe limits"
}

def analyze_system_drives() -> List[Dict[str, Any]]:
    """Runs smartctl -j to gather telemetry and computes safety margins."""
    try:
        scan_res = subprocess.run(["sudo", "smartctl", "--scan-open", "-j"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        scan_data = json.loads(scan_res.stdout)
    except Exception:
        return []

    devices = scan_data.get("devices", [])
    analyzed_drives = []

    for dev in devices:
        dev_path = dev.get("name")
        if not dev_path:
            continue
        try:
            res = subprocess.run(["sudo", "smartctl", "-a", "-j", dev_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            smart_data = json.loads(res.stdout)
        except subprocess.CalledProcessError as e:
            if e.stdout:
                smart_data = json.loads(e.stdout)
            else:
                continue

        model = smart_data.get("model_name", "Unknown Drive")
        serial = smart_data.get("serial_number", "N/A")
        scored_metrics = []
        worst_hardware_margin = 100.0
        has_critical_failure = False
        has_interface_warning = False

        if "ata_smart_attributes" in smart_data:
            attributes = smart_data["ata_smart_attributes"].get("table", [])
            for attr in attributes:
                attr_id = attr["id"]
                current = attr["value"]
                thresh = attr["thresh"]
                raw_val = attr["raw"]["value"]

                baseline = 200 if current > 100 else 100
                if current > 200:
                    baseline = 253

                if baseline > thresh:
                    margin_pct = ((current - thresh) / (baseline - thresh)) * 100
                    margin_pct = max(0.0, min(100.0, margin_pct))
                else:
                    margin_pct = 100.0

                is_critical = attr_id in CRITICAL_HARDWARE_IDS
                is_interface_attr = attr_id in INTERFACE_ERROR_IDS

                if is_critical and raw_val > 0 and not is_interface_attr:
                    margin_pct = max(0.0, margin_pct - (raw_val * 15))

                if margin_pct <= 0 or current <= thresh:
                    status, status_icon = ("INTERFACE ERR", "🔀") if is_interface_attr else ("FAILING", "🔴")
                    if is_critical and not is_interface_attr:
                        has_critical_failure = True
                elif margin_pct < 40 or (is_critical and raw_val > 0):
                    status, status_icon = "WARNING", "🟡"
                    if is_interface_attr:
                        has_interface_warning = True
                else:
                    status, status_icon = "HEALTHY", "🟢"

                if not is_interface_attr and margin_pct < worst_hardware_margin:
                    worst_hardware_margin = margin_pct

                str_id = f"{attr_id:02d}"
                scored_metrics.append({
                    "jargon_id": str_id,
                    "jargon_name": attr["name"],
                    "clean_name": DEJARGONED_DESCRIPTIONS.get(str_id, attr["name"]),
                    "status": status,
                    "icon": status_icon,
                    "friendly_status": FRIENDLY_STATUS.get(status, status),
                    "margin": f"{round(margin_pct, 1)}%",
                    "margin_val": margin_pct,
                    "current": str(current),
                    "thresh": str(thresh),
                    "raw": attr["raw"]["string"],
                    "_score": margin_pct + (0 if (is_critical or is_interface_attr) else 100)
                })

        elif "nvme_smart_health_information_log" in smart_data:
            nvme = smart_data["nvme_smart_health_information_log"]
            used_pct = nvme.get("percentage_used", 0)
            margin_pct = max(0.0, 100.0 - used_pct)
            worst_hardware_margin = margin_pct

            status, status_icon = ("HEALTHY", "🟢") if margin_pct > 20 else ("WARNING", "🟡") if margin_pct > 5 else ("FAILING", "🔴")
            if status == "FAILING":
                has_critical_failure = True

            scored_metrics.append({
                "jargon_id": "NVMe",
                "jargon_name": "percentage_used",
                "clean_name": DEJARGONED_DESCRIPTIONS.get("NVMe", "NVMe Wear Leveling"),
                "status": status,
                "icon": status_icon,
                "friendly_status": FRIENDLY_STATUS.get(status, status),
                "margin": f"{margin_pct}%",
                "margin_val": margin_pct,
                "current": str(100 - used_pct),
                "thresh": "0",
                "raw": f"{used_pct}% used",
                "_score": margin_pct
            })

        if has_critical_failure or worst_hardware_margin == 0:
            overall_status, overall_icon = "CRITICAL", "🔴"
        elif worst_hardware_margin < 50:
            overall_status, overall_icon = "WARNING", "🟡"
        elif has_interface_warning:
            overall_status, overall_icon = "INTF_WARN", "🟡"
        else:
            overall_status, overall_icon = "HEALTHY", "🟢"

        scored_metrics.sort(key=lambda x: x["_score"])
        macro_priority = 0 if overall_status == "CRITICAL" else 1 if overall_status == "WARNING" else 2 if overall_status == "INTF_WARN" else 3

        analyzed_drives.append({
            "path": dev_path,
            "model": model,
            "serial": serial,
            "status": overall_status,
            "icon": overall_icon,
            "metrics": scored_metrics,
            "sort_key": (macro_priority, worst_hardware_margin)
        })

    return sorted(analyzed_drives, key=lambda x: x["sort_key"])

# =====================================================================
# 2. BACKGROUND WORKER THREADS
# =====================================================================

class DriveScanWorker(QThread):
    """Background worker thread to run smartctl scans without blocking the GUI."""
    scanned = pyqtSignal(list)

    def run(self):
        drives = analyze_system_drives()
        self.scanned.emit(drives)


class DirectIOBenchmarkWorker(QThread):
    """Robust unbuffered storage benchmark engine with full error catching & live feedback."""
    progress = pyqtSignal(int, int, str, float, float)  # step, total, block_label, write_mb_s, read_mb_s
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target_path: str, file_size_mb: int = 128):
        super().__init__()
        self.target_path = target_path
        self.file_size_mb = file_size_mb
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        temp_file = os.path.join(self.target_path, ".smart_bench_test.tmp")
        block_steps = [
            (4096, "4 KB"),
            (16384, "16 KB"),
            (65536, "64 KB"),
            (262144, "256 KB"),
            (1048576, "1 MB"),
            (4194304, "4 MB"),
            (16777216, "16 MB")
        ]

        total_steps = len(block_steps)
        total_bytes = self.file_size_mb * 1024 * 1024

        try:
            for idx, (block_size, label) in enumerate(block_steps):
                if self._is_cancelled:
                    break

                chunk = b'X' * block_size
                chunks_to_write = total_bytes // block_size

                # 1. WRITE TEST: Force synchronous unbuffered write & hardware flush
                try:
                    t0 = time.perf_counter()
                    with open(temp_file, "wb", buffering=0) as f:
                        for _ in range(chunks_to_write):
                            if self._is_cancelled:
                                break
                            f.write(chunk)
                        f.flush()
                        os.fsync(f.fileno()) # Forces disk controller to write to physical media
                    t1 = time.perf_counter()

                    elapsed = t1 - t0
                    written_mb = (chunks_to_write * block_size) / (1024 * 1024)
                    write_speed = written_mb / elapsed if elapsed > 0 else 0.0
                except Exception:
                    write_speed = 0.0

                if self._is_cancelled:
                    break

                # 2. DROP CACHES: Clear Linux VFS page cache so read hits the physical disk
                try:
                    subprocess.run(["sudo", "sh", "-c", "sync && echo 3 > /proc/sys/vm/drop_caches"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                except Exception:
                    pass

                # 3. READ TEST: Measure actual physical retrieval speed from sda
                try:
                    t0 = time.perf_counter()
                    read_bytes = 0
                    with open(temp_file, "rb", buffering=0) as f:
                        while True:
                            if self._is_cancelled:
                                break
                            buf = f.read(block_size)
                            if not buf:
                                break
                            read_bytes += len(buf)
                    t1 = time.perf_counter()

                    elapsed = t1 - t0
                    read_mb = read_bytes / (1024 * 1024)
                    read_speed = read_mb / elapsed if elapsed > 0 else 0.0
                except Exception:
                    read_speed = 0.0

                self.progress.emit(idx + 1, total_steps, label, write_speed, read_speed)

        except Exception as err:
            self.error.emit(str(err))
        finally:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
            self.finished.emit()

# =====================================================================
# 3. CUSTOM ATTO-STYLE SPEED BAR CANVAS WIDGET
# =====================================================================

class SpeedBarCanvas(QWidget):
    """Custom QPainter widget with dynamic sizing and explicit W:/R: labels."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.results: List[Dict[str, Any]] = []
        self.setMinimumHeight(320)

    def set_results(self, results: List[Dict[str, Any]]):
        self.results = results
        # Dynamically adjust minimum height so scrollbar appears when needed
        if results:
            self.setMinimumHeight(45 + (len(results) * 42))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()

        # Background
        painter.fillRect(0, 0, w, h, QColor("#1a1b26"))

        # Draw Legend Bar at Top
        painter.fillRect(0, 0, w, 32, QColor("#1f2335"))
        painter.setPen(QColor("#7aa2f7"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(15, 0, 150, 32, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "📊 Throughput (MB/s):")

        # Write Legend Box
        painter.setBrush(QBrush(QColor("#f97316")))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(170, 11, 12, 12, 2, 2)
        painter.setPen(QColor("#c0caf5"))
        painter.drawText(190, 0, 80, 32, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "🟠 Write (W)")

        # Read Legend Box
        painter.setBrush(QBrush(QColor("#38bdf8")))
        painter.drawRoundedRect(280, 11, 12, 12, 2, 2)
        painter.drawText(300, 0, 80, 32, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "🔵 Read (R)")

        if not self.results:
            painter.setPen(QColor("#565f89"))
            painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "⚡ Select a target mount point and click 'Start Benchmark' to measure Direct I/O throughput.")
            return

        max_speed = max([max(r["write"], r["read"]) for r in self.results] + [100.0])
        margin_left = 75
        margin_right = 110
        chart_w = max(100, w - margin_left - margin_right)

        row_h = 40
        start_y = 45

        # Top Scale Axis Line
        painter.setPen(QPen(QColor("#414868"), 1))
        painter.drawLine(margin_left, 40, margin_left + chart_w, 40)

        # Scale Ticks
        painter.setFont(QFont("Segoe UI", 8))
        for i in range(5):
            ratio = i / 4.0
            tick_x = margin_left + int(ratio * chart_w)
            val = max_speed * ratio
            painter.setPen(QColor("#565f89"))
            painter.drawLine(tick_x, 36, tick_x, 40)
            painter.drawText(tick_x - 25, 22, 50, 14, Qt.AlignmentFlag.AlignCenter, f"{val:.0f} MB/s")

        # Draw Dual Bars with explicit W / R labels
        bar_h = 7
        for idx, res in enumerate(self.results):
            y = start_y + idx * row_h

            # Block Size Label
            painter.setPen(QColor("#c0caf5"))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            painter.drawText(5, y, margin_left - 10, row_h, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, res["label"])

            # Write Bar (Orange)
            w_len = int((res["write"] / max_speed) * chart_w) if max_speed > 0 else 0
            if w_len > 0:
                painter.setBrush(QBrush(QColor("#f97316")))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawRoundedRect(QRectF(margin_left, y + 4, w_len, bar_h), 2, 2)

                painter.setPen(QColor("#f97316"))
                painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
                painter.drawText(int(margin_left + w_len + 6), y + 1, 90, bar_h + 6, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, f"W: {res['write']:.1f}")

            # Read Bar (Cyan)
            r_len = int((res["read"] / max_speed) * chart_w) if max_speed > 0 else 0
            if r_len > 0:
                painter.setBrush(QBrush(QColor("#38bdf8")))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawRoundedRect(QRectF(margin_left, y + bar_h + 8, r_len, bar_h), 2, 2)

                painter.setPen(QColor("#38bdf8"))
                painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
                painter.drawText(int(margin_left + r_len + 6), y + bar_h + 5, 90, bar_h + 6, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, f"R: {res['read']:.1f}")

            # Row separator line
            painter.setPen(QPen(QColor("#24283b"), 1))
            painter.drawLine(margin_left, y + row_h - 2, margin_left + chart_w, y + row_h - 2)

# =====================================================================
# 4. MAIN MODERN DESKTOP DASHBOARD WINDOW
# =====================================================================

class SmartDataGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Disk SMART & Performance Benchmark Dashboard")
        self.resize(1180, 820)
        self.drives: List[Dict[str, Any]] = []
        self.bench_results: List[Dict[str, Any]] = []
        self.bench_worker: Optional[DirectIOBenchmarkWorker] = None

        self.init_ui()
        self.apply_dark_theme()
        self.refresh_drives()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 12, 12, 12)

        # Header Bar
        header = QFrame()
        header.setObjectName("HeaderFrame")
        header.setMaximumHeight(50)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)

        title_lbl = QLabel("💾 Disk SMART Data & Benchmark Dashboard")
        title_lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title_lbl.setStyleSheet("color: #7aa2f7;")

        self.btn_rescan = QPushButton("🔄 Rescan Disks")
        self.btn_rescan.clicked.connect(self.refresh_drives)

        header_layout.addWidget(title_lbl)
        header_layout.addStretch()
        header_layout.addWidget(self.btn_rescan)
        main_layout.addWidget(header)

        # Main Horizontal Splitter (Sidebar + Main View)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Sidebar: Drive Selection List
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)

        side_lbl = QLabel("Storage Drives (Worst ➜ Best)")
        side_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        side_lbl.setStyleSheet("color: #bb9af7;")

        self.drive_list_widget = QListWidget()
        self.drive_list_widget.currentRowChanged.connect(self.on_drive_selected)

        sidebar_layout.addWidget(side_lbl)
        sidebar_layout.addWidget(self.drive_list_widget)
        splitter.addWidget(sidebar)

        # Right Panel: Tabbed Views
        right_panel = QTabWidget()
        right_panel.setObjectName("MainTabs")

        # Tab 1: SMART Telemetry Matrix
        tab_smart = QWidget()
        tab_smart_layout = QVBoxLayout(tab_smart)

        self.lbl_drive_banner = QLabel("Select a drive to view SMART metrics")
        self.lbl_drive_banner.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.lbl_drive_banner.setStyleSheet("color: #7dcfff; padding: 6px; background: #1f2335; border-radius: 6px;")

        self.table_smart = QTableWidget()
        self.table_smart.setColumnCount(6)
        self.table_smart.setHorizontalHeaderLabels(["ID", "Clean Parameter Name", "Status", "Safety Margin", "Current/Thresh", "RAW String"])
        self.table_smart.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        tab_smart_layout.addWidget(self.lbl_drive_banner)
        tab_smart_layout.addWidget(self.table_smart)
        right_panel.addTab(tab_smart, "📊 Worst-to-Best SMART Analytics")

        # Tab 2: Direct I/O Performance Test
        tab_bench = QWidget()
        tab_bench_layout = QVBoxLayout(tab_bench)

        # Benchmark Controls
        ctrl_box = QHBoxLayout()
        ctrl_box.addWidget(QLabel("Target Mount Point:"))

        self.combo_mounts = QComboBox()
        self.populate_mount_points()
        ctrl_box.addWidget(self.combo_mounts)

        ctrl_box.addWidget(QLabel("Workload Size:"))
        self.combo_size = QComboBox()
        self.combo_size.addItems(["64 MB", "128 MB", "256 MB", "512 MB"])
        self.combo_size.setCurrentText("128 MB")
        ctrl_box.addWidget(self.combo_size)

        self.btn_start_bench = QPushButton("▶ Start Benchmark")
        self.btn_start_bench.setStyleSheet("background-color: #10b981; color: white; font-weight: bold;")
        self.btn_start_bench.clicked.connect(self.start_benchmark)
        ctrl_box.addWidget(self.btn_start_bench)

        self.btn_stop_bench = QPushButton("⏹ Stop")
        self.btn_stop_bench.setEnabled(False)
        self.btn_stop_bench.clicked.connect(self.stop_benchmark)
        ctrl_box.addWidget(self.btn_stop_bench)

        tab_bench_layout.addLayout(ctrl_box)

        self.bench_progress = QProgressBar()
        self.bench_progress.setValue(0)
        tab_bench_layout.addWidget(self.bench_progress)

        # Scroll Area wrapping the Speed Chart to eliminate overhang
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self.speed_canvas = SpeedBarCanvas()
        scroll_area.setWidget(self.speed_canvas)

        tab_bench_layout.addWidget(scroll_area)
        right_panel.addTab(tab_bench, "⚡ Direct I/O Performance Test")

        splitter.addWidget(right_panel)
        splitter.setSizes([300, 880])
        main_layout.addWidget(splitter)

    def populate_mount_points(self):
        self.combo_mounts.clear()
        try:
            res = subprocess.run(["df", "-h"], stdout=subprocess.PIPE, text=True)
            lines = res.stdout.strip().split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 6 and parts[0].startswith("/dev/"):
                    self.combo_mounts.addItem(f"{parts[5]} ({parts[0]} - {parts[1]})", parts[5])
        except Exception:
            self.combo_mounts.addItem("/ (Root)", "/")

    def refresh_drives(self):
        self.btn_rescan.setEnabled(False)
        self.btn_rescan.setText("⏳ Scanning...")

        self.scan_worker = DriveScanWorker()
        self.scan_worker.scanned.connect(self.on_drives_scanned)
        self.scan_worker.start()

    def on_drives_scanned(self, drives: List[Dict[str, Any]]):
        self.drives = drives
        self.btn_rescan.setEnabled(True)
        self.btn_rescan.setText("🔄 Rescan Disks")

        self.drive_list_widget.clear()
        if not drives:
            QMessageBox.warning(self, "No Storage Drives", "No SMART storage drives were detected. Make sure you run with sudo privileges.")
            return

        for d in drives:
            item_text = f"{d['icon']}  {d['path']} ({d['model'][:16]})"
            item = QListWidgetItem(item_text)

            if d['status'] == "CRITICAL":
                item.setForeground(QColor("#f7768e"))
            elif d['status'] in {"WARNING", "INTF_WARN"}:
                item.setForeground(QColor("#e0af68"))
            else:
                item.setForeground(QColor("#9ece6a"))

            self.drive_list_widget.addItem(item)

        self.drive_list_widget.setCurrentRow(0)

    def on_drive_selected(self, row: int):
        if row < 0 or row >= len(self.drives):
            return

        drive = self.drives[row]
        self.lbl_drive_banner.setText(f"💾 Drive: {drive['path']} | Model: {drive['model']} | Serial: {drive['serial']}")

        self.table_smart.setRowCount(0)
        for m in drive["metrics"]:
            r = self.table_smart.rowCount()
            self.table_smart.insertRow(r)

            self.table_smart.setItem(r, 0, QTableWidgetItem(m["jargon_id"]))
            self.table_smart.setItem(r, 1, QTableWidgetItem(m["clean_name"]))

            status_item = QTableWidgetItem(f"{m['icon']} {m['status']}")
            if m['status'] == "FAILING":
                status_item.setForeground(QColor("#f7768e"))
            elif m['status'] in {"WARNING", "INTERFACE ERR"}:
                status_item.setForeground(QColor("#e0af68"))
            else:
                status_item.setForeground(QColor("#9ece6a"))

            self.table_smart.setItem(r, 2, status_item)
            self.table_smart.setItem(r, 3, QTableWidgetItem(m["margin"]))
            self.table_smart.setItem(r, 4, QTableWidgetItem(f"{m['current']} / {m['thresh']}"))
            self.table_smart.setItem(r, 5, QTableWidgetItem(m["raw"]))

    def start_benchmark(self):
        mount_path = self.combo_mounts.currentData() or "/"
        size_str = self.combo_size.currentText().split()[0]
        size_mb = int(size_str)

        self.bench_results.clear()
        self.speed_canvas.set_results([])
        self.bench_progress.setValue(0)

        self.btn_start_bench.setEnabled(False)
        self.btn_stop_bench.setEnabled(True)

        self.bench_worker = DirectIOBenchmarkWorker(mount_path, size_mb)
        self.bench_worker.progress.connect(self.on_bench_progress)
        self.bench_worker.finished.connect(self.on_bench_finished)
        self.bench_worker.error.connect(self.on_bench_error)
        self.bench_worker.start()

    def stop_benchmark(self):
        if self.bench_worker:
            self.bench_worker.cancel()

    def on_bench_progress(self, step: int, total: int, label: str, w_speed: float, r_speed: float):
        pct = int((step / total) * 100)
        self.bench_progress.setValue(pct)

        self.bench_results.append({
            "label": label,
            "write": w_speed,
            "read": r_speed
        })
        self.speed_canvas.set_results(self.bench_results)

    def on_bench_finished(self):
        self.btn_start_bench.setEnabled(True)
        self.btn_stop_bench.setEnabled(False)

    def on_bench_error(self, err: str):
        QMessageBox.critical(self, "Benchmark Error", f"An error occurred during direct I/O benchmark:\n{err}")

    def apply_dark_theme(self):
        """Applies modern dark styling using TokyoNight / Catppuccin color palettes."""
        qss = """
        QMainWindow { background-color: #1a1b26; }
        QWidget { color: #a9b1d6; font-family: 'Segoe UI', sans-serif; }
        #HeaderFrame { background-color: #1f2335; border-bottom: 1px solid #414868; }
        QListWidget { background-color: #16161e; border: 1px solid #414868; border-radius: 6px; font-size: 13px; }
        QListWidget::item:selected { background-color: #283451; border-radius: 4px; }
        QTableWidget { background-color: #16161e; border: 1px solid #414868; gridline-color: #24283b; font-size: 12px; }
        QHeaderView::section { background-color: #1f2335; color: #7aa2f7; font-weight: bold; padding: 4px; border: 1px solid #414868; }
        QTabWidget::pane { border: 1px solid #414868; background-color: #1a1b26; }
        QTabBar::tab { background: #1f2335; color: #a9b1d6; padding: 8px 16px; font-weight: bold; border-top-left-radius: 4px; border-top-right-radius: 4px; }
        QTabBar::tab:selected { background: #24283b; color: #7aa2f7; border-bottom: 2px solid #7aa2f7; }
        QPushButton { background-color: #24283b; color: #c0caf5; border: 1px solid #414868; border-radius: 4px; padding: 6px 14px; font-weight: bold; }
        QPushButton:hover { background-color: #3b4261; }
        QComboBox { background-color: #1f2335; border: 1px solid #414868; border-radius: 4px; padding: 4px; }
        QProgressBar { border: 1px solid #414868; border-radius: 4px; text-align: center; background: #16161e; }
        QProgressBar::chunk { background-color: #7aa2f7; }
        """
        self.setStyleSheet(qss)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SmartDataGUI()
    window.show()
    sys.exit(app.exec())
