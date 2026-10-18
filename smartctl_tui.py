#!/usr/bin/env python3
import subprocess
import json
import sys
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, ListView, ListItem, Label, DataTable
from textual.containers import Horizontal, Vertical

CRITICAL_HARDWARE_IDS = {5, 187, 196, 197, 198}
INTERFACE_ERROR_IDS = {188, 199}

def get_system_drives():
    """Discovers system drives and analyzes their metrics using smartctl JSON."""
    try:
        scan_res = subprocess.run(["sudo", "smartctl", "--scan-open", "-j"], 
                                  stdout=subprocess.PIPE, text=True, check=True)
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
            res = subprocess.run(["sudo", "smartctl", "-a", "-j", dev_path], 
                                 stdout=subprocess.PIPE, text=True, check=True)
            smart_data = json.loads(res.stdout)
        except subprocess.CalledProcessError as e:
            if e.stdout:
                smart_data = json.loads(e.stdout)
            else:
                continue

        model = smart_data.get("model_name", "Unknown Drive")
        scored_metrics = []
        worst_hardware_margin = 100.0
        has_critical_failure = False
        has_interface_warning = False

        if "ata_smart_attributes" in smart_data:
            attributes = smart_data["ata_smart_attributes"].get("table", [])
            for attr in attributes:
                attr_id = attr["id"]
                name = attr["name"]
                current = attr["value"]
                worst = attr["worst"]
                thresh = attr["thresh"]
                raw_val = attr["raw"]["value"]
                
                baseline = 200 if current > 100 else 100
                if current > 200: baseline = 253

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
                    if is_interface_attr:
                        status, status_icon = "INTERFACE ERR", "🔀"
                        has_interface_warning = True
                    else:
                        status, status_icon = "FAILING", "🔴"
                        if is_critical: has_critical_failure = True
                elif margin_pct < 40 or (is_critical and raw_val > 0):
                    status, status_icon = "WARNING", "🟡"
                    if is_interface_attr: has_interface_warning = True
                else:
                    status, status_icon = "HEALTHY", "🟢"

                if not is_interface_attr and margin_pct < worst_hardware_margin:
                    worst_hardware_margin = margin_pct

                sorting_score = margin_pct + (0 if (is_critical or is_interface_attr) else 100)

                scored_metrics.append({
                    "id": f"{attr_id:02d}", "name": name, "status": status, "icon": status_icon,
                    "margin": f"{round(margin_pct, 1)}%", "current": str(current),
                    "thresh": str(thresh), "raw": attr["raw"]["string"], "_score": sorting_score
                })

        elif "nvme_smart_health_information_log" in smart_data:
            nvme = smart_data["nvme_smart_health_information_log"]
            used_pct = nvme.get("percentage_used", 0)
            margin_pct = max(0.0, 100.0 - used_pct)
            worst_hardware_margin = margin_pct
            
            status, status_icon = ("HEALTHY", "🟢") if margin_pct > 20 else ("WARNING", "🟡") if margin_pct > 5 else ("FAILING", "🔴")
            if status == "FAILING": has_critical_failure = True
            
            scored_metrics.append({
                "id": "NVMe", "name": "Percentage Life Remaining", "status": status, "icon": status_icon,
                "margin": f"{margin_pct}%", "current": str(100 - used_pct), "thresh": "0", "raw": f"{used_pct}% used", "_score": margin_pct
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
            "path": dev_path, "model": model, "status": overall_status, "icon": overall_icon,
            "metrics": scored_metrics, "sort_key": (macro_priority, worst_hardware_margin)
        })

    analyzed_drives.sort(key=lambda x: x["sort_key"])
    return analyzed_drives


class SmartctlDiskApp(App):
    """A clean, professional Python TUI for smartctl analytics."""
    TITLE = "📊 smartctl-TUI // Drive Analytics Dashboard"
    BINDINGS = [("q", "quit", "Exit Dashboard"), ("r", "refresh", "Scan Disks")]
    
    CSS = """
    Screen { background: #11121d; color: #a9b1d6; }
    Header { background: #1f2335; color: #7aa2f7; text-style: bold; }
    Footer { background: #1f2335; color: #565f89; }
    #sidebar { width: 35%; border: round #414868; padding: 1; background: #1a1b26; }
    #main_panel { width: 65%; border: round #414868; padding: 1; background: #1a1b26; }
    ListItem { padding: 0 1; background: transparent; }
    ListItem:hover { background: #24283b; text-style: bold; }
    DataTable { background: transparent; color: #a9b1d6; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("[bold #7aa2f7]Drives (Worst ➜ Best)[/bold #7aa2f7]\n")
                yield ListView(id="drive_list")
            with Vertical(id="main_panel"):
                yield Label("[bold #7aa2f7]S.M.A.R.T. Metrics (Worst ➜ Best)[/bold #7aa2f7]\n")
                yield DataTable(id="metric_table")
        yield Footer()

    def on_mount(self) -> None:
        self.table = self.query_one("#metric_table", DataTable)
        self.table.add_columns("ID", "Parameter Name", "Status", "Margin", "Current", "Thresh", "Raw Value")
        self.action_refresh()

    def action_refresh(self) -> None:
        self.drives = get_system_drives()
        drive_list = self.query_one("#drive_list", ListView)
        drive_list.clear()

        if not self.drives:
            drive_list.append(ListItem(Label("No SMART storage drives found.")))
            return

        for idx, drive in enumerate(self.drives):
            if drive["status"] == "CRITICAL":
                color = "red"
            elif drive["status"] in {"WARNING", "INTF_WARN"}:
                color = "yellow"
            else:
                color = "green"
            
            label_text = f"{drive['icon']} [{color}]{drive['path']}[/{color}] [dim]{drive['model'][:14]}[/dim]"
            drive_list.append(ListItem(Label(label_text), id=f"drive_{idx}"))
            
        drive_list.index = 0
        self.display_metrics(0)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.item and event.item.id:
            idx = int(event.item.id.split("_")[1])
            self.display_metrics(idx)

    def display_metrics(self, drive_idx: int) -> None:
        self.table.clear()
        if drive_idx >= len(self.drives):
            return
            
        drive = self.drives[drive_idx]
        for m in drive["metrics"]:
            if m["status"] == "FAILING":
                color = "red"
            elif m["status"] in {"WARNING", "INTERFACE ERR"}:
                color = "yellow"
            else:
                color = "green"
            status_cell = f"{m['icon']} [{color}]{m['status']}[/{color}]"
            
            self.table.add_row(
                f"[dim]{m['id']}[/dim]",
                f"[bold]{m['name']}[/bold]",
                status_cell,
                m["margin"],
                m["current"],
                m["thresh"],
                f"[cyan]{m['raw']}[/cyan]"
            )

if __name__ == "__main__":
    SmartctlDiskApp().run()
