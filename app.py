#!/usr/bin/env python3
import json
import os
from pathlib import Path
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, ListView, ListItem, Label, Tree, DataTable
from textual.containers import Horizontal, Vertical
from drives import get_system_drives

CONFIG_DIR = Path(os.path.expanduser("~/.config/smartctl-tui"))
CONFIG_FILE = CONFIG_DIR / "config.json"

class SmartctlDiskApp(App):
    TITLE = "📊 smartctl-TUI // Drive Analytics Dashboard"
    BINDINGS = [
        ("q", "quit", "Exit Dashboard"), 
        ("r", "refresh", "Scan Disks"),
        ("v", "toggle_view", "Toggle Standard / Advanced Mode")
    ]
    
    CSS = """
    Screen { background: #11121d; color: #a9b1d6; }
    Header { background: #1f2335; color: #7aa2f7; text-style: bold; }
    Footer { background: #1f2335; color: #565f89; }
    #sidebar { width: 30%; border: round #414868; padding: 1; background: #1a1b26; }
    #main_panel { width: 70%; border: round #414868; padding: 1; background: #1a1b26; }
    ListItem { padding: 0 1; background: transparent; }
    ListItem:hover { background: #24283b; text-style: bold; }
    Tree { background: transparent; color: #a9b1d6; }
    DataTable { background: transparent; color: #a9b1d6; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("[bold #7aa2f7]Drives (Worst ➜ Best)[/bold #7aa2f7]\n")
                yield ListView(id="drive_list")
            with Vertical(id="main_panel"):
                yield Label("[bold #7aa2f7]Hardware Parameters[/bold #7aa2f7]", id="panel_title")
                yield Label("[dim #565f89]Standard Mode: Select rows to expand individual metrics. Press 'V' for advanced grid.[/dim #565f89]", id="panel_mode_label")
                yield Tree("Drives", id="metric_tree")
                yield DataTable(id="metric_table")
        yield Footer()

    def on_ready(self) -> None:
        self.advanced_mode = self.load_persisted_config()
        self.current_drive_idx = 0
        self.active_tree = self.query_one("#metric_tree", Tree)
        self.active_table = self.query_one("#metric_table", DataTable)
        
        self.active_tree.show_root = False
        self.active_tree.display = not self.advanced_mode
        self.active_table.display = self.advanced_mode
        
        self.action_refresh()

    def load_persisted_config(self) -> bool:
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    return data.get("advanced_mode", False)
        except Exception:
            pass
        return False

    def save_persisted_config(self) -> None:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_FILE, "w") as f:
                json.dump({"advanced_mode": self.advanced_mode}, f)
        except Exception:
            pass

    def action_toggle_view(self) -> None:
        self.advanced_mode = not self.advanced_mode
        self.save_persisted_config()
        self.sync_view_layout()
        self.render_active_metrics()

    def sync_view_layout(self) -> None:
        mode_label = self.query_one("#panel_mode_label", Label)
        if self.advanced_mode:
            mode_label.update("[bold #ff9e64]Advanced View: Technical S.M.A.R.T. Matrix Active[/bold #ff9e64]")
            self.active_tree.display = False
            self.active_table.display = True
        else:
            mode_label.update("[dim #565f89]Standard Mode: Select rows to expand individual metrics. Press 'V' for advanced grid.[/dim #565f89]")
            self.active_table.display = False
            self.active_tree.display = True

    def action_refresh(self) -> None:
        self.drives = get_system_drives()
        drive_list = self.query_one("#drive_list", ListView)
        drive_list.clear()
        
        if not self.drives:
            drive_list.append(ListItem(Label("No SMART storage drives found.")))
            return

        for drive in self.drives:
            color = "red" if drive["status"] == "CRITICAL" else "yellow" if drive["status"] in {"WARNING", "INTF_WARN"} else "green"
            label_text = f"{drive['icon']} [{color}]{drive['path']}[/{color}] [dim]{drive['model'][:12]}[/dim]"
            drive_list.append(ListItem(Label(label_text)))
            
        drive_list.index = 0
        self.sync_view_layout()
        self.render_active_metrics()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        drive_list_widget = self.query_one("#drive_list", ListView)
        if event.list_view == drive_list_widget:
            if drive_list_widget.index is not None:
                self.current_drive_idx = drive_list_widget.index
                self.render_active_metrics()

    def render_active_metrics(self) -> None:
        if self.current_drive_idx >= len(self.drives): return
        drive = self.drives[self.current_drive_idx]

        if self.advanced_mode:
            self.active_table.clear(columns=True)
            self.active_table.add_columns("ID", "Technical Metric Name", "Status", "Margin", "Current", "Thresh", "Raw Value")
            for m in drive["metrics"]:
                color = "red" if m["status"] == "FAILING" else "yellow" if m["status"] in {"WARNING", "INTERFACE ERR"} else "green"
                status_cell = f"{m['icon']} [{color}]{m['status']}[/{color}]"
                self.active_table.add_row(
                    f"[dim]{m['jargon_id']}[/dim]", f"[bold]{m['jargon_name']}[/bold]",
                    status_cell, m["margin"], m["current"], m["thresh"], f"[cyan]{m['raw']}[/cyan]"
                )
        else:
            self.active_tree.clear()
            for idx, m in enumerate(drive["metrics"]):
                color = "red" if m["status"] == "FAILING" else "yellow" if m["status"] in {"WARNING", "INTERFACE ERR"} else "green"
                parent_label = f"[dim]{idx+1:2d}[/dim]  [bold #7aa2f7]{m['clean_name']:<65}[/bold #7aa2f7]  [{color}]{m['margin']} ({m['status']})[/{color}]"
                
                node = self.active_tree.root.add(parent_label, expand=False)
                
                jargon_details = (
                    f"     └─ [dim]Name:[/dim] [cyan]{m['jargon_name']}[/cyan]"
                    f" | [dim]ID:[/dim] {m['jargon_id']}"
                    f" | [dim]Val/Thresh:[/dim] {m['current']}/{m['thresh']}"
                    f" | [dim]Raw Data:[/dim] [bold #ff9e64]{m['raw']}[/bold #ff9e64]"
                )
                node.add_leaf(jargon_details)

if __name__ == "__main__":
    SmartctlDiskApp().run()
