# 📊 smartctl-TUI

A modern, responsive Terminal User Interface (TUI) for storage drive health diagnostics on Linux. Inspired by the dense aesthetic of `btop`, this dashboard wraps `smartctl` telemetry inside a responsive interface that brings critical insights to your attention.

## 💡 The Core Concept: Worst-to-Best Analytics
Traditional S.M.A.R.T. utilities list parameters alphabetically or by numerical ID, where it's not so simple to spot a weak drive.

`smartctl-TUI` helps by calculating a real-time **Safety Margin %** for every single attribute:
\[\text{Safety Margin \%} = \frac{\text{Current} - \text{Threshold}}{\text{Baseline} - \text{Threshold}} \times 100\]

* **Dynamic Array Sorting:** Drives with the lowest margins or highest structural failure warnings automatically float to the top of your sidebar.
* **Metric Prioritization:** Inside each drive profile, attributes are sorted strictly from **worst to best**. If a single critical sector or parameter begins to degrade, it moves instantly to Row 1.

### 🛠️ The Hotplug & Cable Filter
`smartctl-TUI` implements an intelligent parsing layer that separates **structural media failure** (like bad sectors) from **interface noise** (like `UDMA_CRC_Error_Count` or `Command_Timeout` artifacts triggered by live hotplugging). Interface faults are isolated and labeled without falsely declaring your physical drive dead, though this distinction is not so easy to discern.

## 🚀 Installation & Usage

### 1. Install System Dependencies
Ensure `smartmontools` is installed on your Linux system:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install smartmontools python3-textual

# Fedora
sudo dnf install smartmontools

# Arch Linux
sudo pacman -S smartmontools
```

### 2. Clone and Run
```bash
git clone https://github.com/van0014/smartctl-tui
cd smartctl-tui

# Run with root privileges to allow disk polling
sudo python3 app.py
```

## 🎮 Keybindings
* `R` - Force rescan all system disks and refresh background telemetry.
* `Q` - Cleanly exit the dashboard application.
* `Ctrl + P` - Open the native Textual palette to swap between 18 premium built-in color themes (including Catppuccin and Dracula).
