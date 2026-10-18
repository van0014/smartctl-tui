import subprocess
import json

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
    "WARN": "Solid-State Controller Hardware Critical Status Alerts"
}

FRIENDLY_STATUS = {
    "FAILING": "⚠️ DANGER: Active hardware degradation / backup data immediately",
    "WARNING": "⏳ WEAR: Normal degradation or early warning signs",
    "INTERFACE ERR": "🔀 CABLE NOISE: Glitches detected from hotplugging or a loose cord",
    "HEALTHY": "✅ PERFECT: Parameter is running within normal limits"
}

def get_system_drives():
    try:
        scan_res = subprocess.run(["sudo", "smartctl", "--scan-open", "-j"], stdout=subprocess.PIPE, text=True, check=True)
        scan_data = json.loads(scan_res.stdout)
    except Exception:
        return []

    devices = scan_data.get("devices", [])
    analyzed_drives = []

    for dev in devices:
        dev_path = dev.get("name")
        if not dev_path: continue
        try:
            res = subprocess.run(["sudo", "smartctl", "-a", "-j", dev_path], stdout=subprocess.PIPE, text=True, check=True)
            smart_data = json.loads(res.stdout)
        except subprocess.CalledProcessError as e:
            if e.stdout: smart_data = json.loads(e.stdout)
            else: continue

        model = smart_data.get("model_name", "Unknown Drive")
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
                    status, status_icon = ("INTERFACE ERR", "🔀") if is_interface_attr else ("FAILING", "🔴")
                    if is_critical and not is_interface_attr: has_critical_failure = True
                elif margin_pct < 40 or (is_critical and raw_val > 0):
                    status, status_icon = "WARNING", "🟡"
                    if is_interface_attr: has_interface_warning = True
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
            if status == "FAILING": has_critical_failure = True
            
            scored_metrics.append({
                "jargon_id": "NVMe", "jargon_name": "percentage_used",
                "clean_name": DEJARGONED_DESCRIPTIONS.get("NVMe"),
                "status": status, "icon": status_icon,
                "friendly_status": FRIENDLY_STATUS.get(status, status),
                "margin": f"{margin_pct}%",
                "current": str(100 - used_pct), "thresh": "0", "raw": f"{used_pct}% used", "_score": margin_pct
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

    return sorted(analyzed_drives, key=lambda x: x["sort_key"])
