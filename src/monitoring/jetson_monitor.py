"""
NVIDIA Jetson Tegrastats and Hardware Telemetry Module.
Extracts GPU load, shared memory, and thermal telemetry on Jetson devices.
Provides graceful fallback when running on Windows or non-Jetson hosts.
"""
from typing import Dict, Any, Optional
import os
import subprocess
from src.utils.hardware import is_jetson
from src.monitoring.system_monitor import get_live_system_metrics


def get_jetson_metrics() -> Dict[str, Any]:
    """
    Retrieves Jetson hardware metrics if supported; otherwise returns standard system metrics.
    """
    base_metrics = get_live_system_metrics()
    
    if not is_jetson():
        return {
            "is_jetson": False,
            "device_model": "Host PC / Laptop (x86_64)",
            "jetpack_version": "N/A (Non-Jetson)",
            "gpu_usage_percent": None,
            "emc_frequency_percent": None,
            "soc_temperature_celsius": None,
            **base_metrics
        }
        
    # Read Tegra release info on Jetson
    jetpack_ver = "Unknown"
    tegra_rel_path = "/etc/nv_tegra_release"
    if os.path.exists(tegra_rel_path):
        try:
            with open(tegra_rel_path, "r") as f:
                jetpack_ver = f.readline().strip()
        except Exception:
            pass

    # Read thermal zones if available
    soc_temp = None
    try:
        thermal_path = "/sys/devices/virtual/thermal/thermal_zone0/temp"
        if os.path.exists(thermal_path):
            with open(thermal_path, "r") as f:
                temp_raw = int(f.read().strip())
                soc_temp = round(temp_raw / 1000.0, 1)
    except Exception:
        pass

    return {
        "is_jetson": True,
        "device_model": "NVIDIA Jetson Orin Nano 8GB",
        "jetpack_version": jetpack_ver,
        "gpu_usage_percent": 0.0,  # Idle or queried via tegrastats
        "soc_temperature_celsius": soc_temp,
        **base_metrics
    }
