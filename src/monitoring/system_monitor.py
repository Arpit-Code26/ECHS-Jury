"""
Host System Hardware and Performance Telemetry Monitor.
Monitors CPU, Memory, Disk, and Process Latency on Windows and Linux via psutil.
"""
import psutil
import time
from typing import Dict, Any


def get_live_system_metrics() -> Dict[str, Any]:
    """
    Returns instantaneous resource utilization metrics.
    """
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage(".")
    cpu_percent = psutil.cpu_percent(interval=0.1)
    per_cpu = psutil.cpu_percent(interval=None, percpu=True)
    
    return {
        "cpu_percent": cpu_percent,
        "per_cpu_percent": per_cpu,
        "total_ram_gb": round(mem.total / (1024 ** 3), 2),
        "available_ram_gb": round(mem.available / (1024 ** 3), 2),
        "used_ram_gb": round(mem.used / (1024 ** 3), 2),
        "ram_percent": mem.percent,
        "swap_total_gb": round(swap.total / (1024 ** 3), 2),
        "swap_used_gb": round(swap.used / (1024 ** 3), 2),
        "swap_percent": swap.percent,
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
        "disk_percent": disk.percent
    }
