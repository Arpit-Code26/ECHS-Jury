"""
Hardware and Environment Detection Utility.
Detects runtime host (Windows 11 vs. Jetson ARM64), available CPU/RAM,
and machine learning hardware acceleration support.
"""
import os
import platform
import psutil
from typing import Dict, Any


def is_jetson() -> bool:
    """Check if the current device is an NVIDIA Jetson platform."""
    if platform.system() != "Linux":
        return False
    # Typical indicators for Jetson platforms
    tegra_release = "/etc/nv_tegra_release"
    device_tree_model = "/proc/device-tree/model"
    if os.path.exists(tegra_release) or os.path.exists(device_tree_model):
        return True
    return False


def is_windows() -> bool:
    """Check if the current device is running Windows."""
    return platform.system() == "Windows"


def is_cuda_available() -> bool:
    """Safely check if PyTorch is installed and CUDA is available."""
    try:
        import torch
        return torch.cuda.is_available()
    except Exception:
        return False


def get_hardware_profile() -> Dict[str, Any]:
    """Return a comprehensive profile of the current compute environment."""
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(".")
    
    profile = {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "is_jetson": is_jetson(),
        "is_windows": is_windows(),
        "logical_cpus": psutil.cpu_count(logical=True) or 1,
        "physical_cores": psutil.cpu_count(logical=False) or 1,
        "total_ram_gb": round(mem.total / (1024 ** 3), 2),
        "available_ram_gb": round(mem.available / (1024 ** 3), 2),
        "ram_used_percent": mem.percent,
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
        "cuda_available": is_cuda_available(),
    }
    
    # Check framework versions
    try:
        import sklearn
        profile["sklearn_version"] = sklearn.__version__
    except ImportError:
        profile["sklearn_version"] = None

    try:
        import xgboost
        profile["xgboost_version"] = xgboost.__version__
    except ImportError:
        profile["xgboost_version"] = None

    try:
        import torch
        profile["torch_version"] = torch.__version__
    except ImportError:
        profile["torch_version"] = None

    return profile


if __name__ == "__main__":
    import pprint
    pprint.pprint(get_hardware_profile())
