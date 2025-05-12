# limiter.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address



# rateLimiter.py
import json
import os

port_rate_limits = {}

limiter = Limiter(get_remote_address, default_limits=[])
RATE_LIMITS_FILE = "rate_limits.json"

PREDEFINED_LIMITS = {
    "minimal": "5 per minute",
    "hardcore": "20 per second",
    "burst": "100 per minute",
    "standard": "1000 per hour"
}

def get_all_limits():
    if os.path.exists(RATE_LIMITS_FILE):
        with open(RATE_LIMITS_FILE, "r") as f:
            return json.load(f)
    return {}

def get_limit_for_port(port):
    limits = get_all_limits()
    return limits.get(str(port))

def set_limit_for_port(port, rate=None, unit=None, scheme=None):
    if scheme and scheme in PREDEFINED_LIMITS:
        limit = PREDEFINED_LIMITS[scheme]
    elif rate is not None and unit:
        limit = f"{rate} per {unit}"
    else:
        return False

    port = str(port)
    limits = get_all_limits()
    limits[port] = limit

    with open(RATE_LIMITS_FILE, "w") as f:
        json.dump(limits, f, indent=2)

    return True

def remove_limit_for_port(port):
    port = str(port)
    limits = get_all_limits()
    if port in limits:
        del limits[port]
        with open(RATE_LIMITS_FILE, "w") as f:
            json.dump(limits, f, indent=2)
        return True
    return False

def save_rate_limits():
    with open(RATE_LIMITS_FILE, "w") as f:
        json.dump(port_rate_limits, f, indent=2)

def load_rate_limits():
    global port_rate_limits
    if os.path.exists(RATE_LIMITS_FILE):
        try:
            with open(RATE_LIMITS_FILE, "r") as f:
                port_rate_limits = json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load rate limits: {e}")
            port_rate_limits = {}
