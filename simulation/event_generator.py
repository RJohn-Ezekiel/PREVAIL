"""
PREVAIL - Synthetic Event Generator
Generates realistic telemetry for simulation and training.
"""
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.services.telemetry import TelemetryEvent, EventType, PrivilegeLevel, Protocol

INTERNAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(10, 30)]
EXTERNAL_IPS = ["203.0.113.50", "198.51.100.23", "192.0.2.100", "100.64.0.1"]
USERS = [f"user_{i}" for i in range(1, 30)]
PROCESSES = ["browser", "terminal", "vim", "nano", "python", "curl", "wget", "ssh", "nmap", "sqlmap"]
PRIVILEGES = [PrivilegeLevel.USER, PrivilegeLevel.ADMIN, PrivilegeLevel.SYSTEM]

NORMAL_APPS = {"browser", "terminal", "vim", "nano", "python"}
SUSPICIOUS_APPS = {"nmap", "sqlmap", "hydra", "john", "hashcat", "mimikatz"}


def _base_event(ts: datetime, user: str, src_ip: str) -> Dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "user_id": user,
        "session_id": str(uuid.uuid4())[:8],
        "source_ip": src_ip,
        "device_id": f"host_{random.randint(1,10):02d}",
        "hostname": f"workstation-{random.randint(1,20):02d}",
    }


def generate_normal_event(ts: datetime, user: Optional[str] = None, src_ip: Optional[str] = None) -> TelemetryEvent:
    user = user or random.choice(USERS)
    src_ip = src_ip or random.choice(INTERNAL_IPS[:10])
    event_type = random.choice(["login", "network_connection", "file_access", "process_start", "logout"])
    base = _base_event(ts, user, src_ip)

    if event_type == "login":
        return TelemetryEvent(**base, event_type=EventType.LOGIN, login_success=random.random() > 0.05,
                              failed_login_count=0, privilege_level=PrivilegeLevel.USER,
                              destination_ip=random.choice(INTERNAL_IPS[:5]),
                              bytes_sent=random.randint(500, 2000), bytes_received=random.randint(1000, 5000))
    elif event_type == "network_connection":
        return TelemetryEvent(**base, event_type=EventType.NETWORK_CONNECTION,
                              destination_ip=random.choice(INTERNAL_IPS[:10]),
                              protocol=random.choice([Protocol.HTTP, Protocol.HTTPS, Protocol.DNS]),
                              bytes_sent=random.randint(100, 5000), bytes_received=random.randint(500, 20000))
    elif event_type == "file_access":
        return TelemetryEvent(**base, event_type=EventType.FILE_ACCESS,
                              resource=f"/home/{user}/docs/{random.choice(['report.pdf','data.csv','notes.txt'])}",
                              bytes_sent=0, bytes_received=random.randint(1000, 100000))
    elif event_type == "process_start":
        return TelemetryEvent(**base, event_type=EventType.PROCESS_START,
                              process_name=random.choice(list(NORMAL_APPS)))
    else:
        return TelemetryEvent(**base, event_type=EventType.LOGOUT)


def generate_brute_force_event(ts: datetime, attempt: int, user: str = "user_17") -> TelemetryEvent:
    src_ip = "10.0.2.15"
    base = _base_event(ts, user, src_ip)
    success = attempt >= 8
    return TelemetryEvent(**base,
                          event_type=EventType.LOGIN if success else EventType.AUTH_FAILURE,
                          login_success=success, failed_login_count=attempt,
                          privilege_level=PrivilegeLevel.USER if success else None,
                          destination_ip="10.0.1.10",
                          bytes_sent=1200 if success else 0,
                          bytes_received=3400 if success else 0)


def generate_recon_event(ts: datetime, event_label: str, user: str = "user_17") -> TelemetryEvent:
    src_ip = "10.0.2.15"
    base = _base_event(ts, user, src_ip)
    if "host_discovery" in event_label:
        return TelemetryEvent(**base, event_type=EventType.HOST_DISCOVERY, protocol=Protocol.ICMP,
                              destination_ip="10.0.1.0/24")
    port_map = {"ssh": 22, "http": 80, "https": 443, "db": 3306}
    port = 22
    for key, val in port_map.items():
        if key in event_label:
            port = val
            break
    return TelemetryEvent(**base, event_type=EventType.PORT_SCAN, destination_ip="10.0.1.20",
                          destination_port=port, protocol=Protocol.TCP)


def generate_privilege_event(ts: datetime, event_label: str, user: str = "user_17") -> TelemetryEvent:
    src_ip = "10.0.2.15"
    base = _base_event(ts, user, src_ip)
    if "privilege_escalation" in event_label:
        return TelemetryEvent(**base, event_type=EventType.PRIVILEGE_CHANGE,
                              privilege_level=PrivilegeLevel.ADMIN)
    if "sudo" in event_label:
        return TelemetryEvent(**base, event_type=EventType.COMMAND_EXECUTION, command="sudo su",
                              privilege_level=PrivilegeLevel.ADMIN)
    if "shadow" in event_label:
        return TelemetryEvent(**base, event_type=EventType.FILE_ACCESS, resource="/etc/shadow",
                              privilege_level=PrivilegeLevel.ADMIN, bytes_received=2048)
    if "nmap" in event_label or "ssh_config" in event_label:
        return TelemetryEvent(**base, event_type=EventType.PROCESS_START if "nmap" in event_label else EventType.CONFIG_CHANGE,
                              process_name="nmap" if "nmap" in event_label else None,
                              resource="/etc/ssh/sshd_config" if "ssh" in event_label else None,
                              privilege_level=PrivilegeLevel.ADMIN)
    return TelemetryEvent(**base, event_type=EventType.PRIVILEGE_CHANGE, privilege_level=PrivilegeLevel.ADMIN)


def generate_exfil_event(ts: datetime, event_label: str, user: str = "user_17") -> TelemetryEvent:
    src_ip = "10.0.2.15"
    base = _base_event(ts, user, src_ip)
    size_map = {"small": 1024000, "large": 5242880, "massive": 20971520, "exfiltration": 52428800}
    size = 1024000
    for key, val in size_map.items():
        if key in event_label:
            size = val
            break
    return TelemetryEvent(**base, event_type=EventType.DATA_TRANSFER,
                          destination_ip="203.0.113.50", bytes_sent=size, bytes_received=1024)


def generate_c2_event(ts: datetime, user: str = "user_17") -> TelemetryEvent:
    src_ip = "10.0.2.15"
    base = _base_event(ts, user, src_ip)
    return TelemetryEvent(**base, event_type=EventType.NETWORK_CONNECTION,
                          destination_ip="203.0.113.50", protocol=Protocol.HTTPS,
                          bytes_sent=2097152, bytes_received=0)


DISPATCH = {
    "normal_login": lambda ts, lbl, u: TelemetryEvent(**_base_event(ts, u or "user_17", "10.0.2.15"),
        event_type=EventType.LOGIN, login_success=True, failed_login_count=0,
        privilege_level=PrivilegeLevel.USER, destination_ip="10.0.1.10",
        bytes_sent=1200, bytes_received=3400),
    "normal_traffic": lambda ts, lbl, u: TelemetryEvent(**_base_event(ts, u or "user_17", "10.0.2.15"),
        event_type=EventType.NETWORK_CONNECTION, destination_ip="10.0.1.20",
        protocol=Protocol.HTTPS, bytes_sent=800, bytes_received=12000),
    "normal_process": lambda ts, lbl, u: TelemetryEvent(**_base_event(ts, u or "user_17", "10.0.2.15"),
        event_type=EventType.PROCESS_START, process_name="browser"),
    "normal_file_access": lambda ts, lbl, u: TelemetryEvent(**_base_event(ts, u or "user_17", "10.0.2.15"),
        event_type=EventType.FILE_ACCESS, resource="/home/user_17/docs/report.pdf", bytes_received=500000),
    "login": lambda ts, lbl, u: generate_normal_event(ts, u or "user_17"),
    "user_login": lambda ts, lbl, u: TelemetryEvent(**_base_event(ts, u or "user_17", "10.0.2.15"),
        event_type=EventType.LOGIN, login_success=True, failed_login_count=0,
        privilege_level=PrivilegeLevel.USER, destination_ip="10.0.1.10",
        bytes_sent=1200, bytes_received=3400),
    "auth_failure_1": lambda ts, lbl, u: generate_brute_force_event(ts, 1, u or "user_17"),
    "auth_failure_2": lambda ts, lbl, u: generate_brute_force_event(ts, 2, u or "user_17"),
    "auth_failure_3": lambda ts, lbl, u: generate_brute_force_event(ts, 3, u or "user_17"),
    "auth_failure_4": lambda ts, lbl, u: generate_brute_force_event(ts, 4, u or "user_17"),
    "auth_failure_5": lambda ts, lbl, u: generate_brute_force_event(ts, 5, u or "user_17"),
    "auth_failure_6": lambda ts, lbl, u: generate_brute_force_event(ts, 6, u or "user_17"),
    "auth_failure_7": lambda ts, lbl, u: generate_brute_force_event(ts, 7, u or "user_17"),
    "auth_failure_8": lambda ts, lbl, u: generate_brute_force_event(ts, 8, u or "user_17"),
    "successful_bruteforce": lambda ts, lbl, u: generate_brute_force_event(ts, 8, u or "user_17"),
    "host_discovery": generate_recon_event,
    "port_scan_ssh": generate_recon_event,
    "port_scan_http": generate_recon_event,
    "port_scan_https": generate_recon_event,
    "port_scan_db": generate_recon_event,
    "network_scan": generate_recon_event,
    "ssh_scan": generate_recon_event,
    "db_scan": generate_recon_event,
    "privilege_escalation_attempt": generate_privilege_event,
    "privilege_escalation": generate_privilege_event,
    "sudo_su": generate_privilege_event,
    "root_access": generate_privilege_event,
    "nmap_as_admin": generate_privilege_event,
    "shadow_file_access": generate_privilege_event,
    "ssh_config_change": generate_privilege_event,
    "small_upload": generate_exfil_event,
    "large_upload": generate_exfil_event,
    "massive_upload": generate_exfil_event,
    "exfiltration_upload": generate_exfil_event,
    "exfiltration": generate_exfil_event,
    "data_exfiltration": generate_exfil_event,
    "c2_beacon": lambda ts, lbl, u: generate_c2_event(ts, u or "user_17"),
    "unusual_failure": lambda ts, lbl, u: generate_brute_force_event(ts, 1, u or "user_17"),
    "repeated_failure": lambda ts, lbl, u: generate_brute_force_event(ts, 2, u or "user_17"),
    "successful_after_failures": lambda ts, lbl, u: TelemetryEvent(**_base_event(ts, u or "user_17", "10.0.2.15"),
        event_type=EventType.LOGIN, login_success=True, failed_login_count=0,
        privilege_level=PrivilegeLevel.USER, destination_ip="10.0.1.10",
        bytes_sent=1200, bytes_received=3400),
    "normal_logout": lambda ts, lbl, u: TelemetryEvent(**_base_event(ts, u or "user_17", "10.0.2.15"),
        event_type=EventType.LOGOUT),
}


def load_scenario(scenario_name: str, base_time: Optional[datetime] = None, seed: Optional[int] = None) -> List[TelemetryEvent]:
    if seed is not None:
        random.seed(seed)
    base_time = base_time or datetime.utcnow()
    scenario_path = Path(__file__).resolve().parent.parent / "data" / "scenarios" / f"{scenario_name}.json"
    if not scenario_path.exists():
        return []
    with open(scenario_path) as f:
        steps = json.load(f)
    events = []
    for step in steps:
        ts = base_time + timedelta(seconds=step.get("timestamp_offset", 0))
        label = step.get("event_label", "normal_login")
        user = step.get("user_id", "user_17")
        gen = DISPATCH.get(label)
        if gen:
            try:
                ev = gen(ts, label, user)
                ev.is_attack = step.get("risk_contribution", 0) > 10
                ev.attack_stage = label
                events.append(ev)
            except Exception:
                pass
        else:
            ev = generate_normal_event(ts, user)
            ev.is_attack = False
            events.append(ev)
    return events


def generate_baseline_data(n_events: int = 500, seed: int = 42) -> List[TelemetryEvent]:
    random.seed(seed)
    base = datetime.utcnow() - timedelta(hours=24)
    events = []
    for i in range(n_events):
        ts = base + timedelta(seconds=random.randint(0, 86400))
        ev = generate_normal_event(ts)
        ev.is_attack = False
        events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events


def generate_training_data(n_scenarios: int = 20, seed: int = 42) -> List[TelemetryEvent]:
    random.seed(seed)
    all_events = []
    all_events.extend(generate_baseline_data(300, seed))
    scenarios = ["brute_force", "reconnaissance", "privilege_escalation", "data_exfiltration", "multi_stage_attack"]
    for i in range(n_scenarios):
        for sc in scenarios:
            base_time = datetime.utcnow() - timedelta(hours=random.randint(1, 48))
            evts = load_scenario(sc, base_time, seed=seed + i)
            all_events.extend(evts)
    all_events.sort(key=lambda e: e.timestamp)
    return all_events
