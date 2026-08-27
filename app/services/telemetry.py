"""
PREVAIL - AI19: Event Schema and Telemetry Models

Normalized event schema for cybersecurity behavioral telemetry.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from enum import Enum
import json


class EventType(str, Enum):
    """Types of security events"""
    LOGIN = "login"
    LOGOUT = "logout"
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACCESS = "file_access"
    PRIVILEGE_CHANGE = "privilege_change"
    CONFIG_CHANGE = "config_change"
    AUTH_FAILURE = "auth_failure"
    PORT_SCAN = "port_scan"
    HOST_DISCOVERY = "host_discovery"
    DATA_TRANSFER = "data_transfer"
    COMMAND_EXECUTION = "command_execution"


class PrivilegeLevel(str, Enum):
    """User privilege levels"""
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"
    ROOT = "root"
    SERVICE = "service"


class Protocol(str, Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    RDP = "rdp"
    SMB = "smb"
    DNS = "dns"
    FTP = "ftp"


class TelemetryEvent(BaseModel):
    """
    Normalized cybersecurity telemetry event.
    
    All fields are optional to support partial telemetry from different sources.
    """
    # Core identification
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    event_id: Optional[str] = Field(None, description="Unique event identifier")
    
    # User/Identity
    user_id: Optional[str] = Field(None, description="User identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    
    # Network
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    source_port: Optional[int] = Field(None, description="Source port", ge=0, le=65535)
    destination_port: Optional[int] = Field(None, description="Destination port", ge=0, le=65535)
    protocol: Optional[Protocol] = Field(None, description="Network protocol")
    
    # Event details
    event_type: Optional[EventType] = Field(None, description="Type of event")
    login_success: Optional[bool] = Field(None, description="Whether login succeeded")
    failed_login_count: Optional[int] = Field(0, description="Consecutive failed login attempts", ge=0)
    privilege_level: Optional[PrivilegeLevel] = Field(None, description="Privilege level")
    
    # Process/Resource
    process_name: Optional[str] = Field(None, description="Process name")
    resource: Optional[str] = Field(None, description="Resource accessed")
    command: Optional[str] = Field(None, description="Command executed")
    
    # Data transfer
    bytes_sent: Optional[int] = Field(0, description="Bytes sent", ge=0)
    bytes_received: Optional[int] = Field(0, description="Bytes received", ge=0)
    
    # Device/Host
    device_id: Optional[str] = Field(None, description="Device/host identifier")
    hostname: Optional[str] = Field(None, description="Hostname")
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    # Attack labeling (for training)
    is_attack: Optional[bool] = Field(None, description="Ground truth: is this part of an attack")
    attack_stage: Optional[str] = Field(None, description="Attack stage if applicable")
    attack_type: Optional[str] = Field(None, description="Attack type if applicable")
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        return v
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with ISO format timestamp"""
        d = self.model_dump()
        d['timestamp'] = self.timestamp.isoformat()
        # Convert enums to strings
        if d.get('event_type'):
            d['event_type'] = d['event_type'].value if isinstance(d['event_type'], EventType) else d['event_type']
        if d.get('protocol'):
            d['protocol'] = d['protocol'].value if isinstance(d['protocol'], Protocol) else d['protocol']
        if d.get('privilege_level'):
            d['privilege_level'] = d['privilege_level'].value if isinstance(d['privilege_level'], PrivilegeLevel) else d['privilege_level']
        return d
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TelemetryEvent':
        """Create from dictionary"""
        # Handle timestamp parsing
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'TelemetryEvent':
        """Create from JSON string"""
        return cls.from_dict(json.loads(json_str))


class EventBatch(BaseModel):
    """Batch of telemetry events"""
    events: List[TelemetryEvent]
    source: Optional[str] = None
    batch_id: Optional[str] = None
    received_at: datetime = Field(default_factory=datetime.utcnow)
    
    def to_dataframe(self):
        """Convert to pandas DataFrame"""
        import pandas as pd
        return pd.DataFrame([e.to_dict() for e in self.events])


# Event loader utilities
def load_events_from_json(filepath: str) -> List[TelemetryEvent]:
    """Load events from JSON file (array of objects or newline-delimited)"""
    import json
    events = []
    with open(filepath, 'r') as f:
        content = f.read().strip()
        if not content:
            return events
        
        # Try parsing as JSON array first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    events.append(TelemetryEvent.from_dict(item))
            else:
                events.append(TelemetryEvent.from_dict(data))
        except json.JSONDecodeError:
            # Try newline-delimited JSON
            for line in content.split('\n'):
                line = line.strip()
                if line:
                    events.append(TelemetryEvent.from_json(line))
    return events


def load_events_from_csv(filepath: str) -> List[TelemetryEvent]:
    """Load events from CSV file"""
    import pandas as pd
    df = pd.read_csv(filepath)
    events = []
    for _, row in df.iterrows():
        # Convert row to dict, handling NaN
        data = row.where(pd.notnull(row), None).to_dict()
        # Parse timestamp if present
        if 'timestamp' in data and data['timestamp']:
            data['timestamp'] = pd.to_datetime(data['timestamp']).to_pydatetime()
        events.append(TelemetryEvent.from_dict(data))
    return events


def save_events_to_json(events: List[TelemetryEvent], filepath: str, newline_delimited: bool = False):
    """Save events to JSON file"""
    import json
    with open(filepath, 'w') as f:
        if newline_delimited:
            for event in events:
                f.write(event.to_json() + '\n')
        else:
            json.dump([e.to_dict() for e in events], f, indent=2)


def save_events_to_csv(events: List[TelemetryEvent], filepath: str):
    """Save events to CSV file"""
    import pandas as pd
    df = pd.DataFrame([e.to_dict() for e in events])
    df.to_csv(filepath, index=False)