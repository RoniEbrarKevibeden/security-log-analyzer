from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class AuthEvent:
    timestamp: datetime
    host: str
    process: str
    pid: Optional[int]
    outcome: str          # "failed", "accepted", "other"
    username: Optional[str]
    ip: Optional[str]
    raw: str
    invalid_user: bool = False
