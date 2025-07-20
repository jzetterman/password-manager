from dataclasses import dataclass
from typing import Optional

@dataclass
class User:
    id: Optional[int] = None
    username: str = ""
    password: str = ""
    confirm_password: Optional[str] = ""
    salt: Optional[bytes] = b""
    role: str = "user"