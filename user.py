#########################################
# John Zetterman
# Final Project
# Date Completed: July 28, 2025
#
# Description: This file describes a user dataclass.
#########################################

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
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
