from dataclasses import dataclass
from user import User

@dataclass
class AppState:
    user: User
    selected_vault_id: int | None = None
    selected_login_id: int | None = None