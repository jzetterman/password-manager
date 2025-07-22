import logging
from dataclasses import dataclass
from database.db import get_logins, get_vaults
from textual.app import ComposeResult
from textual.screen import Screen
from textual.containers import Container, Vertical
from textual.widgets import Header, Footer, Tree, DataTable, Label, Input
from textual.widgets.tree import TreeNode
from textual import events
from user import User


@dataclass
class AppState:
    user: User
    selected_vault_id: int | None = None
    selected_login_id: int | None = None


class VaultTree(Tree):
    def __init__(self, state: AppState, *args, **kwargs):
        super().__init__(label="Vaults", *args, **kwargs)
        self.state = state
        self.show_root = False

    def on_mount(self) -> None:
        if self.state.user.id is None:
            logging.error(f"No user ID provided for VaultTree (username: {self.user.username})")
            self.log.error(f"No user ID provided for VaultTree (username: {self.user.username})")
            return
        self.log(f"User ID: {self.state.user.id}")
        vaults = get_vaults(self.state.user.id)
        self.log(f"Vaults for user {self.state.user.id}: {vaults}")
        for vault in vaults:
            node = self.root.add_leaf(vault['vault_name'])
            node.data = vault["id"]


class ItemList(DataTable):
    def __init__(self, state: AppState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state

    def on_mount(self) -> None:
        self.add_columns("Name", "Updated")
        
    def refresh_logins(self, vault_id) -> None:
        self.clear()
        if vault_id is None:
            return
        logins = get_logins(vault_id, self.state.user.username, self.state.user.password)
        for login in logins:
            self.add_row([login['name'], login['updated_at']])
        

class ItemDetails(Container):
    def compose(self) -> ComposeResult:
        yield Label("Item Details")
        yield Label("Name: Google")
        yield Label("Username: user@example.com")
        yield Input(placeholder="Password (hidden)", password=True, disabled=True)
        yield Label("Website: https://google.com")

class DashboardScreen(Screen):
    BINDINGS = [
        ("c", "on_input_submitted", "Create an entry"),
        ("u", "go_back", "Update an entry"),
        ("D", "delete", "Delete an entry")
    ]
    CSS = """
    #main-content {
        layout: horizontal;
        height: 100%;
    }
    #left-sidebar {
        width: 20%;  /* Adjust as needed */
        background: $panel;
        border: heavy $accent;
    }
    #item-list {
        width: 30%;
        background: $panel;
    }
    #item-details {
        width: 50%;
        background: $panel;
    }
    """

    def __init__(self, user: User):
        super().__init__()
        self.user = user
        self.state = AppState(user=self.user)

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main-content"):
            yield Container(VaultTree(self.state), id="left-sidebar")
            yield Container(ItemList(self.state), id="item-list")
            yield ItemDetails(id="item-details")
        yield Footer()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if hasattr(event.node, 'data') and event.node.data is not None:
            vault_id = event.node.data
            item_list = self.query_one(ItemList)
            item_list.refresh_logins(vault_id)
        else:
            return

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        selected_row = event.row
        item_details = self.query_one(ItemDetails)