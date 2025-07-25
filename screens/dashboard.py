import datetime
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
from modals.add_login_modal import AddLoginScreen
from modals.add_vault_modal import AddVaultScreen
from app.models import AppState


class VaultTree(Tree):
    BINDINGS = [
        ("c", "create_entry", "Create a new vault"),
    ]

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
            logging.info(f"Added vault node: name={vault['vault_name']}, id={vault['id']}")

        # Auto select the first vault in the vault list
        if self.root.children:
            first_node = self.root.children[0]
            self.select_node(first_node)
            self.state.selected_vault_id = first_node.data
            logging.info(f"Auto-selected first vault: id={first_node.data}, name={first_node.label}")
            self.post_message(Tree.NodeSelected(node=first_node))

    def refresh_vaults(self) -> None:
        self.clear()
        vaults = get_vaults(self.state.user.id)
        for vault in vaults:
            node = self.root.add_leaf(vault['vault_name'])
            node.data = vault['id']

        if self.root.children:
            first_node = self.root.children[0]
            self.select_node(first_node)
            self.state.selected_vault_id = first_node.data
            self.post_message(Tree.NodeSelected(node=first_node))

    def action_create_entry(self) -> None:
        logging.info(f"Opening AddVaultScreen with state: {self.state}")
        def handle_new_entry(result: bool) -> None:
            if result:
                self.refresh_vaults()
                logging.info("Vault saved, refreshed VaultTree")

        self.app.push_screen(AddVaultScreen(self.state), callback=handle_new_entry)


class ItemList(DataTable):
    BINDINGS = [
        ("c", "create_entry", "Create a new login"),
    ]
    def __init__(self, state: AppState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state

    def on_mount(self) -> None:
        self.add_columns("Name", "Updated")
        self.refresh_logins()

    def refresh_logins(self) -> None:
        self.clear()
        vault_id = self.state.selected_vault_id
        if vault_id is None:
            self.add_row("No vault selected", "")
            return
        logins = get_logins(vault_id, self.state.user.username, self.state.user.password)
        for login in logins:
            name = login['name'] or ""
            updated_at = login['updated_at'] or ""
            # Format updated_at (e.g., "2025-07-23 04:08")
            if updated_at:
                try:
                    updated_at = datetime.datetime.strptime(updated_at, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
                except ValueError:
                    self.log.warning(f"Invalid updated_at format: {updated_at}")
            self.add_row(name, updated_at)
            self.log.info(f"Added row: Name={name}, Updated={updated_at}")

    def action_create_entry(self) -> None:
        logging.info(f"Opening AddLoginScreen with state: {self.state}")
        def handle_new_entry(result: bool) -> None:
            if result:
                self.refresh_logins()
                logging.info("Login saved, refreshed ItemList")

        self.app.push_screen(AddLoginScreen(self.state), callback=handle_new_entry)


class ItemDetails(Container):
    def compose(self) -> ComposeResult:
        yield Label("Password Details", id="title")
        yield Label("Name: ", id="name")
        yield Label("Username: ", id="username")
        yield Input(placeholder="Password (hidden)", password=True, disabled=True, id="password")
        yield Label("Website: ", id="website")
        yield Label("Created At: ", id="created_at")
        yield Label("Updated At: ", id="updated_at")

    def update_details(self, login: dict | None) -> None:
        if login is None:
            self.query_one("#title").update("Password Details")
            self.query_one("#name").update("Name: ")
            self.query_one("#username").update("Username: ")
            self.query_one("#password").value = ""
            self.query_one("#website").update("Website: ")
            self.query_one("#created_at").update("Created At: ")
            self.query_one("#updated_at").update("Updated At: ")
        else:
            self.query_one("#title").update("Password Details")
            self.query_one("#name").update(f"Name: {login['name']}")
            self.query_one("#username").update(f"Username: {login['username'] or ''}")
            self.query_one("#password").value = login['password'] or ""
            self.query_one("#website").update(f"Website: {login['website'] or ''}")
            self.query_one("#created_at").update(f"Created At: {login['created_at']}")
            self.query_one("#updated_at").update(f"Updated At: {login['updated_at']}")

class DashboardScreen(Screen):
    BINDINGS = [
        ("u", "update_entry", "Update an entry"),
        ("D", "delete_entry", "Delete an entry"),
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
    ItemList {
        min-width: 40;  /* Ensure table has enough space */
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
        logging.info(f"Initialized DashboardScreen with user_id={self.state.user.id}, username={self.state.user.username}, password={'***' if self.state.user.password else None}")

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main-content"):
            yield Container(VaultTree(self.state), id="left-sidebar")
            yield Container(ItemList(self.state), id="item-list")
            yield ItemDetails(id="item-details")
        yield Footer()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if hasattr(event.node, 'data') and event.node.data is not None:
            self.state.selected_vault_id = event.node.data
            item_list = self.query_one(ItemList)
            item_list.refresh_logins()
        else:
            self.state.selected_vault_id = None
            item_list = self.query_one(ItemList)
            item_list.refresh_logins()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        item_list = self.query_one(ItemList)
        cursor = event.cursor_row
        if cursor is not None and cursor < len(item_list.rows):
            login = get_logins(self.state.selected_vault_id)[cursor]
            item_details = self.query_one(ItemDetails)
            item_details.update_details(login)
        else:
            item_details = self.query_one(ItemDetails)
            item_details.update_details(None)
