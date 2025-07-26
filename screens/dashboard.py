import datetime
import logging
from dataclasses import dataclass
from database.db import get_logins, get_vaults
from textual.app import ComposeResult
from textual.screen import Screen
from textual.containers import Container, Horizontal
from textual.widgets import Header, Footer, Tree, DataTable, Label
from textual import events
from user import User
from modals.add_login_modal import AddLoginScreen
from modals.add_vault_modal import AddVaultScreen
from app.models import AppState


class PasswordLabel(Label):
    BINDINGS = [
        ("ctrl+c", "copy_password", "Copy Password"),
    ]
    can_focus = True  # Allow focusing to "highlight"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.real_password = ""
        self.password_visible = False

    def update_password(self, real_password: str, visible: bool) -> None:
        self.real_password = real_password
        self.password_visible = visible
        display_text = real_password if visible else ("*" * len(real_password))
        self.update(display_text)

    def action_copy_password(self) -> None:
        if self.real_password:
            self.app.copy_to_clipboard(self.real_password)
            self.notify("Password copied to clipboard!", severity="information")


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
        ("u", "update_entry", "Update an entry"),
        ("D", "delete_entry", "Delete an entry"),
    ]

    def __init__(self, state: AppState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.cursor_type = "row"

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
            if updated_at:
                try:
                    updated_at = datetime.datetime.strptime(updated_at, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
                except ValueError:
                    self.log.warning(f"Invalid updated_at format: {updated_at}")
            self.add_row(name, updated_at, key=str(login['id']))
            self.log.info(f"Added row: Name={name}, Updated={updated_at}")

    def action_create_entry(self) -> None:
        logging.info(f"Opening AddLoginScreen with state: {self.state}")
        def handle_new_entry(result: bool) -> None:
            if result:
                self.refresh_logins()
                logging.info("Login saved, refreshed ItemList")

        self.app.push_screen(AddLoginScreen(self.state), callback=handle_new_entry)


class ItemDetails(Container):
    def __init__(self, state: AppState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.password_visible = False

    def compose(self) -> ComposeResult:
        yield Label("Password Details", id="title")
        yield Label("Name: ", id="name")
        yield Label("Username: ", id="username")
        with Horizontal():
            yield Label("Password: ")
            yield PasswordLabel(id="password")
        yield Label("Website: ", id="website")
        yield Label("Created At: ", id="created_at")
        yield Label("Updated At: ", id="updated_at")

    def on_mount(self) -> None:
        self.update_details(None)

    def toggle_password(self) -> None:
        password_label = self.query_one("#password")
        self.password_visible = not self.password_visible
        password_label.update_password(password_label.real_password, self.password_visible)

    def update_details(self, login: dict | None) -> None:
        password_label = self.query_one("#password")
        if login is None:
            self.query_one("#title").update("Password Details")
            self.query_one("#name").update("Name: ")
            self.query_one("#username").update("Username: ")
            password_label.update_password("", False)
            self.query_one("#website").update("Website: ")
            self.query_one("#created_at").update("Created At: ")
            self.query_one("#updated_at").update("Updated At: ")
            self.password_visible = False
        else:
            self.query_one("#title").update("Password Details")
            self.query_one("#name").update(f"Name: {login['name']}")
            self.query_one("#username").update(f"Username: {login['username'] or ''}")
            password_label.update_password(login['password'] or "", self.password_visible)
            self.query_one("#website").update(f"Website: {login['website'] or ''}")
            self.query_one("#created_at").update(f"Created At: {login['created_at']}")
            self.query_one("#updated_at").update(f"Updated At: {login['updated_at']}")



class DashboardScreen(Screen):
    BINDINGS = [
        ("v", "toggle_password_visibility", "Toggle Password Visibility"),
    ]
    CSS = """
    #main-content {
        layout: horizontal;
        height: 100%;
    }
    #left-sidebar {
        width: 20%;
        background: $panel;
        border: solid $primary;
    }
    #item-list {
        width: 30%;
        background: $panel;
    }
    ItemList {
        min-width: 40;
        height: 100%;
        border: solid $primary;
    }
    #item-details {
        width: 50%;
        background: $panel;
        border: solid $primary;
    }
    Horizontal {
        height: 1;
    }
    PasswordLabel {
        padding: 0 1;
        background: $boost;
    }
    PasswordLabel:focus {
        background: $accent-lighten-1;
        color: $primary-darken-3;
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
            yield ItemDetails(self.state, id="item-details")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(VaultTree).focus()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        item_details = self.query_one(ItemDetails)
        item_details.update_details(None)
        if hasattr(event.node, 'data') and event.node.data is not None:
            self.state.selected_vault_id = event.node.data
            item_list = self.query_one(ItemList)
            item_list.refresh_logins()
            item_list.focus()
        else:
            self.state.selected_vault_id = None
            item_list = self.query_one(ItemList)
            item_list.refresh_logins()
            item_list.focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        item_list = self.query_one(ItemList)
        cursor = event.cursor_row
        logging.info(f"Cursor defined: {cursor}")
        if cursor is not None and cursor < len(item_list.rows):
            row_key = event.row_key.value
            logging.info(f"Selected row_key: {row_key}")
            if row_key is None:
                logging.warning("No row_key found for selected row")
                return
            logins = get_logins(self.state.selected_vault_id, self.state.user.username, self.state.user.password)
            login = next((l for l in logins if str(l['id']) == row_key), None)
            if login:
                logging.info(f"Selected login: ID={row_key}, Name={login['name']}")
                item_details = self.query_one(ItemDetails)
                item_details.update_details(login)
            else:
                logging.warning(f"No login found for row_key: {row_key}")
                item_details = self.query_one(ItemDetails)
                item_details.update_details(None)
        else:
            logging.info("No valid cursor or empty table, clearing ItemDetails")
            item_details = self.query_one(ItemDetails)
            item_details.update_details(None)

    def action_toggle_password_visibility(self) -> None:
        item_details = self.query_one(ItemDetails)
        item_details.toggle_password()
