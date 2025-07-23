import logging
from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.containers import Vertical, Container
from textual.widgets import Button, Input, Label
from textual import on
from database.db import create_login
from app.models import AppState

class AddLoginScreen(ModalScreen[bool]):
    CSS = """
    AddLoginScreen {
        align: center middle;
    }
    #dialog {
        grid-size: 2;
        grid-gutter: 1 2;
        grid-rows: 1fr;
        padding: 0 1;
        width: 60;
        height: 25;
        border: thick $primary 50%;
        background: $boost;
    }
    #dialog Label {
        column-span: 2;
    }
    #dialog Input {
        column-span: 2;
    }
    Button {
        width: 100%;
    }
    #error-label {
        color: red;
        column-span: 2;
    }
    """

    def __init__(self, state: AppState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.error_label = Label("", id="error-label")

    def compose(self) -> ComposeResult:
        with Container(id="dialog"):
            yield Label("Add New Login")
            yield Input(placeholder="Name (e.g., Google)", id="name-input")
            yield Input(placeholder="Username", id="username-input")
            yield Input(placeholder="Password", id="password-input", password=True)
            yield Input(placeholder="Website (optional)", id="website-input")
            yield self.error_label
            yield Button("Save", variant="success", id="save")
            yield Button("Cancel", variant="error", id="cancel")

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(False)
        elif event.button.id == "save":
            name = self.query_one("#name-input", Input).value.strip()
            username = self.query_one("#username-input", Input).value.strip() or None
            password = self.query_one("#password-input", Input).value.strip() or None
            website = self.query_one("#website-input", Input).value.strip() or None

            if not name:
                self.error_label.update("A name is required.")
                return
            if self.state.selected_vault_id is None:
                self.error_label.update("No vault selected. Please select a vault first.")
                return

            logging.info(f"Saving login: vault_id={self.state.selected_vault_id}, name={name}, username={username}, website={website}, account_username={self.state.user.username}")
            result = create_login(
                vault_id=self.state.selected_vault_id,
                record_name=name,
                record_username=username,
                record_password=password,
                account_username=self.state.user.username,
                account_password=self.state.user.password,
                website=website
            )
            if not result['success']:
                self.error_label.update(f"Error saving login: {result['error']}")
                return
            self.dismiss(True)