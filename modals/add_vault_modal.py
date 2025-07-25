import logging
from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.containers import Vertical, Container
from textual.widgets import Button, Input, Label
from textual import on
from database.db import create_vault
from app.models import AppState

class AddVaultScreen(ModalScreen[bool]):
    CSS = """
    AddVaultScreen {
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
            yield Label("Add New Vault")
            yield Input(placeholder="New vault name", id="name-input")
            yield self.error_label
            yield Button("Add Vault", variant="success", id="add-vault")
            yield Button("Cancel", variant="error", id="cancel")

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(False)
        elif event.button.id == "add-vault":
            name = self.query_one("#name-input", Input).value.strip()

            if not name:
                self.error_label.update("A name is required.")
                return

            logging.info(f"Creating vault: vault_name={name}, user_id={self.state.user.id}")
            result = create_vault(
                vault_name=name,
                user_id=self.state.user.id
            )
            if not result['success']:
                self.error_label.update(f"Error creating vault: {result['error']}")
                return
            self.dismiss(True)
