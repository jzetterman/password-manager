import logging
from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.containers import Container, Horizontal
from textual.widgets import Button, Label
from textual import on
from database.db import delete_login
from app.models import AppState


class DeleteLoginModal(ModalScreen[bool]):
    CSS = """
    DeleteLoginModal {
        align: center middle;
    }
    #dialog {
        layout: vertical;
        padding: 2;
        width: 60;
        height: 20;
        border: thick $error 80%;
        background: $boost;
    }
    #dialog Label {
        text-align: center;
        margin: 1 0;
    }
    #warning-text, #warning-subtext {
        color: $error;
        text-align: center;
        content-align: center middle;
    }
    #button-container {
        layout: horizontal;
        height: auto;
        margin: 2 0 0 0;
    }
    Button {
        width: 1fr;
        margin: 0 1;
    }
    #confirm {
        background: $error;
    }
    #cancel {
        background: $primary;
    }
    """

    def __init__(self, state: AppState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state

    def compose(self) -> ComposeResult:
        login_name = self.state.current_login.get('name', 'Unknown') if self.state.current_login else 'Unknown'

        with Container(id="dialog"):
            yield Label("Delete Login Entry", id="title")
            yield Label(f"Are you sure you want to delete '{login_name}'?", id="warning-text")
            yield Label("This action cannot be undone.", id="warning-subtext")
            with Horizontal(id="button-container"):
                yield Button("Cancel", variant="primary", id="cancel")
                yield Button("Delete", variant="error", id="confirm")

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(False)
        elif event.button.id == "confirm":
            # Perform the deletion
            if self.state.current_login is None:
                logging.error("No login selected for deletion")
                self.dismiss(False)
                return

            if self.state.selected_vault_id is None:
                logging.error("No vault selected for deletion")
                self.dismiss(False)
                return

            result = delete_login(
                vault_id=self.state.selected_vault_id,
                login_id=self.state.current_login['id'],
                record_name=self.state.current_login['name'],
                account_username=self.state.user.username,
                account_password=self.state.user.password
            )

            if result['success']:
                logging.info(f"Successfully deleted login: {self.state.current_login['name']}")
                # Clear the current login from state since it's been deleted
                self.state.current_login = None
                self.state.selected_login_id = None
                self.dismiss(True)
            else:
                logging.error(f"Failed to delete login: {result.get('error', 'Unknown error')}")
                self.dismiss(False)
