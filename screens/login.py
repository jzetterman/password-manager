import bcrypt, logging
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Input, Button, Static
from textual.containers import Container, Vertical, Center
from database.db import create_user, get_user
from screens.dashboard import DashboardScreen
from user import User

class LoginScreen(Screen):
    BINDINGS = [
        ("enter", "on_input_submitted", "Toggle dark mode"),
        ("escape", "go_back", "Go back to username")
    ]

    CSS = """
    Container.center-container {
        height: 1fr;
        align: center middle;
    }

    Static.title {
        text-align: center;
    }
    Vertical {
        align: center middle;
        width: 50%;
        height: auto;
        background: $panel;
        border: tall $primary;
        padding: 2;
    }
    Input { margin: 1; width: 100%; }
    Input.hidden { display: none; }
    Button.hidden { display: none; }
    Button { width: 100%; margin: 1; }
    Static#message { margin: 1; }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = "login"
        self.user = User()
        self.db_user = User()

    def compose(self) -> ComposeResult:
        with Container(classes="center-container"):
            with Vertical():
                yield Button("Back", id="back", classes="hidden")
                yield Static("Login", id="title", classes="title")
                yield Input(placeholder="Username", id="username")
                yield Input(placeholder="Password", password=True, id="password", classes="hidden")
                yield Input(placeholder="Confirm Password", password=True, id="confirm_password", classes="hidden")
                with Center():
                    yield Button("Next", id="login", variant="primary")
                yield Static("", id="message")

    def submit(self) -> None:
        message = self.query_one("#message", Static)
        message.styles.color = "red"
        if self.mode == "login":
            self.user.password = self.query_one("#password", Input).value
            if self.user.username and self.user.password:
                stored_hash = self.db_user.password.encode('utf-8')
                if bcrypt.checkpw(self.user.password.encode('utf-8'), stored_hash):
                    self.user = self.db_user
                    logging.debug(f"Successful login for {self.user.username} (ID: {self.user.id})")
                    self.app.push_screen(DashboardScreen(self.db_user))
                else:
                    message.update("Password is incorrect")
                    message.styles.color = "red"
                    print(message.styles.color)
            else:
                message.update("Please fill in both fields.")
                message.styles.color = "red"
        elif self.mode == "create":
            if self.user.password == self.user.confirm_password:
                create_user(self.user.username, self.user.password, self.user.role)
                self.app.push_screen(DashboardScreen(self.db_user))
            else:
                message.update("Passwords don't match. Try again.")
                message.styles.color = "red"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "login":
            self.submit()

        if event.button.id == "back":
            # Reset to username-only state
            self.mode = "username"
            self.user = User()
            self.db_user = None
            self.query_one("#password", Input).value = ""
            self.query_one("#password", Input).add_class("hidden")
            self.query_one("#confirm_password", Input).value = ""
            self.query_one("#confirm_password", Input).add_class("hidden")
            self.query_one("#login").label = "Next"
            self.query_one("#back", Button).add_class("hidden")
            self.query_one("#message", Static).update("")
            self.query_one("#username", Input).focus()            

    def on_input_submitted(self, event: Input.Submitted) -> None:
        username = self.query_one("#username", Input)
        pw_input = self.query_one("#password", Input)
        confirm_pw_input = self.query_one("#confirm_password", Input)

        if event.input.id == "username":
            self.user.username = username.value
            self.db_user = get_user(self.user.username)
            logging.info(f"User lookup returned: {self.db_user}")
            back_button = self.query_one("#back", Button)
            if self.db_user:
                pw_input.remove_class("hidden")
                pw_input.focus()
                back_button.remove_class("hidden")
                login_button = self.query_one("#login", Button)
                login_button.label = "Login"
            else:
                self.mode = "create"
                title = self.query_one("#title", Static)
                title._content = "Register"
                back_button.remove_class("hidden")
                pw_input.remove_class("hidden")
                pw_input.focus()
                confirm_pw_input.remove_class("hidden")
        elif event.input.id == "password":
            if self.mode == "login":
                self.user.password = pw_input.value
                self.submit()
            else:
                confirm_pw_input.focus()
        elif event.input.id == "confirm_password":
            self.user.password = pw_input.value
            self.user.confirm_password = confirm_pw_input.value
            self.submit()
            
    def action_go_back(self) -> None:
        back_button = self.query_one("#back", Button)
        if not back_button.has_class("hidden"):
            self.on_button_pressed(Button.Pressed(back_button))