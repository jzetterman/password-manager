from textual.app import App, ComposeResult
from screens.dashboard import DashboardScreen
from screens.login import LoginScreen
from textual.widgets import Header


class PasswordManagerApp(App):
    BINDINGS = [("d", "toggle_dark", "Toggle dark mode")]
    SCREENS = {"login": LoginScreen, "dashboard": DashboardScreen}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

    def on_mount(self) -> None:
        self.app.push_screen(LoginScreen())

    def action_toggle_dark(self) -> None:
        self.theme = (
            "textual-dark" if self.theme == "textual-light" else "textual-light"
        )


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.run()
