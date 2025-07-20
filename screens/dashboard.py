from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Static, Footer

class DashboardScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Welcome to the Dashboard!")
        yield Footer()