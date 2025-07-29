import logging, os
from app.password_manager import PasswordManagerApp
from database.db import db_init, create_user, get_user
from textual.app import App

logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def main():
    # Initialize DB if it doesn't exist already
    if os.path.exists("password_manager.db"):
        print("Database already exists")
    else:
        db_init()

    app = PasswordManagerApp()
    app.run()


if __name__ == "__main__":
    main()
