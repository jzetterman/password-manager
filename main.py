#########################################
# John Zetterman
# Final Project
# Date Completed: July 28, 2025
#
# Description: This file initializes the database and launches the password manager application.
#########################################

import logging, os
from app.password_manager import PasswordManagerApp
from database.db import db_init

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
