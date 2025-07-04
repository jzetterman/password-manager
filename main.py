import bcrypt, os, sys
from database.db import db_conn, db_init, create_user, get_user
from functions.get_credential import get_credential

def main():
    # Initialize DB if it doesn't exist already
    if os.path.exists("password_manager.db"):
        print("Database already exists")
    else:
        db_init()

    username = input("Enter your username: ")
    user = get_user(username)
    while True:
        if user == "User not found":
            master_pw_first = input("Enter a master password: ")
            master_pw_second = input("Enter your master password again: ")
            if master_pw_first == master_pw_second:
                create_user(username, master_pw_first, "standard")
                break
            else:
                continue
        else:
            master_pw = input("Enter your master password: ")
            stored_hash = user[2].encode('utf-8')
            if bcrypt.checkpw(master_pw.encode('utf-8'), stored_hash):
                break
            else:
                return "Incorrect password"
    
    while True:
        print("Welcome to Password Manager!")
        print("1: Look up a credential")
        print("2: Save a new credential")
        print("q to quit")

        choice = input("\nMake a choice: ")

        if choice == "1":
            get_credential()
        elif choice == "2":
            print("Save a new credential")
        elif choice == "q":
            sys.exit(0)


if __name__ == "__main__":
    main()