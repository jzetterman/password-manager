#########################################
# John Zetterman
# Final Project
# Date Completed: July 28, 2025
#
# Description: This file handles all database operations.
#########################################

import base64, bcrypt, logging, os, sqlite3
from contextlib import contextmanager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from user import User

@contextmanager
def db_conn():
    load_dotenv()
    conn = sqlite3.connect(os.getenv("DATABASE_NAME"))
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()
    try:
        yield conn, cursor
    finally:
        cursor.close()
        conn.close()


def db_init():
    try:
        with db_conn() as (conn, cursor):
            cursor.execute('PRAGMA foreign_keys = ON')

            # Create the users table
            # User ID must be unique
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER UNIQUE PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    role TEXT NOT NULL
                )
            ''')

            # Create the vaults table
            # Vault ID and name must be unique per user_id
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vaults (
                    id INTEGER UNIQUE PRIMARY KEY AUTOINCREMENT,
                    vault_name TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE (vault_name, user_id)
                )
            ''')

            # Create the passwords table if it doesn't exist.
            # Password ID must be unqiue
            # Links to a vault and cascades vault deletions to linked passwords
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER UNIQUE PRIMARY KEY AUTOINCREMENT,
                    vault_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    username TEXT,
                    password TEXT,
                    website TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
                )
            ''')

            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise


def get_user(user) -> dict | None:
    try:
        with db_conn() as (conn, cursor):

            result = cursor.execute(
                "SELECT * FROM users WHERE username = ?", (user,)
            )
            result = cursor.fetchone()

            if not result:
                logging.warning(f"User record not found: {user}")
                return None

            # Convert tuple to dictionary. I chose to do this for two reasons.
            # 1. It doesn't require the calling function to know the order of the columns
            # 2. It's consistent with the return types of my other database functions
            return User(
                id = result[0],        # User ID (integer)
                username = result[1],      # Username (text)
                password = result[2],  # Hashed master password (text)
                salt = result[3],      # Salt for key derivation (blob)
                role = result[4]      # User role (text)
            )
    except sqlite3.Error as e:
        logging.error(f"Database error in get_user: {e}")
        return None


def create_user(username, password, role):
    salt = os.urandom(16)
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        with db_conn() as (conn, cursor):
            cursor.execute(
                "INSERT INTO users (username, password, salt, role) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, salt, role)
            )
            # Automatically create one vault called Personal for every user
            user_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO vaults (vault_name, user_id) VALUES (?, ?)",
                ("Personal", user_id)
            )
            # new_id = cursor.lastrowid
            conn.commit()
            return User(id=user_id, username=username, password=password, confirm_password="", salt=salt, role=role)
    except sqlite3.Error as e:
        logging.error(f"Database error in create_user: {e}")
        raise


def create_login(vault_id, record_name, record_username, record_password, account_username, account_password, website=""):
    logging.info(f"Creating login: vault_id={vault_id}, name={record_name}, username={record_username}, website={website}, account_username={account_username}")
    if not account_username or not account_password:
        return {'success': False, 'error': 'Username and password are required'}

    # STEP 1: Get the Salt from the user record
    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT salt FROM users WHERE username = ?", (account_username,))
            result = cursor.fetchone()
            if not result:
                logging.error(f"User {account_username} not found")
                return {'success': False, 'error': f"User {account_username} not found"}
            salt = result[0]
            logging.info(f"Retrieved salt for {account_username}")
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving user salt: {e}")
        return {'success': False, 'error': f"Database error: {e}"}
    except Exception as e:
        logging.error(f"Unexpected error retrieving user salt: {e}")
        return {'success': False, 'error': f"Unexpected error retrieving user salt: {e}"}

    # STEP 2: Derive Fernet key from password and salt
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        encryption_key = base64.urlsafe_b64encode(kdf.derive(account_password.encode('utf-8')))
        cipher = Fernet(encryption_key)
        logging.info("Encryption key derived successfully")
    except Exception as e:
        logging.error(f"Encryption setup failed: {e}")
        return {'success': False, 'error': f"Encryption error: {e}"}

    # STEP 3: Create the record in the database
    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT id FROM vaults WHERE id = ?", (vault_id,))
            if cursor.fetchone() is None:
                logging.error(f"Vault ID {vault_id} not found")
                return {'success': False, 'error': f"Vault ID {vault_id} not found"}

            # Encrypt the password and insert record into database
            encrypted_pw = cipher.encrypt(record_password.encode('utf-8')).decode('utf-8')
            cursor.execute(
                "INSERT INTO passwords (vault_id, name, username, password, website) VALUES (?, ?, ?, ?, ?)",
                (vault_id, record_name, record_username, encrypted_pw, website)
            )
            new_id = cursor.lastrowid
            logging.info(f"Inserted login with ID {new_id}")
            conn.commit()
            return {'success': True, 'id': new_id}
    except sqlite3.Error as e:
        logging.error(f"Database error in create_login: {e}")
        return {'success': False, 'error': f"Database error: {e}"}
    except Exception as e:
        logging.error(f"Unexpected error in create_login: {e}")
        return {'success': False, 'error': f"Unexpected error in create_login: {e}"}


# Get a list of logins saved in the database.
# Return a list of dictionaries or an empty list.
def get_logins(vault_id, username, password):
    # PART 1: Retrieve user-specific salt
    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            if not result:
                logging.warning(f"User {username} not found")
                return []
            salt = result[0]
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving user salt: {e}")
        return []

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    cipher = Fernet(encryption_key)

    # PART 2: Fetch data from passwords table
    try:
        with db_conn() as (conn, cursor):
            # Validate vault_id
            cursor.execute("SELECT id FROM vaults WHERE id = ?", (vault_id,))
            if cursor.fetchone() is None:
                logging.warning(f"Vault ID {vault_id} not found")
                return []

            cursor.execute("SELECT * FROM passwords WHERE vault_id = ?", (vault_id,))
            result = cursor.fetchall()

            # Convert rows returned to a list of dictionaries
            login_records = []
            for row in result:
                # STEP 1: Decrypt the stored password for the row
                try:
                    # Decrypt the password
                    decrypted_password = cipher.decrypt(row[4].encode('utf-8')).decode('utf-8')
                except Fernet.InvalidToken:
                    logging.error(f"Decryption failed for login ID {row[0]}: Invalid master password or corrupted data")
                    continue  # Skip invalid records

                # STEP 2: Get the record with plaintext password and add it to the records list
                login_dict = {
                    'id': row[0],
                    'vault_id': row[1],
                    'name': row[2],
                    'username': row[3],
                    'password': decrypted_password,
                    'website': row[5],
                    'created_at': row[6],
                    'updated_at': row[7]
                }
                login_records.append(login_dict)
            return login_records
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving login records: {e}")
        return []


def update_login(vault_id, login_id,  account_username, account_password, record_name=None, record_username=None, record_password=None, website=None):
    logging.info(f"Updating login: vault_id={vault_id}, name={record_name}, username={record_username}, website={website}, account_username={account_username}")
    if not account_username or not account_password:
        return {'success': False, 'error': 'Username and password are required'}

    # STEP 1: Get the Salt from the user record
    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT salt FROM users WHERE username = ?", (account_username,))
            result = cursor.fetchone()
            if not result:
                logging.error(f"User {account_username} not found")
                return {'success': False, 'error': f"User {account_username} not found"}
            salt = result[0]
            logging.info(f"Retrieved salt for {account_username}")
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving user salt: {e}")
        return {'success': False, 'error': f"Database error: {e}"}
    except Exception as e:
        logging.error(f"Unexpected error retrieving user salt: {e}")
        return {'success': False, 'error': f"Unexpected error retrieving user salt: {e}"}

    # STEP 2: Derive Fernet key from password and salt
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        encryption_key = base64.urlsafe_b64encode(kdf.derive(account_password.encode('utf-8')))
        cipher = Fernet(encryption_key)
        logging.info("Encryption key derived successfully")
    except Exception as e:
        logging.error(f"Encryption setup failed: {e}")
        return {'success': False, 'error': f"Encryption error: {e}"}

    # STEP 3: Build dynamic UPDATE query
    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT name, username, password, website FROM passwords WHERE id = ? AND vault_id = ?",
                            (login_id, vault_id))
            current = cursor.fetchone()
            if not current:
                return {'success': False, 'error': 'Login record not found'}

            update_fields = []
            values = []

            if record_name is not None:
                update_fields.append("name = ?")
                values.append(record_name)

            if record_username is not None:
                update_fields.append("username = ?")
                values.append(record_username)

            if record_password is not None:
                encrypted_pw = cipher.encrypt(record_password.encode('utf-8')).decode('utf-8')
                update_fields.append("password = ?")
                values.append(encrypted_pw)

            if website is not None:
                update_fields.append("website = ?")
                values.append(website)

            update_fields.append("updated_at = datetime('now')")

            values.extend([login_id, vault_id])

            if update_fields:
                query = f"UPDATE passwords SET {', '.join(update_fields)} WHERE id = ? AND vault_id = ?"
                cursor.execute(query, values)
                conn.commit()
                return {'success': True}
    except sqlite3.Error as e:
        logging.error(f"Database error updating login record: {e}")
        return {'success': False, 'error': f"Unexpected error in update_login: {e}"}


def delete_login(vault_id, login_id, record_name, account_username, account_password):
    logging.info(f"Deleting login: vault_id={vault_id}, login_id={login_id}, name={record_name}")
    if not account_username or not account_password:
        return {'success': False, 'error': 'Username and password are required'}

    try:
        with db_conn() as (conn, cursor):
            cursor.execute("DELETE FROM passwords WHERE id = ? and vault_id = ?", (login_id, vault_id))
            conn.commit()
            return {'success': True}
    except sqlite3.Error as e:
        logging.error(f"Database error deleting login record: {e}")
        return {'success': False, 'error': f"Unexpected error in delete_login: {e}"}


def get_vaults(user_id) -> list:
    if not isinstance(user_id, int):
        logging.error(f"Invalid user_id type: expected int, got {type(user_id)}")
        return []

    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT * FROM vaults WHERE user_id = ?", (user_id,))
            result = cursor.fetchall()
            if not result:
                logging.warning(f"No vaults found for user ID {user_id}")
                return []

            vaults = [
                {
                    'id': row[0],
                    'vault_name': row[1],
                    'user_id': row[2]
                }
                for row in result
            ]
            return vaults
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving users vaults: {e}")
        return []


def create_vault(vault_name, user_id):
    if not vault_name or not user_id:
        logging.error(f"Vault name is required.")
        return[]

    try:
        with db_conn() as (conn, cursor):
            cursor.execute(
                "INSERT INTO vaults (vault_name, user_id) VALUES (?, ?)",
                (vault_name, user_id)
            )
            new_id = cursor.lastrowid
            logging.info(f"Inserted vault with ID {new_id}")
            conn.commit()
            return {'success': True, 'id': new_id}
    except sqlite3.Error as e:
        logging.error(f"Database error creating vault: {e}")
        return {'success': False, 'error': f"Database error: {e}"}
    except Exception as e:
        logging.error(f"Unexpected error in create_vault: {e}")
        return {'success': False, 'error': f"Unexpected error in create_vault: {e}"}
