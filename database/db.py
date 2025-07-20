import base64, bcrypt, logging, os, sqlite3
from contextlib import contextmanager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

@contextmanager
def db_conn():
    load_dotenv()
    conn = sqlite3.connect(os.getenv("DATABASE_NAME"))
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
                    name TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    role TEXT NOT NULL
                )
            ''')

            # Create the vaults table
            # Vault ID and name must be unique
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vaults (
                    id INTEGER UNIQUE PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                )
            ''')

            # Create the passwords table if it doesn't exist.
            # Password ID must be unqiue
            # Links to a vault and cascades vault deletions to linked passwords
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER UNIQUE PRIMARY KEY AUTOINCREMENT,
                    vault_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    website TEXT NULL,
                    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
                )
            ''')

            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise


def get_user(user):
    try:
        with db_conn() as (conn, cursor):

            result = cursor.execute(
                "SELECT * FROM users WHERE name = ?", (user,)
            )
            result = cursor.fetchone()

            if not result:
                logging.warning(f"User record not found: {user}")
                return None
            
            # Convert tuple to dictionary. I chose to do this for two reasons.
            # 1. It doesn't require the calling function to know the order of the columns
            # 2. It's consistent with the return types of my other database functions
            user_dict = {
                'id': result[0],        # User ID (integer)
                'name': result[1],      # Username (text)
                'password': result[2], # Hashed master password (text)
                'salt': result[3],      # Salt for key derivation (blob)
                'role': result[4]       # User role (text)
            }
            return user_dict
    except sqlite3.Error as e:
        logging.error(f"Database error in get_user: {e}")
        return None
    

def create_user(name, password, role):
    salt = os.urandom(16)
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    try:
        with db_conn() as (conn, cursor):
            cursor.execute(
                "INSERT INTO users (name, password, salt, role) VALUES (?, ?, ?, ?)",
                (name, hashed_pw, salt, role)
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error in create_user: {e}")
        raise


def create_login(vault_id, record_username, record_password, account_username, account_password, website=""):
    if not account_username or not account_password:
        return {'success': False, 'error': 'User name and password are required'}
    
    # STEP 1: Get the Salt from the user record
    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT salt FROM users WHERE name = ?", (account_username,))
            result = cursor.fetchone()
            if not result:
                logging.error(f"User {account_username} not found")
                return {'success': False, 'error': f"User {account_username} not found"}
            salt = result[0]
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving user salt: {e}")
        return {'success': False, 'error': f"Database error: {e}"}

    # STEP 2: Derive Fernet key from password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(account_password.encode('utf-8')))
    cipher = Fernet(encryption_key)

    # STEP 3: Create the record in the database
    try:
        with db_conn() as (conn, cursor):
            # Validate vault_id
            cursor.execute("SELECT id FROM vaults WHERE id = ?", (vault_id,))
            if cursor.fetchone() is None:
                logging.error(f"Vault ID {vault_id} not found")
                return {'success': False, 'error': f"Vault ID {vault_id} not found"}
            
            # Encrypt the password and insert record into database
            encrypted_pw = cipher.encrypt(record_password.encode('utf-8')).decode('utf-8')
            cursor.execute(
                "INSERT INTO passwords (vault_id, username, password, website) VALUES (?, ?, ?, ?)",
                (vault_id, record_username, encrypted_pw, website)
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error in create_login: {e}")
        return {'success': False, 'error': f"Database error: {e}"}


# Get a list of logins saved in the database. 
# Return a list of dictionaries or an empty list.
def get_logins(vault_id, username, password):
    # PART 1: Retrieve user-specific salt
    try:
        with db_conn() as (conn, cursor):
            cursor.execute("SELECT salt FROM users WHERE name = ?", (username,))
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
                    decrypted_password = cipher.decrypt(row[3].encode('utf-8')).decode('utf-8')
                except Fernet.InvalidToken:
                    logging.error(f"Decryption failed for login ID {row[0]}: Invalid master password or corrupted data")
                    continue  # Skip invalid records

                # STEP 2: Get the record with plaintext password and add it to the records list
                login_dict = {
                    'id': row[0],
                    'vault_id': row[1],
                    'username': row[2],
                    'password': decrypted_password,
                    'website': row[4]
                }
                login_records.append(login_dict)
            return login_records
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving login records: {e}")
        return []

