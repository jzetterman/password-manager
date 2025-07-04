import bcrypt, os, sqlite3
from dotenv import load_dotenv

def db_conn():
    load_dotenv()
    conn = sqlite3.connect(os.getenv("DATABASE_NAME"))
    cursor = conn.cursor()
    return conn, cursor
    

def db_init():
    conn, cursor = db_conn()
    cursor.execute('PRAGMA foreign_keys = ON')

    # Create the users table
    # User ID must be unique
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER UNIQUE PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            master_pw TEXT NOT NULL,
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
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
        )
    ''')

    conn.commit()
    conn.close()

# TODO: Usernames aren't unique, potential for conflicts
def get_user(user):
    conn, cursor = db_conn()

    result = cursor.execute(
        "SELECT * FROM users WHERE name = ?", (user,)
    )
    result = cursor.fetchone()

    if not result or result == "":
        conn.close()
        return "User not found"
    
    conn.close()
    return result
    

def create_user(name, master_pw, role):
    conn, cursor = db_conn()

    hashed_pw = bcrypt.hashpw(master_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cursor.execute(
        "INSERT INTO users (name, master_pw, role) VALUES (?, ?, ?)",
        (name, hashed_pw, role)
    )
    conn.commit()
    conn.close()
