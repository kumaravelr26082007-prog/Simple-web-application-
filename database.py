import sqlite3
import getpass
import re
from werkzeug.security import generate_password_hash

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def create_admin(username, email, password):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
            (username, email.lower(), generate_password_hash(password)),
        )
        conn.commit()
        print("Admin account created.")
    except sqlite3.IntegrityError:
        print("Username or email already exists.")
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized.")
    if input("Create an admin account? (y/n): ").strip().lower() == "y":
        name = input("Admin username: ").strip()
        mail = input("Admin email: ").strip()
        pw = getpass.getpass("Admin password (min 8 chars): ")
        if not re.fullmatch(r"\w{3,20}", name) or len(pw) < 8:
            print("Invalid username (3-20 letters/digits/_) or password too short.")
        else:
            create_admin(name, mail, pw)
