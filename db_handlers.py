from typing import *
import sqlite3
import random
import string
from datetime import datetime, timedelta

from .base_cipher import Cipher


class Handler: ...


class SQLite_Handler(Handler):
    def __init__(self, filepath: str = 'db.sqlite3'):
        self.filepath = filepath

        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS buys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    tariff_name TEXT,
                    bought_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (username) REFERENCES users(username)
                );
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT,
                    cipher TEXT,
                    key TEXT,
                    balance INTEGER DEFAULT 0,
                    is_superuser INTEGER DEFAULT 0
                );
            ''')

    def buy(self, username: str, tariff_name: str, duration_days: int, price: int) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT balance FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()

            if row is None: # user not exists
                return False
            balance = row[0]
            if balance < price: # not enough money
                return False

            cursor.execute('''
                        SELECT MAX(expires_at) FROM buys
                        WHERE username = ? AND tariff_name = ?
                    ''', (username, tariff_name))
            last_expiry_row = cursor.fetchone()
            last_expiry = last_expiry_row[0] if last_expiry_row and last_expiry_row[0] else None

            now = datetime.now()
            if last_expiry:
                last_expiry_dt = datetime.fromisoformat(last_expiry)
                start_time = max(now, last_expiry_dt)
            else:
                start_time = now
            new_expiry = start_time + timedelta(days=duration_days)

            cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (balance - price, username))

            cursor.execute(
                """
                INSERT INTO buys (username, tariff_name, expires_at)
                VALUES (?, ?, ?)
                """,
                (username, tariff_name, new_expiry.isoformat())
            )

            conn.commit()
            return True

    def pay(self, username: str, amount: int) -> bool:
        if amount <= 0:
            return False
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT balance FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                return False
            new_balance = row[0] + amount
            cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
            conn.commit()
            return True

    def is_subscriber(self, username: str) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 1 FROM buys
                WHERE username = ?
                  AND expires_at > CURRENT_TIMESTAMP
                LIMIT 1
            ''', (username,))
            result = cursor.fetchone()
            return result is not None


    def save_key(self, username: str, key: str) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET key = ? WHERE username = ?', (key, username))
            conn.commit()
        return True

    def save_cipher(self, username: str, cipher: str) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET cipher = ? WHERE username = ?', (cipher, username))
            conn.commit()
        return True

    def save_password(self, username: str, password: str) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', (password, username))
            conn.commit()
        return True


    def find_key(self, username: str) -> str:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT key FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return result[0] if result else ''

    def find_cipher(self, username: str) -> str:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cipher FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return result[0] if result else ''

    def find_password(self, username: str) -> str:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return result[0] if result else ''


    def get_user_balance(self, username: str) -> int:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT balance FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return result[0] if result else 0

    def get_access_expiry(self, username: str) -> Optional[datetime]:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT MAX(expires_at) FROM buys
                WHERE username = ? AND expires_at > CURRENT_TIMESTAMP
            ''', (username,))
            result = cursor.fetchone()
            if result and result[0]:
                return datetime.fromisoformat(result[0])
            return None

    def tarif_was(self, username: str, tarif_name: str = "free_3_days") -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT bought_at FROM buys
                WHERE username = ? AND tariff_name = ?
                ORDER BY bought_at ASC
                LIMIT 1
            ''', (username, tarif_name))
            result = cursor.fetchone()
            if result is None:
                return True

            first_buy_date = datetime.fromisoformat(result[0])
            now = datetime.now()
            return (now - first_buy_date).days < 3


    def set_superuser(self, username: str, value: bool) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET is_superuser = ? WHERE username = ?',
                (1 if value else 0, username)
            )
            conn.commit()
            return True

    def is_superuser(self, username: str) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT is_superuser FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return bool(row and row[0])

    def promote_user(self, username: str) -> bool:
        return self.set_superuser(username, True)

    def demote_user(self, username: str) -> bool:
        return self.set_superuser(username, False)


    def get_user_auth_data(self, username: str, check_subscription: bool = True) -> Tuple[Optional[str], Optional[str]]:
        if self.is_subscriber(username) or not check_subscription:
            with sqlite3.connect(self.filepath) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT password, key FROM users WHERE username = ?',
                    (username,)
                )
                result = cursor.fetchone()
                if result:
                    return result[0], bytes.fromhex(result[1]) if result[1] else None
        return None, None

    def get_user(self, username: str) -> dict:
        with sqlite3.connect(self.filepath) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()

            if row is None:
                return None

            return dict(row)
        return {}

    def get_users(self, usernames: List[str] = [], do: Optional[Callable[List[str], Any]] = None) -> List[dict]:
        with sqlite3.connect(self.filepath) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if usernames:
                placeholders = ','.join(['?'] * len(usernames))
                cursor.execute(f'SELECT * FROM users WHERE username IN ({placeholders})', usernames)
            else:
                cursor.execute('SELECT * FROM users')

            rows = cursor.fetchall()
            result = [dict(row) for row in rows] if rows else []
            return do(result) if do else result

    def add_user(self, username: str, show_password: bool = False) -> bool:
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 32)))
        if show_password:
            print('password:', password)
        # try:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
            one = cursor.fetchone()
            if one:
                print(f'[i] User {username} already exists, skipping. {one} {type(one)}')
                return False

            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
        return True
        # except sqlite3.IntegrityError:
        #     pass
        return False

    def delete_user(self, username: str) -> bool:
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM buys WHERE username = ?", (username,))
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted