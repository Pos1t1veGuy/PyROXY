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
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT,
                    cipher TEXT,
                    key TEXT,
                    balance INTEGER DEFAULT 0
                );
            ''')

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

    def get_user(self, username: str) -> Tuple[Optional[str], Optional[str]]:
        if self.is_subscriber(username):
            with sqlite3.connect(self.filepath) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT password, key FROM users WHERE username = ?',
                    (username,)
                )
                result = cursor.fetchone()
                if result:
                    return result[0], bytes.fromhex(result[1])
                return None, None