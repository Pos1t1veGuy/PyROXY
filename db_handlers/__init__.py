from typing import *
import asyncpg

from ..base_db_handlers import Handler


class PostgresHandler(Handler):
    def __init__(self, username: str, password: str, host: str = '127.0.0.1', port: int = 5432, db_name = 'proxy_db'):
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.db_name = db_name

        self.dsn = f'postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.db_name}'
        self.pool = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(dsn=self.dsn)
        await self.init_tables()

    async def close(self):
        if self.pool:
            await self.pool.close()

    async def init_tables(self):
        async with self.pool.acquire() as conn:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT,
                    cipher TEXT,
                    key TEXT,
                    balance INTEGER DEFAULT 0,
                    is_superuser BOOLEAN DEFAULT FALSE
                );
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS buys (
                    id SERIAL PRIMARY KEY,
                    username TEXT REFERENCES users(username) ON DELETE CASCADE,
                    tariff_name TEXT,
                    bought_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                );
            ''')


    async def buy(self, username: str, tariff_name: str, duration_days: int, price: int) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT balance FROM users WHERE username = $1", username)
            if row is None:
                return False
            balance = row['balance']
            if balance < price:
                return False

            last_expiry_row = await conn.fetchrow('''
                SELECT MAX(expires_at) AS last_expiry
                FROM buys
                WHERE username = $1 AND tariff_name = $2
            ''', username, tariff_name)

            now = datetime.now()
            last_expiry = last_expiry_row['last_expiry'] if last_expiry_row and last_expiry_row['last_expiry'] else None
            start_time = max(now, last_expiry) if last_expiry else now
            new_expiry = start_time + timedelta(days=duration_days)

            await conn.execute("UPDATE users SET balance = $1 WHERE username = $2", balance - price, username)
            await conn.execute(
                "INSERT INTO buys(username, tariff_name, expires_at) VALUES($1, $2, $3)",
                username, tariff_name, new_expiry
            )

            return True

    async def pay(self, username: str, amount: int) -> bool:
        if amount <= 0:
            return False

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT balance FROM users WHERE username = $1", username)
            if row is None:
                return False

            new_balance = row['balance'] + amount
            await conn.execute("UPDATE users SET balance = $1 WHERE username = $2", new_balance, username)
            return True

    async def is_subscriber(self, username: str) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow('''
                SELECT 1 FROM buys
                WHERE username = $1
                  AND expires_at > CURRENT_TIMESTAMP
                LIMIT 1
            ''', username)
            return row is not None


    async def save_key(self, username: str, key: str) -> bool:
        async with self.pool.acquire() as conn:
            await conn.execute(
                'UPDATE users SET key = $1 WHERE username = $2',
                key, username
            )
            return True

    async def save_cipher(self, username: str, cipher: str) -> bool:
        async with self.pool.acquire() as conn:
            await conn.execute(
                'UPDATE users SET cipher = $1 WHERE username = $2',
                cipher, username
            )
            return True

    async def save_password(self, username: str, password: str) -> bool:
        async with self.pool.acquire() as conn:
            await conn.execute(
                'UPDATE users SET password = $1 WHERE username = $2',
                password, username
            )
            return True


    async def find_key(self, username: str) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT key FROM users WHERE username = $1',
                username
            )
            return row['key'] if row else ''

    async def find_cipher(self, username: str) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT cipher FROM users WHERE username = $1',
                username
            )
            return row['cipher'] if row else ''

    async def find_password(self, username: str) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT password FROM users WHERE username = $1',
                username
            )
            return row['password'] if row else ''


    async def get_user_balance(self, username: str) -> int:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT balance FROM users WHERE username = $1',
                username
            )
            return row['balance'] if row else 0

    async def get_access_expiry(self, username: str) -> Optional[datetime]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow('''
                SELECT MAX(expires_at) AS expiry
                FROM buys
                WHERE username = $1 AND expires_at > CURRENT_TIMESTAMP
            ''', username)
            if row.get('expiry'):
                return row['expiry']
            return None

    async def tarif_was(self, username: str, tarif_name: str = "free_3_days") -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow('''
                SELECT bought_at
                FROM buys
                WHERE username = $1 AND tariff_name = $2
                ORDER BY bought_at ASC
                LIMIT 1
            ''', username, tarif_name)

            if row is None:
                return True

            first_buy_date = row['bought_at']
            now = datetime.now()
            return (now - first_buy_date).days < 3


    async def set_superuser(self, username: str, value: bool) -> bool:
        async with self.pool.acquire() as conn:
            await conn.execute(
                'UPDATE users SET is_superuser = $1 WHERE username = $2',
                value, username
            )
        return True

    async def is_superuser(self, username: str) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT is_superuser FROM users WHERE username = $1',
                username
            )
            return bool(row and row['is_superuser'])

    async def promote_user(self, username: str) -> bool:
        return await self.set_superuser(username, True)

    async def demote_user(self, username: str) -> bool:
        return await self.set_superuser(username, False)


    async def get_user_auth_data(self, username: str, check_subscription: bool = True
                                 ) -> Tuple[Optional[str], Optional[bytes]]:
        if not check_subscription or await self.is_subscriber(username):
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    'SELECT password, key FROM users WHERE username = $1',
                    username
                )
                if row:
                    password = row['password']
                    key = bytes.fromhex(row['key']) if row['key'] else None
                    return password, key
        return None, None

    async def get_user(self, username: str) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE username=$1", username)
            if row is None:
                return None
            return dict(row)

    async def get_users(self, usernames: List[str] = [], do: Optional[Callable[[List[dict]], Any]] = None) -> List[dict]:
        async with self.pool.acquire() as conn:
            if usernames:
                placeholders = ','.join(f"${i + 1}" for i in range(len(usernames)))
                query = f"SELECT * FROM users WHERE username IN ({placeholders})"
                rows = await conn.fetch(query, *usernames)
            else:
                rows = await conn.fetch("SELECT * FROM users")

            result = [dict(row) for row in rows] if rows else []
            return do(result) if do else result

    async def add_user(self, username: str, password: str, key: str) -> bool:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO users(username, password, key) VALUES($1, $2, $3)",
                username, password, key
            )
            return True

    async def delete_user(self, username: str) -> bool:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM users WHERE username=$1",
                username
            )
            return True