from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection
import sqlite3


class User:
    def __init__(self, username, email, password=None, password_hash=None, is_verified=0):
        self.username = username
        self.email = email
        self.is_verified = is_verified
        self.password_hash = (
            generate_password_hash(password)
            if password else password_hash
        )

    def save(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                '''
                INSERT INTO users (username, email, password_hash, created_at, is_verified)
                VALUES (?, ?, ?, ?, ?)
                ''',
                (
                    self.username,
                    self.email,
                    self.password_hash,
                    datetime.now().isoformat(),
                    self.is_verified
                )
            )
            user_id = cursor.lastrowid
            conn.commit()
            self._register_default_consents(user_id)
            return user_id
        except sqlite3.IntegrityError:
            conn.rollback()
            raise ValueError("Nome de usuário ou e-mail já existe")
        finally:
            conn.close()

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_verified(self, user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET is_verified = 1 WHERE id = ?',
            (user_id,)
        )
        conn.commit()
        conn.close()

    def _register_default_consents(self, user_id):
        now = datetime.now().isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.executemany(
                '''
                INSERT INTO consents (user_id, consent_type, consent_given, given_at)
                VALUES (?, ?, ?, ?)
                ''',
                [
                    (user_id, 'data_processing', 1, now),
                    (user_id, 'cookies', 0, now)
                ]
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()

        if not user_data:
            raise ValueError("Usuário não encontrado")

        return (
            User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=user_data['password_hash'],
                is_verified=user_data['is_verified']
            ),
            user_data['id']
        )

    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()

        if not user_data:
            return None

        return User(
            username=user_data['username'],
            email=user_data['email'],
            password_hash=user_data['password_hash'],
            is_verified=user_data['is_verified']
        )

    @staticmethod
    def log_access(user_id, action, ip_address=None, user_agent=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO access_logs (user_id, action, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (user_id, action, ip_address, user_agent, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()


class DataRequest:
    @staticmethod
    def create_request(user_id, request_type, request_data=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO data_requests (user_id, request_type, request_data, created_at)
            VALUES (?, ?, ?, ?)
            ''',
            (user_id, request_type, request_data, datetime.now().isoformat())
        )
        request_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return request_id

    @staticmethod
    def get_user_requests(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT * FROM data_requests
            WHERE user_id = ?
            ORDER BY created_at DESC
            ''',
            (user_id,)
        )
        requests = cursor.fetchall()
        conn.close()
        return requests

class PasswordResetToken:
    @staticmethod
    def create_token(user_id, token, expires_at):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            ''',
            (user_id, token, expires_at, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

    @staticmethod
    def get_valid_token(token):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT * FROM password_reset_tokens
            WHERE token = ? AND used = 0 AND expires_at > ?
            ''',
            (token, datetime.now().isoformat())
        )
        token_data = cursor.fetchone()
        conn.close()
        return token_data

    @staticmethod
    def is_token_used(token):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT used FROM password_reset_tokens WHERE token = ?
            ''',
            (token,)
        )
        result = cursor.fetchone()
        conn.close()
        if result:
            return result['used'] != 0
        return True

    @staticmethod
    def mark_token_used(token):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            UPDATE password_reset_tokens SET used = 1 WHERE token = ?
            ''',
            (token,)
        )
        conn.commit()
        conn.close()
