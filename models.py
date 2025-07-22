import os
import requests
import base64
from typing import Optional
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from config import Config

bcrypt = Bcrypt()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
SUPABASE_USERS_ENDPOINT = f"{SUPABASE_URL}/rest/v1/users"

HEADERS = {
    "apikey": SUPABASE_API_KEY,
    "Authorization": f"Bearer {SUPABASE_API_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}


class User(UserMixin):
    def __init__(self, id, username, email, password_hash, is_verified, secret_key=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.secret_key = secret_key  # raw bytes

    def get_id(self) -> str:
        return str(self.id)

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)

    def generate_verification_token(self) -> str:
        s = Serializer(Config.SECRET_KEY)
        return s.dumps(self.email)

    @staticmethod
    def verify_token(token: str, expiration=3600) -> Optional[str]:
        s = Serializer(Config.SECRET_KEY)
        try:
            return s.loads(token, max_age=expiration)
        except Exception:
            return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "password_hash": self.password_hash,
            "is_verified": self.is_verified,
            "secret_key": base64.b64encode(self.secret_key).decode() if self.secret_key else None
        }

    def save_to_supabase(self):
        payload = self.to_dict()
        res = requests.post(SUPABASE_USERS_ENDPOINT, headers=HEADERS, json=payload)
        if res.status_code not in (200, 201):
            print("❌ Supabase save error:", res.status_code, res.text)
            raise Exception(f"Supabase save error: {res.status_code} - {res.text}")
        try:
            self.id = res.json()[0]["id"]
        except Exception as e:
            print("⚠️ Failed to parse Supabase response:", res.text)
            raise e

    def update_in_supabase(self):
        if not self.id:
            raise ValueError("User ID is required for update.")

        # 🛡 Fetch existing to preserve the real secret_key
        existing = User.get_by_id(self.id)
        if not existing or not existing.secret_key:
            raise Exception("User not found or missing secret_key.")

        preserved_secret_key = existing.secret_key

        # Prepare only fields to update — never touch secret_key
        payload = {}

        if self.username != existing.username:
            payload["username"] = self.username
        if self.email != existing.email:
            payload["email"] = self.email
        if self.password_hash and self.password_hash != existing.password_hash:
            payload["password_hash"] = self.password_hash
        if self.is_verified != existing.is_verified:
            payload["is_verified"] = self.is_verified

        # Always preserve secret_key
        payload["secret_key"] = base64.b64encode(preserved_secret_key).decode()

        url = f"{SUPABASE_USERS_ENDPOINT}?id=eq.{self.id}"
        res = requests.patch(url, headers=HEADERS, json=payload)
        if res.status_code not in (200, 204):
            print("❌ Supabase update error:", res.status_code, res.text)
            raise Exception(f"Supabase update error: {res.status_code} - {res.text}")

        # Update in-memory
        self.secret_key = preserved_secret_key

    @staticmethod
    def get_by_email(email: str) -> Optional['User']:
        url = f"{SUPABASE_USERS_ENDPOINT}?email=eq.{email}&select=*"
        res = requests.get(url, headers=HEADERS)
        if res.status_code == 200 and res.json():
            return User._from_dict(res.json()[0])
        return None

    @staticmethod
    def get_by_username(username: str) -> Optional['User']:
        url = f"{SUPABASE_USERS_ENDPOINT}?username=eq.{username}&select=*"
        res = requests.get(url, headers=HEADERS)
        if res.status_code == 200 and res.json():
            return User._from_dict(res.json()[0])
        return None

    @staticmethod
    def get_by_id(user_id: int) -> Optional['User']:
        url = f"{SUPABASE_USERS_ENDPOINT}?id=eq.{user_id}&select=*"
        res = requests.get(url, headers=HEADERS)
        if res.status_code == 200 and res.json():
            return User._from_dict(res.json()[0])
        return None

    @staticmethod
    def decode_secret_key(key_str: str) -> Optional[bytes]:
        import binascii
        try:
            if key_str.startswith("\\x"):
                return bytes.fromhex(key_str[2:])
            return base64.b64decode(key_str)
        except (binascii.Error, ValueError) as e:
            print(f"❌ Error decoding secret_key: {e}")
            return None

    @staticmethod
    def _from_dict(data: dict) -> 'User':
        secret_key_raw = data.get("secret_key")
        decoded_key = User.decode_secret_key(secret_key_raw) if secret_key_raw else None

        return User(
            id=data.get("id"),
            username=data.get("username"),
            email=data.get("email"),
            password_hash=data.get("password_hash"),
            is_verified=data.get("is_verified"),
            secret_key=decoded_key
        )
