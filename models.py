from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    
    # ➕ Add this line
    secret_key = db.Column(db.LargeBinary(128), nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def generate_verification_token(self):
        s = Serializer(Config.SECRET_KEY)
        return s.dumps(self.email)

    @staticmethod
    def verify_token(token, expiration=3600):
        s = Serializer(Config.SECRET_KEY)
        try:
            email = s.loads(token, max_age=expiration)
        except Exception:
            return None
        return email
