import os
from dotenv import load_dotenv

# Load environment variables from .env (for local dev)
load_dotenv()

class Config:
    # Secret Key for session management & CSRF protection
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_dev_key')  # Should be overridden in production!

    # Database connection URI (e.g., Supabase PostgreSQL)
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-Mail Configuration (Gmail SMTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

    # Optional: Environment (used by Flask or your app logic)
    ENV = os.getenv('FLASK_ENV', 'development')

    # Optional: Enable debug in development only
    DEBUG = ENV == 'development'
