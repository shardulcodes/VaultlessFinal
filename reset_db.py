# reset_db.py
from app import app, db

with app.app_context():
    db.drop_all()
    db.create_all()
    print("✅ Database reset successfully.")
