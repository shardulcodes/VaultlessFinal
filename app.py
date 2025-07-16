from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, bcrypt, User
from forms import RegistrationForm, LoginForm
from forms import ChangeUsernameForm, ChangePasswordForm
from flask import make_response
from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import os
import base64
import hashlib
import string
import hmac
from dotenv import load_dotenv
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ==================== App Setup ====================
app = Flask(__name__)
app.config.from_object(Config)


load_dotenv()


# Security Headers
if os.getenv("FLASK_ENV") == "production":
    Talisman(app, content_security_policy=None)
else:
    Talisman(app, content_security_policy=None, force_https=False)

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["30 per minute"])

# Flask Extensions
db.init_app(app)
bcrypt.init_app(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ==================== Secret Keys ====================
DEVICE_SECRET_FILE = "device_secret.key"



def get_or_create_secret_from_env(length=64):
    env_secret = os.environ.get("DEVICE_SECRET")
    if not env_secret:
        raise RuntimeError("DEVICE_SECRET environment variable not set in Vercel.")
    return base64.urlsafe_b64decode(env_secret)

DEVICE_SECRET = get_or_create_secret_from_env()


# ==================== Password Generator ====================
def generate_password(name: str, master_password: str, length: int, key: bytes = None) -> str:
    if length < 8 or length > 64:
        return None

    secret = key or DEVICE_SECRET
    combined = secret + f"{name}{master_password}{length}".encode()


    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=secret,
        iterations=100000,
    )
    derived_key = kdf.derive(combined)

    hash_digest = hmac.new(derived_key, combined, hashlib.sha256).hexdigest()
    charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    password = ''.join(charset[int(hash_digest[i * 2:(i * 2) + 2], 16) % len(charset)] for i in range(length))

    return password

# ==================== User Loader ====================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== Routes ====================
@app.route('/')
def index():
    response = make_response(render_template('index.html'))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/generate', methods=['POST'])
#@limiter.limit("5 per minute")
def generate():
    data = request.json

    if not data or "name" not in data or "master_password" not in data or "length" not in data:
        return jsonify({"error": "Invalid request format"}), 400

    try:
        length = int(data["length"])
    except ValueError:
        return jsonify({"error": "Length must be an integer"}), 400

    if length < 8 or length > 64:
        return jsonify({"error": "Password length must be between 8 and 64."}), 400

    key = current_user.secret_key if current_user.is_authenticated and current_user.secret_key else None
    password = generate_password(data["name"], data["master_password"], length, key)
    return jsonify({"password": password})

@app.route('/get-local')
def get_local():
    return render_template('docker_install.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        token = user.generate_verification_token()
        verify_url = url_for('verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
        msg.body = f'Click the link to verify your email: {verify_url}'
        mail.send(msg)

        flash('Account created! Please check your email to verify.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/verify/<token>')
def verify_email(token):
    email = User.verify_token(token)
    if not email:
        flash('The verification link is invalid or expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()
        flash('Email verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if user.is_verified:
                if not user.secret_key:
                    user.secret_key = generate_user_key()
                    db.session.commit()
                login_user(user, remember=form.remember.data)
                flash('Login successful.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Please verify your email before logging in.', 'warning')
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/how-to-use')
def how_to_use():
    return render_template('how_to_use.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change_username', methods=['GET', 'POST'])
@login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password_hash, form.password.data):
            current_user.username = form.new_username.data
            db.session.commit()
            flash('Username updated successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Incorrect password.', 'danger')
    return render_template('change_username.html', form=form)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password_hash, form.current_password.data):
            hashed_pw = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            current_user.password = hashed_pw
            db.session.commit()
            flash('Password updated successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Current password is incorrect.', 'danger')
    return render_template('change_password.html', form=form)



# ==================== Run App ====================
if __name__ == "__main__":
    from models import db
    with app.app_context():
        db.create_all()
    app.run()

