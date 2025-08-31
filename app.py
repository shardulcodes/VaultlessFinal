from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, make_response
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from forms import RegistrationForm, LoginForm, ChangeUsernameForm, ChangePasswordForm, ForgotPasswordForm, ResetPasswordForm
from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from models import bcrypt, User  # No longer using db
from dotenv import load_dotenv
import os, base64, hashlib, string, hmac, requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask import current_app  # for BASE_URL fallback

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
bcrypt.init_app(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ==================== Secret Keys ====================
def get_or_create_secret_from_env(length=64):
    env_secret = os.environ.get("DEVICE_SECRET")
    if not env_secret:
        raise RuntimeError("DEVICE_SECRET environment variable not set in Vercel.")

    # Fix padding if required
    missing_padding = len(env_secret) % 4
    if missing_padding:
        env_secret += '=' * (4 - missing_padding)

    return base64.urlsafe_b64decode(env_secret)


DEVICE_SECRET = get_or_create_secret_from_env()

# ==================== Password Generator ====================
def generate_password(name: str, master_password: str, length: int, key: bytes = None) -> str:
    if length < 8 or length > 64:
        return None
    secret = key or DEVICE_SECRET
    combined = secret + f"{name}{master_password}{length}".encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secret, iterations=100000)
    derived_key = kdf.derive(combined)
    hash_digest = hmac.new(derived_key, combined, hashlib.sha256).hexdigest()
    charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(charset[int(hash_digest[i * 2:(i * 2) + 2], 16) % len(charset)] for i in range(length))

# ==================== User Loader ====================
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# ==================== Routes ====================
@app.route('/')
def index():
    response = make_response(render_template('index.html'))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/generate', methods=['POST'])
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
        if User.get_by_email(form.email.data):
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        user = User(
            id=None,
            username=form.username.data,
            email=form.email.data,
            password_hash=None,
            is_verified=False
        )
        user.set_password(form.password.data)

        #   Generate a secret key once — and only once
        user.secret_key = os.urandom(64)

        try:
            user.save_to_supabase()
        except Exception as e:
            print(f"[  Supabase Error] While saving user: {e}")
            flash("Something went wrong while registering. Please try again.", "danger")
            return redirect(url_for("register"))

        #   Email Verification
        try:
            token = user.generate_verification_token()
            base_url = os.getenv("BASE_URL", "http://localhost:5000")
            verify_url = f"{base_url}/verify/{token}"

            msg = Message('Verify Your Email',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[user.email])
            msg.body = f'Click the link to verify your email: {verify_url}'
            mail.send(msg)
        except Exception as e:
            print(f"[  Email Error] Failed to send email: {e}")
            flash("Account created, but email failed to send. Contact support.", "warning")

        flash('Account created! Please check your email to verify.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)




@app.route('/verify/<token>')
def verify_email(token):
    email = User.verify_token(token)
    if not email:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.get_by_email(email)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('register'))

    if user.is_verified:
        flash('Your email is already verified. You can log in.', 'info')
    else:
        try:
            user.is_verified = True
            user.update_in_supabase()
            flash('Email verified! You can now log in.', 'success')
        except Exception as e:
            print(f"[  Supabase Error] While verifying user: {e}")
            flash('Verification failed. Please try again later.', 'danger')

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and user.check_password(form.password.data):
            if user.is_verified:
                if not user.secret_key:
                    flash('Your account is missing a secret key. Please contact support.', 'danger')
                    return redirect(url_for('login'))

                login_user(user, remember=form.remember.data)
                
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
            #   Update while preserving secret_key
            current_user.update_in_supabase()
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
            current_user.password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            #   Update while preserving secret_key
            current_user.update_in_supabase()
            flash('Password updated successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Current password is incorrect.', 'danger')
    return render_template('change_password.html', form=form)

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password_section():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user:
            try:
                token = user.generate_reset_token()
                base_url = os.getenv("BASE_URL","https://localhost:5000")
                base_url="http://localhost:5000" #just for development purpose
                reset_url = f"{base_url}/reset-password/{token}"
                
                msg = Message("Passwrd Reset Request",
                              sender = app.config['MAIL_USERNAME'],
                              recipients=[user.email])
                
                msg.body = f"Click the link to reset your password: {reset_url}\nIf you did not request this, please ignore."
                mail.send(msg)
            except Exception as e:
                print(f"[ Email Error ] {e}")
                flash("Error sending reset email. Try again later.", "danger")
                return redirect(url_for('forgot_password'))
        flash("If that email exists, a password reset link has been sent","info")
        return redirect(url_for('login'))
    return render_template('forgot_password.html',form=form)

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    user = User.verify_reset_token(token)
    if not user:
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password_section'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        try:
            user.update_in_supabase()
            flash("Your password has been updated! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"[ Supabase Error ] {e}")
            flash("Something went wrong updating your password.", "danger")
            return redirect(url_for('forgot_password_section'))
    
    return render_template('reset_password.html', form=form)

    





#if __name__ == "__main__":
  #  app.run(ssl_context="adhoc")

if __name__ == "__main__":
    app.run(debug=True) 