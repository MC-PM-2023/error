from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

login_bp = Blueprint('login', __name__)

SMTP_SERVER = "smtp.datasolve-analytics.com"
SMTP_PORT = 587
WEBMAIL_USER = "apps.admin@datasolve-analytics.com"
WEBMAIL_PASSWORD = "datasolve@2025"

@login_bp.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return render_template('home.html')

# Login Route
@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        pwd = request.form['password']
        
        # Fetch user from `desktop_userstable`
        user = db.session.query(User).filter_by(username=username, verified=True).first()

        if user and check_password_hash(user.password, pwd):
            session['username'] = user.username
            return redirect(url_for('tools.tools_home'))  # Redirect after successful login
        elif user:
            return render_template('login.html', error="Account is not verified. Please verify your email.")
        else:
            return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')

# Logout Route
@login_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login.login'))
@login_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # ✅ Only allow emails from @datasolve-analytics.com
        allowed_domain = "datasolve-analytics.com"
        if not email.endswith(f"@{allowed_domain}"):
            return render_template('register.html', error="Only datasolve-analytics.com emails are allowed.")

        hashed_password = generate_password_hash(password)
        verification_code = random.randint(100000, 999999)

        # Check if username or email already exists
        existing_user = db.session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            return render_template('register.html', error="Username or email already exists.")

        # Create new user
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            verification_code=verification_code,
            verified=False
        )

        db.session.add(new_user)
        db.session.commit()

        # Send OTP for verification
        send_otp_email(email, verification_code)

        # Store verification details in session
        session['email'] = email
        session['verification_code'] = verification_code

        return redirect(url_for('login.verify'))

    return render_template('register.html', error="Only datasolve-analytics.com emails are allowed.")


# Registration Route
# @login_bp.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         email = request.form['email']
#         password = request.form['password']

#         hashed_password = generate_password_hash(password)
#         verification_code = random.randint(100000, 999999)

#         # Check if username or email already exists
#         existing_user = db.session.query(User).filter((User.username == username) | (User.email == email)).first()
#         if existing_user:
#             return render_template('register.html', error="Username or email already exists.")

#         # Create new user
#         new_user = User(
#             username=username, 
#             email=email, 
#             password=hashed_password,
#             verification_code=verification_code, 
#             verified=False
#         )
        
#         db.session.add(new_user)
#         db.session.commit()

#         # Send OTP for verification
#         send_otp_email(email, verification_code)

#         # Store verification details in session
#         session['email'] = email
#         session['verification_code'] = verification_code

#         return redirect(url_for('login.verify'))

#     return render_template('register.html')

# Verification Route
@login_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp = request.form['otp']

        if 'verification_code' in session and str(session['verification_code']) == otp:
            email = session.get('email')
            user = db.session.query(User).filter_by(email=email).first()
            if user:
                user.verified = True
                user.verification_code = None  # Clear the OTP after successful verification
                db.session.commit()

                session.pop('email', None)
                session.pop('verification_code', None)

                return render_template('login.html', success="Your account has been verified successfully!")
            return render_template('verify.html', error="User not found or verification error.")

    return render_template('verify.html')

# Function to send OTP via email
def send_otp_email(email, otp):
    try:
        otp_str = str(otp)
        subject = "Email Verification OTP"
        plain_text = f"Your OTP is: {otp_str}"
        html_content = f"""
        <html>
            <body>
                <h1>Email Verification</h1>
                <p>Your OTP is: <strong>{otp_str}</strong></p>
            </body>
        </html>
        """
        msg = MIMEMultipart("alternative")
        msg["From"] = f"Your App <{WEBMAIL_USER}>"
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(plain_text, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(WEBMAIL_USER, WEBMAIL_PASSWORD)
            server.sendmail(WEBMAIL_USER, email, msg.as_string())

    except Exception as error:
        print("Error sending OTP email:", error)
        
# Forgot Password Route
@login_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = db.session.query(User).filter_by(email=email, verified=True).first()

        if user:
            reset_code = random.randint(100000, 999999)
            user.verification_code = reset_code
            db.session.commit()

            send_otp_email(email, reset_code)
            session['reset_email'] = email

            flash("An OTP has been sent to your email to reset your password.", "info")
            return redirect(url_for('login.reset_password'))
        else:
            return render_template('forgot_password.html', error="No verified account found with this email.")

    return render_template('forgot_password.html')

        
# Reset Password Route
@login_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']

        if 'reset_email' in session:
            email = session['reset_email']
            user = db.session.query(User).filter_by(email=email).first()

            if user and str(user.verification_code) == otp:
                user.password = generate_password_hash(new_password)
                user.verification_code = None
                db.session.commit()

                session.pop('reset_email', None)
                flash("Your password has been reset. Please log in.", "success")
                return redirect(url_for('login.login'))
            else:
                return render_template('reset_password.html', error="Invalid OTP or email.")
    
    return render_template('reset_password.html')

