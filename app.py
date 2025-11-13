import os
import random
import smtplib
import traceback
import hashlib

import pandas as pd
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy import create_engine, text

from models import db, User  # <- your existing models.py

# ---------------------------------------------------------------------
#  ENV / CONFIG  (reads from app.yaml in App Engine)
# ---------------------------------------------------------------------
DATABASE_TYPE = "mysql"
DB_DRIVER = "pymysql"

DB_USER = os.getenv("DB_USER", "appsadmin")
DB_PASS = os.getenv("DB_PASS", "appsadmin2025")
DB_HOST = os.getenv("DB_HOST", "10.19.64.3")
DB_PORT = os.getenv("DB_PORT", "3306")

TGT_DB          = os.getenv("TGT_DB", "InSolvo_Documents")
DB_NAME         = os.getenv("DB_NAME", "elicita")       # For SQLAlchemy db
DATABASE_NAME   = os.getenv("DATABASE_NAME", "mc")      # Insolvo log
DATABASE_NAME_A = os.getenv("DATABASE_NAME_A", "elicita")  # Analytica log

SMTP_SERVER      = os.getenv("SMTP_SERVER", "smtp.datasolve-analytics.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT", "587"))
WEBMAIL_USER     = os.getenv("WEBMAIL_USER", "apps.admin@datasolve-analytics.com")
WEBMAIL_PASSWORD = os.getenv("WEBMAIL_PASSWORD", "datasolve@2025")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

# ---------------------------------------------------------------------
#  ENGINES
# ---------------------------------------------------------------------
# Analytica engine (elicita DB)
enginea = create_engine(
    f"{DATABASE_TYPE}+{DB_DRIVER}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DATABASE_NAME_A}"
)

# Insolvo engine (mc DB)
engine = create_engine(
    f"{DATABASE_TYPE}+{DB_DRIVER}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DATABASE_NAME}"
)

# Error tracker engine (InSolvo_Documents DB)
tgt_engine = create_engine(
    f"{DATABASE_TYPE}+{DB_DRIVER}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{TGT_DB}"
)

# ---------------------------------------------------------------------
#  FLASK APP
# ---------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Main SQLAlchemy DB bind (elicita DB with User model)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+{DB_DRIVER}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

# ---------------------------------------------------------------------
#  PROFILE MODEL (other schema: mainapp)
# ---------------------------------------------------------------------
class UserProfile(db.Model):
    __tablename__  = "User_Profiles"
    __table_args__ = {"extend_existing": True, "schema": "mainapp"}

    Email_ID    = db.Column(db.String(255), primary_key=True)
    Image_URL   = db.Column(db.Text)
    Designation = db.Column(db.String(200))
    Team        = db.Column(db.String(100))

# ---------------------------------------------------------------------
#  RESPONSE / CACHE HEADERS
# ---------------------------------------------------------------------
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

# ---------------------------------------------------------------------
#  AUTH HELPERS
# ---------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.")
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------------------------------------------
#  BASIC ROUTES
# ---------------------------------------------------------------------
@app.route("/")
def home():
    return redirect("/login")

@app.route("/welcome")
@login_required
def welcome():
    username = session.get("username")
    return render_template("welcome.html", username=username)

# ---------------------------------------------------------------------
#  OTP / VERIFY / REGISTER
# ---------------------------------------------------------------------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        otp = request.form.get("otp")

        if "verification_code" in session and str(session["verification_code"]) == otp:
            email = session.get("email")
            user = db.session.query(User).filter_by(email=email).first()
            if user:
                user.verified = True
                user.verification_code = None
                db.session.commit()

                session.pop("email", None)
                session.pop("verification_code", None)

                return render_template(
                    "login.html",
                    success="Your account has been verified successfully!",
                )
            return render_template("verify.html", error="User not found or verification error.")

    return render_template("verify.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    allowed_domain = "datasolve-analytics.com"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Only allow datasolve-analytics.com emails
        if not email.endswith(f"@{allowed_domain}"):
            return render_template(
                "register.html",
                error="Only datasolve-analytics.com emails are allowed."
            )

        hashed_password   = generate_password_hash(password)
        verification_code = random.randint(100000, 999999)

        # Check if username or email already exists
        existing_user = db.session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            return render_template(
                "register.html",
                error="Username or email already exists."
            )

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            verification_code=verification_code,
            verified=False,
        )
        db.session.add(new_user)
        db.session.commit()

        # Send OTP
        send_otp_email(email, verification_code)

        session["email"] = email
        session["verification_code"] = verification_code

        return redirect(url_for("verify"))

    # GET
    return render_template(
        "register.html",
        error="Only datasolve-analytics.com emails are allowed."
    )

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
        msg["From"] = f"InSolvo App <{WEBMAIL_USER}>"
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
        traceback.print_exc()

# ---------------------------------------------------------------------
#  LOGIN / LOGOUT
# ---------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pwd      = request.form.get("password", "")

        user = User.query.filter_by(username=username, verified=True).first()
        if user and check_password_hash(user.password, pwd):
            session["username"] = user.username
            session["role"]     = user.role
            session["email"]    = user.email
            return redirect("/welcome")
        else:
            flash("❌ Invalid credentials or not verified.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------------------------------------------------------------
#  FORGOT / RESET PASSWORD
# ---------------------------------------------------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        user = db.session.query(User).filter_by(email=email, verified=True).first()

        if user:
            reset_code = random.randint(100000, 999999)
            user.verification_code = reset_code
            db.session.commit()

            send_otp_email(email, reset_code)
            session["reset_email"] = email

            flash("An OTP has been sent to your email to reset your password.", "info")
            return redirect(url_for("reset_password"))
        else:
            return render_template(
                "forgot_password.html",
                error="No verified account found with this email."
            )

    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        otp          = request.form.get("otp", "")
        new_password = request.form.get("new_password", "")

        if "reset_email" in session:
            email = session["reset_email"]
            user  = db.session.query(User).filter_by(email=email).first()

            if user and str(user.verification_code) == otp:
                user.password = generate_password_hash(new_password)
                user.verification_code = None
                db.session.commit()

                session.pop("reset_email", None)
                flash("Your password has been reset. Please log in.", "success")
                return redirect(url_for("login"))
            else:
                return render_template(
                    "reset_password.html",
                    error="Invalid OTP or email."
                )
    return render_template("reset_password.html")

# ---------------------------------------------------------------------
#  HELPERS
# ---------------------------------------------------------------------
def clean_time_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Remove '0 days ' from Start_Time, End_Time, Runtime."""
    for field in ["Start_Time", "End_Time", "Runtime"]:
        if field in df.columns:
            df[field] = df[field].astype(str).str.replace("0 days ", "", regex=False)
    return df

def get_profile_for_email(email: str):
    """Return (Designation, Team, Image_URL) for an email from mainapp.User_Profiles."""
    if not email:
        return None, None, None
    rec = (
        db.session.query(UserProfile.Designation, UserProfile.Team, UserProfile.Image_URL)
        .filter(UserProfile.Email_ID == email)
        .first()
    )
    if not rec:
        return None, None, None
    return rec[0], rec[1], rec[2]

def gravatar_url(email: str, size=64, default="identicon"):
    if not email:
        return ""
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?s={size}&d={default}&r=g"

@app.context_processor
def inject_gravatar():
    return dict(gravatar_url=gravatar_url)

@app.context_processor
def inject_profile_image():
    """
    Make user_email + profile_image_url available in ALL templates.
    Uses session['email']; falls back to DB lookup by username.
    """
    img_url = None
    display_name = session.get("username")
    email = session.get("email")

    try:
        if not email and display_name:
            u = User.query.filter_by(username=display_name).first()
            email = u.email if u else None

        if email:
            rec = (
                db.session.query(UserProfile.Image_URL)
                .filter(UserProfile.Email_ID == email)
                .first()
            )
            if rec and rec[0]:
                img_url = rec[0]
    except Exception as e:
        app.logger.exception("Profile inject failed: %s", e)

    return {
        "user_email": email,
        "profile_image_url": img_url,
        "profile_name": display_name,
    }

# ---------------------------------------------------------------------
#  ERROR TRACKER MAIN VIEW (/file)
# ---------------------------------------------------------------------
@app.route("/file")
@login_required
def index():
    df = pd.read_sql(f"SELECT * FROM {TGT_DB}.{ 'insolvo_error_tracker' }", tgt_engine)
    df = clean_time_fields(df)
    return render_template(
        "tracker.html",
        data=df.to_dict(orient="records"),
        username=session.get("username"),
    )

@app.route("/approve", methods=["POST"])
@login_required
def approve():
    row_id    = request.form["id"]
    solution  = request.form.get("solution", "").strip()
    developer = request.form.get("developer", "").strip()
    remarks   = request.form.get("remarks", "").strip()

    query = text(f"""
        UPDATE {TGT_DB}.insolvo_error_tracker
        SET Solution = :solution,
            Developer = :developer,
            Remarks = :remarks
        WHERE id = :row_id
    """)

    with tgt_engine.begin() as conn:
        conn.execute(
            query,
            {
                "solution": solution,
                "developer": developer,
                "remarks": remarks,
                "row_id": row_id,
            },
        )

    return redirect("/file")

# ---------------------------------------------------------------------
#  INSOLVO LOGS (/log)
# ---------------------------------------------------------------------
@app.route("/log")
def log_page_with_data():
    if "fetch_data" in request.args:
        query = """
            SELECT
                id AS ID,
                Users AS Username,
                tool_name AS Tool_Name,
                status AS Status,
                start_date AS Tool_Start_Date,
                start_time AS Exec_Start_Time,
                end_time AS Exec_End_Time,
                runtime AS Duration
            FROM mc.`mc.desktop_user`
            ORDER BY start_date DESC
        """
        try:
            with engine.connect() as connection:
                result = pd.read_sql(query, connection)

            # ensure JSON-friendly types
            for col in result.columns:
                if pd.api.types.is_timedelta64_dtype(result[col]):
                    result[col] = result[col].astype(str)

            return jsonify(result.to_dict(orient="records"))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # HTML (unchanged)
    return '''  <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Execution Logs</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.datatables.net/searchpanes/2.2.0/css/searchPanes.dataTables.min.css">
  <link rel="stylesheet" href="https://cdn.datatables.net/select/1.7.0/css/select.dataTables.min.css">
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/searchpanes/2.2.0/js/dataTables.searchPanes.min.js"></script>
  <script src="https://cdn.datatables.net/select/1.7.0/js/dataTables.select.min.js"></script>

  <style>
    body {
      background: linear-gradient(135deg, #1f1c2c, #928dab);
      font-family: 'Segoe UI', sans-serif;
      color: #fff;
      padding: 20px;
    }

    .table-container {
      background: rgba(255, 255, 255, 0.1);
      border-radius: 15px;
      padding: 25px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
      max-width: 95%;
      margin: auto;
      overflow-x: auto;
      backdrop-filter: blur(10px);
    }

    h1 {
      text-align: center;
      font-size: 2.5rem;
      margin-bottom: 25px;
      color: #fff;
      font-weight: 600;
    }

    table.dataTable thead th {
      background-color: #343a40;
      color: #fff;
      text-align: center;
      font-size: 0.9rem;
      white-space: nowrap;
    }

    table.dataTable thead th span {
      font-size: 0.85rem;
    }

    table.dataTable tbody tr {
      background-color: #f8f9fa;
      height: 36px;
      transition: background 0.3s;
    }

    table.dataTable tbody tr:nth-child(even) {
      background-color: #e9ecef;
    }

    table.dataTable tbody tr:hover {
      background-color: #dee2e6;
    }

    .column-filter {
      width: 100%;
      padding: 4px;
      font-size: 0.8rem;
      border-radius: 5px;
    }

    #log-table {
      width: 100%;
      table-layout: fixed;
    }

    #log-table td {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    #log-table tbody tr.expanded {
      height: auto;
    }

    #log-table tbody tr.expanded td {
      white-space: normal;
      overflow: visible;
      text-overflow: clip;
    }

    .mt-4.text-center {
      margin-top: 40px !important;
    }

    #id-input {
      background-color: #fff;
      border-radius: 6px;
      padding: 6px 10px;
      font-size: 0.95rem;
    }

    .btn-warning {
      background-color: #f39c12;
      border-color: #f39c12;
      font-weight: bold;
      transition: background 0.3s ease;
    }

    .btn-warning:hover {
      background-color: #e67e22;
      border-color: #e67e22;
    }
  </style>
</head>
<body>
<a href="/file" style="position: absolute; top: 30px; left: 80px; z-index: 999; font-weight: bold; display: flex; align-items: center; gap: 6px; background-color: white; padding: 6px 6px; border-radius: 6px; border: 1px solid #ccc;">
  <img src="/static/home.png" alt="Home Icon" style="width: 25px; height: 25px;">
</a>

<div class="table-container">
  <h1>Execution Logs</h1>
  <table id="log-table" class="display table table-striped table-bordered">
    <thead>
      <tr id="table-head"></tr>
    </thead>
    <tbody id="table-body"></tbody>
  </table>
</div>

<div class="mt-4 text-center">
  <label for="id-input" class="text-light fw-bold">Enter ID to Push:</label>
  <input type="number" id="id-input" class="form-control d-inline w-auto mx-2" placeholder="Enter ID" />
  <button class="btn btn-warning" onclick="pushRowToDB()">Push to Error Tracker</button>
</div>

<script>
  async function fetchData() {
    try {
      const response = await $.get('/log?fetch_data=true');
      populateTable(response);
    } catch (error) {
      console.error('Error fetching data:', error);
      alert('Failed to fetch execution logs. Please try again later.');
    }
  }

  function populateTable(data) {
    const tableHead = $('#table-head');
    const tableBody = $('#table-body');
    const columnOrder = ['ID', 'Username', 'Tool_Name', 'Status', 'Tool_Start_Date', 'Exec_Start_Time', 'Exec_End_Time', 'Duration'];

    tableHead.empty();
    tableBody.empty();

    if (data.length === 0) {
      tableBody.append('<tr><td colspan="100%" class="text-center">No data available</td></tr>');
      return;
    }

    columnOrder.forEach(header => {
      const titleCaseHeader = header
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(' ');
      tableHead.append(`
        <th>
          <div class="d-flex flex-column align-items-center">
            <span>${titleCaseHeader}</span>
            <select class="column-filter" data-column="${header}">
              <option value="">All</option>
            </select>
          </div>
        </th>
      `);
    });

    data.forEach(row => {
      const tr = $('<tr></tr>');
      columnOrder.forEach(header => {
        tr.append(`<td>${row[header] || ''}</td>`);
      });
      tableBody.append(tr);
    });

    const table = $('#log-table').DataTable({
      destroy: true,
      paging: true,
      searching: true,
      scrollX: true,
      dom: 'frtip',
      order: [[0, 'desc']]
    });

    columnOrder.forEach((header, index) => {
      const uniqueValues = [...new Set(data.map(item => item[header]))].sort();
      const select = tableHead.find(`select[data-column="${header}"]`);
      uniqueValues.forEach(value => {
        select.append(`<option value="${value}">${value}</option>`);
      });
      select.on('change', function () {
        const column = table.column(index);
        const selectedValue = $(this).val();
        column.search(selectedValue).draw();
      });
    });

    $('#log-table tbody').on('click', 'tr', function () {
      $(this).toggleClass('expanded');
    });
  }

  function pushRowToDB() {
    const id = $('#id-input').val();
    if (!id) {
      alert("Please enter a valid ID.");
      return;
    }

    fetch(`/push_to_error_tracker?id=${id}`)
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          alert("✅ Row successfully pushed to Error Tracker table.");
        } else {
          alert("❌ Failed to push row: " + data.error);
        }
      })
      .catch(err => {
        console.error("Error:", err);
        alert("Something went wrong.");
      });
  }

  fetchData();
</script>
</body>
</html>
'''

# ---------------------------------------------------------------------
#  ANALYTICA LOGS (/loga)
# ---------------------------------------------------------------------
@app.route("/loga")
def log_page_with_dataa():
    if "fetch_data" in request.args:
        query = """
            SELECT 
                id AS ID,
                Users AS Username,
                tool_name AS Tool_Name,
                status AS Status,
                start_date AS Tool_Start_Date,
                start_time AS Exec_Start_Time,
                end_time AS Exec_End_Time,
                runtime AS Duration
            FROM elicita.`desktop_user_ip`
            ORDER BY start_date DESC
        """
        try:
            with enginea.connect() as connection:
                result = pd.read_sql(query, connection)

            for col in result.columns:
                if pd.api.types.is_timedelta64_dtype(result[col]):
                    result[col] = result[col].astype(str)

            return jsonify(result.to_dict(orient="records"))
        except Exception as e:
            print("ERROR FETCHING LOGS:", e)
            return jsonify({"error": str(e)}), 500

    # HTML (unchanged)
    return '''   <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Execution Logs</title>

  <!-- Bootstrap and DataTables CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.datatables.net/searchpanes/2.2.0/css/searchPanes.dataTables.min.css">
  <link rel="stylesheet" href="https://cdn.datatables.net/select/1.7.0/css/select.dataTables.min.css">

  <!-- jQuery and DataTables JS -->
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/searchpanes/2.2.0/js/dataTables.searchPanes.min.js"></script>
  <script src="https://cdn.datatables.net/select/1.7.0/js/dataTables.select.min.js"></script>

  <style>
    body {
      background: linear-gradient(to right, #2c3e50, #4ca1af);
      font-family: 'Segoe UI', sans-serif;
      color: #fff;
      padding: 30px;
    }

    h1 {
      text-align: center;
      font-size: 2.8rem;
      margin-bottom: 30px;
      font-weight: bold;
      letter-spacing: 1px;
    }

    .table-container {
      background: rgba(255, 255, 255, 0.12);
      border-radius: 16px;
      padding: 30px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
      max-width: 100%;
      overflow-x: auto;
      backdrop-filter: blur(8px);
    }

    table.dataTable {
      width: 100% !important;
    }

    table.dataTable thead th {
      background-color: #2c3e50;
      color: #fff;
      font-size: 0.95rem;
      vertical-align: middle;
      padding: 10px 8px;
      white-space: nowrap;
      text-align: center;
    }

    table.dataTable thead select {
      width: 100%;
      margin-top: 6px;
      font-size: 0.8rem;
      padding: 3px 4px;
      border-radius: 5px;
      border: none;
      box-shadow: inset 0 0 3px rgba(0,0,0,0.2);
    }

    table.dataTable tbody td {
      font-size: 0.9rem;
      text-align: center;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      padding: 10px 6px;
    }

    table.dataTable tbody tr:nth-child(even) {
      background-color: #f1f1f1;
    }

    table.dataTable tbody tr:hover {
      background-color: #dce3e8;
    }

    .dataTables_wrapper .dataTables_filter {
      float: right;
      margin-bottom: 10px;
    }

    .dataTables_wrapper .dataTables_filter input {
      border-radius: 5px;
      padding: 5px;
    }

    .action-bar {
      margin-top: 40px;
      text-align: center;
    }

    #id-input {
      background-color: #fff;
      border-radius: 8px;
      padding: 6px 12px;
      font-size: 1rem;
      width: 200px;
      display: inline-block;
      margin-left: 10px;
    }

    .btn-warning {
      background-color: #f39c12;
      border-color: #f39c12;
      font-weight: bold;
      padding: 8px 16px;
      font-size: 1rem;
      margin-left: 10px;
      transition: 0.3s ease;
    }

    .btn-warning:hover {
      background-color: #e67e22;
      border-color: #e67e22;
    }
  </style>
</head>
<body>
  
 <a href="/file" style="position: absolute; top: 40px; left: 40px; z-index: 999; font-weight: bold; display: flex; align-items: center; gap: 6px; background-color: white; padding: 6px 6px; border-radius: 6px; border: 1px solid #ccc;">
  <img src="/static/home.png" alt="Home Icon" style="width: 25px; height: 25px;">
</a>
  <div class="table-container">
    <h1>Execution Logs</h1>
    <table id="log-table" class="display table table-bordered table-striped">
      <thead>
        <tr id="table-head"></tr>
      </thead>
      <tbody id="table-body"></tbody>
    </table>
  </div>

  <div class="action-bar">
    <label for="id-input" class="fw-bold text-white">Enter ID to Push:</label>
    <input type="number" id="id-input" class="form-control d-inline" placeholder="Enter ID" />
    <button class="btn btn-warning" onclick="pushRowToDB()">Push to Error Tracker</button>
  </div>

  <script>
    async function fetchData() {
      try {
        const response = await $.get('/loga?fetch_data=true');
        populateTable(response);
      } catch (error) {
        console.error('Error fetching data:', error);
        alert('Failed to fetch execution logs. Please try again later.');
      }
    }

    function populateTable(data) {
      const tableHead = $('#table-head');
      const tableBody = $('#table-body');
      const columnOrder = ['ID', 'Username', 'Tool_Name', 'Status', 'Tool_Start_Date', 'Exec_Start_Time', 'Exec_End_Time', 'Duration'];

      tableHead.empty();
      tableBody.empty();

      if (data.length === 0) {
        tableBody.append('<tr><td colspan="100%" class="text-center text-white">No data available</td></tr>');
        return;
      }

      columnOrder.forEach(header => {
        tableHead.append(`<th>${header}<br><select class="column-filter" data-column="${header}"><option value="">All</option></select></th>`);
      });

      data.forEach(row => {
        const tr = $('<tr></tr>');
        columnOrder.forEach(header => {
          tr.append(`<td>${row[header] || ''}</td>`);
        });
        tableBody.append(tr);
      });

      const table = $('#log-table').DataTable({
        destroy: true,
        paging: true,
        searching: true,
        scrollX: true,
        autoWidth: false,
        columnDefs: [{ targets: '_all', className: 'dt-center' }],
        dom: 'frtip',
        order: [[0, 'desc']]
      });

      columnOrder.forEach((header, index) => {
        const uniqueValues = [...new Set(data.map(item => item[header]))].sort();
        const select = tableHead.find(`select[data-column="${header}"]`);
        uniqueValues.forEach(value => {
          select.append(`<option value="${value}">${value}</option>`);
        });
        select.on('change', function () {
          const column = table.column(index);
          const selectedValue = $(this).val();
          column.search(selectedValue).draw();
        });
      });

      $('#log-table tbody').on('click', 'tr', function () {
        $(this).toggleClass('expanded');
      });
    }

    function pushRowToDB() {
      const id = $('#id-input').val();
      if (!id) {
        alert("Please enter a valid ID.");
        return;
      }

      fetch(`/push_to_error_tracker?id=${id}`)
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            alert("✅ Row successfully pushed to Error Tracker table.");
          } else {
            alert("❌ Failed to push row: " + data.error);
          }
        })
        .catch(err => {
          console.error("Error:", err);
          alert("Something went wrong.");
        });
    }

    fetchData();
  </script>
</body>
</html>
'''

# ---------------------------------------------------------------------
#  MAIN (local dev only)
# ---------------------------------------------------------------------
if __name__ == "__main__":
    # For local testing only. In App Engine, gunicorn runs this app.
    app.run(host="0.0.0.0", port=5008, debug=True)
