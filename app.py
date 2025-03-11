import os
import hashlib
import time
import random
from flask import Flask, render_template, flash, request, url_for, send_file, jsonify, redirect
from reportlab.pdfgen import canvas
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_session import Session
import logging
from google.oauth2 import id_token  # ✅ Import this
from google.auth.transport import requests as google_requests
from flask import session
from datetime import datetime
from datetime import datetime, timedelta

from sqlalchemy import func, cast, Date
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from azure.storage.blob import BlobServiceClient
from io import BytesIO
from werkzeug.utils import secure_filename
import json
from reportlab.lib.pagesizes import A4
from markupsafe import Markup
import bleach  # ✅ Sanitize HTML to prevent XSS
from sqlalchemy.exc import SQLAlchemyError
from flask_caching import Cache  # ✅ Import Cache


from dotenv import load_dotenv




app = Flask(__name__)
load_dotenv()




# ✅ Configure Logging
logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"  # Stores session data
app.config["SESSION_COOKIE_SECURE"] = False  # Force HTTPS only
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protect against CSRF attacks

Session(app)  # Initialize Flask-Session



# Load PayU credentials from environment variables
MERCHANT_KEY = os.getenv("PAYU_MERCHANT_KEY")
MERCHANT_SALT = os.getenv("PAYU_MERCHANT_SALT")

# Validate that the credentials are set
if not MERCHANT_KEY or not MERCHANT_SALT:
    raise ValueError("PayU credentials are missing. Set PAYU_MERCHANT_KEY and PAYU_MERCHANT_SALT environment variables.")

PAYU_URL = os.getenv("PAYU_URL", "https://secure.payu.in/_payment")  # Fetch from environment


# Azure Blob Storage Configuration
AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")


BLOB_SERVICE_CLIENT = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)

CONTAINER_MAPPING = {
    "worksheet": "pdf-storage",   # Store worksheets in pdf-storage container
    "flashcard": "flashcards-storage"  # Store flashcards in flashcards-storage container
}




# ✅ Database Configuration (Using ODBC)
DB_SERVER = os.getenv("DB_SERVER")
DB_NAME = os.getenv("DB_NAME")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DRIVER = os.getenv("DB_DRIVER", "ODBC Driver 18 for SQL Server")

DATABASE_URL = f"mssql+pyodbc://{DB_USERNAME}:{DB_PASSWORD}@{DB_SERVER}/{DB_NAME}?driver={DB_DRIVER.replace(' ', '+')}"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secret_key'

db = SQLAlchemy(app)




# ✅ Hash Generation Function for PayU
def generate_payu_hash(txnid, amount, productinfo, firstname, email):
    hash_sequence = f"{MERCHANT_KEY}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{MERCHANT_SALT}"
    return hashlib.sha512(hash_sequence.encode('utf-8')).hexdigest().lower()

# ✅ Define User Model (With Picture)
# ✅ Define User Model (With Picture)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    picture = db.Column(db.String(300), nullable=True)
    is_active = db.Column(db.Boolean, default=True)  # ✅ For enabling/disabling user access
    is_admin = db.Column(db.Boolean, default=False)   # ✅ For enabling/disabling admin access
 # ✅ New column for admin access

    def __init__(self, google_id, email, name, picture=None, is_admin=False):
        self.google_id = google_id
        self.name = name
        self.email = email
        self.picture = picture
        self.is_admin = is_admin  # ✅ Initialize is_admin


   

    
# ✅ Define Payment Model
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)  # User's email
    name = db.Column(db.String(100), nullable=False)  # User's name
    plan_name = db.Column(db.String(50), nullable=False)  # Subscription Plan
    amount = db.Column(db.Float, nullable=False)  # Amount Paid
    txnid = db.Column(db.String(50), unique=True, nullable=False)  # Transaction ID
    payment_status = db.Column(db.String(20), nullable=False, default="Pending")  # Success, Failed, Pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp

    def __init__(self, email, name, plan_name, amount, txnid, payment_status="Pending"):
        self.email = email
        self.name = name
        self.plan_name = plan_name
        self.amount = amount
        self.txnid = txnid
        self.payment_status = payment_status





    

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    room = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", backref=db.backref("messages", lazy=True))



class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("questions", lazy=True))


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    answer_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("answers", lazy=True))
    question = db.relationship("Question", backref=db.backref("answers", lazy=True))
    



class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_name = db.Column(db.String(255), nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default="AI Generated")
    pdf_base64 = db.Column(db.Text, nullable=True)  # ✅ Ensure this column exists

    user = db.relationship("User", backref=db.backref("activity_logs", lazy=True))


class FounderMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ExpertQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("expert_questions", lazy=True))
    
    
class Batch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String(20), nullable=False)
    week = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    
# ✅ Ensure Tables are Created
with app.app_context():
    db.create_all()
    print("✅ Database tables created successfully!")


app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Load Flask secret key from .env
# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

app.config["GOOGLE_DISCOVERY_URL"] = "https://accounts.google.com/.well-known/openid-configuration"



oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params={"scope": "openid email profile"},
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url=app.config["GOOGLE_DISCOVERY_URL"],
)


ADMIN_EMAILS = {"msamiksha1607@gmail.com", "snaik0704@gmail.com", "talk2cshah@gmail.com"}  # Add more admins as needed
  # Add more if needed




@app.route("/")
def home():
    return render_template("index.html")

import secrets


@app.route("/login")
def login():
    """Handles login and sets next_url based on action"""

    # Allowed domains for OAuth redirection
    allowed_domains = {
        "levelupai.azurewebsites.net": "https://levelupai.azurewebsites.net/auth/callback",
        "leveluponline.shop": "https://leveluponline.shop/auth/callback",
        "127.0.0.1": "http://127.0.0.1:8000/auth/callback",  # Local testing
        "localhost": "http://localhost:8000/auth/callback",  # Localhost testing
    }

    current_domain = request.host.split(":")[0]  # Extract domain without port
    redirect_url = allowed_domains.get(current_domain)

    if not redirect_url:
        return "Unauthorized domain", 400  # Reject if domain is not in the list

    session["is_payment_flow"] = False  # ❌ Not a payment flow
    # ✅ Store the next page user should visit
    next_url = request.args.get("next", url_for("chatbot"))  # Default is chatbot
    session["next_url"] = next_url
    session["oauth_state"] = secrets.token_urlsafe(16)  # ✅ Store CSRF state token

    logging.info(f"Redirecting to Google OAuth: {redirect_url}")  # Debugging
    return google.authorize_redirect(
        redirect_url, state=session["oauth_state"]  # ✅ Include CSRF state
    )

@app.route("/auth/callback")
def auth_callback():
    logging.info("🔄 Google OAuth callback hit!")

    try:
        # ✅ Validate OAuth state to prevent CSRF attacks
        received_state = request.args.get("state")
        expected_state = session.pop("oauth_state", None)

        if not received_state or received_state != expected_state:
            logging.error("❌ CSRF Warning! State mismatch detected.")
            return "<h3>CSRF Warning! Invalid OAuth state.</h3>", 400

        # ✅ Retrieve OAuth Token
        token = google.authorize_access_token()
        if not token:
            logging.error("❌ No token received from Google!")
            return "<h3>Authentication failed</h3>", 400

        # ✅ Get user info from Google
        resp = google.get("https://www.googleapis.com/oauth2/v3/userinfo")
        if resp.status_code != 200:
            logging.error(f"❌ Google API Error: {resp.status_code} - {resp.text}")
            return "<h3>Error retrieving user info</h3>", 400

        user_info = resp.json()
        email = user_info.get("email")
        google_id = user_info.get("sub")
        name = user_info.get("name", "User")
        picture = user_info.get("picture", "/static/images/default.png")  # Default if missing

        logging.info(f"✅ Google Login Successful - Email: {email}")

        # 🔄 Check user in the database
        user = db.session.query(User).filter((User.google_id == google_id) | (User.email == email)).first()

        if user:
            # 🔄 Update session to reflect the latest status from the database
            user.is_admin = user.is_admin  # ✅ Ensure admin status is fetched correctly
            user.picture = picture  # ✅ Update profile picture in DB
            session_data = {
                "google_id": google_id,
                "email": email,
                "name": name,
                "is_admin": user.is_admin,  # ✅ Store admin status
                "user_id": user.id,
                "picture": picture  # ✅ Store picture in session
            }
            if user.is_admin:
                session["admin_session"] = session_data
            else:
                session["user_session"] = session_data
        else:
            # 🆕 Create new user
            logging.info(f"🆕 Creating new user in DB: {email}")
            user = User(
                google_id=google_id,
                email=email,
                name=name,
                picture=picture,  # ✅ Save profile picture
                is_admin=False  # 🛑 New users are not admin by default
            )
            db.session.add(user)
            db.session.commit()

            # ✅ Store in correct session structure
            session["user_session"] = {
                "google_id": google_id,
                "email": email,
                "name": name,
                "is_admin": False,
                "user_id": user.id,
                "picture": picture  # ✅ Store picture
            }

        db.session.commit()  # ✅ Save changes

        logging.info(f"✅ User {email} processed successfully.")

        # 🔄 Redirect based on admin status
        if user.is_admin:
            return redirect(url_for("admin_dashboard"))  # Admin dashboard
        else:
            return redirect(url_for("chatbot"))  # User dashboard

    except Exception as e:
        logging.error(f"❌ Error in OAuth callback: {str(e)}", exc_info=True)
        return "<h3>Internal Server Error</h3>", 500


@app.route('/save_email', methods=['POST'])
def save_email():
    token = request.json.get('token')
    try:
        # ✅ Verify the token using Google ID Token verification
        info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)

        google_id = info.get('sub')  # ✅ Extract Google ID
        email = info.get('email')
        name = info.get('name', 'Unknown User')  # ✅ Set a default name
        picture = info.get('picture')  # ✅ Store profile picture (optional)

        if email and google_id:
            with app.app_context():
                user = User.query.filter_by(email=email).first()

                if user:
                    # ✅ If user exists, update details
                    logging.info(f"🔄 User {email} already exists. Updating info.")
                    user.name = name
                    user.google_id = google_id  # ✅ Ensure correct Google ID is stored
                    user.picture = picture
                    # ✅ Check if the user should be an Admin (logic to define whether to switch roles)
                    user.is_admin = info.get("is_admin", user.is_admin)  # Update is_admin if needed
                else:
                    # ✅ Create a new user with the correct Google ID
                    logging.info(f"🆕 Creating new user in DB: {email}")
                    new_user = User(
                        google_id=google_id, 
                        email=email, 
                        name=name, 
                        picture=picture,
                        is_admin=False  # Default is not admin
                    )
                    db.session.add(new_user)
                    user = new_user  # Set the user to the newly created one

                db.session.commit()
                logging.info(f"✅ User {email} saved/updated in database.")

                # ✅ Store in session based on role
                session_data = {
                    "google_id": google_id,
                    "email": email,
                    "name": name,
                    "is_admin": user.is_admin,  # Store admin status
                    "user_id": user.id,
                    "picture": picture  # Store picture
                }
                
                if user.is_admin:
                    session["admin_session"] = session_data
                else:
                    session["user_session"] = session_data

            return jsonify({"success": True})

    except ValueError as e:
        logging.error(f"❌ Invalid token: {str(e)}")
        return jsonify({"success": False, "error": "Invalid token"}), 401

    except Exception as e:
        logging.error(f"❌ Error in save_email: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
@app.route("/chatbot")
def chatbot():
    try:
        logging.info(f"📌 DEBUG: Session Data - {dict(session)}")
        print(f"📌 DEBUG: Session Data - {dict(session)}")  # Print session data to console

        user_session = session.get("user_session")
        if not user_session:
            logging.error("🚫 No active session! Redirecting to login.")
            return redirect(url_for("login"))

        email = user_session["email"]
        user = User.query.filter_by(email=email).first()

        if not user:
            logging.error(f"🚫 User {email} not found in database! Logging out user.")
            session.clear()  # ✅ Clear session to prevent looping redirects
            return redirect(url_for("login"))

        # ✅ Only check for payment IF user came from "Subscribe"
        next_url = session.pop("next_url", None)
        if next_url == "pay":
            payment = Payment.query.filter_by(email=email, payment_status="Success").first()
            if not payment:
                logging.warning(f"🚫 Access Denied: {email} has NOT paid! Redirecting to home.")
                return redirect(url_for("home"))

        # ✅ Use a default profile picture if missing
        profile_picture = user_session.get("picture", "/static/images/default.png")

        # ✅ Normal login users get direct access
        return render_template(
            "chatbot.html",
            name=user_session["name"],
            email=user_session["email"],
            picture=profile_picture  # Use safe fallback
        )

    except Exception as e:
        logging.error(f"❌ ERROR in /chatbot: {str(e)}", exc_info=True)
        return "<h3>Internal Server Error. Please check logs.</h3>", 500


from flask import redirect, url_for  # ✅ Import redirect function


@app.route("/admin")
def admin_log():
    # ✅ Check if admin session exists
    if not session.get("admin_session"):  # Admin session is required
        return "Access Denied", 403  # Restrict non-admin users
    return redirect(url_for("admin_dashboard"))  # ✅ Redirect to admin dashboard if admin session exists

# ✅ Admin Dashboard
@app.route("/admin_dashboard", methods=["GET"])
def admin_dashboard():
    try:
        # 🛠️ Debug print for session values
        logging.info(f"📌 DEBUG: Session values -> {dict(session)}")
        print(f"📌 DEBUG: Session values -> {dict(session)}")  # Print to console

        # ✅ Check if admin session exists
        admin_session = session.get("admin_session")
        if not admin_session:
            logging.error("🚫 No admin session found. Redirecting to re-authenticate.")
            return redirect(url_for("auth_callback"))  # Redirect to re-authenticate if no admin session

        # ✅ Fetch all users in one query
        users = User.query.all()

        # Ensure columns exist (optional, can be moved to a migration check)
        for user in users:
            if not hasattr(user, 'is_active'):
                logging.error("❌ 'is_active' column is missing in the User model!")
            if not hasattr(user, 'is_admin'):
                logging.error("❌ 'is_admin' column is missing in the User model!")

        # ✅ Fetch activity logs for 'Worksheet' and 'Flashcard' in one query
        activity_logs = ActivityLog.query.filter(ActivityLog.resource_type.in_(["Worksheet", "Flashcard"])).all()

        # ✅ Fetch successful payments in one query
        payments = {payment.email: payment for payment in Payment.query.filter_by(payment_status="Success").all()}

        # Aggregate counts
        total_users = len(users)
        total_worksheets = sum(1 for log in activity_logs if log.resource_type == "Worksheet")
        total_flashcards = sum(1 for log in activity_logs if log.resource_type == "Flashcard")

        # Map user activity logs
        activity_counts = {}
        for log in activity_logs:
            if log.user_id not in activity_counts:
                activity_counts[log.user_id] = {
                    "worksheets": 0,
                    "flashcards": 0,
                    "worksheet_topics": [],  # 🆕 Store worksheet topic names
                    "flashcard_topics": [],  # 🆕 Store flashcard topic names
                }
            if log.resource_type == "Worksheet":
                activity_counts[log.user_id]["worksheets"] += 1
                activity_counts[log.user_id]["worksheet_topics"].append(log.resource_name)  # 🆕 Add topic name
            elif log.resource_type == "Flashcard":
                activity_counts[log.user_id]["flashcards"] += 1
                activity_counts[log.user_id]["flashcard_topics"].append(log.resource_name)  # 🆕 Add topic name

        # Prepare user data efficiently
        user_data = [
            {
                "id": user.id,
                "profile_picture": user.picture or "/static/images/default.png",
                "name": user.name,
                "email": user.email,
                "is_active": user.is_active,
                "is_admin": user.is_admin,
                "worksheets_used": activity_counts.get(user.id, {}).get("worksheets", 0),
                "flashcards_used": activity_counts.get(user.id, {}).get("flashcards", 0),
                "worksheet_topics": activity_counts.get(user.id, {}).get("worksheet_topics", []),  # 🆕 Include topics
                "flashcard_topics": activity_counts.get(user.id, {}).get("flashcard_topics", []),  # 🆕 Include topics
                "subscription": "Paid" if user.email in payments else "Free",
            }
            for user in users
        ]

        # ✅ Render the admin dashboard page with necessary data
        return render_template(
            "admin_dashboard.html",
            total_users=total_users,
            total_worksheets=total_worksheets,
            total_flashcards=total_flashcards,
            users=user_data,
            user=admin_session,  # ✅ Pass correct session user
        )

    except Exception as e:
        logging.error(f"❌ ERROR in /admin_dashboard: {str(e)}", exc_info=True)
        return "<h3>Internal Server Error. Please check logs.</h3>", 500


@app.route("/admin_logout")
def admin_logout():
    # ✅ Clear the admin session completely
    session.clear()
    logging.info("✅ Admin logged out. Session cleared.")
    return redirect(url_for("index"))  # ✅ Redirect to homepage after logging out


@app.route("/log_activity", methods=["POST"])
def log_activity():
    # ✅ Check if user is authenticated via session
    user_session = session.get("user_session")
    admin_session = session.get("admin_session")
    
    if not user_session and not admin_session:
        return jsonify({"error": "Unauthorized"}), 401  # Unauthorized if no session found

    # ✅ Get the logged-in user (either user or admin session)
    user = None
    if user_session:
        user = User.query.filter_by(email=user_session["email"]).first()
    elif admin_session:
        user = User.query.filter_by(email=admin_session["email"]).first()

    if not user:
        return jsonify({"error": "User not found"}), 404  # User not found

    # ✅ Get activity data from the request body
    data = request.get_json()
    action = data.get("action")
    resource_type = data.get("resource_type")
    resource_name = data.get("resource_name")
    source = data.get("source", "AI Generated")
    pdf_base64 = data.get("pdf")

    if not action or not resource_type:
        return jsonify({"error": "Invalid activity data"}), 400  # Missing required data

    # Fix duplicate flashcard entry issue (leave other worksheet actions untouched)
    if action == "Generated Flashcards":
        action = "Generated Flashcard"

    # ✅ Admins can log activity for any user, normal users can only log their own activity
    if admin_session:
        # Admin is allowed to log activity for any user
        user_id = data.get("user_id")  # Get user_id from the request data for admin logging
        if not user_id:
            return jsonify({"error": "Missing user_id for admin activity log"}), 400  # Admin needs a user ID
        
        # Check if the admin wants to log activity for another user
        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({"error": "Target user not found"}), 404  # User to log activity for doesn't exist
        user = target_user  # Log activity for the target user

    elif user_session:
        # Normal user can only log activity for themselves
        if action == "Generated Flashcard":
            existing_log = ActivityLog.query.filter_by(
                user_id=user.id, action=action, resource_type=resource_type, resource_name=resource_name
            ).first()

            if existing_log:
                existing_log.pdf_base64 = pdf_base64  # Update PDF if necessary
                db.session.commit()
                return jsonify({"message": "Existing flashcard entry updated"})
            
        # Log new activity for the user
        new_log = ActivityLog(
            user_id=user.id,
            action=action,
            resource_type=resource_type,
            resource_name=resource_name,
            source=source,
            pdf_base64=pdf_base64
        )
        db.session.add(new_log)
        db.session.commit()

        return jsonify({"message": "Activity logged successfully"})

    return jsonify({"error": "Forbidden"}), 403  # Forbidden if access is not allowed for the current user type















@app.route('/table')
def table():
    return render_template('table.html')









@app.route("/login_for_payment")
def login_for_payment():
    """Handles login for payment and redirects to /pay after login"""
    
    # ✅ Check if the session is a user session (not admin)
    user_session = session.get("user_session")
    
    # If no user session exists or an admin session is found, deny access
    if not user_session:
        return jsonify({"error": "Unauthorized. Only users can access this route."}), 401  # Only users allowed

    # ✅ If the session is a valid user session, proceed with the payment flow
    allowed_domains = {
        "levelupai.azurewebsites.net": "https://levelupai.azurewebsites.net/auth/callback",
        "leveluponline.shop": "https://leveluponline.shop/auth/callback",
        "127.0.0.1": "http://127.0.0.1:8000/auth/callback",
        "localhost": "http://localhost:8000/auth/callback",
    }

    current_domain = request.host.split(":")[0]
    redirect_url = allowed_domains.get(current_domain)

    if not redirect_url:
        return "Unauthorized domain", 400  # If domain is not allowed, reject the request

    # ✅ Mark the session as part of a payment flow
    session["is_payment_flow"] = True  # Set flag indicating it's a payment flow
    
    next_url = request.args.get("next")  # Store the next URL (should be /pay)
    session["next_url"] = next_url  
    session["oauth_state"] = secrets.token_urlsafe(16)  # Generate a unique state to prevent CSRF attacks

    # ✅ Redirect to Google OAuth for authentication
    return google.authorize_redirect(
        redirect_url, state=session["oauth_state"]
    )



@app.route("/pay", methods=["GET", "POST"])
def pay():
    # ✅ Ensure the session is for a regular user (not admin)
    user_session = session.get("user_session")
    if not user_session:
        return redirect(url_for("login"))  # Ensure the user is logged in (no admin allowed)

    email = user_session["email"]  # ✅ Fetch email from user session
    name = user_session.get("name", "User")  # ✅ Fetch name from user session

    if request.method == "POST":  # Payment initiated via form submission
        txnid = str(int(time.time()))  # Unique transaction ID
        amount = request.form.get("amount", "0.00")
        productinfo = request.form.get("productinfo", "Subscription Plan")

    else:  # If request is GET (from a button click)
        plan = request.args.get("plan")
        amount = request.args.get("amount")
        txnid = "TXN" + str(int(time.time() * 1000)) + str(random.randint(1000, 9999))  # Unique txnid
        productinfo = plan if plan else "Subscription Plan"

    # ✅ Generate PayU Hash
    hash_value = generate_payu_hash(txnid, amount, productinfo, name, email)

    # ✅ Store transaction in DB (status: "Pending")
    payment = Payment(email=email, name=name, amount=amount, plan_name=productinfo, txnid=txnid, payment_status="Pending")
    db.session.add(payment)
    db.session.commit()

    # ✅ Prepare PayU Data
    payu_data = {
        "key": MERCHANT_KEY,
        "txnid": txnid,
        "amount": amount,
        "productinfo": productinfo,
        "firstname": name,
        "email": email,
        "phone": session.get("phone", "-"),  # ✅ Use '-' if phone is not available
        "surl": url_for('success', _external=True) + f"?txnid={txnid}&productinfo={productinfo}&amount={amount}",
        "furl": url_for("failure", _external=True),
        "hash": hash_value
    }

    return render_template("payment.html", payu_url=PAYU_URL, payu_data=payu_data)

@app.route('/success', methods=['GET', 'POST'])
def success():
    # ✅ Ensure the session is for a regular user (not admin)
    user_session = session.get("user_session")
    if not user_session:
        return redirect(url_for("login"))  # Ensure the user is logged in (no admin allowed)

    if request.method == 'POST' and 'txnid' in request.form:
        txnid = request.form.get('txnid', 'Unknown')
        plan = request.form.get('productinfo', 'N/A')
        amount = request.form.get('amount', '0.00')
    else:
        txnid = request.args.get('txnid', 'Unknown')
        plan = request.args.get('productinfo', 'N/A')
        amount = request.args.get('amount', '0.00')

    # ✅ Fetch name and email from session
    name = user_session.get("name", "User")
    email = user_session.get("email", "-")
    phone = user_session.get("phone", "-")  # Optional: If you store phone in session

    # ✅ Generate Receipt PDF with all details
    pdf_path = f"receipt_{txnid}.pdf"
    generate_pdf(txnid, name, email, plan, amount, pdf_path)

    return render_template('payment_success.html', txnid=txnid, plan=plan, amount=amount, pdf_path=pdf_path)


def generate_pdf(txnid, name, email, plan, amount, pdf_path):
    c = canvas.Canvas(pdf_path, pagesize=A4)
    c.setTitle("Payment Receipt")

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(300, 800, "Payment Receipt")

    # Payment details
    c.setFont("Helvetica", 12)
    y = 750
    line_spacing = 20

    c.drawString(100, y, f"Transaction ID: {txnid}")
    y -= line_spacing
    c.drawString(100, y, f"Name: {name}")
    y -= line_spacing
    c.drawString(100, y, f"Email: {email}")
    y -= line_spacing
    c.drawString(100, y, f"Phone: {session.get('phone', '-')}")
    y -= line_spacing
    c.drawString(100, y, f"Plan: {plan}")
    y -= line_spacing
    c.drawString(100, y, f"Amount Paid: ${amount}")

    # Date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    y -= line_spacing
    c.drawString(100, y, f"Date & Time: {current_datetime}")

    # Thank you note
    y -= (line_spacing * 2)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y, "Thank you for your purchase!")

    c.save()





# ✅ Generate receipt only for users
@app.route('/generate_receipt/<txnid>')
def generate_receipt(txnid):
    # Ensure the user is logged in and it's a user session (not admin)
    if "user_session" not in session:
        logging.warning("🚫 Unauthorized access to generate receipt.")
        return redirect(url_for("login"))  # Redirect to login if no user session
    
    # Fetch plan and amount from URL parameters
    plan = request.args.get('plan')
    amount = request.args.get('amount')
    
    # Ensure the payment relates to the logged-in user
    payment = Payment.query.filter_by(txnid=txnid).first()
    if not payment or payment.email != session.get("email"):
        logging.warning(f"🚫 Unauthorized receipt request. Payment not found or user mismatch for TXN {txnid}.")
        return redirect(url_for("home"))  # Redirect to home if payment doesn't match user

    # Define path to save the PDF receipt
    pdf_path = f"receipt_{txnid}.pdf"
    
    # Generate the PDF receipt
    generate_pdf(txnid, session.get("name"), session.get("email"), plan, amount, pdf_path)
    
    # Send the generated PDF as a file download
    return send_file(pdf_path, as_attachment=True)

# ✅ Failure Route (Update Payment Status) - Ensuring only the user can see their failure
@app.route('/failure')
def failure():
    txnid = request.args.get("txnid")
    payment = Payment.query.filter_by(txnid=txnid).first()
    
    if payment:
        # Ensure the logged-in user matches the payment email
        if "user_session" in session and payment.email == session.get("email"):
            payment.payment_status = "Failed"
            db.session.commit()
            logging.warning(f"🚨 Payment Failed for {payment.email} - TXN: {txnid}")
        else:
            logging.warning(f"🚫 Unauthorized access to failure route for TXN {txnid}. User mismatch.")

    return render_template('payment_failure.html')


@app.route('/get_questions', methods=['GET'])
def get_questions():
    try:
        # Ensure user is logged in
        if "user_session" not in session and "admin_session" not in session:
            return jsonify({'error': 'Unauthorized access'}), 401  # User must be logged in (either admin or user)

        # Get the role from the session
        is_admin = "admin_session" in session

        # Fetch all questions
        if is_admin:
            # Admin can view all questions and their answers
            questions = Question.query.order_by(Question.created_at.desc()).all()
        else:
            # Regular user can only view questions they have asked (optional filtering)
            user_email = session.get("email")
            questions = Question.query.filter_by(user_email=user_email).order_by(Question.created_at.desc()).all()

        # Prepare response data
        questions_data = [
            {
                'id': q.id,
                'username': q.user.name if q.user else "Unknown User",
                'user_picture': q.user.picture if q.user and q.user.picture else "/static/images/default-user.png",
                'question_text': q.question_text,
                'timestamp': q.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'answers': [
                    {
                        'username': a.user.name,
                        'user_picture': a.user.picture if a.user.picture else "/static/images/default-user.png",
                        'answer_text': a.answer_text,
                        'timestamp': a.created_at.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    for a in q.answers
                ]
            }
            for q in questions
        ]

        return jsonify(questions_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error', 'details': str(e)}), 500

@app.route('/ask_expert', methods=['POST'])
def ask_expert():
    # Ensure user is logged in (either admin or regular user)
    if "user_session" not in session and "admin_session" not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # Get the email from session to find the user
    email = session.get("email")
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get the question data from the request
    data = request.get_json()
    question_text = data.get('question')

    if not question_text:
        return jsonify({'error': 'No question provided'}), 400

    # Store expert question with the user's details
    expert_question = ExpertQuestion(
        user_id=user.id, 
        username=user.name, 
        question_text=question_text
    )
    
    db.session.add(expert_question)
    db.session.commit()

    # Return the success response with profile picture and confirmation message
    return jsonify({
        'message': 'Expert question submitted successfully',
        'profile_picture': user.picture if user.picture else "/static/images/default-user.png"
    })



@app.route('/reports_data', methods=['GET'])
def reports_data():
    try:
        total_messages = Message.query.count()
        total_questions = Question.query.count()
        total_expert_questions = ExpertQuestion.query.count()

        return jsonify({
            'total_messages': total_messages,
            'total_questions': total_questions,
            'total_expert_questions': total_expert_questions
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error', 'details': str(e)}), 500









@app.route('/ask_question', methods=['POST'])
def ask_question():
    try:
        # Ensure the user is authenticated (either user_session or admin_session)
        if 'user_session' not in session and 'admin_session' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        # Retrieve the session data from either user_session or admin_session
        user_data = session.get("user_session") or session.get("admin_session")

        # Find the user (either from user_session or admin_session)
        user = User.query.filter_by(id=user_data['user_id']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check that the question is present in the data
        data = request.get_json()
        if not data or 'question' not in data:
            return jsonify({'error': 'Invalid request'}), 400

        question_text = data['question'].strip()
        if not question_text:
            return jsonify({'error': 'Question cannot be empty'}), 400

        # Add the new question to the database
        new_question = Question(user_id=user.id, question_text=question_text, created_at=datetime.utcnow())
        db.session.add(new_question)
        db.session.commit()

        return jsonify({'message': 'Question posted successfully'})

    except Exception as e:
        import traceback
        traceback.print_exc()  # Print error in terminal
        return jsonify({'error': 'Internal Server Error', 'details': str(e)}), 500

@app.route("/answer_question", methods=["POST"])
def answer_question():
    try:
        # Ensure the user is authenticated (either user_session or admin_session)
        if "user_session" not in session and "admin_session" not in session:
            return jsonify({"error": "Unauthorized"}), 401

        # Retrieve the session data from either user_session or admin_session
        user_data = session.get("user_session") or session.get("admin_session")

        # Find the user (either from user_session or admin_session)
        user = User.query.filter_by(id=user_data['user_id']).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Get the question ID and answer text from the request data
        data = request.get_json()
        question_id = data.get("question_id")
        answer_text = data.get("answer")

        if not question_id or not answer_text:
            return jsonify({"error": "Invalid input"}), 400

        # Find the question to answer
        question = Question.query.get(question_id)
        if not question:
            return jsonify({"error": "Question not found"}), 404

        # If the user is a regular user, they can only answer their own questions
        if 'user_session' in session and question.user_id != user.id:
            return jsonify({"error": "You can only answer your own questions"}), 403

        # Add the answer to the database
        new_answer = Answer(user_id=user.id, question_id=question_id, answer_text=answer_text)
        db.session.add(new_answer)
        db.session.commit()

        return jsonify({
            "message": "Answer posted successfully",
            "user_picture": user.picture or "/static/images/default-user.png"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


@app.route("/get_user_profile")
def get_user_profile():
    """Fetch user profile details, including admin status."""

    # ✅ Prioritize `admin_session` for admin-specific logic
    admin_session = session.get("admin_session")
    user_session = session.get("user_session")

    # Ensure at least one valid session exists
    if not admin_session and not user_session:
        logging.warning("Unauthorized access to profile data")
        return jsonify({"error": "Unauthorized"}), 401

    # ✅ Use admin session first (higher priority)
    session_data = admin_session or user_session
    email = session_data.get("email")
    
    if not email:
        logging.error("No email found in session")
        return jsonify({"error": "User not found"}), 404

    # ✅ Fetch user from database
    user = User.query.filter_by(email=email).first()
    if not user:
        logging.error(f"User not found: {email}")
        return jsonify({"error": "User not found"}), 404

    # ✅ Mark as admin if `admin_session` exists
    is_admin = bool(admin_session)

    # ✅ Return user profile data with admin status
    return jsonify({
        "name": user.name,
        "email": user.email,
        "picture": user.picture or "/static/images/default-user.png",
        "is_admin": is_admin  # Admin status determined by session
    })








@app.route('/update_profile', methods=['POST'])
def update_profile():
    if "email" not in session:
        logging.warning("Unauthorized access to profile update")
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        logging.error(f"User not found: {session.get('email')}")
        return jsonify({"success": False, "error": "User not found"}), 404

    try:
        # Update password if provided
        password = request.json.get("password")
        if password:
            user.password = hashlib.sha256(password.encode()).hexdigest()

        db.session.commit()
        logging.info(f"User {user.email} updated profile successfully")
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Error updating profile: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


def get_deleted_user():
    """Ensure a default 'Deleted User' exists and return its ID."""
    deleted_user = User.query.filter_by(email="deleted_user@system.com").first()
    if not deleted_user:
        deleted_user = User(
            google_id="deleted_system_id",
            name="Deleted User",
            email="deleted_user@system.com",
            picture="/static/images/default-user.png"
        )
        db.session.add(deleted_user)
        db.session.commit()
    return deleted_user


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if "email" not in session:
        logging.warning("Unauthorized attempt to delete account")
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        logging.error(f"Attempted to delete non-existent user: {session.get('email')}")
        return jsonify({"success": False, "error": "User not found"}), 404

    try:
        deleted_user = get_deleted_user()  # Get or create the default 'Deleted User'

        logging.info(f"Replacing user {user.id} with deleted user {deleted_user.id}")

        # ✅ Replace user_id in all related tables instead of setting NULL
        db.session.query(Question).filter(Question.user_id == user.id).update({"user_id": deleted_user.id})
        db.session.query(Answer).filter(Answer.user_id == user.id).update({"user_id": deleted_user.id})
        db.session.query(ActivityLog).filter(ActivityLog.user_id == user.id).update({"user_id": deleted_user.id})

        db.session.delete(user)  # Now safe to delete the user
        db.session.commit()

        session.clear()  # Log the user out after deletion
        logging.info(f"User {user.email} deleted their account")

        return jsonify({"success": True})  # ✅ Ensure returning JSON
    except Exception as e:
        db.session.rollback()  # Rollback any partial changes
        logging.error(f"Error deleting account: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500



@app.route("/get_top_users")
def get_top_users():
    # Check if the user has admin privileges or is logged in
    if "role" not in session or session["role"] != "admin":
        logging.warning("Unauthorized attempt to access top users data")
        return jsonify({"error": "Unauthorized"}), 401

    try:
        top_users = (
            db.session.query(User.name, User.email, db.func.count(ActivityLog.id).label("activity_count"))
            .join(ActivityLog, User.id == ActivityLog.user_id)
            .group_by(User.id, User.name, User.email)
            .order_by(db.desc("activity_count"))
            .limit(5)
            .all()
        )
        return jsonify([{
            "name": user.name, 
            "email": user.email, 
            "activity_count": user.activity_count
        } for user in top_users])
    
    except Exception as e:
        app.logger.error(f"Error fetching top users: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


import traceback
@app.route('/get_activity_logs', methods=['GET'])
def get_activity_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 7, type=int)
        filter_type = request.args.get('filter', 'all')
        search_query = request.args.get('search', '').strip().lower()
        sort_order = request.args.get('type', 'latest')  # Sorting: latest/oldest
        resource_type = request.args.get('resource_type', '').strip().lower()  # Worksheets/Flashcards

        # ✅ Use `session["user_session"]` to check login status
        user_session = session.get("user_session")
        if not user_session:
            return jsonify({"error": "Unauthorized"}), 401

        user = User.query.filter_by(email=user_session["email"]).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        print(f"Fetching logs: Filter = {filter_type}, Search = {search_query}, Sort = {sort_order}, Resource Type = {resource_type}")

        # Base Query
        logs_query = ActivityLog.query if filter_type == "all" else ActivityLog.query.filter_by(user_id=user.id)

        # Apply Search Filter
        if search_query:
            logs_query = logs_query.filter(
                (ActivityLog.resource_name.ilike(f"%{search_query}%")) |
                (ActivityLog.action.ilike(f"%{search_query}%"))
            )

        # Apply Worksheets/Flashcards Filter
        if resource_type:
            logs_query = logs_query.filter(ActivityLog.resource_type.ilike(f"%{resource_type}%"))

        # 🔹 Fix Sorting (Keep "Latest" & "Oldest" Functional)
        if sort_order == "latest":
            logs_query = logs_query.order_by(ActivityLog.date.desc())
        elif sort_order == "oldest":
            logs_query = logs_query.order_by(ActivityLog.date.asc())

        # Pagination
        logs = logs_query.paginate(page=page, per_page=per_page, error_out=False)

        activity_data = [{
            "user": log.user.name if log.user else "Unknown User",
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_name": log.resource_name,
            "date": log.date.strftime("%Y-%m-%d %H:%M:%S"),
            "source": log.source,
            "pdf": log.pdf_base64
        } for log in logs.items]

        return jsonify({
            "activities": activity_data,
            "total_pages": logs.pages,
            "current_page": logs.page
        })

    except Exception as e:
        print("🔥 ERROR:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500


@app.route('/get_all_activity_logs', methods=['GET'])
def get_all_activity_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 7, type=int)
        filter_type = request.args.get('filter', 'all')
        search_query = request.args.get('search', '').strip().lower()
        sort_order = request.args.get('type', 'latest')
        resource_type = request.args.get('resource_type', '').strip().lower()

        # ✅ Check for both `admin_session` and `user_session`
        user_session = session.get("user_session")
        admin_session = session.get("admin_session")
        if not user_session and not admin_session:
            return jsonify({"error": "Unauthorized"}), 401

        print(f"Fetching ALL logs: Filter = {filter_type}, Search = {search_query}, Sort = {sort_order}, Resource Type = {resource_type}")

        # Fetch all users' logs by default
        logs_query = ActivityLog.query

        # Apply Search Filter (🔄 Fix: Added User.name filter)
        if search_query:
            logs_query = logs_query.filter(
                (ActivityLog.resource_name.ilike(f"%{search_query}%")) |
                (ActivityLog.action.ilike(f"%{search_query}%")) |
                (ActivityLog.user.has(User.name.ilike(f"%{search_query}%")))
            )

        # Apply Worksheets/Flashcards Filter
        if resource_type:
            logs_query = logs_query.filter(ActivityLog.resource_type.ilike(f"%{resource_type}%"))

        # Sorting
        if sort_order == "latest":
            logs_query = logs_query.order_by(ActivityLog.date.desc())
        elif sort_order == "oldest":
            logs_query = logs_query.order_by(ActivityLog.date.asc())

        # Debug SQL Query
        print("Executed SQL Query:", str(logs_query))

        # Pagination
        logs = logs_query.paginate(page=page, per_page=per_page, error_out=False)

        # Prepare JSON Response
        activity_data = [{
            "user": log.user.name if log.user else "Unknown User",
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_name": log.resource_name,
            "date": log.date.strftime("%Y-%m-%d %H:%M:%S") if log.date else "Unknown Date",
            "source": log.source,
            "pdf": log.pdf_base64
        } for log in logs.items]

        return jsonify({
            "activities": activity_data,
            "total_pages": logs.pages,
            "current_page": logs.page
        })

    except Exception as e:
        print("🔥 ERROR in /get_all_activity_logs:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/get_activity_data")
def get_activity_data():
    try:
        filter_type = request.args.get("filter", "daily")

        if filter_type == "daily":
            start_date = datetime.utcnow() - timedelta(days=7)
        elif filter_type == "weekly":
            start_date = datetime.utcnow() - timedelta(weeks=4)
        else:  # Monthly
            start_date = datetime.utcnow() - timedelta(days=30)

        app.logger.info(f"Fetching activity data from: {start_date}")  # Debug log

        # Use CAST instead of date() for SQL Server compatibility
        activity_data = (
            db.session.query(cast(ActivityLog.timestamp, Date).label("date"), func.count(ActivityLog.id))
            .filter(ActivityLog.timestamp >= start_date)
            .group_by(cast(ActivityLog.timestamp, Date))
            .order_by(cast(ActivityLog.timestamp, Date))
            .all()
        )

        if not activity_data:
            app.logger.warning("No activity data found!")
            return jsonify({"labels": [], "values": []})  # Return empty if no data

        labels = [str(data.date) for data in activity_data]
        values = [data[1] for data in activity_data]

        return jsonify({"labels": labels, "values": values})
    
    except Exception as e:
        app.logger.error(f"Error fetching activity data: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500




@app.route("/save_admin_settings", methods=["POST"])
def save_admin_settings():
    data = request.json
    session["theme"] = data.get("theme", "light")
    session["admin_notifications"] = data.get("admin_notifications", False)
    session["content_moderation"] = data.get("content_moderation", False)
    
    return jsonify({"message": "Settings saved successfully"})





import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify
from email.mime.base import MIMEBase
from email import encoders

@app.route("/send_bulk_email", methods=["POST"])
def send_bulk_email():
    try:
        data = request.json
        emails = data.get("emails", [])
        message = data.get("message", "")

        if not emails or not message:
            return jsonify({"message": "Invalid request. Please select recipients and enter a message."}), 400

        sender_email = "snehafrankocean@gmail.com"
        sender_password = "sjgo tbpe ovow typt"  # Use App Password if 2FA is enabled

        # Setup the email server
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)

        # Compose and send the email
        for recipient_email in emails:
            msg = MIMEMultipart()
            msg["From"] = sender_email
            msg["To"] = recipient_email
            msg["Subject"] = "Bulk Email"
            msg.attach(MIMEText(message, "plain"))

            server.sendmail(sender_email, recipient_email, msg.as_string())
        
        server.quit()
        return jsonify({"message": "Emails sent successfully!"})

    except Exception as e:
        print(f"Error: {e}")  # Print the error for debugging
        return jsonify({"message": f"Failed to send emails. Error: {str(e)}"}), 500

from flask import Flask, request, jsonify, url_for
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import os

# Ensure PDF directory exists
PDF_DIR = "static/pdfs"
if not os.path.exists(PDF_DIR):
    os.makedirs(PDF_DIR)

@app.route('/generate_flashcard_pdf', methods=['POST'])
def generate_flashcard_pdf():
    try:
        data = request.json  
        topic = data.get('topic', 'Unknown_Topic').replace(" ", "_")
        age_group = data.get('age_group', 'Unknown_Age').replace(" ", "_")
        flashcards = data.get('flashcards', [])

        if not flashcards:
            return jsonify({'error': 'No flashcards provided'}), 400

        # Generate filename
        pdf_filename = f"{topic}_{age_group}.pdf"
        pdf_path = os.path.join(PDF_DIR, pdf_filename)

        # Create PDF
        doc = canvas.Canvas(pdf_path, pagesize=letter)
        doc.setFont("Helvetica-Bold", 14)

        y_position = 750  # Start position

        # Add Topic and Age Group at the top
        doc.drawString(50, y_position, f"Flashcards for Topic: {topic.replace('_', ' ')}")
        y_position -= 20
        doc.drawString(50, y_position, f"Age Group: {age_group.replace('_', ' ')}")
        y_position -= 40  # Extra spacing

        doc.setFont("Helvetica", 12)  # Reset font

        for index, flashcard in enumerate(flashcards):
            question = flashcard.get('question', 'Question')
            answer = flashcard.get('answer', 'Answer')

            # Add Question
            doc.drawString(50, y_position, f"Q{index+1}: {question}")
            y_position -= 40  # Larger space between question and answer

            # Add Placeholder for fold
            doc.drawString(50, y_position, "___________________________")
            y_position -= 40  

            # Add Answer
            doc.drawString(50, y_position, f"A: {answer}")
            y_position -= 60  # Extra space before next question

            # Start a new page if needed
            if y_position < 100:
                doc.showPage()
                doc.setFont("Helvetica", 12)
                y_position = 750  

        doc.save()

        return jsonify({'pdf_url': f"/static/pdfs/{pdf_filename}"})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


from collections import defaultdict
from flask import jsonify, session
from datetime import datetime, timedelta



@app.route("/get_user_stats", methods=["GET"])
def get_user_stats():
    """Fetch user-specific stats for worksheets and flashcards usage."""

    # ✅ Ensure the user is logged in (either as User or Admin)
    user_session = session.get("user_session") or session.get("admin_session")
    if not user_session:
        return jsonify({"error": "Unauthorized"}), 401  # ✅ Restrict access to logged-in users only

    try:
        user = User.query.filter_by(email=user_session["email"]).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # ✅ Fetch total downloads for user
        total_worksheets = ActivityLog.query.filter_by(user_id=user.id, resource_type="Worksheet").count()
        total_flashcards = ActivityLog.query.filter_by(user_id=user.id, resource_type="Flashcard").count()

        # ✅ Get the last 7 days for weekly report
        today = datetime.today()
        start_date = today - timedelta(days=6)

        # ✅ Fetch logs within the last 7 days
        logs = ActivityLog.query.filter(
            ActivityLog.user_id == user.id,
            ActivityLog.date >= start_date
        ).all()

        # ✅ Group data for weekly chart
        daily_totals = defaultdict(lambda: {"worksheets": 0, "flashcards": 0})
        all_entries = defaultdict(list)
        resource_counts = defaultdict(int)  # Store download counts per resource

        for log in logs:
            date_str = log.date.strftime("%Y-%m-%d")
            if log.resource_type == "Worksheet":
                daily_totals[date_str]["worksheets"] += 1
            elif log.resource_type == "Flashcard":
                daily_totals[date_str]["flashcards"] += 1

            # ✅ Track most downloaded resource
            resource_counts[log.resource_name] += 1

            all_entries[date_str].append({"name": log.resource_name, "time": log.date.strftime("%H:%M:%S")})

        # ✅ Find the most downloaded resource
        most_downloaded_resource = max(resource_counts, key=resource_counts.get, default="-")

        # ✅ Ensure all 7 days exist
        weekly_data = []
        for i in range(7):
            date = (start_date + timedelta(days=i)).strftime("%Y-%m-%d")
            weekly_data.append({
                "date": date,
                "worksheets": daily_totals[date]["worksheets"],
                "flashcards": daily_totals[date]["flashcards"]
            })

        return jsonify({
            "total_worksheets": total_worksheets,
            "total_flashcards": total_flashcards,
            "most_downloaded": most_downloaded_resource,
            "weekly_data": weekly_data,
            "daily_entries": all_entries
        })

    except Exception as e:
        logging.error(f"🔥 ERROR in /get_user_stats: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500



@app.route("/get_user_activity/<email>", methods=["GET"])
def get_user_activity(email):
    """Allow both Admins and Users to fetch user activity logs."""

    # ✅ Ensure the requester is logged in (either as User or Admin)
    user_session = session.get("user_session") or session.get("admin_session")
    if not user_session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403  # ✅ Restrict access to logged-in users only

    try:
        # ✅ Fetch the requested user from the database
        requested_user = User.query.filter_by(email=email).first()
        if not requested_user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        # ✅ Determine if the requester is an admin or a normal user
        is_admin = session.get("admin_session", {}).get("is_admin", False)
        requester_email = user_session.get("email")

        # ✅ If user is not an admin and is trying to access another user's logs, allow it
        if not is_admin and requester_email != email:
            logging.info(f"👤 User {requester_email} is viewing logs of {email}.")

        # ✅ Fetch activity logs for the requested user
        logs = ActivityLog.query.filter_by(user_id=requested_user.id).order_by(ActivityLog.date.desc()).all()

        log_data = [
            {
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_name": log.resource_name or "N/A",
                "date": log.date.strftime('%Y-%m-%d %H:%M:%S'),
                "source": log.source or "AI Generated",
                "pdf": log.pdf_base64 or ""
            }
            for log in logs
        ]

        return jsonify({"status": "success", "logs": log_data})

    except Exception as e:
        logging.error(f"🔥 ERROR in /get_user_activity/{email}: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500



@app.route("/get_filtered_activity_logs", methods=["GET"])
def get_filtered_activity_logs():
    """Fetch filtered activity logs for logged-in Users & Admins."""

    # ✅ Ensure the user is logged in (either as User or Admin)
    user_session = session.get("user_session") or session.get("admin_session")
    if not user_session:
        return jsonify({"error": "Unauthorized"}), 401  # ✅ Restrict access to logged-in users only

    user = User.query.filter_by(email=user_session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        filter_type = request.args.get("filter", "all")

        query = ActivityLog.query.order_by(ActivityLog.date.desc())
        if filter_type == "user":
            query = query.filter_by(user_id=user.id)

        logs = query.limit(10).all()  # Fetch last 10 logs

        log_data = [
            {
                "user": log.user.name if log.user else "Unknown",
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_name": log.resource_name or "N/A",
                "date": log.date.strftime('%Y-%m-%d %H:%M:%S'),
                "source": log.source or "AI Generated",
                "pdf": log.pdf_base64 or ""
            }
            for log in logs
        ]

        return jsonify({"logs": log_data})

    except Exception as e:
        logging.error(f"🔥 ERROR in /get_filtered_activity_logs: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500








@app.route("/post_founder_message", methods=["POST"])
def post_founder_message():
    """Allow only Admins to post founder messages."""

    # ✅ Check for admin session
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict non-admin users

    try:
        data = request.get_json()
        message_content = data.get("message")

        if not message_content.strip():
            return jsonify({"error": "Message cannot be empty"}), 400  # Prevent empty messages

        new_message = FounderMessage(message=message_content)
        db.session.add(new_message)
        db.session.commit()

        return jsonify({"message": "Message posted successfully!"})

    except Exception as e:
        logging.error(f"🔥 ERROR in /post_founder_message: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500



# ✅ Route to get founder messages (With Pagination)



@app.route("/get_founder_messages", methods=["GET"])
def get_founder_messages():
    """Fetch paginated messages (2 per request) for faster loading."""
    
    user_session = session.get("user_session") or session.get("admin_session")
    if not user_session:
        return jsonify({"error": "Unauthorized"}), 403  

    try:
        # ✅ Implement pagination
        page = request.args.get("page", 1, type=int)
        per_page = 2  

        messages = (
            FounderMessage.query
            .order_by(FounderMessage.timestamp.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )

        return jsonify([
            {"message": msg.message, "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
            for msg in messages.items
        ])

    except Exception as e:
        logging.error(f"🔥 ERROR in /get_founder_messages: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/send_message', methods=['POST'])
def send_message():
    """Allow only logged-in Users or Admins to send messages."""

    # ✅ Ensure the user is logged in (either as User or Admin)
    user_session = session.get("user_session") or session.get("admin_session")
    if not user_session:
        return jsonify({'error': 'Unauthorized'}), 401  # ✅ Restrict access to logged-in users only

    user = User.query.filter_by(email=user_session["email"]).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        data = request.get_json()

        # ✅ Validate required fields
        if not data.get("room") or not data.get("message"):
            return jsonify({'error': 'Missing required fields: room, message'}), 400

        # ✅ Save message in the database
        new_message = Message(
            user_id=user.id, 
            username=user.name, 
            room=data["room"], 
            message=data["message"]
        )
        db.session.add(new_message)
        db.session.commit()

        return jsonify({'message': 'Message sent successfully'})

    except Exception as e:
        logging.error(f"🔥 ERROR in /send_message: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/get_messages/<room>', methods=['GET'])
def get_messages(room):
    """Fetch chat messages for a specific room, accessible to logged-in users only."""

    # ✅ Ensure the user is logged in (either as User or Admin)
    user_session = session.get("user_session") or session.get("admin_session")
    if not user_session:
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to logged-in users only

    try:
        messages = Message.query.filter_by(room=room).order_by(Message.timestamp).all()

        return jsonify([
            {
                'username': m.username,
                'message': m.message,
                'timestamp': m.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'profile_picture': m.user.picture if m.user and m.user.picture else "/static/images/default-user.png"
            }
            for m in messages
        ])

    except Exception as e:
        logging.error(f"🔥 ERROR in /get_messages/{room}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500




@app.route('/get_user_contributions', methods=['GET'])
def get_user_contributions():
    # ✅ Use admin session if admin is switched to user mode
    user_session = session.get("user_session") or session.get("admin_session")

    if not user_session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(email=user_session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Count user contributions
    chat_messages = Message.query.filter_by(user_id=user.id).count()
    forum_posts = Question.query.filter_by(user_id=user.id).count()
    qa_answers = Answer.query.filter_by(user_id=user.id).count()

    return jsonify({
        "chat_messages": chat_messages,
        "forum_posts": forum_posts,
        "qa_answers": qa_answers
    })





@app.route('/get_notifications', methods=['GET'])
def get_notifications():
    # Check if 'user_session' or 'admin_session' is in the session, which should be populated during login
    if 'user_session' not in session and 'admin_session' not in session:
        logging.error("No user_session or admin_session in session. User might not be logged in.")
        return jsonify({"notifications": [], "unread_count": 0})

    # Retrieve user session data from either 'user_session' or 'admin_session'
    user_data = session.get("user_session") or session.get("admin_session")

    if not user_data:
        logging.error("No user session data found in session.")
        return jsonify({"notifications": [], "unread_count": 0})

    # Fetch user from database using the email from the session
    user = User.query.filter_by(email=user_data['email']).first()

    if not user:
        logging.error(f"No user found in the database with email: {user_data['email']}")
        return jsonify({"notifications": [], "unread_count": 0})

    # Fetch latest founder messages
    founder_messages = FounderMessage.query.order_by(FounderMessage.timestamp.desc()).limit(5).all()
    logging.debug(f"Found founder messages: {founder_messages}")

    # Fetch user questions and their answers
    user_questions = Question.query.filter_by(user_id=user.id).all()
    question_ids = [q.id for q in user_questions]
    logging.debug(f"User questions: {user_questions}")

    # Fetch replies to user's questions
    replies = Answer.query.filter(Answer.question_id.in_(question_ids)).order_by(Answer.created_at.desc()).limit(5).all()
    logging.debug(f"Replies to user questions: {replies}")

    # Fetch most downloaded worksheets
    top_downloads = ActivityLog.query.filter(ActivityLog.resource_type == "Worksheet").order_by(ActivityLog.date.desc()).limit(5).all()
    logging.debug(f"Top downloads: {top_downloads}")

    # Prepare notifications list
    notifications = []
    unread_count = 0

     # Messages from Founder (allow rich HTML content)
    for msg in founder_messages:
        if "<img" in msg.message:  # If the message contains an image tag
            message_content = Markup(f"""
                <strong>Founder Message:</strong>
                <a href="#founderSpeaks">Founder posted a new image. View here.</a>
            """)
        else:
            message_content = Markup(f"<strong>Founder Message:</strong> {msg.message}")

        notifications.append({"message": message_content})
        unread_count += 1


    # Add replies to notifications
    for reply in replies:
        responder = User.query.get(reply.user_id)
        if responder:
            message_content = Markup(f"<strong>Reply from {responder.email}:</strong> {reply.answer_text}")
            notifications.append({"message": message_content})
            unread_count += 1

    # Add top download notifications
    for log in top_downloads:
        message_content = Markup(f"<strong>Trending:</strong> {log.resource_name} has been downloaded frequently!")
        notifications.append({"message": message_content})
        unread_count += 1

    # Return response with notifications and unread count
    return jsonify({
        "notifications": [{"message": str(msg["message"])} for msg in notifications],
        "unread_count": unread_count
    })







@app.route('/upload_blob', methods=['POST'])
def upload_blob():
    """Upload worksheets or flashcards to Azure Blob Storage."""
    if 'file' not in request.files or 'type' not in request.form:
        return jsonify({"success": False, "error": "Missing file or type"}), 400

    file = request.files['file']
    file_type = request.form['type']

    if file_type not in CONTAINER_MAPPING:
        return jsonify({"success": False, "error": "Invalid file type"}), 400

    container_name = CONTAINER_MAPPING[file_type]
    filename = secure_filename(file.filename)

    try:
        blob_client = BLOB_SERVICE_CLIENT.get_blob_client(container=container_name, blob=filename)
        blob_client.upload_blob(file, overwrite=True)  # 🔥 Upload to Azure

        return jsonify({"success": True, "url": blob_client.url})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/get_user_id", methods=["GET"])
def get_user_id():
    """Fetch the user ID from the session and database."""
    
    # ✅ Use the correct session (Admin or User)
    user_session = session.get("user_session") or session.get("admin_session")

    if not user_session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(email=user_session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user_id": user.id})  # ✅ Return only the user ID


@app.route('/add_batch', methods=['POST'])
def add_batch():
    """Allow only Admins to add a batch."""
    
    # ✅ Use `session["admin_session"]` instead of `session["is_admin"]`
    admin_session = session.get("admin_session")

    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Only admins can access

    # ✅ Get batch details from request
    data = request.get_json()
    month = data.get("month")
    week = data.get("week")
    name = data.get("name")
    start_date = data.get("start_date")
    end_date = data.get("end_date")

    if not all([month, week, name, start_date, end_date]):
        return jsonify({"error": "All batch details are required"}), 400

    try:
        new_batch = Batch(
            month=month,
            week=week,
            name=name,
            start_date=datetime.strptime(start_date, "%Y-%m-%d"),
            end_date=datetime.strptime(end_date, "%Y-%m-%d")
        )
        db.session.add(new_batch)
        db.session.commit()
        
        return jsonify({"message": "Batch added successfully"})

    except Exception as e:
        logging.error(f"🔥 ERROR in /add_batch: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/get_batches', methods=['GET'])
def get_batches():
    """Fetch all batches (accessible to both Admins and Users)."""

    # ✅ Ensure the user is logged in (either as User or Admin)
    user_session = session.get("user_session") or session.get("admin_session")

    if not user_session:
        return jsonify({"error": "Unauthorized"}), 401  # Prevent unauthorized access

    try:
        batches = Batch.query.order_by(Batch.created_at.desc()).all()

        return jsonify([
            {
                "id": batch.id,
                "month": batch.month,
                "week": batch.week,
                "name": batch.name,
                "start_date": batch.start_date.strftime('%Y-%m-%d'),
                "end_date": batch.end_date.strftime('%Y-%m-%d')
            }
            for batch in batches
        ])

    except Exception as e:
        logging.error(f"🔥 ERROR in /get_batches: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/edit_batch/<int:batch_id>', methods=['PUT'])
def edit_batch(batch_id):
    """Allow only Admins to edit a batch."""
    
    # ✅ Use `session["admin_session"]` instead of `session["is_admin"]`
    admin_session = session.get("admin_session")

    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Only admins can access

    batch = Batch.query.get(batch_id)
    if not batch:
        return jsonify({"error": "Batch not found"}), 404

    data = request.get_json()

    try:
        batch.month = data.get("month", batch.month)
        batch.week = data.get("week", batch.week)
        batch.name = data.get("name", batch.name)

        # ✅ Only update start_date and end_date if provided
        if data.get("start_date"):
            batch.start_date = datetime.strptime(data["start_date"], "%Y-%m-%d")
        if data.get("end_date"):
            batch.end_date = datetime.strptime(data["end_date"], "%Y-%m-%d")

        db.session.commit()
        return jsonify({"message": "Batch updated successfully"})

    except Exception as e:
        logging.error(f"🔥 ERROR in /edit_batch: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500



@app.route('/delete_batch/<int:batch_id>', methods=['DELETE'])
def delete_batch(batch_id):
    """Allow only Admins to delete a batch."""
    
    # ✅ Use `session["admin_session"]` to check if the user is an admin
    admin_session = session.get("admin_session")

    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict non-admins

    try:
        batch = Batch.query.get(batch_id)
        if not batch:
            return jsonify({"error": "Batch not found"}), 404

        db.session.delete(batch)
        db.session.commit()

        return jsonify({"message": "Batch deleted successfully"})

    except Exception as e:
        logging.error(f"🔥 ERROR in /delete_batch: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500


@app.route('/api/users', methods=['GET'])
def get_users():
    """Fetch user data, only accessible to Admins."""
    
    # ✅ Ensure only admins can access this API
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to admins only

    # Fetch query parameters
    role = request.args.get('role', 'all').lower()  # Convert to lowercase
    search_query = request.args.get('search', '').strip().lower()  # Convert to lowercase for consistent search
    page = request.args.get('page')
    limit = request.args.get('limit')

    logging.info(f"Role filter received: {role}, Search query received: {search_query}")  # Debug log

    query = User.query

    # Apply role filter
    if role == 'admin':
        query = query.filter_by(is_admin=True)
    elif role == 'user':
        query = query.filter_by(is_admin=False)

    # Apply search filter if search query is provided
    if search_query:
        query = query.filter(
            (User.name.ilike(f"%{search_query}%")) | 
            (User.email.ilike(f"%{search_query}%"))
        )

    try:
        # Check if pagination parameters are provided
        if page and limit:
            page = int(page)
            limit = int(limit)
            offset = (page - 1) * limit

            total_users = query.count()  # Get total count for pagination

            # Apply pagination using limit and offset
            users = query.offset(offset).limit(limit).all()
        else:
            # If no pagination parameters, fetch all users
            users = query.all()
            total_users = len(users)

        # Prepare user data
        user_list = [
            {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': 'Admin' if user.is_admin else 'User',
                'is_active': user.is_active,
                'is_admin': user.is_admin
            }
            for user in users
        ]

        # Return paginated data
        return jsonify({
            'users': user_list,
            'total': total_users
        }) if page and limit else jsonify(user_list)

    except ValueError:
        logging.error("🔥 ERROR: Invalid pagination parameters.")
        return jsonify({"error": "Invalid pagination parameters"}), 400

    except Exception as e:
        logging.error(f"🔥 ERROR in /api/users: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

from flask import request
@app.route('/api/users/<int:user_id>/status', methods=['PATCH'])
def update_user_status(user_id):
    """Allow only Admins to update user active status."""

    # ✅ Ensure only admins can access this API
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to admins only

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        data = request.json
        if "is_active" not in data:
            return jsonify({"error": "Missing 'is_active' field"}), 400  # ✅ Ensure required field is present

        user.is_active = data["is_active"]  # ✅ Update user status
        db.session.commit()

        return jsonify({"message": f"User status updated to {'Active' if user.is_active else 'Inactive'}"}), 200

    except Exception as e:
        logging.error(f"🔥 ERROR in /api/users/{user_id}/status: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

# ✅ API to Update User Admin Access
@app.route('/api/users/<int:user_id>/admin', methods=['PATCH'])
def update_user_admin(user_id):
    """Allow only Admins to update another user's admin access."""

    # ✅ Ensure only admins can access this API
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to admins only

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        data = request.json
        if "is_admin" not in data:
            return jsonify({"error": "Missing 'is_admin' field"}), 400  # ✅ Ensure required field is present

        user.is_admin = data["is_admin"]  # ✅ Update admin access
        db.session.commit()

        return jsonify({"message": f"User admin access updated to {'Admin' if user.is_admin else 'User'}"}), 200

    except Exception as e:
        logging.error(f"🔥 ERROR in /api/users/{user_id}/admin: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500



@app.route("/admin_get_activity_data", methods=["GET"])
def admin_get_activity_data():
    """Fetch worksheets and flashcards download activity for Admin Reports."""
    
    # ✅ Ensure only admins can access this API
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to admins only

    try:
        logs = ActivityLog.query.filter(
            ActivityLog.resource_type.in_(["Worksheet", "Flashcard"])
        ).order_by(ActivityLog.date.asc()).all()

        result = {}
        for log in logs:
            date = log.date.strftime("%Y-%m-%d")
            if date not in result:
                result[date] = {"worksheets": 0, "flashcards": 0}

            if log.resource_type == "Worksheet":
                result[date]["worksheets"] += 1
            elif log.resource_type == "Flashcard":
                result[date]["flashcards"] += 1

        return jsonify([
            {"date": date, "worksheets": data["worksheets"], "flashcards": data["flashcards"]}
            for date, data in result.items()
        ])

    except Exception as e:
        logging.error(f"🔥 ERROR in /admin_get_activity_data: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500


@app.route("/admin_get_engagement_data", methods=["GET"])
def admin_get_engagement_data():
    """Fetch user engagement statistics for Admin Reports."""

    # ✅ Ensure only admins can access this API
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to admins only

    try:
        engagement_data = {
            "forum_posts": db.session.query(func.count(Message.id)).scalar(),
            "questions_asked": db.session.query(func.count(Question.id)).scalar(),
            "answers_given": db.session.query(func.count(Answer.id)).scalar(),
        }

        return jsonify(engagement_data)

    except Exception as e:
        logging.error(f"🔥 ERROR in /admin_get_engagement_data: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/admin_get_recent_activity", methods=["GET"])
def admin_get_recent_activity():
    """Fetch the latest 10 user activities for the Admin Reports section"""
    recent_logs = (
        db.session.query(ActivityLog, User.name)
        .join(User, ActivityLog.user_id == User.id)
        .order_by(ActivityLog.date.desc())
        .limit(10)
        .all()
    )

    result = [
        {
            "user": log.name,
            "action": log.ActivityLog.action,
            "resource": log.ActivityLog.resource_name,
            "date": log.ActivityLog.date.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for log in recent_logs
    ]

    return jsonify(result)

@app.route('/get_all_users', methods=['GET'])
def get_all_users():
    users = User.query.filter_by(is_active=True).all()
    profile_pictures = [user.picture for user in users if user.picture]
    return jsonify({'pictures': profile_pictures})



@app.route("/admin_get_community_interactions", methods=["GET"])
def admin_get_community_interactions():
    """Fetch the latest 10 user community interactions for the Admin Reports section."""

    # ✅ Ensure only admins can access this API
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to admins only

    try:
        community_interactions = (
            db.session.query(User.name, Message.message, Message.timestamp)
            .join(User, Message.user_id == User.id)
            .order_by(Message.timestamp.desc())
            .limit(10)
            .all()
        )

        result = [
            {
                "user": row.name,
                "message": row.message,
                "date": row.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for row in community_interactions
        ]

        return jsonify(result)

    except Exception as e:
        logging.error(f"🔥 ERROR in /admin_get_community_interactions: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500




@app.route("/admin_get_forum_stats", methods=["GET"])
def admin_get_forum_stats():
    """Fetch forum-related statistics for Admin Dashboard."""

    # ✅ Ensure only admins can access this API
    admin_session = session.get("admin_session")
    if not admin_session or not admin_session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to admins only

    try:
        forum_stats = {
            "total_forum_posts": Message.query.count(),  # Total forum messages
            "total_questions": Question.query.count(),   # Total questions asked
            "total_answers": Answer.query.count(),       # Total answers given
        }

        return jsonify(forum_stats)

    except Exception as e:
        logging.error(f"🔥 ERROR in /admin_get_forum_stats: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500



@app.route("/get_calendar_events", methods=["GET"])
def get_calendar_events():
    """Fetch batch events for the calendar (accessible to both Admins and Users)."""

    # ✅ Ensure the user is logged in (either as User or Admin)
    user_session = session.get("user_session") or session.get("admin_session")
    if not user_session:
        return jsonify({"error": "Unauthorized"}), 403  # ✅ Restrict access to logged-in users only

    try:
        batches = Batch.query.all()
        events = {}

        for batch in batches:
            date_key = batch.start_date.strftime("%Y-%m-%d")  # Format: "YYYY-MM-DD"
            events[date_key] = {
                "id": batch.id,
                "title": batch.name,  # Display batch name as the event title
                "payment": "N/A"  # Change this if you have a payment column
            }

        return jsonify(events)

    except Exception as e:
        logging.error(f"🔥 ERROR in /get_calendar_events: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500



@app.route('/get_top_contributors', methods=['GET'])
def get_top_contributors():
    try:
        top_users = (
            db.session.query(
                User.id,
                User.name,
                User.picture,
                db.func.count(Question.id).label("question_count"),
                db.func.count(Answer.id).label("answer_count"),
                (db.func.count(Question.id) + db.func.count(Answer.id)).label("total_contributions")
            )
            .outerjoin(Question, User.id == Question.user_id)
            .outerjoin(Answer, User.id == Answer.user_id)
            .group_by(User.id, User.name, User.picture)
            .order_by(db.desc("total_contributions"))
            .limit(5)  # Show top 5 contributors
            .all()
        )

        # Convert data to JSON format
        return jsonify([
            {
                "name": user.name,
                "picture": user.picture if user.picture else "/static/images/default-user.png",
                "questions": user.question_count,
                "answers": user.answer_count,
                "points": user.total_contributions * 10  # Assign 10 points per contribution
            }
            for user in top_users
        ])

    except Exception as e:
        app.logger.error(f"Error fetching top contributors: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500



@app.route("/logout")
def logout():
    """Logs out the user and clears the session."""

    # ✅ Detect if an Admin or User is logging out
    user_email = session.get("admin_session", {}).get("email") or session.get("user_session", {}).get("email")
    
    logging.info(f"🔴 Logging out user: {user_email}")

    # ✅ Clear only relevant session keys
    session.pop("admin_session", None)
    session.pop("user_session", None)

    return redirect(url_for("home"))





# Run the Flask app
if __name__ == '__main__':
    logging.info("🚀 Starting Flask app...")
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))


