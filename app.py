import os
import json
import time
import hashlib
import secrets
import smtplib
from email.message import EmailMessage

from flask import Flask, request, jsonify

from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload


# =========================================================
# Flask
# =========================================================

app = Flask(__name__)


# =========================================================
# Environment Variables
# =========================================================

DRIVE_FOLDER_ID = os.environ.get("DRIVE_FOLDER_ID", "").strip()
GOOGLE_SERVICE_ACCOUNT_JSON = os.environ.get(
    "GOOGLE_SERVICE_ACCOUNT_JSON", ""
).strip()

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "").strip()
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD", "").strip()

USERS_FILE_NAME = "users.json"


# =========================================================
# Google Drive
# =========================================================

_drive_service = None


def get_drive_service():
    global _drive_service

    if _drive_service is None:
        if not GOOGLE_SERVICE_ACCOUNT_JSON:
            raise RuntimeError(
                "GOOGLE_SERVICE_ACCOUNT_JSON is not configured."
            )

        if not DRIVE_FOLDER_ID:
            raise RuntimeError(
                "DRIVE_FOLDER_ID is not configured."
            )

        try:
            service_account_info = json.loads(
                GOOGLE_SERVICE_ACCOUNT_JSON
            )
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Invalid GOOGLE_SERVICE_ACCOUNT_JSON: {e}"
            )

        credentials = Credentials.from_service_account_info(
            service_account_info,
            scopes=[
                "https://www.googleapis.com/auth/drive"
            ],
        )

        _drive_service = build(
            "drive",
            "v3",
            credentials=credentials,
            cache_discovery=False,
        )

    return _drive_service


# =========================================================
# users.json - Google Drive
# =========================================================

def find_users_file():
    service = get_drive_service()

    query = (
        f"name = '{USERS_FILE_NAME}' "
        f"and '{DRIVE_FOLDER_ID}' in parents "
        f"and trashed = false"
    )

    result = service.files().list(
        q=query,
        spaces="drive",
        fields="files(id,name)",
        pageSize=1,
    ).execute()

    files = result.get("files", [])

    if files:
        return files[0]["id"]

    return None


def load_users():
    service = get_drive_service()

    file_id = find_users_file()

    if not file_id:
        return {}

    content = service.files().get_media(
        fileId=file_id
    ).execute()

    if not content:
        return {}

    try:
        return json.loads(
            content.decode("utf-8")
        )
    except Exception:
        return {}


def save_users(users):
    service = get_drive_service()

    data = json.dumps(
        users,
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")

    media = MediaIoBaseUpload(
        __import__("io").BytesIO(data),
        mimetype="application/json",
        resumable=False,
    )

    file_id = find_users_file()

    if file_id:
        service.files().update(
            fileId=file_id,
            media_body=media,
        ).execute()
    else:
        metadata = {
            "name": USERS_FILE_NAME,
            "parents": [DRIVE_FOLDER_ID],
        }

        service.files().create(
            body=metadata,
            media_body=media,
            fields="id",
        ).execute()


# =========================================================
# Password Hashing
# =========================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()

    return password_hash, salt


def verify_password(password, salt, expected_hash):
    password_hash, _ = hash_password(
        password,
        salt,
    )

    return secrets.compare_digest(
        password_hash,
        expected_hash,
    )


# =========================================================
# User Functions
# =========================================================

def get_user(email):
    users = load_users()
    return users.get(email)


def create_user(email, password):
    users = load_users()

    password_hash, salt = hash_password(password)

    code = f"{secrets.randbelow(1_000_000):06d}"

    users[email] = {
        "password_hash": password_hash,
        "salt": salt,

        "verified": False,

        "verify_code": code,
        "verify_code_expires": time.time() + 600,

        "reset_code": None,
        "reset_code_expires": None,
    }

    save_users(users)

    return code


def set_new_verify_code(email):
    users = load_users()

    if email not in users:
        return None

    code = f"{secrets.randbelow(1_000_000):06d}"

    users[email]["verify_code"] = code
    users[email]["verify_code_expires"] = time.time() + 600

    save_users(users)

    return code


def mark_verified(email):
    users = load_users()

    if email not in users:
        return False

    users[email]["verified"] = True
    users[email]["verify_code"] = None
    users[email]["verify_code_expires"] = None

    save_users(users)

    return True


def set_reset_code(email):
    users = load_users()

    if email not in users:
        return None

    code = f"{secrets.randbelow(1_000_000):06d}"

    users[email]["reset_code"] = code
    users[email]["reset_code_expires"] = time.time() + 600

    save_users(users)

    return code


def reset_password(email, new_password):
    users = load_users()

    if email not in users:
        return False

    password_hash, salt = hash_password(new_password)

    users[email]["password_hash"] = password_hash
    users[email]["salt"] = salt

    users[email]["reset_code"] = None
    users[email]["reset_code_expires"] = None

    save_users(users)

    return True


# =========================================================
# Email
# =========================================================

def send_email(to_email, subject, text):
    try:
        if not SMTP_EMAIL:
            return False, "SMTP_EMAIL is not configured."

        if not SMTP_APP_PASSWORD:
            return False, "SMTP_APP_PASSWORD is not configured."

        message = EmailMessage()

        message["Subject"] = subject
        message["From"] = SMTP_EMAIL
        message["To"] = to_email

        message.set_content(text)

        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=15,
        ) as server:

            server.starttls()

            server.login(
                SMTP_EMAIL,
                SMTP_APP_PASSWORD,
            )

            server.send_message(message)

        return True, None

    except Exception as e:
        return False, str(e)


def send_verification_email(to_email, code):
    return send_email(
        to_email,
        "کد تایید ثبت‌نام - ابر نابغه",
        f"کد تایید شما: {code}\n\nاین کد تا ۱۰ دقیقه معتبره.",
    )


def send_password_reset_email(to_email, code):
    return send_email(
        to_email,
        "بازیابی رمز عبور - ابر نابغه",
        f"کد بازیابی رمز عبور شما: {code}\n\nاین کد تا ۱۰ دقیقه معتبره.",
    )


# =========================================================
# Helpers
# =========================================================

def is_valid_email(email):
    if not email:
        return False

    email = email.strip()

    return (
        "@" in email
        and "." in email.split("@")[-1]
        and " " not in email
    )


def get_json():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return {}

    return data


# =========================================================
# Home
# =========================================================

@app.route("/", methods=["GET"])
def home():
    return "Laitner Backend is running!"


# =========================================================
# Health
# =========================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok"
    })


# =========================================================
# Register
# =========================================================

@app.route("/register", methods=["POST"])
def register():
    try:
        data = get_json()

        email = str(
            data.get("email", "")
        ).strip().lower()

        password = str(
            data.get("password", "")
        )

        if not is_valid_email(email):
            return jsonify({
                "success": False,
                "error": "ایمیل معتبر نیست."
            }), 400

        if len(password) < 6:
            return jsonify({
                "success": False,
                "error": "رمز عبور باید حداقل ۶ کاراکتر باشد."
            }), 400

        existing_user = get_user(email)

        if existing_user:
            return jsonify({
                "success": False,
                "error": "این ایمیل قبلاً ثبت‌نام شده."
            }), 409

        code = create_user(
            email,
            password,
        )

        sent, error = send_verification_email(
            email,
            code,
        )

        if not sent:
            return jsonify({
                "success": False,
                "error": "خطا در ارسال ایمیل تایید.",
                "details": error,
            }), 500

        return jsonify({
            "success": True,
            "message": "ثبت‌نام انجام شد. کد تایید ارسال شد."
        }), 201

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "خطای سرور.",
            "details": str(e),
        }), 500


# =========================================================
# Verify Email
# =========================================================

@app.route("/verify", methods=["POST"])
def verify():
    try:
        data = get_json()

        email = str(
            data.get("email", "")
        ).strip().lower()

        code = str(
            data.get("code", "")
        ).strip()

        if not email or not code:
            return jsonify({
                "success": False,
                "error": "ایمیل و کد تایید الزامی هستند."
            }), 400

        user = get_user(email)

        if not user:
            return jsonify({
                "success": False,
                "error": "کاربر پیدا نشد."
            }), 404

        if user.get("verified"):
            return jsonify({
                "success": True,
                "message": "ایمیل قبلاً تایید شده."
            })

        if time.time() > user.get(
            "verify_code_expires",
            0,
        ):
            return jsonify({
                "success": False,
                "error": "کد تایید منقضی شده."
            }), 400

        if not secrets.compare_digest(
            code,
            str(user.get("verify_code", "")),
        ):
            return jsonify({
                "success": False,
                "error": "کد تایید اشتباه است."
            }), 400

        mark_verified(email)

        return jsonify({
            "success": True,
            "message": "ایمیل با موفقیت تایید شد."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "خطای سرور.",
            "details": str(e),
        }), 500


# =========================================================
# Login
# =========================================================

@app.route("/login", methods=["POST"])
def login():
    try:
        data = get_json()

        email = str(
            data.get("email", "")
        ).strip().lower()

        password = str(
            data.get("password", "")
        )

        if not email or not password:
            return jsonify({
                "success": False,
                "error": "ایمیل و رمز عبور الزامی هستند."
            }), 400

        user = get_user(email)

        if not user:
            return jsonify({
                "success": False,
                "error": "ایمیل یا رمز عبور اشتباه است."
            }), 401

        if not user.get("verified", False):
            return jsonify({
                "success": False,
                "error": "ایمیل شما هنوز تایید نشده."
            }), 403

        valid = verify_password(
            password,
            user.get("salt", ""),
            user.get("password_hash", ""),
        )

        if not valid:
            return jsonify({
                "success": False,
                "error": "ایمیل یا رمز عبور اشتباه است."
            }), 401

        return jsonify({
            "success": True,
            "message": "ورود موفق بود.",
            "email": email,
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "خطای سرور.",
            "details": str(e),
        }), 500


# =========================================================
# Resend Verification
# =========================================================

@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    try:
        data = get_json()

        email = str(
            data.get("email", "")
        ).strip().lower()

        if not email:
            return jsonify({
                "success": False,
                "error": "ایمیل الزامی است."
            }), 400

        user = get_user(email)

        if not user:
            return jsonify({
                "success": False,
                "error": "کاربر پیدا نشد."
            }), 404

        if user.get("verified"):
            return jsonify({
                "success": False,
                "error": "این ایمیل قبلاً تایید شده."
            }), 400

        code = set_new_verify_code(email)

        if not code:
            return jsonify({
                "success": False,
                "error": "ساخت کد جدید ناموفق بود."
            }), 500

        sent, error = send_verification_email(
            email,
            code,
        )

        if not sent:
            return jsonify({
                "success": False,
                "error": "خطا در ارسال ایمیل.",
                "details": error,
            }), 500

        return jsonify({
            "success": True,
            "message": "کد جدید ارسال شد."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "خطای سرور.",
            "details": str(e),
        }), 500


# =========================================================
# Forgot Password
# =========================================================

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    try:
        data = get_json()

        email = str(
            data.get("email", "")
        ).strip().lower()

        if not email:
            return jsonify({
                "success": False,
                "error": "ایمیل الزامی است."
            }), 400

        user = get_user(email)

        if not user:
            return jsonify({
                "success": False,
                "error": "کاربری با این ایمیل پیدا نشد."
            }), 404

        code = set_reset_code(email)

        if not code:
            return jsonify({
                "success": False,
                "error": "ساخت کد بازیابی ناموفق بود."
            }), 500

        sent, error = send_password_reset_email(
            email,
            code,
        )

        if not sent:
            return jsonify({
                "success": False,
                "error": "خطا در ارسال ایمیل بازیابی.",
                "details": error,
            }), 500

        return jsonify({
            "success": True,
            "message": "کد بازیابی ارسال شد."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "خطای سرور.",
            "details": str(e),
        }), 500


# =========================================================
# Reset Password
# =========================================================

@app.route("/reset-password", methods=["POST"])
def reset_password_route():
    try:
        data = get_json()

        email = str(
            data.get("email", "")
        ).strip().lower()

        code = str(
            data.get("code", "")
        ).strip()

        new_password = str(
            data.get("new_password", "")
        )

        if not email or not code or not new_password:
            return jsonify({
                "success": False,
                "error": "ایمیل، کد و رمز جدید الزامی هستند."
            }), 400

        if len(new_password) < 6:
            return jsonify({
                "success": False,
                "error": "رمز عبور باید حداقل ۶ کاراکتر باشد."
            }), 400

        user = get_user(email)

        if not user:
            return jsonify({
                "success": False,
                "error": "کاربر پیدا نشد."
            }), 404

        if time.time() > user.get(
            "reset_code_expires",
            0,
        ):
            return jsonify({
                "success": False,
                "error": "کد بازیابی منقضی شده."
            }), 400

        if not secrets.compare_digest(
            code,
            str(user.get("reset_code", "")),
        ):
            return jsonify({
                "success": False,
                "error": "کد بازیابی اشتباه است."
            }), 400

        success = reset_password(
            email,
            new_password,
        )

        if not success:
            return jsonify({
                "success": False,
                "error": "تغییر رمز عبور ناموفق بود."
            }), 500

        return jsonify({
            "success": True,
            "message": "رمز عبور با موفقیت تغییر کرد."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "خطای سرور.",
            "details": str(e),
        }), 500


# =========================================================
# Run
# =========================================================

if __name__ == "__main__":
    port = int(
        os.environ.get("PORT", 5000)
    )

    app.run(
        host="0.0.0.0",
        port=port,
    )
