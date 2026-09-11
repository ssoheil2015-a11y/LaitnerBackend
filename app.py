import os
import io
import json
import time
import secrets
import hashlib
import smtplib
from email.message import EmailMessage

from flask import Flask, request, jsonify

app = Flask(__name__)


# =========================
# تنظیمات
# =========================

DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID")
USERS_FILE_NAME = "users.json"

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD")


# =========================
# Google Drive
# =========================

_drive_service = None


def get_drive_service():
    global _drive_service

    if _drive_service is None:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build

        service_account_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")

        if not service_account_json:
            raise RuntimeError("GOOGLE_SERVICE_ACCOUNT_JSON is not configured")

        if not DRIVE_FOLDER_ID:
            raise RuntimeError("DRIVE_FOLDER_ID is not configured")

        credentials_info = json.loads(service_account_json)

        credentials = Credentials.from_service_account_info(
            credentials_info,
            scopes=["https://www.googleapis.com/auth/drive"],
        )

        _drive_service = build(
            "drive",
            "v3",
            credentials=credentials,
        )

    return _drive_service


def find_users_file_id():
    service = get_drive_service()

    query = (
        f"name='{USERS_FILE_NAME}' "
        f"and '{DRIVE_FOLDER_ID}' in parents "
        f"and trashed=false"
    )

    result = service.files().list(
        q=query,
        fields="files(id,name)"
    ).execute()

    files = result.get("files", [])

    return files[0]["id"] if files else None


def load_users():
    from googleapiclient.http import MediaIoBaseDownload

    file_id = find_users_file_id()

    if not file_id:
        return {}

    service = get_drive_service()

    request = service.files().get_media(fileId=file_id)

    buffer = io.BytesIO()
    downloader = MediaIoBaseDownload(buffer, request)

    done = False

    while not done:
        _, done = downloader.next_chunk()

    buffer.seek(0)

    try:
        return json.loads(
            buffer.read().decode("utf-8")
        )
    except Exception:
        return {}


def save_users(users):
    from googleapiclient.http import MediaIoBaseUpload

    service = get_drive_service()

    content = json.dumps(
        users,
        ensure_ascii=False,
        indent=2
    ).encode("utf-8")

    buffer = io.BytesIO(content)

    media = MediaIoBaseUpload(
        buffer,
        mimetype="application/json",
        resumable=False
    )

    file_id = find_users_file_id()

    if file_id:
        service.files().update(
            fileId=file_id,
            media_body=media
        ).execute()

    else:
        metadata = {
            "name": USERS_FILE_NAME,
            "parents": [DRIVE_FOLDER_ID]
        }

        service.files().create(
            body=metadata,
            media_body=media,
            fields="id"
        ).execute()


# =========================
# رمز عبور
# =========================

def hash_password(password, salt=None):

    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()

    return password_hash, salt


def verify_password(password, salt, expected_hash):

    password_hash, _ = hash_password(
        password,
        salt
    )

    return secrets.compare_digest(
        password_hash,
        expected_hash
    )


# =========================
# ایمیل
# =========================

def send_email(to_email, subject, text):

    if not SMTP_EMAIL or not SMTP_APP_PASSWORD:
        raise RuntimeError("SMTP settings are not configured")

    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = SMTP_EMAIL
    message["To"] = to_email

    message.set_content(text)

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT,
        timeout=15
    ) as server:

        server.starttls()

        server.login(
            SMTP_EMAIL,
            SMTP_APP_PASSWORD
        )

        server.send_message(message)


# =========================
# بررسی ایمیل
# =========================

def valid_email(email):

    return (
        isinstance(email, str)
        and "@" in email
        and "." in email.split("@")[-1]
    )


# =========================
# صفحه اصلی
# =========================

@app.route("/")
def home():

    return "Laitner Backend is running!"


@app.route("/health")
def health():

    return jsonify({
        "status": "ok"
    })


# =========================
# ثبت نام
# =========================

@app.route("/register", methods=["POST"])
def register():

    try:

        data = request.get_json(silent=True) or {}

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not valid_email(email):

            return jsonify({
                "success": False,
                "error": "invalid_email"
            }), 400

        if len(password) < 6:

            return jsonify({
                "success": False,
                "error": "password_too_short"
            }), 400

        users = load_users()

        if email in users:

            return jsonify({
                "success": False,
                "error": "email_already_registered"
            }), 409

        password_hash, salt = hash_password(password)

        code = f"{secrets.randbelow(1_000_000):06d}"

        users[email] = {
            "password_hash": password_hash,
            "salt": salt,
            "verified": False,
            "verify_code": code,
            "verify_code_expires": time.time() + 600,
            "reset_code": None,
            "reset_code_expires": None
        }

        save_users(users)

        try:

            send_email(
                email,
                "کد تایید ثبت‌نام - لایتنر",
                f"کد تایید شما: {code}\n\nاین کد تا ۱۰ دقیقه معتبر است."
            )

        except Exception as email_error:

            # اگر ارسال ایمیل شکست خورد،
            # حساب ساخته‌شده را حذف می‌کنیم.
            users.pop(email, None)
            save_users(users)

            print("EMAIL ERROR:", email_error)

            return jsonify({
                "success": False,
                "error": "email_send_failed"
            }), 500

        return jsonify({
            "success": True,
            "message": "verification_code_sent"
        })


    except Exception as e:

        print("REGISTER ERROR:", e)

        return jsonify({
            "success": False,
            "error": "server_error"
        }), 500


# =========================
# تایید ایمیل
# =========================

@app.route("/verify", methods=["POST"])
def verify():

    try:

        data = request.get_json(silent=True) or {}

        email = data.get("email", "").strip().lower()
        code = str(data.get("code", "")).strip()

        users = load_users()

        user = users.get(email)

        if not user:

            return jsonify({
                "success": False,
                "error": "user_not_found"
            }), 404

        if user.get("verified"):

            return jsonify({
                "success": True,
                "message": "already_verified"
            })

        if time.time() > user.get(
            "verify_code_expires",
            0
        ):

            return jsonify({
                "success": False,
                "error": "code_expired"
            }), 400

        if not secrets.compare_digest(
            code,
            str(user.get("verify_code", ""))
        ):

            return jsonify({
                "success": False,
                "error": "wrong_code"
            }), 400

        user["verified"] = True
        user["verify_code"] = None
        user["verify_code_expires"] = None

        save_users(users)

        return jsonify({
            "success": True,
            "message": "email_verified"
        })


    except Exception as e:

        print("VERIFY ERROR:", e)

        return jsonify({
            "success": False,
            "error": "server_error"
        }), 500


# =========================
# ورود
# =========================

@app.route("/login", methods=["POST"])
def login():

    try:

        data = request.get_json(silent=True) or {}

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        users = load_users()

        user = users.get(email)

        if not user:

            return jsonify({
                "success": False,
                "error": "user_not_found"
            }), 404

        if not verify_password(
            password,
            user["salt"],
            user["password_hash"]
        ):

            return jsonify({
                "success": False,
                "error": "wrong_password"
            }), 401

        if not user.get("verified", False):

            return jsonify({
                "success": False,
                "error": "email_not_verified"
            }), 403

        return jsonify({
            "success": True,
            "message": "login_success"
        })


    except Exception as e:

        print("LOGIN ERROR:", e)

        return jsonify({
            "success": False,
            "error": "server_error"
        }), 500


# =========================
# ارسال دوباره کد تایید
# =========================

@app.route("/resend-verification", methods=["POST"])
def resend_verification():

    try:

        data = request.get_json(silent=True) or {}

        email = data.get("email", "").strip().lower()

        users = load_users()

        user = users.get(email)

        if not user:

            return jsonify({
                "success": False,
                "error": "user_not_found"
            }), 404

        if user.get("verified"):

            return jsonify({
                "success": False,
                "error": "already_verified"
            }), 400

        code = f"{secrets.randbelow(1_000_000):06d}"

        user["verify_code"] = code
        user["verify_code_expires"] = time.time() + 600

        save_users(users)

        send_email(
            email,
            "کد تایید جدید - لایتنر",
            f"کد تایید جدید شما: {code}\n\nاین کد تا ۱۰ دقیقه معتبر است."
        )

        return jsonify({
            "success": True
        })


    except Exception as e:

        print("RESEND ERROR:", e)

        return jsonify({
            "success": False,
            "error": "server_error"
        }), 500


# =========================
# درخواست بازیابی رمز
# =========================

@app.route("/forgot-password", methods=["POST"])
def forgot_password():

    try:

        data = request.get_json(silent=True) or {}

        email = data.get("email", "").strip().lower()

        users = load_users()

        user = users.get(email)

        if not user:

            return jsonify({
                "success": False,
                "error": "user_not_found"
            }), 404

        code = f"{secrets.randbelow(1_000_000):06d}"

        user["reset_code"] = code
        user["reset_code_expires"] = time.time() + 600

        save_users(users)

        send_email(
            email,
            "بازیابی رمز عبور - لایتنر",
            f"کد بازیابی رمز عبور شما: {code}\n\nاین کد تا ۱۰ دقیقه معتبر است."
        )

        return jsonify({
            "success": True
        })


    except Exception as e:

        print("FORGOT PASSWORD ERROR:", e)

        return jsonify({
            "success": False,
            "error": "server_error"
        }), 500


# =========================
# تغییر رمز با کد بازیابی
# =========================

@app.route("/reset-password", methods=["POST"])
def reset_password():

    try:

        data = request.get_json(silent=True) or {}

        email = data.get("email", "").strip().lower()
        code = str(data.get("code", "")).strip()
        new_password = data.get("new_password", "")

        if len(new_password) < 6:

            return jsonify({
                "success": False,
                "error": "password_too_short"
            }), 400

        users = load_users()

        user = users.get(email)

        if not user:

            return jsonify({
                "success": False,
                "error": "user_not_found"
            }), 404

        if time.time() > user.get(
            "reset_code_expires",
            0
        ):

            return jsonify({
                "success": False,
                "error": "code_expired"
            }), 400

        if not secrets.compare_digest(
            code,
            str(user.get("reset_code", ""))
        ):

            return jsonify({
                "success": False,
                "error": "wrong_code"
            }), 400

        password_hash, salt = hash_password(
            new_password
        )

        user["password_hash"] = password_hash
        user["salt"] = salt
        user["reset_code"] = None
        user["reset_code_expires"] = None

        save_users(users)

        return jsonify({
            "success": True,
            "message": "password_reset_success"
        })


    except Exception as e:

        print("RESET PASSWORD ERROR:", e)

        return jsonify({
            "success": False,
            "error": "server_error"
        }), 500


# =========================
# اجرای سرور
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )
