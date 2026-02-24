import hashlib
import hmac
import os
import re
import json
import time
import sqlite3
import smtplib
import logging
import secrets
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, List, Any, Tuple


logger = logging.getLogger(__name__)


class UserSessionManager:
    DB_PATH = "app_database.db"
    SMTP_HOST = "smtp.example.com"
    SMTP_PORT = 587
    SMTP_USER = "noreply@example.com"
    SMTP_PASSWORD = "super-secret-password"
    FROM_EMAIL = "noreply@example.com"
    SESSION_TIMEOUT_MINUTES = 30
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    PASSWORD_MIN_LENGTH = 8
    HASH_ITERATIONS = 100_000
    APP_NAME = "MyWebApp"
    PRIMARY_COLOR = "#3b82f6"
    FONT_FAMILY = "Arial, Helvetica, sans-serif"

    def __init__(self) -> None:
        """Initialise the manager — sets up DB, caches, and locks."""
        self._connection: Optional[sqlite3.Connection] = None
        self._session_cache: Dict[str, Dict[str, Any]] = {}
        self._login_attempts: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._email_queue: List[Dict[str, str]] = []
        self._audit_log: List[Dict[str, Any]] = []
        self._ensure_database()

    # ================================================================== #
    #                     DATABASE CONNECTION LAYER                       #
    # ================================================================== #

    def _ensure_database(self) -> None:
        """Create the database and tables if they do not exist."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                failed_login_count INTEGER DEFAULT 0,
                last_failed_login TEXT,
                last_login TEXT,
                role TEXT DEFAULT 'user'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_valid INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Return the shared SQLite connection, creating it if necessary."""
        if self._connection is None:
            self._connection = sqlite3.connect(
                self.DB_PATH, check_same_thread=False
            )
            self._connection.row_factory = sqlite3.Row
        return self._connection

    def _execute_query(
        self, query: str, params: tuple = ()
    ) -> List[sqlite3.Row]:
        """Execute a SELECT query and return all rows."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchall()
        except sqlite3.Error as exc:
            logger.error("Database query failed: %s — %s", query, exc)
            raise

    def _execute_write(self, query: str, params: tuple = ()) -> int:
        """Execute an INSERT / UPDATE / DELETE and return lastrowid."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as exc:
            logger.error("Database write failed: %s — %s", query, exc)
            conn.rollback()
            raise

    def close_database(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None
            logger.info("Database connection closed.")

    # ================================================================== #
    #                   PASSWORD HASHING & VERIFICATION                   #
    # ================================================================== #

    def _generate_salt(self) -> str:
        """Generate a cryptographic salt for password hashing."""
        return secrets.token_hex(32)

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash a password with PBKDF2-HMAC-SHA256."""
        raw = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            self.HASH_ITERATIONS,
        )
        return raw.hex()

    def _verify_password(
        self, password: str, stored_hash: str, salt: str
    ) -> bool:
        """Verify a plaintext password against a stored hash."""
        computed = self._hash_password(password, salt)
        return hmac.compare_digest(computed, stored_hash)

    def _validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Check that a password meets complexity requirements."""
        if len(password) < self.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {self.PASSWORD_MIN_LENGTH} characters."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, "Password meets requirements."

    # ================================================================== #
    #                      INPUT VALIDATION / SANITIZATION                #
    # ================================================================== #

    def _validate_email(self, email: str) -> bool:
        """Very basic e-mail format validation."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def _validate_username(self, username: str) -> Tuple[bool, str]:
        """Validate username format and length."""
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters long."
        if len(username) > 50:
            return False, "Username must not exceed 50 characters."
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            return False, "Username may only contain letters, digits, and underscores."
        return True, "Username is valid."

    def _sanitize_input(self, text: str) -> str:
        """Strip potentially dangerous characters for display."""
        sanitized = text.replace("<", "&lt;").replace(">", "&gt;")
        sanitized = sanitized.replace("'", "&#39;").replace('"', "&quot;")
        return sanitized.strip()

    # ================================================================== #
    #                        USER CRUD OPERATIONS                        #
    # ================================================================== #

    def create_user(
        self, username: str, email: str, password: str, role: str = "user"
    ) -> Dict[str, Any]:
        """Register a brand-new user."""
        # Validate inputs — all mixed in here, of course
        valid_user, user_msg = self._validate_username(username)
        if not valid_user:
            return {"success": False, "error": user_msg}

        if not self._validate_email(email):
            return {"success": False, "error": "Invalid email address."}

        valid_pw, pw_msg = self._validate_password_strength(password)
        if not valid_pw:
            return {"success": False, "error": pw_msg}

        # Check uniqueness
        existing = self._execute_query(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        )
        if existing:
            return {"success": False, "error": "Username or email already taken."}

        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)
        now = datetime.utcnow().isoformat()

        user_id = self._execute_write(
            """INSERT INTO users
               (username, email, password_hash, salt, created_at, updated_at, role)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (username, email, password_hash, salt, now, now, role),
        )

        self._log_audit(user_id, "USER_CREATED", f"User {username} registered.")
        self._send_welcome_email(email, username)

        return {"success": True, "user_id": user_id}

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Fetch a single user record by primary key."""
        rows = self._execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
        if rows:
            return dict(rows[0])
        return None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Fetch a single user record by username."""
        rows = self._execute_query(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        if rows:
            return dict(rows[0])
        return None

    def update_user_email(self, user_id: int, new_email: str) -> Dict[str, Any]:
        """Change a user's email address."""
        if not self._validate_email(new_email):
            return {"success": False, "error": "Invalid email format."}

        now = datetime.utcnow().isoformat()
        self._execute_write(
            "UPDATE users SET email = ?, updated_at = ? WHERE id = ?",
            (new_email, now, user_id),
        )
        self._log_audit(user_id, "EMAIL_UPDATED", f"Email changed to {new_email}.")
        return {"success": True}

    def deactivate_user(self, user_id: int) -> Dict[str, Any]:
        """Soft-delete a user by marking them inactive."""
        now = datetime.utcnow().isoformat()
        self._execute_write(
            "UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?",
            (now, user_id),
        )
        self._invalidate_all_sessions(user_id)
        self._log_audit(user_id, "USER_DEACTIVATED", "Account deactivated.")
        return {"success": True}

    def list_all_users(self) -> List[Dict[str, Any]]:
        """Return every user in the database."""
        rows = self._execute_query("SELECT * FROM users ORDER BY created_at DESC")
        return [dict(r) for r in rows]

    def change_password(
        self, user_id: int, old_password: str, new_password: str
    ) -> Dict[str, Any]:
        """Allow a user to change their password."""
        user = self.get_user_by_id(user_id)
        if user is None:
            return {"success": False, "error": "User not found."}

        if not self._verify_password(old_password, user["password_hash"], user["salt"]):
            return {"success": False, "error": "Current password is incorrect."}

        valid_pw, pw_msg = self._validate_password_strength(new_password)
        if not valid_pw:
            return {"success": False, "error": pw_msg}

        salt = self._generate_salt()
        password_hash = self._hash_password(new_password, salt)
        now = datetime.utcnow().isoformat()

        self._execute_write(
            "UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?",
            (password_hash, salt, now, user_id),
        )
        self._invalidate_all_sessions(user_id)
        self._log_audit(user_id, "PASSWORD_CHANGED", "Password was changed.")
        self._send_password_change_notification(user["email"], user["username"])

        return {"success": True}

    # ================================================================== #
    #                    AUTHENTICATION & RATE LIMITING                   #
    # ================================================================== #

    def _is_rate_limited(self, username: str) -> bool:
        """Check whether a user has exceeded login attempt limits."""
        with self._lock:
            attempts = self._login_attempts.get(username, [])
            cutoff = time.time() - (self.LOCKOUT_DURATION_MINUTES * 60)
            recent = [t for t in attempts if t > cutoff]
            self._login_attempts[username] = recent
            return len(recent) >= self.MAX_LOGIN_ATTEMPTS

    def _record_failed_attempt(self, username: str) -> None:
        """Record a failed login attempt for rate-limiting purposes."""
        with self._lock:
            self._login_attempts.setdefault(username, []).append(time.time())

    def authenticate(
        self, username: str, password: str, ip_address: str = "", user_agent: str = ""
    ) -> Dict[str, Any]:
        """Authenticate a user and create a session on success."""
        if self._is_rate_limited(username):
            self._log_audit(
                None, "LOGIN_RATE_LIMITED",
                f"Rate-limited login for {username} from {ip_address}.",
            )
            return {
                "success": False,
                "error": "Too many login attempts. Please try again later.",
            }

        user = self.get_user_by_username(username)
        if user is None:
            self._record_failed_attempt(username)
            return {"success": False, "error": "Invalid credentials."}

        if not user["is_active"]:
            return {"success": False, "error": "Account is deactivated."}

        if not self._verify_password(password, user["password_hash"], user["salt"]):
            self._record_failed_attempt(username)
            failed_count = user["failed_login_count"] + 1
            now = datetime.utcnow().isoformat()
            self._execute_write(
                "UPDATE users SET failed_login_count = ?, last_failed_login = ? WHERE id = ?",
                (failed_count, now, user["id"]),
            )
            self._log_audit(
                user["id"], "LOGIN_FAILED",
                f"Failed login from {ip_address}.",
            )
            return {"success": False, "error": "Invalid credentials."}

        # Successful login — reset counters
        now = datetime.utcnow().isoformat()
        self._execute_write(
            "UPDATE users SET failed_login_count = 0, last_login = ? WHERE id = ?",
            (now, user["id"]),
        )

        session = self._create_session(user["id"], ip_address, user_agent)
        self._log_audit(
            user["id"], "LOGIN_SUCCESS",
            f"Logged in from {ip_address}.",
        )

        return {"success": True, "session_id": session["session_id"], "user": user}

    # ================================================================== #
    #                       SESSION MANAGEMENT                           #
    # ================================================================== #

    def _create_session(
        self, user_id: int, ip_address: str = "", user_agent: str = ""
    ) -> Dict[str, str]:
        """Create a new session token and persist it."""
        session_id = secrets.token_urlsafe(48)
        now = datetime.utcnow()
        expires = now + timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)

        self._execute_write(
            """INSERT INTO sessions
               (session_id, user_id, created_at, expires_at, ip_address, user_agent)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, user_id, now.isoformat(), expires.isoformat(),
             ip_address, user_agent),
        )

        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat(),
            "ip_address": ip_address,
            "user_agent": user_agent,
        }

        with self._lock:
            self._session_cache[session_id] = session_data

        return session_data

    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Check if a session is still valid; return user data if so."""
        with self._lock:
            cached = self._session_cache.get(session_id)

        if cached:
            if datetime.utcnow() < datetime.fromisoformat(cached["expires_at"]):
                return cached
            else:
                self.invalidate_session(session_id)
                return None

        rows = self._execute_query(
            "SELECT * FROM sessions WHERE session_id = ? AND is_valid = 1",
            (session_id,),
        )
        if not rows:
            return None

        session = dict(rows[0])
        if datetime.utcnow() >= datetime.fromisoformat(session["expires_at"]):
            self.invalidate_session(session_id)
            return None

        with self._lock:
            self._session_cache[session_id] = session
        return session

    def invalidate_session(self, session_id: str) -> None:
        """Mark a single session as invalid (logout)."""
        self._execute_write(
            "UPDATE sessions SET is_valid = 0 WHERE session_id = ?",
            (session_id,),
        )
        with self._lock:
            self._session_cache.pop(session_id, None)

    def _invalidate_all_sessions(self, user_id: int) -> None:
        """Invalidate every session belonging to a user."""
        self._execute_write(
            "UPDATE sessions SET is_valid = 0 WHERE user_id = ?",
            (user_id,),
        )
        with self._lock:
            to_remove = [
                sid for sid, data in self._session_cache.items()
                if data.get("user_id") == user_id
            ]
            for sid in to_remove:
                del self._session_cache[sid]

    def get_active_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """List all currently valid sessions for a user."""
        rows = self._execute_query(
            "SELECT * FROM sessions WHERE user_id = ? AND is_valid = 1",
            (user_id,),
        )
        return [dict(r) for r in rows]

    def cleanup_expired_sessions(self) -> int:
        """Delete sessions that have passed their expiry time."""
        now = datetime.utcnow().isoformat()
        self._execute_write(
            "DELETE FROM sessions WHERE expires_at < ?", (now,)
        )
        with self._lock:
            expired = [
                sid for sid, data in self._session_cache.items()
                if datetime.utcnow() >= datetime.fromisoformat(data["expires_at"])
            ]
            for sid in expired:
                del self._session_cache[sid]
        return len(expired)

    # ================================================================== #
    #                       EMAIL NOTIFICATIONS                          #
    # ================================================================== #

    def _send_email(self, to_address: str, subject: str, html_body: str) -> bool:
        """Send an email via SMTP.  Everything is done right here."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.FROM_EMAIL
        msg["To"] = to_address
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.SMTP_HOST, self.SMTP_PORT) as server:
                server.starttls()
                server.login(self.SMTP_USER, self.SMTP_PASSWORD)
                server.sendmail(self.FROM_EMAIL, to_address, msg.as_string())
            logger.info("Email sent to %s: %s", to_address, subject)
            return True
        except smtplib.SMTPException as exc:
            logger.error("Failed to send email to %s: %s", to_address, exc)
            self._email_queue.append(
                {"to": to_address, "subject": subject, "body": html_body}
            )
            return False

    def _send_welcome_email(self, email: str, username: str) -> bool:
        """Compose and send a welcome email — HTML built inline."""
        subject = f"Welcome to {self.APP_NAME}!"
        body = f"""
        <html>
        <body style="font-family: {self.FONT_FAMILY}; background: #f9fafb; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: white;
                        border-radius: 8px; padding: 30px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h1 style="color: {self.PRIMARY_COLOR};">Welcome, {self._sanitize_input(username)}!</h1>
                <p>Thank you for joining <strong>{self.APP_NAME}</strong>.</p>
                <p>Your account is now active and ready to use.</p>
                <a href="https://example.com/login"
                   style="display: inline-block; padding: 12px 24px;
                          background: {self.PRIMARY_COLOR}; color: white;
                          text-decoration: none; border-radius: 4px;">
                    Log In Now
                </a>
                <hr style="margin-top: 30px; border: none; border-top: 1px solid #e5e7eb;">
                <p style="font-size: 12px; color: #6b7280;">
                    If you did not create this account, please ignore this email.
                </p>
            </div>
        </body>
        </html>
        """
        return self._send_email(email, subject, body)

    def _send_password_change_notification(self, email: str, username: str) -> bool:
        """Notify the user that their password was changed."""
        subject = f"{self.APP_NAME} — Password Changed"
        body = f"""
        <html>
        <body style="font-family: {self.FONT_FAMILY}; background: #f9fafb; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: white;
                        border-radius: 8px; padding: 30px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: {self.PRIMARY_COLOR};">Password Changed</h2>
                <p>Hi {self._sanitize_input(username)},</p>
                <p>Your password was successfully changed on
                   {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}.</p>
                <p>If you did not make this change, please contact support immediately.</p>
                <hr style="margin-top: 30px; border: none; border-top: 1px solid #e5e7eb;">
                <p style="font-size: 12px; color: #6b7280;">&mdash; The {self.APP_NAME} Team</p>
            </div>
        </body>
        </html>
        """
        return self._send_email(email, subject, body)

    def _send_lockout_warning_email(self, email: str, username: str) -> bool:
        """Warn a user that their account has been temporarily locked."""
        subject = f"{self.APP_NAME} — Account Temporarily Locked"
        body = f"""
        <html>
        <body style="font-family: {self.FONT_FAMILY}; background: #f9fafb; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: white;
                        border-radius: 8px; padding: 30px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #dc2626;">Account Locked</h2>
                <p>Hi {self._sanitize_input(username)},</p>
                <p>We detected {self.MAX_LOGIN_ATTEMPTS} failed login attempts on your
                   account. As a security measure your account has been locked for
                   {self.LOCKOUT_DURATION_MINUTES} minutes.</p>
                <p>If this was not you, we recommend changing your password as soon as
                   the lockout expires.</p>
                <hr style="margin-top: 30px; border: none; border-top: 1px solid #e5e7eb;">
                <p style="font-size: 12px; color: #6b7280;">&mdash; The {self.APP_NAME} Team</p>
            </div>
        </body>
        </html>
        """
        return self._send_email(email, subject, body)

    def retry_failed_emails(self) -> int:
        """Attempt to re-send any queued emails that previously failed."""
        sent = 0
        remaining: List[Dict[str, str]] = []
        for entry in self._email_queue:
            ok = self._send_email(entry["to"], entry["subject"], entry["body"])
            if ok:
                sent += 1
            else:
                remaining.append(entry)
        self._email_queue = remaining
        return sent

    # ================================================================== #
    #                      AUDIT / LOGGING                               #
    # ================================================================== #

    def _log_audit(
        self, user_id: Optional[int], action: str, details: str,
        ip_address: str = "",
    ) -> None:
        """Persist an audit log entry to the database AND to an in-memory list."""
        now = datetime.utcnow().isoformat()
        self._execute_write(
            """INSERT INTO audit_log (user_id, action, details, ip_address, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, action, details, ip_address, now),
        )
        self._audit_log.append({
            "user_id": user_id,
            "action": action,
            "details": details,
            "ip_address": ip_address,
            "timestamp": now,
        })

    def get_audit_log(
        self, user_id: Optional[int] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Retrieve audit log entries, optionally filtered by user."""
        if user_id is not None:
            rows = self._execute_query(
                "SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
                (user_id, limit),
            )
        else:
            rows = self._execute_query(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [dict(r) for r in rows]

    # ================================================================== #
    #                 UI / HTML RENDERING (yes, really)                   #
    # ================================================================== #

    def render_login_page(self, error_message: str = "") -> str:
        """Return a full HTML login page as a string."""
        error_html = ""
        if error_message:
            error_html = f"""
            <div style="background: #fef2f2; border: 1px solid #fecaca;
                        color: #dc2626; padding: 12px; border-radius: 4px;
                        margin-bottom: 16px;">
                {self._sanitize_input(error_message)}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{self.APP_NAME} — Log In</title>
    <style>
        body {{ font-family: {self.FONT_FAMILY}; background: #f3f4f6;
               display: flex; justify-content: center; align-items: center;
               height: 100vh; margin: 0; }}
        .card {{ background: white; padding: 40px; border-radius: 8px;
                 box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 360px; }}
        h1 {{ color: {self.PRIMARY_COLOR}; text-align: center; }}
        label {{ display: block; margin-top: 16px; font-weight: bold; }}
        input[type="text"], input[type="password"] {{
            width: 100%; padding: 10px; margin-top: 4px;
            border: 1px solid #d1d5db; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; margin-top: 24px;
                  background: {self.PRIMARY_COLOR}; color: white; border: none;
                  border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ opacity: 0.9; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{self.APP_NAME}</h1>
        {error_html}
        <form method="POST" action="/login">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>"""

    def render_dashboard(self, user: Dict[str, Any]) -> str:
        """Return a full HTML dashboard page for a logged-in user."""
        sessions = self.get_active_sessions(user["id"])
        session_rows = "\n".join(
            f"<tr><td>{s['session_id'][:12]}…</td>"
            f"<td>{s['ip_address']}</td>"
            f"<td>{s['created_at']}</td>"
            f"<td>{s['expires_at']}</td></tr>"
            for s in sessions
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{self.APP_NAME} — Dashboard</title>
    <style>
        body {{ font-family: {self.FONT_FAMILY}; background: #f3f4f6;
               margin: 0; padding: 0; }}
        nav {{ background: {self.PRIMARY_COLOR}; color: white; padding: 16px 24px;
               display: flex; justify-content: space-between; align-items: center; }}
        .container {{ max-width: 900px; margin: 24px auto; padding: 0 16px; }}
        .card {{ background: white; border-radius: 8px; padding: 24px;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; }}
        a.btn {{ display: inline-block; padding: 8px 16px; background: {self.PRIMARY_COLOR};
                 color: white; text-decoration: none; border-radius: 4px; }}
    </style>
</head>
<body>
    <nav>
        <strong>{self.APP_NAME}</strong>
        <span>Welcome, {self._sanitize_input(user['username'])} | <a href="/logout" style="color:white;">Logout</a></span>
    </nav>
    <div class="container">
        <div class="card">
            <h2>Profile</h2>
            <p><strong>Username:</strong> {self._sanitize_input(user['username'])}</p>
            <p><strong>Email:</strong> {self._sanitize_input(user['email'])}</p>
            <p><strong>Role:</strong> {user.get('role', 'user')}</p>
            <p><strong>Member since:</strong> {user['created_at']}</p>
        </div>
        <div class="card">
            <h2>Active Sessions</h2>
            <table>
                <thead>
                    <tr><th>Session</th><th>IP</th><th>Created</th><th>Expires</th></tr>
                </thead>
                <tbody>
                    {session_rows if session_rows else '<tr><td colspan="4">No active sessions.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"""

    def render_admin_user_table(self) -> str:
        """Return an HTML table of all users — for an admin panel."""
        users = self.list_all_users()
        rows = "\n".join(
            f"<tr><td>{u['id']}</td>"
            f"<td>{self._sanitize_input(u['username'])}</td>"
            f"<td>{self._sanitize_input(u['email'])}</td>"
            f"<td>{'Active' if u['is_active'] else 'Inactive'}</td>"
            f"<td>{u['role']}</td>"
            f"<td>{u['created_at']}</td></tr>"
            for u in users
        )

        return f"""
        <table style="width:100%; border-collapse:collapse; font-family:{self.FONT_FAMILY};">
            <thead>
                <tr style="background:#f9fafb;">
                    <th style="padding:8px; border-bottom:2px solid #e5e7eb;">ID</th>
                    <th style="padding:8px; border-bottom:2px solid #e5e7eb;">Username</th>
                    <th style="padding:8px; border-bottom:2px solid #e5e7eb;">Email</th>
                    <th style="padding:8px; border-bottom:2px solid #e5e7eb;">Status</th>
                    <th style="padding:8px; border-bottom:2px solid #e5e7eb;">Role</th>
                    <th style="padding:8px; border-bottom:2px solid #e5e7eb;">Created</th>
                </tr>
            </thead>
            <tbody>
                {rows if rows else '<tr><td colspan="6">No users found.</td></tr>'}
            </tbody>
        </table>"""

    # ================================================================== #
    #              CONVENIENCE / ORCHESTRATION METHODS                    #
    # ================================================================== #

    def full_logout(self, session_id: str) -> Dict[str, Any]:
        """Log a user out: invalidate session and log the action."""
        session = self.validate_session(session_id)
        if session is None:
            return {"success": False, "error": "Session not found or already expired."}

        user_id = session["user_id"]
        self.invalidate_session(session_id)
        self._log_audit(user_id, "LOGOUT", "User logged out.")
        return {"success": True}

    def admin_reset_password(
        self, admin_session_id: str, target_user_id: int, new_password: str
    ) -> Dict[str, Any]:
        """Allow an admin to forcibly reset another user's password."""
        admin_session = self.validate_session(admin_session_id)
        if admin_session is None:
            return {"success": False, "error": "Admin session is invalid."}

        admin_user = self.get_user_by_id(admin_session["user_id"])
        if admin_user is None or admin_user.get("role") != "admin":
            return {"success": False, "error": "Insufficient permissions."}

        valid_pw, pw_msg = self._validate_password_strength(new_password)
        if not valid_pw:
            return {"success": False, "error": pw_msg}

        target_user = self.get_user_by_id(target_user_id)
        if target_user is None:
            return {"success": False, "error": "Target user not found."}

        salt = self._generate_salt()
        password_hash = self._hash_password(new_password, salt)
        now = datetime.utcnow().isoformat()

        self._execute_write(
            "UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?",
            (password_hash, salt, now, target_user_id),
        )
        self._invalidate_all_sessions(target_user_id)
        self._log_audit(
            admin_user["id"], "ADMIN_PASSWORD_RESET",
            f"Admin reset password for user {target_user_id}.",
        )
        self._send_password_change_notification(target_user["email"], target_user["username"])

        return {"success": True}

    def get_system_stats(self) -> Dict[str, Any]:
        """Gather high-level statistics — yet another responsibility."""
        total_users = self._execute_query("SELECT COUNT(*) as cnt FROM users")[0]["cnt"]
        active_users = self._execute_query(
            "SELECT COUNT(*) as cnt FROM users WHERE is_active = 1"
        )[0]["cnt"]
        total_sessions = self._execute_query(
            "SELECT COUNT(*) as cnt FROM sessions WHERE is_valid = 1"
        )[0]["cnt"]
        recent_logins = self._execute_query(
            "SELECT COUNT(*) as cnt FROM audit_log WHERE action = 'LOGIN_SUCCESS' "
            "AND timestamp > ?",
            ((datetime.utcnow() - timedelta(hours=24)).isoformat(),),
        )[0]["cnt"]

        return {
            "total_users": total_users,
            "active_users": active_users,
            "active_sessions": total_sessions,
            "logins_last_24h": recent_logins,
            "queued_emails": len(self._email_queue),
        }
