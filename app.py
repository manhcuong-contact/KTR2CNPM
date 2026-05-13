from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parent
# Hỗ trợ Railway Volume: đọc đường dẫn từ biến môi trường nếu có
DB_PATH = Path(os.environ.get("DB_PATH", str(BASE_DIR / "webchat.db")))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(BASE_DIR / "storage" / "uploads")))
PASSWORD_ITERATIONS = 210_000
SESSION_TTL_DAYS = 7
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = FastAPI(title="WebChat", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

online_connections: dict[str, WebSocket] = {}
connection_lock = asyncio.Lock()
db_lock = asyncio.Lock()


class SignupPayload(BaseModel):
    email: str
    display_name: str
    password: str


class LoginPayload(BaseModel):
    email: str
    password: str


class GoogleLoginPayload(BaseModel):
    email: str
    display_name: str
    id_token: str | None = None


class CreateDirectPayload(BaseModel):
    target_email: str


class CreateConversationPayload(BaseModel):
    kind: str
    name: str
    member_emails: list[str] = []
    admin_emails: list[str] = []


class SendMessagePayload(BaseModel):
    body: str = ""
    attachment_ids: list[str] = []


class WeRTCSignalPayload(BaseModel):
    target_user: str
    signal_type: str
    payload: dict[str, Any] | list[Any] | str | int | float | None = None


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


def normalize_email(value: str) -> str:
    return value.strip().lower()


def validate_email(value: str) -> str:
    email = normalize_email(value)
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Email không hợp lệ")
    return email


def generate_id(prefix: str = "") -> str:
    token = uuid.uuid4().hex
    return f"{prefix}{token}" if prefix else token


def direct_conversation_id(user_a: str, user_b: str) -> str:
    pair = "::".join(sorted([normalize_email(user_a), normalize_email(user_b)]))
    digest = hashlib.sha1(pair.encode("utf-8")).hexdigest()[:24]
    return f"direct-{digest}"


def open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db() -> Any:
    conn = open_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                auth_provider TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS conversation_members (
                conversation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                joined_at TEXT NOT NULL,
                PRIMARY KEY(conversation_id, user_id),
                FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS uploads (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                url TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                upload_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
                FOREIGN KEY(upload_id) REFERENCES uploads(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_members_user_id ON conversation_members(user_id);
            CREATE INDEX IF NOT EXISTS idx_members_conversation_id ON conversation_members(conversation_id);
            CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages(conversation_id);
            CREATE INDEX IF NOT EXISTS idx_uploads_owner_id ON uploads(owner_id);
            CREATE INDEX IF NOT EXISTS idx_attachments_message_id ON attachments(message_id);
            """
        )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_b64.encode("ascii"))
        computed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
        )
        return secrets.compare_digest(computed, expected)
    except Exception:
        return False


def serialize_user(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "auth_provider": row["auth_provider"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def serialize_attachment(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "upload_id": row["upload_id"],
        "original_name": row["original_name"],
        "stored_name": row["stored_name"],
        "mime_type": row["mime_type"],
        "size": row["size"],
        "url": row["url"],
        "download_url": row["url"],
        "created_at": row["created_at"],
    }


def get_user_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (normalize_email(email),),
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_session(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
    if not row:
        return None
    if row["expires_at"] <= now_iso():
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        return None
    return row


def issue_session(conn: sqlite3.Connection, user_id: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = (now_utc() + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now_iso(), expires_at),
    )
    return token, expires_at


def extract_token_from_request(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    cookie = request.cookies.get("webchat_token")
    if cookie:
        return cookie.strip()
    return None


def current_user_from_token(token: str | None) -> sqlite3.Row:
    if not token:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    with db() as conn:
        session = get_session(conn, token)
        if not session:
            raise HTTPException(status_code=401, detail="Phiên đăng nhập không hợp lệ")
        user = get_user_by_id(conn, session["user_id"])
        if not user:
            raise HTTPException(status_code=401, detail="Người dùng không tồn tại")
        return user


def current_user_from_request(request: Request) -> sqlite3.Row:
    return current_user_from_token(extract_token_from_request(request))


def get_membership(conn: sqlite3.Connection, conversation_id: str, user_id: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT *
        FROM conversation_members
        WHERE conversation_id = ? AND user_id = ?
        """,
        (conversation_id, user_id),
    ).fetchone()


def get_conversation(conn: sqlite3.Connection, conversation_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM conversations WHERE id = ?",
        (conversation_id,),
    ).fetchone()


def get_conversation_members(conn: sqlite3.Connection, conversation_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT cm.user_id, cm.role, cm.joined_at, u.email, u.display_name, u.auth_provider
        FROM conversation_members cm
        JOIN users u ON u.id = cm.user_id
        WHERE cm.conversation_id = ?
        ORDER BY u.display_name COLLATE NOCASE, u.email COLLATE NOCASE
        """,
        (conversation_id,),
    ).fetchall()
    return [
        {
            "id": row["user_id"],
            "role": row["role"],
            "joined_at": row["joined_at"],
            "email": row["email"],
            "display_name": row["display_name"],
            "auth_provider": row["auth_provider"],
        }
        for row in rows
    ]


def get_last_message(conn: sqlite3.Connection, conversation_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT m.*, u.email AS sender_email, u.display_name AS sender_display_name
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = ?
        ORDER BY m.created_at DESC
        LIMIT 1
        """,
        (conversation_id,),
    ).fetchone()
    if not row:
        return None
    attachment_count = conn.execute(
        "SELECT COUNT(*) AS total FROM attachments WHERE message_id = ?",
        (row["id"],),
    ).fetchone()["total"]
    return {
        "id": row["id"],
        "conversation_id": row["conversation_id"],
        "sender": {
            "id": row["sender_id"],
            "email": row["sender_email"],
            "display_name": row["sender_display_name"],
        },
        "body": row["body"],
        "created_at": row["created_at"],
        "attachment_count": attachment_count,
    }


def serialize_message(conn: sqlite3.Connection, row: sqlite3.Row, current_user_id: str) -> dict[str, Any]:
    sender = get_user_by_id(conn, row["sender_id"])
    if not sender:
        raise HTTPException(status_code=500, detail="Người gửi không tồn tại")
    attachments = conn.execute(
        """
        SELECT *
        FROM attachments
        WHERE message_id = ?
        ORDER BY created_at ASC
        """,
        (row["id"],),
    ).fetchall()
    return {
        "id": row["id"],
        "conversation_id": row["conversation_id"],
        "sender": serialize_user(sender),
        "body": row["body"],
        "created_at": row["created_at"],
        "date_key": row["created_at"][:10],
        "mine": row["sender_id"] == current_user_id,
        "attachments": [serialize_attachment(item) for item in attachments],
    }


def conversation_title(conn: sqlite3.Connection, conversation: sqlite3.Row, members: list[dict[str, Any]], current_user_id: str) -> tuple[str, str]:
    if conversation["kind"] == "direct":
        other = next((member for member in members if member["id"] != current_user_id), None)
        if other:
            return other["display_name"], other["email"]
        return conversation["name"], conversation["name"]
    subtitle = f"{len(members)} thành viên"
    return conversation["name"], subtitle


def conversation_summary(conn: sqlite3.Connection, conversation: sqlite3.Row, current_user_id: str) -> dict[str, Any]:
    members = get_conversation_members(conn, conversation["id"])
    membership = next((member for member in members if member["id"] == current_user_id), None)
    last_message = get_last_message(conn, conversation["id"])
    online_count = sum(1 for member in members if member["id"] in online_connections)
    title, subtitle = conversation_title(conn, conversation, members, current_user_id)
    can_send = True
    if conversation["kind"] == "channel" and (not membership or membership["role"] != "admin"):
        can_send = False
    return {
        "id": conversation["id"],
        "kind": conversation["kind"],
        "name": conversation["name"],
        "title": title,
        "subtitle": subtitle,
        "created_by": conversation["created_by"],
        "created_at": conversation["created_at"],
        "updated_at": conversation["updated_at"],
        "is_admin": bool(membership and membership["role"] == "admin"),
        "role": membership["role"] if membership else None,
        "can_send": can_send,
        "member_count": len(members),
        "online_count": online_count,
        "members": members,
        "last_message": last_message,
        "last_message_text": last_message["body"] if last_message else "",
        "last_message_at": last_message["created_at"] if last_message else conversation["updated_at"],
    }


def validate_member_emails(member_emails: list[str]) -> list[str]:
    emails = []
    for email in member_emails:
        cleaned = validate_email(email)
        if cleaned not in emails:
            emails.append(cleaned)
    return emails


def create_or_update_user(conn: sqlite3.Connection, email: str, display_name: str, password_hash: str, auth_provider: str) -> sqlite3.Row:
    now = now_iso()
    existing = get_user_by_email(conn, email)
    if existing:
        conn.execute(
            """
            UPDATE users
            SET display_name = ?, password_hash = ?, auth_provider = ?, updated_at = ?
            WHERE id = ?
            """,
            (display_name, password_hash, auth_provider, now, existing["id"]),
        )
        return get_user_by_id(conn, existing["id"])
    user_id = normalize_email(email)
    conn.execute(
        """
        INSERT INTO users (id, email, password_hash, display_name, auth_provider, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, normalize_email(email), password_hash, display_name, auth_provider, now, now),
    )
    return get_user_by_id(conn, user_id)


def create_session_for_user(conn: sqlite3.Connection, user_id: str) -> dict[str, Any]:
    token, expires_at = issue_session(conn, user_id)
    return {"token": token, "expires_at": expires_at}


def read_conversation_list(conn: sqlite3.Connection, current_user_id: str, category: str | None, search: str | None) -> list[dict[str, Any]]:
    category_map = {
        "personal": "direct",
        "announcements": "channel",
        "groups": "group",
    }
    kind_filter = category_map.get(category or "")
    conversations = conn.execute(
        """
        SELECT c.*
        FROM conversations c
        JOIN conversation_members cm ON cm.conversation_id = c.id
        WHERE cm.user_id = ?
        ORDER BY c.updated_at DESC
        """,
        (current_user_id,),
    ).fetchall()
    results = []
    lowered_search = search.strip().lower() if search else ""
    for conversation in conversations:
        if kind_filter and conversation["kind"] != kind_filter:
            continue
        summary = conversation_summary(conn, conversation, current_user_id)
        haystack = " ".join(
            str(value)
            for value in [
                summary["title"],
                summary["subtitle"],
                summary["last_message_text"],
                summary["kind"],
                summary["name"],
            ]
        ).lower()
        if lowered_search and lowered_search not in haystack:
            continue
        results.append(summary)
    return results


def ensure_direct_conversation(conn: sqlite3.Connection, current_user_id: str, target_email: str) -> dict[str, Any]:
    target_email = validate_email(target_email)
    target = get_user_by_email(conn, target_email)
    if not target:
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại")
    if target["id"] == current_user_id:
        raise HTTPException(status_code=400, detail="Không thể tạo chat riêng với chính bạn")

    conversation_id = direct_conversation_id(current_user_id, target["id"])
    conversation = get_conversation(conn, conversation_id)
    if not conversation:
        now = now_iso()
        conn.execute(
            """
            INSERT INTO conversations (id, kind, name, created_by, created_at, updated_at)
            VALUES (?, 'direct', ?, ?, ?, ?)
            """,
            (conversation_id, "Direct", current_user_id, now, now),
        )
        for user_id in sorted({current_user_id, target["id"]}):
            conn.execute(
                """
                INSERT INTO conversation_members (conversation_id, user_id, role, joined_at)
                VALUES (?, ?, 'member', ?)
                """,
                (conversation_id, user_id, now),
            )
        conversation = get_conversation(conn, conversation_id)
    return conversation_summary(conn, conversation, current_user_id)


def create_group_or_channel(
    conn: sqlite3.Connection,
    current_user_id: str,
    kind: str,
    name: str,
    member_emails: list[str],
    admin_emails: list[str],
) -> dict[str, Any]:
    kind = kind.strip().lower()
    if kind not in {"channel", "group"}:
        raise HTTPException(status_code=400, detail="kind chỉ nhận channel hoặc group")
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(status_code=400, detail="Tên phòng không được để trống")

    members = validate_member_emails(member_emails)
    admins = validate_member_emails(admin_emails)
    current_user = get_user_by_id(conn, current_user_id)
    if not current_user:
        raise HTTPException(status_code=401, detail="Người dùng không tồn tại")

    if current_user["email"] not in members:
        members.append(current_user["email"])
    if current_user["email"] not in admins:
        admins.append(current_user["email"])
    if not admins:
        admins.append(current_user["email"])

    member_rows = []
    for email in members:
        user = get_user_by_email(conn, email)
        if not user:
            raise HTTPException(status_code=404, detail=f"Không tìm thấy user: {email}")
        member_rows.append(user)

    admin_ids = set()
    for email in admins:
        user = get_user_by_email(conn, email)
        if not user:
            raise HTTPException(status_code=404, detail=f"Không tìm thấy admin: {email}")
        admin_ids.add(user["id"])

    conversation_id = generate_id(f"{kind}-")
    now = now_iso()
    conn.execute(
        """
        INSERT INTO conversations (id, kind, name, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (conversation_id, kind, clean_name, current_user_id, now, now),
    )
    for row in member_rows:
        role = "admin" if row["id"] in admin_ids else "member"
        conn.execute(
            """
            INSERT INTO conversation_members (conversation_id, user_id, role, joined_at)
            VALUES (?, ?, ?, ?)
            """,
            (conversation_id, row["id"], role, now),
        )
    conversation = get_conversation(conn, conversation_id)
    return conversation_summary(conn, conversation, current_user_id)


def get_conversation_detail(conn: sqlite3.Connection, conversation_id: str, current_user_id: str) -> dict[str, Any]:
    conversation = get_conversation(conn, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Không tìm thấy cuộc trò chuyện")
    membership = get_membership(conn, conversation_id, current_user_id)
    if not membership:
        raise HTTPException(status_code=403, detail="Bạn chưa là thành viên của cuộc trò chuyện")
    summary = conversation_summary(conn, conversation, current_user_id)
    summary["messages_count"] = conn.execute(
        "SELECT COUNT(*) AS total FROM messages WHERE conversation_id = ?",
        (conversation_id,),
    ).fetchone()["total"]
    return summary


def get_conversation_messages(conn: sqlite3.Connection, conversation_id: str, current_user_id: str, limit: int = 100) -> list[dict[str, Any]]:
    conversation = get_conversation(conn, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Không tìm thấy cuộc trò chuyện")
    membership = get_membership(conn, conversation_id, current_user_id)
    if not membership:
        raise HTTPException(status_code=403, detail="Bạn chưa là thành viên của cuộc trò chuyện")
    rows = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE conversation_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (conversation_id, limit),
    ).fetchall()
    return [serialize_message(conn, row, current_user_id) for row in reversed(rows)]


def send_message_record(
    conn: sqlite3.Connection,
    conversation_id: str,
    current_user_id: str,
    body: str,
    attachment_ids: list[str] | None = None,
) -> dict[str, Any]:
    conversation = get_conversation(conn, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Không tìm thấy cuộc trò chuyện")
    membership = get_membership(conn, conversation_id, current_user_id)
    if not membership:
        raise HTTPException(status_code=403, detail="Bạn chưa là thành viên của cuộc trò chuyện")
    if conversation["kind"] == "channel" and membership["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only Admin can send messages")

    clean_body = body.strip()
    attachment_ids = [item for item in (attachment_ids or []) if str(item).strip()]
    if not clean_body and not attachment_ids:
        raise HTTPException(status_code=400, detail="Tin nhắn hoặc file đính kèm là bắt buộc")

    now = now_iso()
    message_id = generate_id("msg-")
    conn.execute(
        """
        INSERT INTO messages (id, conversation_id, sender_id, body, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (message_id, conversation_id, current_user_id, clean_body, now),
    )

    for upload_id in dict.fromkeys(attachment_ids):
        upload = conn.execute(
            """
            SELECT *
            FROM uploads
            WHERE id = ? AND owner_id = ? AND used = 0
            """,
            (upload_id, current_user_id),
        ).fetchone()
        if not upload:
            raise HTTPException(status_code=404, detail=f"Attachment không hợp lệ: {upload_id}")
        attachment_id = generate_id("att-")
        conn.execute(
            """
            INSERT INTO attachments (
                id, message_id, upload_id, original_name, stored_name, mime_type, size, url, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attachment_id,
                message_id,
                upload["id"],
                upload["original_name"],
                upload["stored_name"],
                upload["mime_type"],
                upload["size"],
                upload["url"],
                now,
            ),
        )
        conn.execute("UPDATE uploads SET used = 1 WHERE id = ?", (upload["id"],))

    conn.execute(
        "UPDATE conversations SET updated_at = ? WHERE id = ?",
        (now, conversation_id),
    )
    message_row = conn.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()
    return serialize_message(conn, message_row, current_user_id)


def upload_files(conn: sqlite3.Connection, user_id: str, files: list[UploadFile]) -> list[dict[str, Any]]:
    results = []
    for file in files:
        filename = file.filename or "file"
        stored_name = f"{uuid.uuid4().hex}{Path(filename).suffix}"
        stored_path = UPLOAD_DIR / stored_name
        data = file.file.read()
        size = len(data)
        stored_path.write_bytes(data)
        url = f"/uploads/{stored_name}"
        upload_id = generate_id("upl-")
        conn.execute(
            """
            INSERT INTO uploads (
                id, owner_id, original_name, stored_name, mime_type, size, url, used, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                upload_id,
                user_id,
                filename,
                stored_name,
                file.content_type or "application/octet-stream",
                size,
                url,
                now_iso(),
            ),
        )
        results.append(
            {
                "id": upload_id,
                "original_name": filename,
                "stored_name": stored_name,
                "mime_type": file.content_type or "application/octet-stream",
                "size": size,
                "url": url,
                "download_url": url,
            }
        )
    return results


async def broadcast_to_users(user_ids: list[str], payload: dict[str, Any]) -> None:
    async with connection_lock:
        items = [(user_id, online_connections.get(user_id)) for user_id in user_ids]
    tasks = []
    for user_id, websocket in items:
        if websocket:
            tasks.append(_send_safe(user_id, websocket, payload))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _send_safe(user_id: str, websocket: WebSocket, payload: dict[str, Any]) -> None:
    try:
        await websocket.send_json(payload)
    except Exception:
        async with connection_lock:
            if online_connections.get(user_id) == websocket:
                online_connections.pop(user_id, None)


async def notify_conversation_change(conn: sqlite3.Connection, conversation_id: str) -> None:
    conversation = get_conversation(conn, conversation_id)
    if not conversation:
        return
    members = get_conversation_members(conn, conversation_id)
    payload = {
        "type": "conversation_updated",
        "conversation": conversation_summary(conn, conversation, members[0]["id"] if members else ""),
        "at": now_iso(),
    }
    await broadcast_to_users([member["id"] for member in members], payload)


async def notify_message(conn: sqlite3.Connection, conversation_id: str, message: dict[str, Any]) -> None:
    members = get_conversation_members(conn, conversation_id)
    payload = {
        "type": "message_created",
        "conversation_id": conversation_id,
        "message": message,
        "at": now_iso(),
    }
    await broadcast_to_users([member["id"] for member in members], payload)


def get_request_user(request: Request) -> sqlite3.Row:
    return current_user_from_request(request)


class AuthResponse(BaseModel):
    token: str
    expires_at: str
    user: dict[str, Any]


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html_file = BASE_DIR / "client.html"
    if not html_file.exists():
        return HTMLResponse("<h3>client.html không tồn tại.</h3>", status_code=404)
    return HTMLResponse(html_file.read_text(encoding="utf-8"))


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "time": now_iso(), "database": str(DB_PATH)}


@app.post("/api/auth/signup")
async def signup(payload: SignupPayload) -> dict[str, Any]:
    email = validate_email(payload.email)
    display_name = payload.display_name.strip()
    password = payload.password.strip()
    if len(display_name) < 2:
        raise HTTPException(status_code=400, detail="Tên hiển thị quá ngắn")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Mật khẩu phải có ít nhất 8 ký tự")

    with db() as conn:
        if get_user_by_email(conn, email):
            raise HTTPException(status_code=409, detail="Email đã tồn tại")
        user = create_or_update_user(conn, email, display_name, hash_password(password), "password")
        session = create_session_for_user(conn, user["id"])
    return {**session, "user": serialize_user(user)}


@app.post("/api/auth/login")
async def login(payload: LoginPayload) -> dict[str, Any]:
    email = validate_email(payload.email)
    with db() as conn:
        user = get_user_by_email(conn, email)
        if not user or user["auth_provider"] == "google" and not user["password_hash"]:
            raise HTTPException(status_code=401, detail="Sai email hoặc mật khẩu")
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Sai email hoặc mật khẩu")
        session = create_session_for_user(conn, user["id"])
    return {**session, "user": serialize_user(user)}


@app.post("/api/auth/google")
async def google_login(payload: GoogleLoginPayload) -> dict[str, Any]:
    email = validate_email(payload.email)
    display_name = payload.display_name.strip() or email.split("@", 1)[0]
    with db() as conn:
        user = get_user_by_email(conn, email)
        if user:
            now = now_iso()
            conn.execute(
                """
                UPDATE users
                SET display_name = ?, auth_provider = 'google', updated_at = ?
                WHERE id = ?
                """,
                (display_name, now, user["id"]),
            )
            user = get_user_by_id(conn, user["id"])
        else:
            user = create_or_update_user(conn, email, display_name, "", "google")
        session = create_session_for_user(conn, user["id"])
    return {**session, "user": serialize_user(user)}


@app.post("/api/auth/logout")
async def logout(request: Request) -> dict[str, Any]:
    token = extract_token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return {"status": "ok"}


@app.get("/api/auth/me")
async def me(request: Request) -> dict[str, Any]:
    user = get_request_user(request)
    return {"user": serialize_user(user)}


@app.get("/api/users/search")
async def search_users(request: Request, q: str = "") -> dict[str, Any]:
    current_user = get_request_user(request)
    query = q.strip().lower()
    with db() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM users
            WHERE id != ?
            ORDER BY display_name COLLATE NOCASE, email COLLATE NOCASE
            """,
            (current_user["id"],),
        ).fetchall()
    results = []
    for row in rows:
        user = serialize_user(row)
        haystack = f'{user["display_name"]} {user["email"]}'.lower()
        if query and query not in haystack:
            continue
        results.append(user)
    return {"users": results[:20]}


@app.get("/api/conversations")
async def list_conversations(request: Request, category: str | None = None, search: str | None = None) -> dict[str, Any]:
    current_user = get_request_user(request)
    with db() as conn:
        conversations = read_conversation_list(conn, current_user["id"], category, search)
    return {"conversations": conversations}


@app.post("/api/conversations/direct")
async def create_direct_conversation(request: Request, payload: CreateDirectPayload) -> dict[str, Any]:
    current_user = get_request_user(request)
    with db() as conn:
        conversation = ensure_direct_conversation(conn, current_user["id"], payload.target_email)
    await notify_after_conversation(conversation["id"])
    return {"conversation": conversation}


@app.post("/api/conversations")
async def create_conversation(request: Request, payload: CreateConversationPayload) -> dict[str, Any]:
    current_user = get_request_user(request)
    with db() as conn:
        conversation = create_group_or_channel(
            conn,
            current_user["id"],
            payload.kind,
            payload.name,
            payload.member_emails,
            payload.admin_emails,
        )
    await notify_after_conversation(conversation["id"])
    return {"conversation": conversation}


@app.get("/api/conversations/{conversation_id}")
async def get_conversation_detail_endpoint(conversation_id: str, request: Request) -> dict[str, Any]:
    current_user = get_request_user(request)
    with db() as conn:
        conversation = get_conversation_detail(conn, conversation_id, current_user["id"])
    return {"conversation": conversation}


@app.get("/api/conversations/{conversation_id}/messages")
async def get_messages_endpoint(conversation_id: str, request: Request, limit: int = 100) -> dict[str, Any]:
    current_user = get_request_user(request)
    limit = max(1, min(limit, 200))
    with db() as conn:
        messages = get_conversation_messages(conn, conversation_id, current_user["id"], limit=limit)
    return {"messages": messages}


@app.post("/api/conversations/{conversation_id}/messages")
async def send_message_endpoint(conversation_id: str, request: Request, payload: SendMessagePayload) -> dict[str, Any]:
    current_user = get_request_user(request)
    with db() as conn:
        message = send_message_record(conn, conversation_id, current_user["id"], payload.body, payload.attachment_ids)
        conversation = conversation_summary(
            conn,
            get_conversation(conn, conversation_id),
            current_user["id"],
        )
    await notify_after_message(conversation_id, message, conversation)
    await notify_after_conversation(conversation_id)
    return {"message": message, "conversation": conversation}


@app.post("/api/uploads")
async def upload_endpoint(request: Request, files: list[UploadFile] = File(...)) -> dict[str, Any]:
    current_user = get_request_user(request)
    if not files:
        raise HTTPException(status_code=400, detail="Không có file nào được gửi lên")
    with db() as conn:
        uploads = upload_files(conn, current_user["id"], files)
    return {"uploads": uploads}


async def notify_after_message(conversation_id: str, message: dict[str, Any], conversation: dict[str, Any]) -> None:
    with db() as conn:
        members = get_conversation_members(conn, conversation_id)
    await broadcast_to_users([member["id"] for member in members], {
        "type": "message_created",
        "conversation_id": conversation_id,
        "message": message,
        "conversation": conversation,
        "at": now_iso(),
    })


async def notify_after_conversation(conversation_id: str) -> None:
    with db() as conn:
        conversation = get_conversation(conn, conversation_id)
        if not conversation:
            return
        members = get_conversation_members(conn, conversation_id)
    await broadcast_to_users(
        [member["id"] for member in members],
        {
            "type": "conversation_updated",
            "conversation_id": conversation_id,
            "at": now_iso(),
        },
    )


async def notify_presence(user_id: str, status: str) -> None:
    async with connection_lock:
        targets = list(online_connections.keys())
    payload = {"type": "presence", "user_id": user_id, "status": status, "at": now_iso()}
    await broadcast_to_users(targets, payload)


async def ws_send_error(user_id: str, message: str) -> None:
    await broadcast_to_users([user_id], {"type": "error", "message": message, "at": now_iso()})


async def handle_webrtc_signal(current_user_id: str, payload: dict[str, Any]) -> None:
    target_user = normalize_email(payload.get("target_user", ""))
    signal_type = str(payload.get("signal_type", "")).strip()
    signal_payload = payload.get("payload")
    media_kind = str(payload.get("media_kind", "video")).strip().lower() or "video"
    if not target_user or not signal_type:
        raise HTTPException(status_code=400, detail="Thiếu dữ liệu WebRTC")
    await broadcast_to_users(
        [target_user],
        {
            "type": "webrtc_signal",
            "from": current_user_id,
            "signal_type": signal_type,
            "payload": signal_payload,
            "media_kind": media_kind,
            "at": now_iso(),
        },
    )


async def handle_ws_message(current_user_id: str, raw_message: str) -> None:
    try:
        data = json.loads(raw_message)
    except json.JSONDecodeError:
        await ws_send_error(current_user_id, "Payload phải là JSON object")
        return
    if not isinstance(data, dict):
        await ws_send_error(current_user_id, "Payload phải là JSON object")
        return

    action = str(data.get("action", "")).strip().lower()
    if not action:
        await ws_send_error(current_user_id, "Thiếu action")
        return

    try:
        if action in {"send_message", "message_send"}:
            conversation_id = str(data.get("conversation_id", "")).strip()
            body = str(data.get("body", ""))
            attachment_ids = data.get("attachment_ids") or []
            if not isinstance(attachment_ids, list):
                raise HTTPException(status_code=400, detail="attachment_ids phải là danh sách")
            with db() as conn:
                message = send_message_record(conn, conversation_id, current_user_id, body, attachment_ids)
                conversation = conversation_summary(conn, get_conversation(conn, conversation_id), current_user_id)
            await notify_after_message(conversation_id, message, conversation)
        elif action == "create_direct":
            target_email = str(data.get("target_email", "")).strip()
            with db() as conn:
                conversation = ensure_direct_conversation(conn, current_user_id, target_email)
            await notify_after_conversation(conversation["id"])
        elif action == "create_conversation":
            with db() as conn:
                conversation = create_group_or_channel(
                    conn,
                    current_user_id,
                    str(data.get("kind", "")),
                    str(data.get("name", "")),
                    list(data.get("member_emails") or []),
                    list(data.get("admin_emails") or []),
                )
            await notify_after_conversation(conversation["id"])
        elif action == "get_conversations":
            category = str(data.get("category", "")).strip() or None
            search = str(data.get("search", "")).strip() or None
            with db() as conn:
                conversations = read_conversation_list(conn, current_user_id, category, search)
            await broadcast_to_users([current_user_id], {"type": "conversations", "conversations": conversations, "at": now_iso()})
        elif action == "get_messages":
            conversation_id = str(data.get("conversation_id", "")).strip()
            limit = int(data.get("limit", 100))
            with db() as conn:
                messages = get_conversation_messages(conn, conversation_id, current_user_id, limit=max(1, min(limit, 200)))
            await broadcast_to_users([current_user_id], {"type": "messages", "conversation_id": conversation_id, "messages": messages, "at": now_iso()})
        elif action == "webrtc_signal":
            await handle_webrtc_signal(current_user_id, data)
        else:
            await ws_send_error(current_user_id, f"Action không được hỗ trợ: {action}")
    except HTTPException as exc:
        await ws_send_error(current_user_id, exc.detail if isinstance(exc.detail, str) else "Đã xảy ra lỗi")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str | None = None) -> None:
    if not token:
        await websocket.close(code=1008, reason="Thiếu token")
        return

    try:
        user = current_user_from_token(token)
    except HTTPException:
        await websocket.close(code=1008, reason="Token không hợp lệ")
        return

    await websocket.accept()
    async with connection_lock:
        old_connection = online_connections.get(user["id"])
        if old_connection and old_connection != websocket:
            try:
                await old_connection.close(code=4001, reason="Kết nối mới đã thay thế")
            except Exception:
                pass
        online_connections[user["id"]] = websocket

    with db() as conn:
        conversations = read_conversation_list(conn, user["id"], None, None)
    await websocket.send_json(
        {
            "type": "connected",
            "user": serialize_user(user),
            "online_users": list(online_connections.keys()),
            "conversations": conversations,
            "at": now_iso(),
        }
    )
    await notify_presence(user["id"], "online")

    try:
        while True:
            raw_message = await websocket.receive_text()
            await handle_ws_message(user["id"], raw_message)
    except WebSocketDisconnect:
        pass
    finally:
        async with connection_lock:
            if online_connections.get(user["id"]) == websocket:
                online_connections.pop(user["id"], None)
        await notify_presence(user["id"], "offline")


if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
