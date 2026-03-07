#!/usr/bin/env python3
"""
Ursa Major — Database Layer
============================
SQLite-backed storage for sessions, tasks, and results.
"""

import sqlite3
import json
import os
import time
import uuid
from pathlib import Path

from major.config import get_config


DB_PATH = Path(get_config().get("major.db_path"))


def get_db():
    """Get a database connection with WAL mode for concurrent access."""
    db = sqlite3.connect(str(DB_PATH), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db():
    """Create all tables if they don't exist."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            remote_ip TEXT NOT NULL,
            hostname TEXT DEFAULT '',
            username TEXT DEFAULT '',
            os TEXT DEFAULT '',
            arch TEXT DEFAULT '',
            pid INTEGER DEFAULT 0,
            process_name TEXT DEFAULT '',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            beacon_interval INTEGER DEFAULT 5,
            jitter REAL DEFAULT 0.1,
            status TEXT DEFAULT 'active',
            encryption_key TEXT DEFAULT '',
            metadata TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            task_type TEXT NOT NULL,
            args TEXT DEFAULT '{}',
            status TEXT DEFAULT 'pending',
            created_at REAL NOT NULL,
            picked_up_at REAL,
            completed_at REAL,
            result TEXT DEFAULT '',
            error TEXT DEFAULT '',
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            direction TEXT NOT NULL,
            size INTEGER DEFAULT 0,
            data BLOB,
            created_at REAL NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS listeners (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            bind_host TEXT DEFAULT '0.0.0.0',
            bind_port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'http',
            status TEXT DEFAULT 'stopped',
            created_at REAL NOT NULL,
            config TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            level TEXT DEFAULT 'info',
            source TEXT DEFAULT '',
            message TEXT NOT NULL,
            session_id TEXT,
            details TEXT DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
        CREATE INDEX IF NOT EXISTS idx_events_session ON event_log(session_id);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON event_log(timestamp);
    """)
    db.commit()
    db.close()


# ── Session Operations ──


def create_session(remote_ip, hostname="", username="", os_info="",
                   arch="", pid=0, process_name="", encryption_key="",
                   beacon_interval=5, jitter=0.1):
    """Register a new implant session."""
    db = get_db()
    session_id = str(uuid.uuid4())[:8]
    now = time.time()
    db.execute("""
        INSERT INTO sessions (id, remote_ip, hostname, username, os, arch,
                             pid, process_name, first_seen, last_seen,
                             beacon_interval, jitter, encryption_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, remote_ip, hostname, username, os_info, arch,
          pid, process_name, now, now, beacon_interval, jitter, encryption_key))
    db.commit()
    db.close()
    log_event("info", "session", f"New session {session_id} from {remote_ip} ({username}@{hostname})",
              session_id=session_id)
    return session_id


def update_session_checkin(session_id, remote_ip=None):
    """Update last_seen timestamp for a session heartbeat."""
    db = get_db()
    if remote_ip:
        db.execute("UPDATE sessions SET last_seen=?, remote_ip=? WHERE id=?",
                   (time.time(), remote_ip, session_id))
    else:
        db.execute("UPDATE sessions SET last_seen=? WHERE id=?",
                   (time.time(), session_id))
    db.commit()
    db.close()


def get_session(session_id):
    """Get a single session by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_sessions(status=None):
    """List all sessions, optionally filtered by status."""
    db = get_db()
    if status:
        rows = db.execute("SELECT * FROM sessions WHERE status=? ORDER BY last_seen DESC",
                         (status,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM sessions ORDER BY last_seen DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


def kill_session(session_id):
    """Mark a session as dead."""
    db = get_db()
    db.execute("UPDATE sessions SET status='dead' WHERE id=?", (session_id,))
    db.commit()
    db.close()
    log_event("info", "session", f"Session {session_id} marked as dead",
              session_id=session_id)


def update_session_info(session_id, **kwargs):
    """Update session metadata fields."""
    db = get_db()
    allowed = {"hostname", "username", "os", "arch", "pid", "process_name",
               "beacon_interval", "jitter", "status", "metadata"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [session_id]
        db.execute(f"UPDATE sessions SET {set_clause} WHERE id=?", values)
        db.commit()
    db.close()


# ── Task Operations ──


def create_task(session_id, task_type, args=None):
    """Queue a new task for a session."""
    db = get_db()
    task_id = str(uuid.uuid4())[:8]
    db.execute("""
        INSERT INTO tasks (id, session_id, task_type, args, status, created_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
    """, (task_id, session_id, task_type, json.dumps(args or {}), time.time()))
    db.commit()
    db.close()
    log_event("info", "task", f"Task {task_id} ({task_type}) queued for session {session_id}",
              session_id=session_id)
    return task_id


def get_pending_tasks(session_id):
    """Get all pending tasks for a session and mark them as picked up."""
    db = get_db()
    rows = db.execute("""
        SELECT * FROM tasks WHERE session_id=? AND status='pending'
        ORDER BY created_at ASC
    """, (session_id,)).fetchall()

    task_ids = [r["id"] for r in rows]
    if task_ids:
        placeholders = ",".join("?" * len(task_ids))
        db.execute(f"""
            UPDATE tasks SET status='in_progress', picked_up_at=?
            WHERE id IN ({placeholders})
        """, [time.time()] + task_ids)
        db.commit()

    db.close()
    return [dict(r) for r in rows]


def complete_task(task_id, result="", error=""):
    """Mark a task as completed with results."""
    db = get_db()
    status = "error" if error else "completed"
    db.execute("""
        UPDATE tasks SET status=?, completed_at=?, result=?, error=?
        WHERE id=?
    """, (status, time.time(), result, error, task_id))
    db.commit()
    db.close()


def get_task(task_id):
    """Get a single task by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_tasks(session_id=None, status=None, limit=50):
    """List tasks, optionally filtered by session and/or status."""
    db = get_db()
    query = "SELECT * FROM tasks WHERE 1=1"
    params = []
    if session_id:
        query += " AND session_id=?"
        params.append(session_id)
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ── File Operations ──


def store_file(session_id, filename, data, direction="download"):
    """Store a file transferred to/from an implant."""
    db = get_db()
    file_id = str(uuid.uuid4())[:8]
    db.execute("""
        INSERT INTO files (id, session_id, filename, direction, size, data, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (file_id, session_id, filename, direction, len(data), data, time.time()))
    db.commit()
    db.close()
    log_event("info", "file", f"File {filename} ({len(data)}B) {direction} via session {session_id}",
              session_id=session_id)
    return file_id


def get_file(file_id):
    """Retrieve a stored file."""
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_files(session_id=None):
    """List stored files."""
    db = get_db()
    if session_id:
        rows = db.execute("SELECT id, session_id, filename, direction, size, created_at FROM files WHERE session_id=? ORDER BY created_at DESC",
                         (session_id,)).fetchall()
    else:
        rows = db.execute("SELECT id, session_id, filename, direction, size, created_at FROM files ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


# ── Listener Operations ──


def create_listener(name, bind_port, bind_host="0.0.0.0", protocol="http", config=None):
    """Register a new listener."""
    db = get_db()
    listener_id = str(uuid.uuid4())[:8]
    db.execute("""
        INSERT INTO listeners (id, name, bind_host, bind_port, protocol, status, created_at, config)
        VALUES (?, ?, ?, ?, ?, 'stopped', ?, ?)
    """, (listener_id, name, bind_host, bind_port, protocol, time.time(),
          json.dumps(config or {})))
    db.commit()
    db.close()
    return listener_id


def update_listener_status(listener_id, status):
    """Update listener status."""
    db = get_db()
    db.execute("UPDATE listeners SET status=? WHERE id=?", (status, listener_id))
    db.commit()
    db.close()


def list_listeners():
    """List all listeners."""
    db = get_db()
    rows = db.execute("SELECT * FROM listeners ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


def get_listener(listener_id=None, name=None):
    """Get a listener by ID or name."""
    db = get_db()
    if listener_id:
        row = db.execute("SELECT * FROM listeners WHERE id=?", (listener_id,)).fetchone()
    elif name:
        row = db.execute("SELECT * FROM listeners WHERE name=?", (name,)).fetchone()
    else:
        row = None
    db.close()
    return dict(row) if row else None


# ── Event Log ──


def log_event(level, source, message, session_id=None, details=None):
    """Log an event to the event log."""
    db = get_db()
    db.execute("""
        INSERT INTO event_log (timestamp, level, source, message, session_id, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (time.time(), level, source, message, session_id, json.dumps(details or {})))
    db.commit()
    db.close()


def get_events(limit=100, level=None, session_id=None):
    """Retrieve recent events."""
    db = get_db()
    query = "SELECT * FROM event_log WHERE 1=1"
    params = []
    if level:
        query += " AND level=?"
        params.append(level)
    if session_id:
        query += " AND session_id=?"
        params.append(session_id)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


# Initialize DB on import
init_db()
