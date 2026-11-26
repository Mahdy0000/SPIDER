"""Intentionally insecure sample for testing the reviewer. Never deploy."""
import hashlib
import sqlite3
import subprocess

API_KEY = "sk-live-1234567890abcdef"


def get_user(db, name):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
