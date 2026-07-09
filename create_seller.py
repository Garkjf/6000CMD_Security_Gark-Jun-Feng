import sqlite3
from werkzeug.security import generate_password_hash
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")

username = "seller"
email = "seller@example.com"
password = "Seller123!"

password_hash = generate_password_hash(password)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
    INSERT INTO users (username, email, password_hash, role)
    VALUES (?, ?, ?, 'seller')
""", (username, email, password_hash))

conn.commit()
conn.close()

print("Seller created successfully!")
print("Username:", username)
print("Password:", password)
