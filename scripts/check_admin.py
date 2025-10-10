#!/usr/bin/env python3
"""
Check admin status in database
"""
import sqlite3

conn = sqlite3.connect('shadow1834.db')
cursor = conn.cursor()

print("=" * 60)
print("Checking admin user status...")
print("=" * 60)
print()

# Check if is_admin column exists
cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()
print("Users table columns:")
for col in columns:
    print(f"  {col[1]} ({col[2]})")
print()

# Check admin user
cursor.execute("SELECT id, username, email, is_admin FROM users WHERE username = 'admin'")
result = cursor.fetchone()

if result:
    print(f"Admin user found:")
    print(f"  ID: {result[0]}")
    print(f"  Username: {result[1]}")
    print(f"  Email: {result[2]}")
    print(f"  is_admin: {result[3]}")
    print()

    if result[3] == 1:
        print("[SUCCESS] Admin has admin privileges")
    else:
        print("[WARNING] Admin does NOT have admin privileges")
else:
    print("[ERROR] Admin user not found")

print()
print("=" * 60)

conn.close()
