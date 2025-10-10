#!/usr/bin/env python3
"""
Script to set admin privileges for existing user and display credentials
"""
import sqlite3
import secrets
import string
from app import hash_password

def generate_secure_password(length=16):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    # Ensure it has required components
    while not (any(c.isupper() for c in password) and
               any(c.islower() for c in password) and
               any(c.isdigit() for c in password)):
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def main():
    print("=" * 60)
    print("SHADOW1834 - Set Admin Privileges")
    print("=" * 60)
    print()

    conn = sqlite3.connect('shadow1834.db')
    cursor = conn.cursor()

    admin_username = "admin"
    new_password = generate_secure_password(16)

    try:
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (admin_username,))
        result = cursor.fetchone()

        if result:
            # Update existing user
            password_hash = hash_password(new_password)
            cursor.execute("""
                UPDATE users
                SET is_admin = 1, password_hash = ?
                WHERE username = ?
            """, (password_hash, admin_username))
            conn.commit()
            print("[SUCCESS] Admin privileges set successfully!")
        else:
            print(f"[ERROR] User '{admin_username}' not found")
            conn.close()
            return

        print()
        print("=" * 60)
        print("ADMIN CREDENTIALS - SAVE THESE SECURELY!")
        print("=" * 60)
        print(f"Username: {admin_username}")
        print(f"Password: {new_password}")
        print("=" * 60)
        print()
        print("WARNING: Copy these credentials now!")
        print("   The password has been reset.")
        print()
        print("You can now login at http://localhost:5000")
        print("Navigate to /admin to access the admin panel")
        print()

    except Exception as e:
        print(f"[ERROR] {e}")

    finally:
        conn.close()

    print("=" * 60)

if __name__ == '__main__':
    main()
