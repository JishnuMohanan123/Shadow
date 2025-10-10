#!/usr/bin/env python3
"""
Script to create an admin user for Shadow1834 platform
"""
import secrets
import string
from app import init_database, create_user

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
    print("SHADOW1834 - Admin User Creation")
    print("=" * 60)
    print()

    # Initialize database
    init_database()

    # Admin credentials
    admin_username = "admin"
    admin_password = generate_secure_password(16)
    admin_email = "admin@shadow1834.local"

    # Create admin user
    success, message = create_user(admin_username, admin_password, admin_email, is_admin=True)

    if success:
        print("[SUCCESS] Admin user created successfully!")
        print()
        print("=" * 60)
        print("ADMIN CREDENTIALS - SAVE THESE SECURELY!")
        print("=" * 60)
        print(f"Username: {admin_username}")
        print(f"Password: {admin_password}")
        print(f"Email:    {admin_email}")
        print("=" * 60)
        print()
        print("WARNING: Copy these credentials now!")
        print("   The password will not be shown again.")
        print()
        print("You can now login at http://localhost:5000")
        print("Navigate to /admin to access the admin panel")
        print()
    else:
        print(f"[ERROR] Error creating admin user: {message}")
        print()
        if "already exists" in message.lower():
            print("The admin user already exists.")
            print("If you need to reset the password, delete the user from")
            print("the database first or use a different username.")

    print("=" * 60)

if __name__ == '__main__':
    main()
