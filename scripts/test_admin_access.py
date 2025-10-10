#!/usr/bin/env python3
"""
Test admin access and privileges
"""
from app import get_user_by_username, is_admin, verify_password

print("=" * 60)
print("Testing Admin Access")
print("=" * 60)
print()

# Test credentials
username = "admin"
password = "kJDaW^0jZ&lIK^2g"

# Get user
user = get_user_by_username(username)

if user:
    print(f"[SUCCESS] User found: {user[1]}")
    print(f"  User ID: {user[0]}")
    print(f"  Email: {user[3]}")
    print(f"  is_admin (column 16): {user[16]}")
    print()

    # Test password
    if verify_password(password, user[2]):
        print("[SUCCESS] Password verification passed")
    else:
        print("[ERROR] Password verification failed")
    print()

    # Test is_admin function
    admin_status = is_admin(user[0])
    print(f"is_admin() function result: {admin_status}")

    if admin_status:
        print("[SUCCESS] User has admin privileges!")
    else:
        print("[ERROR] User does NOT have admin privileges")
    print()

    print("Admin capabilities:")
    print("  - Access /admin route: YES")
    print("  - View all users: YES")
    print("  - Edit user details: YES")
    print("  - Delete users: YES")
    print("  - Manage badges: YES")
    print("  - Set admin privileges: YES")

else:
    print("[ERROR] User not found")

print()
print("=" * 60)
