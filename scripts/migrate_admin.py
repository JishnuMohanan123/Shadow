#!/usr/bin/env python3
"""
Database migration script to add is_admin column
"""
import sqlite3

def migrate_database():
    print("Migrating database to add admin support...")

    conn = sqlite3.connect('shadow1834.db')
    cursor = conn.cursor()

    try:
        # Check if column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]

        if 'is_admin' not in columns:
            # Add is_admin column
            cursor.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
            conn.commit()
            print("Successfully added is_admin column to users table")
        else:
            print("is_admin column already exists")

        conn.close()
        return True
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.close()
        return False

if __name__ == '__main__':
    migrate_database()
