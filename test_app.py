import pytest
from app import init_database, create_user, get_user_by_username

def test_user_creation():
    init_database()
    result = create_user("testuser", "testpass", "test@email.com")
    assert result == True

def test_user_login():
    user = get_user_by_username("testuser")
    assert user is not None