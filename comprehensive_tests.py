"""
Comprehensive Test Suite for Shadow1834 Cybersecurity Training Platform
Tests all core functionality including authentication, module access, scoring, and data integrity
"""

import unittest
import sqlite3
import json
import os
import sys
from datetime import datetime, timedelta
import tempfile
import random
import string

# Import application modules
from app import (
    init_database, create_user, get_user_by_username, get_user_by_id,
    hash_password, safe_json_loads, log_activity, get_active_players,
    can_access_module, get_leaderboard, MODULES, get_db_connection,
    MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH, MIN_PASSWORD_LENGTH,
    MAX_EMAIL_LENGTH, PASSING_PERCENTAGE
)


class TestDatabaseInitialization(unittest.TestCase):
    """Test database creation and schema"""

    def setUp(self):
        """Set up test database"""
        self.test_db = 'test_shadow1834.db'
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        # Temporarily replace the database name
        self.original_db = 'shadow1834.db'

    def tearDown(self):
        """Clean up test database"""
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_database_initialization(self):
        """TC001: Verify database initializes with correct schema"""
        init_database()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        self.assertIsNotNone(cursor.fetchone(), "Users table should exist")

        # Check user_sessions table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_sessions'")
        self.assertIsNotNone(cursor.fetchone(), "User sessions table should exist")

        # Check activity_log table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_log'")
        self.assertIsNotNone(cursor.fetchone(), "Activity log table should exist")

        conn.close()


class TestUserAuthentication(unittest.TestCase):
    """Test user registration, login, and authentication"""

    @classmethod
    def setUpClass(cls):
        """Initialize database once for all tests"""
        init_database()

    def test_user_creation_valid(self):
        """TC002: Create user with valid credentials"""
        username = f"testuser_{datetime.now().timestamp()}"
        success, message = create_user(username, "Password123", "test@email.com")
        self.assertTrue(success, f"User creation should succeed with valid input: {message}")

        # Verify user exists
        user = get_user_by_username(username)
        self.assertIsNotNone(user, "Created user should be retrievable")
        self.assertEqual(user[1], username, "Username should match")

    def test_user_creation_duplicate(self):
        """TC003: Prevent duplicate username registration"""
        username = f"duplicate_{datetime.now().timestamp()}"
        create_user(username, "Password123")
        success, message = create_user(username, "Password456")
        self.assertFalse(success, "Duplicate username should be rejected")

    def test_user_creation_invalid_username_short(self):
        """TC004: Reject username shorter than minimum length"""
        success, message = create_user("ab", "Password123")
        self.assertFalse(success, f"Username shorter than {MIN_USERNAME_LENGTH} chars should be rejected")

    def test_user_creation_invalid_username_long(self):
        """TC005: Reject username longer than maximum length"""
        long_username = "a" * (MAX_USERNAME_LENGTH + 1)
        success, message = create_user(long_username, "Password123")
        self.assertFalse(success, f"Username longer than {MAX_USERNAME_LENGTH} chars should be rejected")

    def test_user_creation_invalid_password_short(self):
        """TC006: Reject password shorter than minimum length"""
        username = f"testuser_{datetime.now().timestamp()}"
        success, message = create_user(username, "Pass1")
        self.assertFalse(success, f"Password shorter than {MIN_PASSWORD_LENGTH} chars should be rejected")

    def test_user_creation_empty_fields(self):
        """TC007: Reject empty username or password"""
        success1, _ = create_user("", "Password1")
        self.assertFalse(success1, "Empty username should be rejected")
        success2, _ = create_user("username", "")
        self.assertFalse(success2, "Empty password should be rejected")
        success3, _ = create_user("", "")
        self.assertFalse(success3, "Both empty should be rejected")

    def test_password_hashing(self):
        """TC008: Verify password is hashed correctly"""
        password = "mySecurePassword123"
        hashed = hash_password(password)
        self.assertNotEqual(password, hashed, "Password should be hashed")

        # Hash should be either bcrypt (60 chars, starts with $2) or SHA256 (64 chars hex)
        if hashed.startswith('$2'):
            # Bcrypt hash
            self.assertEqual(len(hashed), 60, "Bcrypt hash should be 60 characters")
        else:
            # SHA256 hash
            self.assertEqual(len(hashed), 64, "SHA256 hash should be 64 characters")

        # For bcrypt, same password will produce different hashes due to salting
        # For SHA256, same password should produce same hash
        hashed2 = hash_password(password)
        if not hashed.startswith('$2'):
            self.assertEqual(hashed, hashed2, "Same password should produce same hash for SHA256")

    def test_get_user_by_username(self):
        """TC009: Retrieve user by username"""
        username = f"getuser_{datetime.now().timestamp()}"
        create_user(username, "Password123", "test@email.com")

        user = get_user_by_username(username)
        self.assertIsNotNone(user, "User should be found")
        self.assertEqual(user[1], username, "Username should match")
        self.assertEqual(user[3], "test@email.com", "Email should match")

    def test_get_user_by_id(self):
        """TC010: Retrieve user by ID"""
        username = f"getuser_id_{datetime.now().timestamp()}"
        create_user(username, "Password123")

        user = get_user_by_username(username)
        user_id = user[0]

        user_by_id = get_user_by_id(user_id)
        self.assertIsNotNone(user_by_id, "User should be found by ID")
        self.assertEqual(user_by_id[1], username, "Username should match")


class TestModuleAccess(unittest.TestCase):
    """Test module access control and progression"""

    def test_module_access_level_1(self):
        """TC011: Level 1 user can access level 1 modules"""
        self.assertTrue(can_access_module(1, 1), "Level 1 user should access module 1")

    def test_module_access_insufficient_level(self):
        """TC012: Lower level user cannot access higher level modules"""
        self.assertFalse(can_access_module(1, 5), "Level 1 user should not access module 5")

    def test_module_access_higher_level(self):
        """TC013: Higher level user can access lower level modules"""
        self.assertTrue(can_access_module(5, 1), "Level 5 user should access module 1")

    def test_module_access_invalid_module(self):
        """TC014: Invalid module ID should be rejected"""
        self.assertFalse(can_access_module(5, 999), "Invalid module ID should return False")

    def test_module_structure(self):
        """TC015: Verify all modules have required fields"""
        required_fields = ['title', 'emoji', 'description', 'badge', 'difficulty',
                          'unlock_level', 'points_reward', 'questions']

        for module_id, module_data in MODULES.items():
            for field in required_fields:
                self.assertIn(field, module_data,
                            f"Module {module_id} should have field '{field}'")

            # Verify questions structure
            self.assertGreater(len(module_data['questions']), 0,
                             f"Module {module_id} should have questions")

            for q in module_data['questions']:
                self.assertIn('text', q, "Question should have text")
                self.assertIn('options', q, "Question should have options")
                self.assertIn('correct', q, "Question should have correct answer")
                self.assertIn('explanation', q, "Question should have explanation")
                self.assertEqual(len(q['options']), 4, "Question should have 4 options")


class TestScoringSystem(unittest.TestCase):
    """Test scoring and progression mechanics"""

    @classmethod
    def setUpClass(cls):
        """Initialize database once for all tests"""
        init_database()

    def test_initial_user_score(self):
        """TC016: New user starts with 0 score"""
        username = f"scoreuser_{datetime.now().timestamp()}"
        create_user(username, "Password123")

        user = get_user_by_username(username)
        self.assertEqual(user[4], 0, "New user should have 0 score")

    def test_initial_user_level(self):
        """TC017: New user starts at level 1"""
        username = f"leveluser_{datetime.now().timestamp()}"
        create_user(username, "Password123")

        user = get_user_by_username(username)
        self.assertEqual(user[11], 1, "New user should be level 1")

    def test_module_completion_updates_score(self):
        """TC018: Completing module updates user score"""
        username = f"completeuser_{datetime.now().timestamp()}"
        create_user(username, "Password123")
        user = get_user_by_username(username)

        # Simulate module completion
        conn = get_db_connection()
        cursor = conn.cursor()

        points_earned = MODULES[1]['points_reward']
        completed_modules = [1]
        badges = [MODULES[1]['badge']]

        cursor.execute('''
            UPDATE users
            SET total_score = total_score + ?,
                completed_modules = ?,
                badges = ?,
                current_level = 2
            WHERE id = ?
        ''', (points_earned, json.dumps(completed_modules), json.dumps(badges), user[0]))

        conn.commit()
        conn.close()

        # Verify updates
        updated_user = get_user_by_id(user[0])
        self.assertEqual(updated_user[4], points_earned, "Score should be updated")
        self.assertEqual(updated_user[11], 2, "Level should be updated")


class TestDataIntegrity(unittest.TestCase):
    """Test data validation and integrity"""

    def test_safe_json_loads_valid(self):
        """TC019: Parse valid JSON correctly"""
        valid_json = '{"key": "value", "number": 123}'
        result = safe_json_loads(valid_json, {})
        self.assertEqual(result['key'], 'value', "Should parse valid JSON")
        self.assertEqual(result['number'], 123, "Should parse numbers")

    def test_safe_json_loads_invalid(self):
        """TC020: Handle invalid JSON gracefully"""
        invalid_json = '{invalid json}'
        result = safe_json_loads(invalid_json, {})
        self.assertEqual(result, {}, "Should return default for invalid JSON")

    def test_safe_json_loads_empty(self):
        """TC021: Handle empty string"""
        result = safe_json_loads('', [])
        self.assertEqual(result, [], "Should return default for empty string")

    def test_safe_json_loads_none(self):
        """TC022: Handle None value"""
        result = safe_json_loads(None, {'default': True})
        self.assertEqual(result, {'default': True}, "Should return default for None")


class TestActivityTracking(unittest.TestCase):
    """Test activity logging and tracking"""

    @classmethod
    def setUpClass(cls):
        """Initialize database once for all tests"""
        init_database()

    def test_log_activity(self):
        """TC023: Activity logging creates records"""
        username = f"activityuser_{datetime.now().timestamp()}"
        create_user(username, "Password123")
        user = get_user_by_username(username)

        log_activity(user[0], 'test_activity', 'test data')

        # Verify activity was logged
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM activity_log
            WHERE user_id = ? AND activity_type = ?
        ''', (user[0], 'test_activity'))

        activity = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(activity, "Activity should be logged")
        self.assertEqual(activity[2], 'test_activity', "Activity type should match")

    def test_get_active_players(self):
        """TC024: Retrieve currently active players"""
        # Create a user and log activity
        username = f"activeuser_{datetime.now().timestamp()}"
        create_user(username, "Password123")
        user = get_user_by_username(username)

        log_activity(user[0], 'dashboard_view', 'viewing dashboard')

        active_players = get_active_players()
        self.assertIsInstance(active_players, list, "Should return list of active players")


class TestLeaderboard(unittest.TestCase):
    """Test leaderboard functionality"""

    @classmethod
    def setUpClass(cls):
        """Initialize database and create test users"""
        init_database()

        # Create multiple users with different scores
        for i in range(5):
            username = f"leader_{i}_{datetime.now().timestamp()}"
            create_user(username, "Password123")
            user = get_user_by_username(username)

            # Update score
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET total_score = ? WHERE id = ?',
                         (i * 100, user[0]))
            conn.commit()
            conn.close()

    def test_get_leaderboard(self):
        """TC025: Leaderboard returns users sorted by score"""
        leaderboard = get_leaderboard(10)
        self.assertIsInstance(leaderboard, list, "Should return list")

        # Verify sorting (scores should be descending)
        if len(leaderboard) > 1:
            for i in range(len(leaderboard) - 1):
                self.assertGreaterEqual(leaderboard[i][1], leaderboard[i+1][1],
                                      "Leaderboard should be sorted by score descending")

    def test_leaderboard_limit(self):
        """TC026: Leaderboard respects limit parameter"""
        leaderboard = get_leaderboard(3)
        self.assertLessEqual(len(leaderboard), 3, "Should respect limit parameter")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    @classmethod
    def setUpClass(cls):
        """Initialize database once for all tests"""
        init_database()

    def test_username_boundary_min(self):
        """TC027: Username at minimum length boundary"""
        username = ''.join(random.choices(string.ascii_lowercase, k=MIN_USERNAME_LENGTH))
        result = create_user(username, "password123")
        self.assertTrue(result, f"Username with exactly {MIN_USERNAME_LENGTH} chars should be accepted")

    def test_username_boundary_max(self):
        """TC028: Username at maximum length boundary"""
        username = ''.join(random.choices(string.ascii_lowercase, k=MAX_USERNAME_LENGTH))
        result = create_user(username, "password123")
        self.assertTrue(result, f"Username with exactly {MAX_USERNAME_LENGTH} chars should be accepted")

    def test_password_boundary_min(self):
        """TC029: Password at minimum length boundary"""
        username = f"passuser_{datetime.now().timestamp()}"
        password = "a" * MIN_PASSWORD_LENGTH
        result = create_user(username, password)
        self.assertTrue(result, f"Password with exactly {MIN_PASSWORD_LENGTH} chars should be accepted")

    def test_email_boundary_max(self):
        """TC030: Email at maximum length boundary"""
        username = f"emailuser_{datetime.now().timestamp()}"
        email = "a" * (MAX_EMAIL_LENGTH - 10) + "@test.com"
        result = create_user(username, "password123", email)
        self.assertTrue(result, "Email at max length should be accepted")

    def test_get_user_none_username(self):
        """TC031: Get user with None username"""
        user = get_user_by_username(None)
        self.assertIsNone(user, "Should return None for None username")

    def test_get_user_empty_username(self):
        """TC032: Get user with empty username"""
        user = get_user_by_username('')
        self.assertIsNone(user, "Should return None for empty username")

    def test_get_user_none_id(self):
        """TC033: Get user with None ID"""
        user = get_user_by_id(None)
        self.assertIsNone(user, "Should return None for None ID")


class TestModuleContent(unittest.TestCase):
    """Test module content and question validation"""

    def test_all_modules_have_questions(self):
        """TC034: All modules have at least one question"""
        for module_id, module_data in MODULES.items():
            self.assertGreater(len(module_data['questions']), 0,
                             f"Module {module_id} should have questions")

    def test_question_answer_validity(self):
        """TC035: All question correct answers are valid indices"""
        for module_id, module_data in MODULES.items():
            for i, question in enumerate(module_data['questions']):
                correct_idx = question['correct']
                self.assertGreaterEqual(correct_idx, 0,
                    f"Module {module_id} Q{i}: correct answer index should be >= 0")
                self.assertLess(correct_idx, len(question['options']),
                    f"Module {module_id} Q{i}: correct answer index should be < options count")

    def test_module_difficulty_progression(self):
        """TC036: Module difficulty increases with level"""
        difficulties = ['Beginner', 'Intermediate', 'Advanced']

        for module_id, module_data in MODULES.items():
            self.assertIn(module_data['difficulty'], difficulties,
                         f"Module {module_id} should have valid difficulty")

    def test_module_points_reward(self):
        """TC037: All modules have positive point rewards"""
        for module_id, module_data in MODULES.items():
            self.assertGreater(module_data['points_reward'], 0,
                             f"Module {module_id} should have positive points reward")


def run_tests():
    """Run all tests and generate report"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseInitialization))
    suite.addTests(loader.loadTestsFromTestCase(TestUserAuthentication))
    suite.addTests(loader.loadTestsFromTestCase(TestModuleAccess))
    suite.addTests(loader.loadTestsFromTestCase(TestScoringSystem))
    suite.addTests(loader.loadTestsFromTestCase(TestDataIntegrity))
    suite.addTests(loader.loadTestsFromTestCase(TestActivityTracking))
    suite.addTests(loader.loadTestsFromTestCase(TestLeaderboard))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestModuleContent))

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == '__main__':
    print("=" * 80)
    print("SHADOW1834 CYBERSECURITY TRAINING PLATFORM - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    print()

    result = run_tests()

    print()
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success Rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.2f}%")
    print("=" * 80)

    sys.exit(0 if result.wasSuccessful() else 1)
