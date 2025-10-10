import sqlite3
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    logging.warning("bcrypt not available, falling back to SHA-256 (install with: pip install bcrypt)")
 
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('shadow1834.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
 
# Constants
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50
MIN_PASSWORD_LENGTH = 8
MAX_EMAIL_LENGTH = 100
PASSING_PERCENTAGE = 60
ACTIVE_MINUTES_THRESHOLD = 5
DEFAULT_LEADERBOARD_LIMIT = 10
DEFAULT_USER_LEVEL = 1
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT_MINUTES = 15
SESSION_TIMEOUT_MINUTES = 30
DATABASE_TIMEOUT = 30.0  # Database connection timeout in seconds
 
 
# Database connection helper function
def get_db_connection():
    """Create a database connection with proper timeout and WAL mode"""
    conn = sqlite3.connect('shadow1834.db', timeout=DATABASE_TIMEOUT)
    conn.execute('PRAGMA journal_mode=WAL')  # Write-Ahead Logging for better concurrency
    return conn
 
# Training modules data with progressive structure
MODULES = {
    1: {
        'title': 'Hook the Phish',
        'emoji': '🎣',
        'description': ('Master the art of identifying phishing attempts and '
                        'social engineering tactics'),
        'badge': '🎣 Phish Fighter',
        'difficulty': 'Beginner',
        'unlock_level': 1,
        'points_reward': 100,
        'questions': [
            {
                'text': ('You receive an email from "your bank" asking you to '
                         'click a link to verify your account. The email '
                         'address is "security@banksafety.net". What should '
                         'you do?'),
                'options': [
                    'Click the link immediately to secure my account',
                    'Call the bank directly using the number on my card',
                    'Forward the email to friends as a warning',
                    'Reply to the email asking for more information'
                ],
                'correct': 1,
                'explanation': (
                    'Never click suspicious links! Always contact your bank '
                    'directly using official contact information.'
                )
            },
            {
                'text': (
                    'Which of these is the BIGGEST red flag in a '
                    'phishing email?'
                ),
                'options': [
                    'The email has a professional logo',
                    'The email creates urgency (act now or lose access!)',
                    'The email is long and detailed',
                    'The email mentions your first name'
                ],
                'correct': 1,
                'explanation': (
                    'Phishing emails often create false urgency to pressure '
                    'victims into acting quickly without thinking.'
                )
            },
            {
                'text': (
                    'You get a text message: "URGENT: Your account will be '
                    'closed! Click here: bit.ly/bank123". This is likely:'
                ),
                'options': [
                    'A legitimate security warning',
                    'A phishing attempt',
                    'A system error message',
                    'A promotional offer'
                ],
                'correct': 1,
                'explanation': (
                    'Legitimate banks don\'t send urgent texts with '
                    'shortened URLs. This is a classic phishing attempt.'
                )
            },
            {
                'text': ('What makes this email suspicious? "Hello Dear Customer, '
                         'Your PayPal account has unusual activity. Please login '
                         'here to review: paypal-security.com"'),
                'options': [
                    'The generic greeting "Dear Customer"',
                    'The suspicious domain "paypal-security.com"',
                    'Creating urgency about "unusual activity"',
                    'All of the above'
                ],
                'correct': 3,
                'explanation': (
                    'This email has multiple red flags: generic greeting, '
                    'fake domain, and false urgency - all typical phishing '
                    'tactics.'
                )
            },
            {
                'text': (
                    'The best way to verify if an email is legitimate '
                    'is to:'
                ),
                'options': [
                    'Check if it has spelling mistakes',
                    'Look at the sender\'s email address carefully',
                    'Contact the company directly through official channels',
                    'Ask friends if they received similar emails'
                ],
                'correct': 2,
                'explanation': (
                    'Always verify suspicious communications by contacting '
                    'the company directly through their official website or '
                    'phone number.'
                )
            }
        ]
    },
    2: {
        'title': 'Hunt the Trojan',
        'emoji': '🦠',
        'description': (
            'Detect and eliminate malware threats before they '
            'compromise systems'
        ),
        'badge': '🦠 Malware Hunter',
        'difficulty': 'Beginner',
        'unlock_level': 2,
        'points_reward': 120,
        'questions': [
            {
                'text': (
                    'You downloaded a file called "free_game.exe" from a '
                    'suspicious website. What should you do?'
                ),
                'options': [
                    'Run it immediately to start playing',
                    'Scan it with antivirus before opening',
                    'Delete it without running it',
                    'Run it in a virtual machine first'
                ],
                'correct': 2,
                'explanation': (
                    'Files from suspicious sources should be deleted '
                    'immediately. Even scanning may not catch all threats.'
                )
            },
            {
                'text': (
                    'Which file extension is most likely to contain '
                    'malware?'
                ),
                'options': [
                    'document.pdf',
                    'photo.jpg',
                    'invoice.pdf.exe',
                    'music.mp3'
                ],
                'correct': 2,
                'explanation': (
                    'Double extensions like ".pdf.exe" are a common malware '
                    'trick to disguise executable files as documents.'
                )
            },
            {
                'text': (
                    'Your computer suddenly starts running very slowly and '
                    'showing pop-up ads. This could indicate:'
                ),
                'options': [
                    'Normal system updates',
                    'Malware infection',
                    'Low disk space',
                    'Network connectivity issues'
                ],
                'correct': 1,
                'explanation': (
                    'Sudden slowness and unexpected pop-ups are classic '
                    'signs of malware infection.'
                )
            },
            {
                'text': 'The safest way to download software is from:',
                'options': [
                    'Torrent sites',
                    'Random download sites',
                    'Official vendor websites',
                    'Email attachments'
                ],
                'correct': 2,
                'explanation': (
                    'Always download software from official vendor websites '
                    'to avoid malware-infected copies.'
                )
            },
            {
                'text': 'A USB drive found in the parking lot should be:',
                'options': [
                    'Plugged in to see who owns it',
                    'Used for extra storage',
                    'Turned in to security without plugging it in',
                    'Formatted before use'
                ],
                'correct': 2,
                'explanation': (
                    'Unknown USB drives may contain malware. Never plug them '
                    'into your computer - turn them in to security.'
                )
            }
        ]
    },
    3: {
        'title': 'Password Bootcamp',
        'emoji': '🔐',
        'description': (
            'Master the creation and management of ultra-secure '
            'passwords'
        ),
        'badge': '🔐 Password Master',
        'difficulty': 'Intermediate',
        'unlock_level': 3,
        'points_reward': 150,
        'questions': [
            {
                'text': 'Which password is the strongest?',
                'options': [
                    'password123',
                    'P@ssw0rd!',
                    'MyDog\'sName1sF1d0&H3Born2015',
                    '123456789'
                ],
                'correct': 2,
                'explanation': (
                    'Long passwords with mixed characters are strongest. The '
                    'dog example uses length, symbols, and personal meaning '
                    'you can remember.'
                )
            },
            {
                'text': 'How often should you change your passwords?',
                'options': [
                    'Every 30 days',
                    'Never, unless there\'s a breach',
                    'Every year',
                    'When you remember to'
                ],
                'correct': 1,
                'explanation': (
                    'Security experts now recommend changing passwords only '
                    'when compromised, focusing instead on strong, unique '
                    'passwords.'
                )
            },
            {
                'text': 'The best way to manage multiple passwords is:',
                'options': [
                    'Use the same password everywhere',
                    'Write them down on paper',
                    'Use a reputable password manager',
                    'Use simple patterns like "site1", "site2"'
                ],
                'correct': 2,
                'explanation': (
                    'Password managers generate and store unique, strong '
                    'passwords for all your accounts safely.'
                )
            }
        ]
    },
    4: {
        'title': 'Firewall Frenzy',
        'emoji': '🛡️',
        'description': (
            'Deploy advanced network security and firewall '
            'configurations'
        ),
        'badge': '🛡️ Firewall Guardian',
        'difficulty': 'Intermediate',
        'unlock_level': 4,
        'points_reward': 180,
        'questions': [
            {
                'text': (
                    'Someone is repeatedly trying to access your company\'s '
                    'SSH port (22) from China. You should:'
                ),
                'options': [
                    'Allow it - they might be legitimate',
                    'Block the IP addresses',
                    'Monitor and log the attempts',
                    'Change the SSH port number'
                ],
                'correct': 1,
                'explanation': (
                    'Repeated unauthorized SSH attempts from foreign IPs are '
                    'likely brute force attacks and should be blocked.'
                )
            },
            {
                'text': (
                    'Your firewall detects traffic on port 80 (HTTP) during '
                    'business hours. This is:'
                ),
                'options': [
                    'Definitely malicious',
                    'Normal web browsing traffic',
                    'A system error',
                    'Requires immediate shutdown'
                ],
                'correct': 1,
                'explanation': (
                    'Port 80 is standard HTTP web traffic, which is normal '
                    'during business hours.'
                )
            },
            {
                'text': (
                    'A new employee can\'t access the company database. The '
                    'most likely cause is:'
                ),
                'options': [
                    'Their computer is infected',
                    'The database is down',
                    'Firewall rules need updating for their access',
                    'They need antivirus software'
                ],
                'correct': 2,
                'explanation': 'New employees typically need firewall rules configured to grant access to internal resources.'
            }
        ]
    },
    5: {
        'title': 'Defend the Net',
        'emoji': '🌐',
        'description': 'Ultimate cybersecurity challenge - prove your mastery',
        'badge': '🌐 Cyber Defender',
        'difficulty': 'Advanced',
        'unlock_level': 5,
        'points_reward': 250,
        'questions': [
            {
                'text': ('CRITICAL ALERT: Multiple threats detected simultaneously! '
                         'A phishing email arrived with a suspicious attachment, '
                         'port scans are hitting your firewall, and users report '
                         'slow computers. Your FIRST priority should be:'),
                'options': [
                    'Investigate the phishing email',
                    'Block the port scanning IPs',
                    'Isolate affected computers from the network',
                    'Update all antivirus software'
                ],
                'correct': 2,
                'explanation': 'In multi-threat scenarios, containment is critical. Isolating infected systems prevents lateral movement.'
            },
            {
                'text': 'You discover that attackers have accessed your network and are moving between systems. This is called:',
                'options': [
                    'Phishing',
                    'Lateral movement',
                    'Social engineering',
                    'Denial of service'
                ],
                'correct': 1,
                'explanation': 'Lateral movement is when attackers spread through a network after initial compromise.'
            }
        ]
    }
}
 
# Database initialization with enhanced schema
 
 
def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()
 
    try:
        # Users table with enhanced fields
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS users (
                                                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                            username TEXT UNIQUE NOT NULL,
                                                            password_hash TEXT NOT NULL,
                                                            email TEXT DEFAULT '',
                                                            total_score INTEGER DEFAULT 0,
                                                            completed_modules TEXT DEFAULT '[]',
                                                            badges TEXT DEFAULT '[]',
                                                            join_date TEXT NOT NULL,
                                                            last_login TEXT,
                                                            last_activity TEXT,
                                                            module_progress TEXT DEFAULT '{}',
                                                            current_level INTEGER DEFAULT 1,
                                                            profile_description TEXT DEFAULT '',
                                                            avatar_emoji TEXT DEFAULT '🎮',
                                                            login_attempts INTEGER DEFAULT 0,
                                                            locked_until TEXT,
                                                            is_admin INTEGER DEFAULT 0
                       )
                       ''')
 
        # Sessions table for tracking module attempts
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS user_sessions (
                                                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                    user_id INTEGER,
                                                                    module_id INTEGER,
                                                                    score INTEGER,
                                                                    completed_at TEXT,
                                                                    time_taken INTEGER DEFAULT 0,
                                                                    FOREIGN KEY (user_id) REFERENCES users (id)
                           )
                       ''')
 
        # Activity log for tracking active players
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS activity_log (
                                                                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                   user_id INTEGER,
                                                                   activity_type TEXT,
                                                                   activity_data TEXT,
                                                                   timestamp TEXT,
                                                                   FOREIGN KEY (user_id) REFERENCES users (id)
                           )
                       ''')
 
        conn.commit()
        logger.info("Database initialized successfully")
 
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
    finally:
        conn.close()
 
 
# Database helper functions
def hash_password(password):
    """Hash password using bcrypt if available, otherwise fall back to SHA-256"""
    if BCRYPT_AVAILABLE:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        return hashlib.sha256(password.encode()).hexdigest()
 
 
def verify_password(password, password_hash):
    """Verify password against hash, supporting both bcrypt and SHA-256"""
    if BCRYPT_AVAILABLE and password_hash.startswith('$2'):
        # Bcrypt hash detected
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    else:
        # SHA-256 hash (legacy or fallback)
        return hashlib.sha256(password.encode()).hexdigest() == password_hash
 
 
def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
 
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
 
    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase, and numbers"
 
    return True, "Password is strong"
 
 
def validate_email(email):
    """Validate email format"""
    if not email:
        return True  # Email is optional
 
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False
 
    return len(email) <= MAX_EMAIL_LENGTH
 
 
def safe_json_loads(json_str, default=None):
    """Safely load JSON with fallback to default value"""
    if default is None:
        default = {}
    try:
        if json_str:
            return json.loads(json_str)
        return default
    except (json.JSONDecodeError, TypeError, ValueError):
        return default
 
 
def check_account_locked(username):
    """Check if account is locked due to too many failed login attempts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT login_attempts, locked_until FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
 
        if not result:
            return False, None
 
        login_attempts, locked_until = result
 
        # Check if account is currently locked
        if locked_until:
            locked_time = datetime.fromisoformat(locked_until)
            if datetime.now() < locked_time:
                minutes_remaining = int((locked_time - datetime.now()).total_seconds() / 60)
                return True, minutes_remaining
            else:
                # Lock expired, reset attempts
                cursor.execute('UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = ?', (username,))
                conn.commit()
                return False, None
 
        return False, None
    except Exception as e:
        logger.error(f"Error checking account lock: {e}")
        return False, None
    finally:
        conn.close()
 
 
def record_failed_login(username):
    """Record a failed login attempt and lock account if threshold exceeded"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT login_attempts FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
 
        if not result:
            return
 
        attempts = result[0] + 1
 
        if attempts >= MAX_LOGIN_ATTEMPTS:
            # Lock the account
            locked_until = (datetime.now() + timedelta(minutes=LOGIN_TIMEOUT_MINUTES)).isoformat()
            cursor.execute('UPDATE users SET login_attempts = ?, locked_until = ? WHERE username = ?',
                         (attempts, locked_until, username))
            logger.warning(f"Account locked for user: {username}")
        else:
            cursor.execute('UPDATE users SET login_attempts = ? WHERE username = ?', (attempts, username))
 
        conn.commit()
    except Exception as e:
        logger.error(f"Error recording failed login: {e}")
    finally:
        conn.close()
 
 
def reset_login_attempts(username):
    """Reset login attempts after successful login"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = ?', (username,))
        conn.commit()
    except Exception as e:
        logger.error(f"Error resetting login attempts: {e}")
    finally:
        conn.close()
 
 
def log_activity(user_id, activity_type, activity_data=""):
    """Log user activity for tracking active players"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
                       INSERT INTO activity_log (user_id, activity_type, activity_data, timestamp)
                       VALUES (?, ?, ?, ?)
                       ''', (user_id, activity_type, activity_data, datetime.now().isoformat()))
 
        # Update user last activity
        cursor.execute('UPDATE users SET last_activity = ? WHERE id = ?',
                       (datetime.now().isoformat(), user_id))
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Activity log error: {e}")
    finally:
        conn.close()
 
 
def get_active_players():
    """Get players active in the last 5 minutes"""
    conn = get_db_connection()
    cursor = conn.cursor()
 
    five_minutes_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
    cursor.execute('''
                   SELECT u.username, u.avatar_emoji, u.total_score, u.last_activity
                   FROM users u
                   WHERE u.last_activity >= ?
                   ORDER BY u.last_activity DESC
                   ''', (five_minutes_ago,))
 
    active_players = cursor.fetchall()
    conn.close()
    return active_players
 
 
def get_user_by_username(username):
    """Get user by username with error handling"""
    try:
        if not username:
            return None
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error getting user by username: {e}")
        return None
 
 
def get_user_by_id(user_id):
    """Get user by ID with error handling"""
    try:
        if not user_id:
            return None
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None
 
 
def create_user(username, password, email='', is_admin=False):
    """Create a new user with enhanced validation and error handling"""
    try:
        # Input validation
        if not username or not password:
            return False, "Username and password are required"
        if len(username) < MIN_USERNAME_LENGTH or len(username) > MAX_USERNAME_LENGTH:
            return False, f"Username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters"
 
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            return False, message
 
        # Validate email if provided
        if email and not validate_email(email):
            return False, "Invalid email format"
 
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                           INSERT INTO users (username, password_hash, email, join_date, total_score,
                                              completed_modules, badges, module_progress, current_level, last_activity,
                                              login_attempts, locked_until, is_admin)
                           VALUES (?, ?, ?, ?, 0, '[]', '[]', '{}', 1, ?, 0, NULL, ?)
                           ''', (username, hash_password(password), email, datetime.now().isoformat(),
                                 datetime.now().isoformat(), 1 if is_admin else 0))
            conn.commit()
            return True, "User created successfully"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False, "An error occurred during registration"
 
 
def can_access_module(user_level, module_id):
    """Check if user can access a specific module based on their current level"""
    if module_id not in MODULES:
        return False
    required_level = MODULES[module_id]['unlock_level']
    # Ensure both values are integers for comparison
    try:
        user_level = int(user_level)
        required_level = int(required_level)
        return user_level >= required_level
    except (ValueError, TypeError):
        return False
 
 
def get_leaderboard(limit=10):
    """Get top players ordered by score and level"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username, total_score, completed_modules, badges, avatar_emoji, current_level
        FROM users
        ORDER BY total_score DESC, current_level DESC
        LIMIT ?
    ''', (limit,))
    users = cursor.fetchall()
    conn.close()
    return users
 
 
def is_admin(user_id):
    """Check if user has admin privileges"""
    try:
        user = get_user_by_id(user_id)
        if not user:
            return False
        return bool(user[16])  # is_admin is at index 16
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        return False
 
 
def get_all_users():
    """Get all users for admin management"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, email, total_score, current_level, join_date,
                   last_login, completed_modules, badges, is_admin
            FROM users
            ORDER BY id DESC
        ''')
        users = cursor.fetchall()
        conn.close()
        return users
    except Exception as e:
        logger.error(f"Error getting all users: {e}")
        return []
 
 
def update_user_admin(user_id, username=None, email=None, total_score=None,
                     current_level=None, badges=None, is_admin=None):
    """Update user details (admin function)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
 
        updates = []
        params = []
 
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if email is not None:
            updates.append("email = ?")
            params.append(email)
        if total_score is not None:
            updates.append("total_score = ?")
            params.append(total_score)
        if current_level is not None:
            updates.append("current_level = ?")
            params.append(current_level)
        if badges is not None:
            updates.append("badges = ?")
            params.append(json.dumps(badges))
        if is_admin is not None:
            updates.append("is_admin = ?")
            params.append(1 if is_admin else 0)
 
        if not updates:
            return False, "No updates provided"
 
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
 
        cursor.execute(query, params)
        conn.commit()
        conn.close()
 
        logger.info(f"User {user_id} updated by admin")
        return True, "User updated successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return False, f"Error updating user: {str(e)}"
 
 
def delete_user_admin(user_id):
    """Delete user (admin function)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
 
        # Delete user sessions first
        cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM activity_log WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
 
        conn.commit()
        conn.close()
 
        logger.info(f"User {user_id} deleted by admin")
        return True, "User deleted successfully"
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return False, f"Error deleting user: {str(e)}"
 
 
def run_core_tests():
    print("Running minimal app.py test case...")
    success, msg = create_user("testuser", "TestPass123!", "test@example.com")
    print(f"User creation: {success}, {msg}")
    success, msg = create_user("testuser", "TestPass123!", "test@example.com")
    print(f"Duplicate user creation: {success}, {msg}")
    valid, msg = validate_password_strength("weak")
    print(f"Password strength: {valid}, {msg}")
    user = get_user_by_username("testuser")
    print(f"Get user by username: {'Found' if user else 'Not found'}")
    leaderboard = get_leaderboard(3)
    print(f"Leaderboard sample: {leaderboard}")
    print("Minimal test case complete.")

if __name__ == '__main__':
    init_database()
    import routes
    routes.app.run(debug=True, host='0.0.0.0', port=5000)