import sqlite3
import hashlib
import json
import logging
from datetime import datetime, timedelta

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
MIN_PASSWORD_LENGTH = 6
MAX_EMAIL_LENGTH = 100
PASSING_PERCENTAGE = 60
ACTIVE_MINUTES_THRESHOLD = 5
DEFAULT_LEADERBOARD_LIMIT = 10
DEFAULT_USER_LEVEL = 1

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
                'explanation': 'Never click suspicious links! Always contact your bank directly using official contact information.'
            },
            {
                'text': 'Which of these is the BIGGEST red flag in a phishing email?',
                'options': [
                    'The email has a professional logo',
                    'The email creates urgency (act now or lose access!)',
                    'The email is long and detailed',
                    'The email mentions your first name'
                ],
                'correct': 1,
                'explanation': 'Phishing emails often create false urgency to pressure victims into acting quickly without thinking.'
            },
            {
                'text': 'You get a text message: "URGENT: Your account will be closed! Click here: bit.ly/bank123". This is likely:',
                'options': [
                    'A legitimate security warning',
                    'A phishing attempt',
                    'A system error message',
                    'A promotional offer'
                ],
                'correct': 1,
                'explanation': 'Legitimate banks don\'t send urgent texts with shortened URLs. This is a classic phishing attempt.'
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
                'explanation': 'This email has multiple red flags: generic greeting, fake domain, and false urgency - all typical phishing tactics.'
            },
            {
                'text': 'The best way to verify if an email is legitimate is to:',
                'options': [
                    'Check if it has spelling mistakes',
                    'Look at the sender\'s email address carefully',
                    'Contact the company directly through official channels',
                    'Ask friends if they received similar emails'
                ],
                'correct': 2,
                'explanation': 'Always verify suspicious communications by contacting the company directly through their official website or phone number.'
            }
        ]
    },
    2: {
        'title': 'Hunt the Trojan',
        'emoji': '🦠',
        'description': 'Detect and eliminate malware threats before they compromise systems',
        'badge': '🦠 Malware Hunter',
        'difficulty': 'Beginner',
        'unlock_level': 2,
        'points_reward': 120,
        'questions': [
            {
                'text': 'You downloaded a file called "free_game.exe" from a suspicious website. What should you do?',
                'options': [
                    'Run it immediately to start playing',
                    'Scan it with antivirus before opening',
                    'Delete it without running it',
                    'Run it in a virtual machine first'
                ],
                'correct': 2,
                'explanation': 'Files from suspicious sources should be deleted immediately. Even scanning may not catch all threats.'
            },
            {
                'text': 'Which file extension is most likely to contain malware?',
                'options': [
                    'document.pdf',4
                    'photo.jpg',
                    'invoice.pdf.exe',
                    'music.mp3'
                ],
                'correct': 2,
                'explanation': 'Double extensions like ".pdf.exe" are a common malware trick to disguise executable files as documents.'
            },
            {
                'text': 'Your computer suddenly starts running very slowly and showing pop-up ads. This could indicate:',
                'options': [
                    'Normal system updates',
                    'Malware infection',
                    'Low disk space',
                    'Network connectivity issues'
                ],
                'correct': 1,
                'explanation': 'Sudden slowness and unexpected pop-ups are classic signs of malware infection.'
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
                'explanation': 'Always download software from official vendor websites to avoid malware-infected copies.'
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
                'explanation': 'Unknown USB drives may contain malware. Never plug them into your computer - turn them in to security.'
            }
        ]
    },
    3: {
        'title': 'Password Bootcamp',
        'emoji': '🔐',
        'description': 'Master the creation and management of ultra-secure passwords',
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
                'explanation': 'Long passwords with mixed characters are strongest. The dog example uses length, symbols, and personal meaning you can remember.'
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
                'explanation': 'Security experts now recommend changing passwords only when compromised, focusing instead on strong, unique passwords.'
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
                'explanation': 'Password managers generate and store unique, strong passwords for all your accounts safely.'
            }
        ]
    },
    4: {
        'title': 'Firewall Frenzy',
        'emoji': '🛡️',
        'description': 'Deploy advanced network security and firewall configurations',
        'badge': '🛡️ Firewall Guardian',
        'difficulty': 'Intermediate',
        'unlock_level': 4,
        'points_reward': 180,
        'questions': [
            {
                'text': 'Someone is repeatedly trying to access your company\'s SSH port (22) from China. You should:',
                'options': [
                    'Allow it - they might be legitimate',
                    'Block the IP addresses',
                    'Monitor and log the attempts',
                    'Change the SSH port number'
                ],
                'correct': 1,
                'explanation': 'Repeated unauthorized SSH attempts from foreign IPs are likely brute force attacks and should be blocked.'
            },
            {
                'text': 'Your firewall detects traffic on port 80 (HTTP) during business hours. This is:',
                'options': [
                    'Definitely malicious',
                    'Normal web browsing traffic',
                    'A system error',
                    'Requires immediate shutdown'
                ],
                'correct': 1,
                'explanation': 'Port 80 is standard HTTP web traffic, which is normal during business hours.'
            },
            {
                'text': 'A new employee can\'t access the company database. The most likely cause is:',
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
    conn = sqlite3.connect('shadow1834.db')
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
                                                            avatar_emoji TEXT DEFAULT '🎮'
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
    return hashlib.sha256(password.encode()).hexdigest()


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


def log_activity(user_id, activity_type, activity_data=""):
    """Log user activity for tracking active players"""
    conn = sqlite3.connect('shadow1834.db')
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
    conn = sqlite3.connect('shadow1834.db')
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
        conn = sqlite3.connect('shadow1834.db')
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
        conn = sqlite3.connect('shadow1834.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None


def create_user(username, password, email=''):
    """Create a new user with enhanced validation and error handling"""
    try:
        # Input validation
        if not username or not password:
            return False
        if len(username) < 3 or len(username) > 50:
            return False
        if len(password) < 6:
            return False
        if len(email) > 100:
            return False

        conn = sqlite3.connect('shadow1834.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                           INSERT INTO users (username, password_hash, email, join_date, total_score,
                                              completed_modules, badges, module_progress, current_level, last_activity)
                           VALUES (?, ?, ?, ?, 0, '[]', '[]', '{}', 1, ?)
                           ''', (username, hash_password(password), email, datetime.now().isoformat(),
                                 datetime.now().isoformat()))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False


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
    conn = sqlite3.connect('shadow1834.db')
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


# Import routes
import routes

if __name__ == '__main__':
    init_database()
    # Flask app is now created in routes.py
    routes.app.run(debug=True, host='0.0.0.0', port=5000)
