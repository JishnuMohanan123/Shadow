"""
SHADOW - Matrix-Themed Cyber Awareness Quiz Game
Flask Backend Application
"""

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'shadow_matrix_secret_key_change_in_production'

# Database configuration
DATABASE = 'shadow.db'

def get_db_connection():
    """Create and return a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initialize the database with schema and sample data"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create questions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_text TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT NOT NULL,
            option_d TEXT NOT NULL,
            correct_option TEXT NOT NULL,
            difficulty TEXT DEFAULT 'medium',
            category TEXT DEFAULT 'general'
        )
    ''')

    # Create scores table to track player results
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            player_name TEXT,
            score INTEGER,
            total_questions INTEGER,
            timestamp TEXT
        )
    ''')

    # Check if questions already exist
    cursor.execute('SELECT COUNT(*) FROM questions')
    count = cursor.fetchone()[0]

    # Insert sample cybersecurity questions if database is empty
    if count == 0:
        sample_questions = [
            (
                "You receive an email from 'security@paypa1.com' asking you to verify your account. What should you do?",
                "Click the link immediately to secure my account",
                "Reply with my password to verify identity",
                "Delete the email - it's a phishing attempt",
                "Forward it to all my contacts as a warning",
                "C",
                "easy",
                "phishing"
            ),
            (
                "What makes a password strong and secure?",
                "Using your birthday and name",
                "Minimum 12 characters with uppercase, lowercase, numbers, and symbols",
                "Using the word 'password' with numbers",
                "Same password for all accounts for easy memory",
                "B",
                "easy",
                "passwords"
            ),
            (
                "You find a USB drive in the parking lot. What should you do?",
                "Plug it into my work computer to find the owner",
                "Take it home and use it for personal files",
                "Report it to security - never plug unknown devices",
                "Share it with coworkers to find the owner",
                "C",
                "medium",
                "malware"
            ),
            (
                "What is two-factor authentication (2FA)?",
                "Using two different passwords",
                "Logging in twice to be extra safe",
                "Security method requiring password + second verification (code/fingerprint)",
                "Having two accounts on the same platform",
                "C",
                "medium",
                "authentication"
            ),
            (
                "Your colleague sends you a suspicious file attachment. What's the FIRST thing you should do?",
                "Download and scan it with antivirus",
                "Contact the colleague directly (not via email) to verify they sent it",
                "Open it on a different computer to be safe",
                "Forward it to IT without opening",
                "B",
                "hard",
                "malware"
            ),
            (
                "What is 'social engineering' in cybersecurity?",
                "Designing social media platforms",
                "Manipulating people to reveal confidential information",
                "Engineering software for social networks",
                "Creating secure social connections",
                "B",
                "medium",
                "social_engineering"
            ),
            (
                "You're working remotely at a coffee shop. How should you connect to the internet?",
                "Use the free public WiFi without protection",
                "Use a VPN (Virtual Private Network) on public WiFi",
                "Share sensitive documents over public WiFi",
                "Disable firewall for faster connection",
                "B",
                "medium",
                "network_security"
            ),
            (
                "What is ransomware?",
                "Software that helps you organize files",
                "Malware that encrypts your files and demands payment",
                "A type of antivirus program",
                "Free software downloaded from the internet",
                "B",
                "easy",
                "malware"
            ),
            (
                "Which of these is a sign of a phishing email?",
                "Email from a known contact with expected content",
                "Urgent message with spelling errors asking for personal info",
                "Company newsletter with unsubscribe link",
                "Automated receipt from a recent purchase",
                "B",
                "easy",
                "phishing"
            ),
            (
                "What should you do before downloading software from the internet?",
                "Download from the first search result",
                "Verify it's from the official source and check reviews",
                "Install everything that pops up",
                "Disable antivirus to speed up download",
                "B",
                "medium",
                "safe_browsing"
            )
        ]

        cursor.executemany('''
            INSERT INTO questions
            (question_text, option_a, option_b, option_c, option_d, correct_option, difficulty, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_questions)

        conn.commit()
        print("[SYSTEM] Database initialized with sample questions")

    conn.close()

@app.route('/')
def index():
    """Welcome screen - Matrix terminal entry point"""
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_game():
    """Initialize game session and redirect to quiz"""
    # Reset session data
    session['current_question'] = 0
    session['score'] = 0
    session['answers'] = []
    session['player_name'] = request.form.get('player_name', 'Agent')

    return redirect(url_for('quiz'))

@app.route('/quiz')
def quiz():
    """Main quiz interface"""
    if 'current_question' not in session:
        return redirect(url_for('index'))

    return render_template('quiz.html')

@app.route('/api/question')
def get_question():
    """API endpoint to fetch current question"""
    if 'current_question' not in session:
        return jsonify({'error': 'No active session'}), 400

    current_idx = session.get('current_question', 0)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get total question count
    cursor.execute('SELECT COUNT(*) FROM questions')
    total = cursor.fetchone()[0]

    # Check if quiz is complete
    if current_idx >= total:
        conn.close()
        return jsonify({'complete': True, 'score': session.get('score', 0), 'total': total})

    # Fetch current question
    cursor.execute('SELECT * FROM questions LIMIT 1 OFFSET ?', (current_idx,))
    question = cursor.fetchone()
    conn.close()

    if question:
        return jsonify({
            'id': question['id'],
            'question': question['question_text'],
            'options': {
                'A': question['option_a'],
                'B': question['option_b'],
                'C': question['option_c'],
                'D': question['option_d']
            },
            'current': current_idx + 1,
            'total': total,
            'category': question['category'],
            'difficulty': question['difficulty']
        })

    return jsonify({'error': 'Question not found'}), 404

@app.route('/api/answer', methods=['POST'])
def submit_answer():
    """Handle answer submission and return result"""
    data = request.get_json()
    user_answer = data.get('answer', '').upper()

    current_idx = session.get('current_question', 0)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT correct_option FROM questions LIMIT 1 OFFSET ?', (current_idx,))
    question = cursor.fetchone()
    conn.close()

    if not question:
        return jsonify({'error': 'Question not found'}), 404

    correct_option = question['correct_option']
    is_correct = (user_answer == correct_option)

    # Update score
    if is_correct:
        session['score'] = session.get('score', 0) + 1

    # Store answer
    if 'answers' not in session:
        session['answers'] = []
    session['answers'].append({
        'question': current_idx + 1,
        'user_answer': user_answer,
        'correct_answer': correct_option,
        'is_correct': is_correct
    })

    # Move to next question
    session['current_question'] = current_idx + 1

    return jsonify({
        'correct': is_correct,
        'correct_option': correct_option,
        'score': session.get('score', 0)
    })

@app.route('/result')
def result():
    """Display final results and player rank"""
    if 'score' not in session:
        return redirect(url_for('index'))

    score = session.get('score', 0)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM questions')
    total = cursor.fetchone()[0]

    # Save score to database
    cursor.execute('''
        INSERT INTO scores (player_name, score, total_questions, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (
        session.get('player_name', 'Anonymous'),
        score,
        total,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))
    conn.commit()
    conn.close()

    # Calculate percentage
    percentage = (score / total * 100) if total > 0 else 0

    # Determine rank
    if percentage >= 90:
        rank = "Cyber Master"
        rank_icon = "👑"
    elif percentage >= 75:
        rank = "Level 5 Guardian"
        rank_icon = "🛡️"
    elif percentage >= 60:
        rank = "Level 3 Operative"
        rank_icon = "⚔️"
    elif percentage >= 40:
        rank = "Level 2 Agent"
        rank_icon = "🎯"
    else:
        rank = "Level 1 Recruit"
        rank_icon = "🔰"

    return render_template('result.html',
                         score=score,
                         total=total,
                         percentage=int(percentage),
                         rank=rank,
                         rank_icon=rank_icon,
                         answers=session.get('answers', []))

@app.route('/reset')
def reset():
    """Clear session and return to home"""
    session.clear()
    return redirect(url_for('index'))

# Initialize database on first run
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        print("[SYSTEM] Initializing SHADOW database...")
        init_db()
        print("[SYSTEM] Database ready")
    else:
        # Ensure database has proper schema
        init_db()

    print("[SYSTEM] Starting SHADOW Matrix Cyber Quiz...")
    print("[ACCESS] Server running on http://127.0.0.1:5000")
    print("[MATRIX] The system is ready...")

    app.run(debug=True, host='127.0.0.1', port=5000)
