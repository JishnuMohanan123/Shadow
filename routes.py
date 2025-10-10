from flask import request, session, redirect, url_for, flash, render_template
from datetime import datetime
import sqlite3
import json

# Import functions from app.py (avoiding circular import)
from app import (
    MODULES, verify_password, safe_json_loads, log_activity,
    get_active_players, get_user_by_username, get_user_by_id,
    create_user, can_access_module, get_leaderboard,
    MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH, MIN_PASSWORD_LENGTH, MAX_EMAIL_LENGTH, PASSING_PERCENTAGE,
    check_account_locked, record_failed_login, reset_login_attempts, SESSION_TIMEOUT_MINUTES,
    is_admin, get_all_users, update_user_admin, delete_user_admin
)

# Create Flask app instance
from flask import Flask
import os
from datetime import timedelta
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            email = request.form.get('email', '').strip()

            # Create user with enhanced validation
            success, message = create_user(username, password, email)

            if success:
                flash('Agent recruitment successful! Access granted to training platform.', 'success')
                return redirect(url_for('index'))
            else:
                flash(f'Registration failed: {message}', 'error')
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
            print(f"Registration error: {e}")

    return render_template('register.html')


@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password', 'error')
            return redirect(url_for('index'))

        # Additional validation
        if len(username) > MAX_USERNAME_LENGTH or len(password) > MAX_EMAIL_LENGTH:
            flash('Invalid credentials format', 'error')
            return redirect(url_for('index'))

        # Check if account is locked
        is_locked, minutes_remaining = check_account_locked(username)
        if is_locked:
            flash(f'Account locked due to too many failed attempts. Try again in {minutes_remaining} minutes.', 'error')
            return redirect(url_for('index'))

        user = get_user_by_username(username)

        if user and verify_password(password, user[2]):
            # Reset login attempts on successful login
            reset_login_attempts(username)

            session['user_id'] = user[0]
            session['username'] = user[1]
            session.permanent = True  # Enable session timeout

            # Update last login and log activity
            try:
                conn = sqlite3.connect('shadow1834.db')
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET last_login = ?, last_activity = ? WHERE id = ?',
                               (datetime.now().isoformat(), datetime.now().isoformat(), user[0]))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(f"Database error during login: {e}")
                # Continue with login even if database update fails

            log_activity(user[0], 'login', 'User logged in')
            return redirect(url_for('dashboard'))
        else:
            # Record failed login attempt
            if user:
                record_failed_login(username)
            flash('Invalid agent credentials. Access denied.', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        flash('An error occurred during login. Please try again.', 'error')
        print(f"Login error: {e}")
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'logout', 'User logged out')
    session.clear()
    flash('Agent logged out successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('logout'))

    # Log dashboard activity
    log_activity(session['user_id'], 'dashboard_view', 'User viewed dashboard')

    # Parse user data safely
    completed_modules = safe_json_loads(user[5], [])
    badges = safe_json_loads(user[6], [])
    module_progress = safe_json_loads(user[9], {})

    # Get active players
    active_players = get_active_players()

    return render_template('dashboard.html',
                           user=user,
                           completed_modules=completed_modules,
                           badges=badges,
                           module_progress=module_progress,
                           active_players=active_players,
                           MODULES=MODULES,
                           can_access_module=can_access_module)


@app.route('/module/<int:module_id>')
def module(module_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('logout'))

    if module_id not in MODULES:
        flash('Training module not found.', 'error')
        return redirect(url_for('dashboard'))

    # Check if user can access this module
    if not can_access_module(user[11], module_id):
        flash(f'Access denied. Reach Level {MODULES[module_id]["unlock_level"]} to unlock this mission.', 'warning')
        return redirect(url_for('dashboard'))

    # Check if already completed
    completed_modules = safe_json_loads(user[5], [])
    if module_id in completed_modules:
        flash('Mission already completed! Choose another challenge.', 'success')
        return redirect(url_for('dashboard'))

    # Log module access
    log_activity(session['user_id'], 'module_start', f'Started module {module_id}')

    module_data = MODULES[module_id]

    return render_template('module.html',
                           user=user,
                           module_id=module_id,
                           module_data=module_data,
                           enumerate=enumerate)


@app.route('/submit/<int:module_id>', methods=['POST'])
def submit_module(module_id):
    try:
        if 'user_id' not in session:
            return redirect(url_for('index'))

        user = get_user_by_id(session['user_id'])
        if not user:
            return redirect(url_for('logout'))

        if module_id not in MODULES:
            flash('Training module not found.', 'error')
            return redirect(url_for('dashboard'))

        # Check if user can access this module
        if not can_access_module(user[11], module_id):
            flash('Access denied.', 'warning')
            return redirect(url_for('dashboard'))

        # Check if already completed
        completed_modules = safe_json_loads(user[5], [])
        if module_id in completed_modules:
            flash('Mission already completed!', 'warning')
            return redirect(url_for('dashboard'))

        module_data = MODULES[module_id]
        questions = module_data['questions']

        # Calculate score with error handling
        correct_answers = 0
        total_questions = len(questions)
        results = []

        for i, question in enumerate(questions):
            try:
                user_answer = int(request.form.get(f'q{i}', -1))
                is_correct = user_answer == question['correct']

                if is_correct:
                    correct_answers += 1

                results.append({
                    'question': question['text'],
                    'user_answer': user_answer,
                    'correct_answer': question['correct'],
                    'is_correct': is_correct,
                    'explanation': question['explanation'],
                    'options': question['options']
                })
            except (ValueError, KeyError) as e:
                print(f"Error processing question {i}: {e}")
                results.append({
                    'question': question['text'],
                    'user_answer': -1,
                    'correct_answer': question['correct'],
                    'is_correct': False,
                    'explanation': question['explanation'],
                    'options': question['options']
                })

        # Calculate percentage and determine if passed
        percentage = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
        passed = percentage >= PASSING_PERCENTAGE  # Need 60% to pass
        points_earned = module_data['points_reward'] if passed else 0

        # Calculate streak (consecutive correct answers from the beginning)
        streak = 0
        for result in results:
            if result['is_correct']:
                streak += 1
            else:
                break

        # Initialize achievement variables for both pass and fail cases
        achievements_earned = []
        bonus_points = 0

        # Calculate achievement bonuses only if passed
        if passed:
            if percentage == 100:
                achievements_earned.append('🏆 Perfect Score')
                bonus_points += 50
            if streak >= 3:
                achievements_earned.append(f'🔥 {streak}-Question Streak')
                bonus_points += streak * 5
            if module_id == 1 and len(safe_json_loads(user[5], [])) == 0:
                achievements_earned.append('⭐ First Mission Complete')
                bonus_points += 25

            points_earned += bonus_points

        # Update database if passed
        if passed:
            try:
                conn = sqlite3.connect('shadow1834.db')
                cursor = conn.cursor()

                # Add to completed modules
                completed_modules.append(module_id)

                # Add badge
                badges = safe_json_loads(user[6], [])
                if module_data['badge'] not in badges:
                    badges.append(module_data['badge'])

                # Update user level if necessary
                new_level = max(user[11], module_id + 1)  # Level up to unlock next module

                # Update user record
                cursor.execute('''
                               UPDATE users
                               SET total_score = total_score + ?,
                                   completed_modules = ?,
                                   badges = ?,
                                   current_level = ?,
                                   last_activity = ?
                               WHERE id = ?
                               ''', (points_earned, json.dumps(completed_modules), json.dumps(badges),
                                     new_level, datetime.now().isoformat(), user[0]))

                # Record session
                cursor.execute('''
                               INSERT INTO user_sessions (user_id, module_id, score, completed_at)
                               VALUES (?, ?, ?, ?)
                               ''', (user[0], module_id, correct_answers, datetime.now().isoformat()))

                conn.commit()
                conn.close()

                # Log activity
                log_activity(session['user_id'], 'module_complete',
                             f'Completed module {module_id} with {correct_answers}/{total_questions} correct')
            except sqlite3.Error as e:
                print(f"Database error during module submission: {e}")
                flash('Error saving progress. Please try again.', 'error')
                return redirect(url_for('dashboard'))

        return render_template('results.html',
                               user=user,
                               module_data=module_data,
                               results=results,
                               correct_answers=correct_answers,
                               total_questions=total_questions,
                               percentage=percentage,
                               passed=passed,
                               points_earned=points_earned,
                               module_id=module_id,
                               enumerate=enumerate,
                               streak=streak,
                               achievements_earned=achievements_earned,
                               bonus_points=bonus_points)
    except Exception as e:
        flash('An error occurred while submitting the module. Please try again.', 'error')
        print(f"Module submission error: {e}")
        return redirect(url_for('dashboard'))


@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('logout'))

    # Log leaderboard view
    log_activity(session['user_id'], 'leaderboard_view', 'User viewed leaderboard')

    leaders = get_leaderboard(20)

    return render_template('leaderboard.html',
                           user=user,
                           leaders=leaders,
                           safe_json_loads=safe_json_loads,
                           enumerate=enumerate)


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('logout'))

    # Log profile view
    log_activity(session['user_id'], 'profile_view', 'User viewed profile')

    # Parse user data safely
    completed_modules = safe_json_loads(user[5], [])
    badges = safe_json_loads(user[6], [])

    # Get user sessions for activity history
    conn = sqlite3.connect('shadow1834.db')
    cursor = conn.cursor()
    cursor.execute('''
                   SELECT module_id, score, completed_at
                   FROM user_sessions
                   WHERE user_id = ?
                   ORDER BY completed_at DESC
                       LIMIT 10
                   ''', (user[0],))
    recent_sessions = cursor.fetchall()
    conn.close()

    return render_template('profile.html',
                           user=user,
                           completed_modules=completed_modules,
                           badges=badges,
                           recent_sessions=recent_sessions,
                           MODULES=MODULES,
                           datetime=datetime)


@app.route('/admin')
def admin_panel():
    """Admin panel for user management"""
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if not is_admin(session['user_id']):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))

    users = get_all_users()
    log_activity(session['user_id'], 'admin_panel_view', 'Admin viewed user management panel')

    return render_template('admin.html',
                           users=users,
                           safe_json_loads=safe_json_loads,
                           datetime=datetime)


@app.route('/admin/user/<int:user_id>/edit', methods=['POST'])
def admin_edit_user(user_id):
    """Edit user details (admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if not is_admin(session['user_id']):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))

    try:
        username = request.form.get('username')
        email = request.form.get('email')
        total_score = request.form.get('total_score')
        current_level = request.form.get('current_level')
        is_admin_flag = request.form.get('is_admin') == 'on'

        # Prepare update parameters
        kwargs = {}
        if username:
            kwargs['username'] = username
        if email:
            kwargs['email'] = email
        if total_score:
            kwargs['total_score'] = int(total_score)
        if current_level:
            kwargs['current_level'] = int(current_level)
        kwargs['is_admin'] = is_admin_flag

        success, message = update_user_admin(user_id, **kwargs)

        if success:
            flash(f'User updated successfully', 'success')
            log_activity(session['user_id'], 'admin_edit_user', f'Edited user {user_id}')
        else:
            flash(f'Error: {message}', 'error')

    except Exception as e:
        flash(f'Error updating user: {str(e)}', 'error')

    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    """Delete user (admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if not is_admin(session['user_id']):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))

    # Prevent admin from deleting themselves
    if user_id == session['user_id']:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin_panel'))

    try:
        success, message = delete_user_admin(user_id)

        if success:
            flash('User deleted successfully', 'success')
            log_activity(session['user_id'], 'admin_delete_user', f'Deleted user {user_id}')
        else:
            flash(f'Error: {message}', 'error')

    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')

    return redirect(url_for('admin_panel'))
