"""
Flask routes for Claude AI integration
Add these routes to your main routes.py file
"""

from flask import request, session, jsonify, render_template
from claude_integration import (
    get_claude_assistant,
    get_hint,
    explain_answer,
    chat_with_claude,
    generate_practice_question,
    analyze_progress
)
import json
import logging

logger = logging.getLogger(__name__)


def register_claude_routes(app):
    """Register Claude AI routes with Flask app"""

    @app.route('/api/claude/chat', methods=['POST'])
    def claude_chat():
        """Chat with Claude AI assistant"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        try:
            data = request.get_json()
            message = data.get('message', '')
            history = data.get('history', [])

            if not message:
                return jsonify({'error': 'No message provided'}), 400

            # Get response from Claude
            response = chat_with_claude(message, history)

            if response is None:
                return jsonify({
                    'error': 'Claude is not available',
                    'message': 'AI assistant is currently unavailable. Please try again later.'
                }), 503

            return jsonify({
                'response': response,
                'success': True
            })

        except Exception as e:
            logger.error(f"Error in Claude chat: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/api/claude/hint', methods=['POST'])
    def claude_hint():
        """Get a hint for a question"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        try:
            data = request.get_json()
            question = data.get('question', '')
            context = data.get('context', '')

            if not question:
                return jsonify({'error': 'No question provided'}), 400

            hint = get_hint(question, context)

            if hint is None:
                return jsonify({
                    'error': 'Hints unavailable',
                    'message': 'AI hints are currently unavailable.'
                }), 503

            return jsonify({
                'hint': hint,
                'success': True
            })

        except Exception as e:
            logger.error(f"Error getting hint: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/api/claude/explain', methods=['POST'])
    def claude_explain():
        """Get enhanced explanation for an answer"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        try:
            data = request.get_json()
            question = data.get('question', '')
            correct_answer = data.get('correct_answer', '')
            user_answer = data.get('user_answer', '')
            base_explanation = data.get('explanation', '')

            explanation = explain_answer(
                question, correct_answer, user_answer, base_explanation
            )

            if explanation is None:
                return jsonify({
                    'error': 'Explanations unavailable',
                    'message': 'AI explanations are currently unavailable.'
                }), 503

            return jsonify({
                'explanation': explanation,
                'success': True
            })

        except Exception as e:
            logger.error(f"Error explaining answer: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/api/claude/practice-question', methods=['POST'])
    def claude_practice():
        """Generate a practice question"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        try:
            data = request.get_json()
            topic = data.get('topic', 'cybersecurity')
            difficulty = data.get('difficulty', 'intermediate')

            question = generate_practice_question(topic, difficulty)

            if question is None:
                return jsonify({
                    'error': 'Question generation unavailable',
                    'message': 'AI question generation is currently unavailable.'
                }), 503

            return jsonify({
                'question': question,
                'success': True
            })

        except Exception as e:
            logger.error(f"Error generating question: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/api/claude/analyze-progress', methods=['GET'])
    def claude_analyze():
        """Get personalized progress analysis"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        try:
            from app import get_user_by_id, safe_json_loads

            user = get_user_by_id(session['user_id'])
            if not user:
                return jsonify({'error': 'User not found'}), 404

            user_data = {
                'total_score': user[4],
                'completed_modules': len(safe_json_loads(user[5], [])),
                'current_level': user[11],
                'badges': len(safe_json_loads(user[6], []))
            }

            analysis = analyze_progress(user_data)

            if analysis is None:
                return jsonify({
                    'error': 'Analysis unavailable',
                    'message': 'AI analysis is currently unavailable.'
                }), 503

            return jsonify({
                'analysis': analysis,
                'success': True
            })

        except Exception as e:
            logger.error(f"Error analyzing progress: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/claude-assistant')
    def claude_assistant_page():
        """Claude AI assistant chat interface"""
        if 'user_id' not in session:
            return redirect(url_for('index'))

        from app import get_user_by_id
        user = get_user_by_id(session['user_id'])
        if not user:
            return redirect(url_for('logout'))

        assistant = get_claude_assistant()

        return render_template('claude_assistant.html',
                             user=user,
                             claude_available=assistant.is_available())

    logger.info("Claude AI routes registered successfully")


# For standalone testing
if __name__ == '__main__':
    print("Claude routes module - import and call register_claude_routes(app)")
