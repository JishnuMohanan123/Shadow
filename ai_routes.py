"""
Flask routes for DeepSeek AI integration
FREE and OPEN SOURCE AI Assistant
"""

from flask import request, session, jsonify, render_template, redirect, url_for
from ai_integration import (
    get_ai_assistant,
    get_hint,
    explain_answer,
    chat_with_ai,
    generate_practice_question,
    analyze_progress
)
import json
import logging

logger = logging.getLogger(__name__)


def register_ai_routes(app):
    """Register DeepSeek AI routes with Flask app"""

    @app.route('/api/ai/chat', methods=['POST'])
    def ai_chat():
        """Chat with DeepSeek AI assistant"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        try:
            data = request.get_json()
            message = data.get('message', '')
            history = data.get('history', [])

            if not message:
                return jsonify({'error': 'No message provided'}), 400

            # Get response from DeepSeek
            response = chat_with_ai(message, history)

            if response is None:
                return jsonify({
                    'error': 'AI is not available',
                    'message': 'AI assistant is currently unavailable. Please check your setup.'
                }), 503

            return jsonify({
                'response': response,
                'success': True
            })

        except Exception as e:
            logger.error(f"Error in AI chat: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/api/ai/hint', methods=['POST'])
    def ai_hint():
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

    @app.route('/api/ai/explain', methods=['POST'])
    def ai_explain():
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

    @app.route('/api/ai/practice-question', methods=['POST'])
    def ai_practice():
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

    @app.route('/api/ai/analyze-progress', methods=['GET'])
    def ai_analyze():
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

    @app.route('/ai-assistant')
    def ai_assistant_page():
        """DeepSeek AI assistant chat interface"""
        if 'user_id' not in session:
            return redirect(url_for('index'))

        from app import get_user_by_id
        user = get_user_by_id(session['user_id'])
        if not user:
            return redirect(url_for('logout'))

        assistant = get_ai_assistant()

        return render_template('ai_assistant.html',
                             user=user,
                             ai_available=assistant.is_available())

    logger.info("Ollama AI routes registered successfully")


# For standalone testing
if __name__ == '__main__':
    print("AI routes module - import and call register_ai_routes(app)")
