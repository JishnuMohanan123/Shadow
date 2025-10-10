"""
Claude AI Integration for Shadow1834
Provides AI-powered assistance and features using Anthropic's Claude API
"""

import os
import json
import logging
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("Anthropic package not installed. Install with: pip install anthropic")


class ClaudeAssistant:
    """
    Claude AI Assistant for cybersecurity training platform
    Provides intelligent help, hints, and explanations
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Claude Assistant

        Args:
            api_key: Anthropic API key (if not provided, reads from environment)
        """
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')
        self.client = None
        self.model = "claude-3-5-sonnet-20241022"  # Latest Claude model

        if not ANTHROPIC_AVAILABLE:
            logger.error("Anthropic package not installed")
            return

        if not self.api_key:
            logger.warning("No API key provided. Set ANTHROPIC_API_KEY environment variable")
            return

        try:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            logger.info("Claude Assistant initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Claude: {e}")

    def is_available(self) -> bool:
        """Check if Claude integration is available"""
        return ANTHROPIC_AVAILABLE and self.client is not None

    def get_hint(self, question: str, context: str = "") -> Optional[str]:
        """
        Get a hint for a training question

        Args:
            question: The question text
            context: Additional context about the module

        Returns:
            A helpful hint or None if unavailable
        """
        if not self.is_available():
            return None

        try:
            system_prompt = """You are a cybersecurity training assistant for Shadow1834,
            a gamified cybersecurity education platform. Provide helpful hints without
            giving away the answer directly. Be encouraging and educational."""

            user_prompt = f"""Question: {question}

Context: {context}

Provide a subtle hint that helps the learner think about the problem without
revealing the answer. Keep it under 100 words."""

            message = self.client.messages.create(
                model=self.model,
                max_tokens=200,
                temperature=0.7,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"Error getting hint: {e}")
            return None

    def explain_answer(self, question: str, correct_answer: str,
                       user_answer: str, explanation: str = "") -> Optional[str]:
        """
        Provide detailed explanation of why an answer is correct/incorrect

        Args:
            question: The question text
            correct_answer: The correct answer
            user_answer: What the user answered
            explanation: Existing explanation from the system

        Returns:
            Enhanced explanation or None
        """
        if not self.is_available():
            return None

        try:
            system_prompt = """You are a cybersecurity training assistant. Provide clear,
            educational explanations that help learners understand cybersecurity concepts."""

            user_prompt = f"""Question: {question}

Correct Answer: {correct_answer}
User's Answer: {user_answer}
Base Explanation: {explanation}

Provide an enhanced explanation that:
1. Explains why the correct answer is right
2. If user was wrong, explain their misconception
3. Provide real-world context
4. Keep it under 150 words and encouraging"""

            message = self.client.messages.create(
                model=self.model,
                max_tokens=300,
                temperature=0.7,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"Error explaining answer: {e}")
            return None

    def chat(self, user_message: str, conversation_history: List[Dict] = None) -> Optional[str]:
        """
        General chat with Claude for user assistance

        Args:
            user_message: User's message
            conversation_history: Previous messages in format [{"role": "user"/"assistant", "content": "..."}]

        Returns:
            Claude's response or None
        """
        if not self.is_available():
            return None

        try:
            system_prompt = """You are a friendly AI assistant for Shadow1834, a cybersecurity
            training platform. Help users with:
            - Understanding cybersecurity concepts
            - Guidance on training modules
            - General questions about security best practices

            Be encouraging, educational, and security-focused. Keep responses concise and practical."""

            # Build message history
            messages = conversation_history or []
            messages.append({"role": "user", "content": user_message})

            message = self.client.messages.create(
                model=self.model,
                max_tokens=500,
                temperature=0.7,
                system=system_prompt,
                messages=messages
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"Error in chat: {e}")
            return None

    def generate_practice_question(self, topic: str, difficulty: str = "intermediate") -> Optional[Dict]:
        """
        Generate a practice question on a cybersecurity topic

        Args:
            topic: Cybersecurity topic (e.g., "phishing", "passwords", "malware")
            difficulty: "beginner", "intermediate", or "advanced"

        Returns:
            Dictionary with question, options, correct answer, and explanation
        """
        if not self.is_available():
            return None

        try:
            system_prompt = """You are an expert cybersecurity educator creating training questions."""

            user_prompt = f"""Create a {difficulty} level multiple-choice question about {topic}.

Return ONLY a JSON object in this exact format (no markdown, no extra text):
{{
    "question": "Question text here",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "correct": 0,
    "explanation": "Why this answer is correct"
}}

The "correct" field should be the index (0-3) of the correct option."""

            message = self.client.messages.create(
                model=self.model,
                max_tokens=400,
                temperature=0.8,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

            response_text = message.content[0].text.strip()

            # Try to extract JSON from response
            if response_text.startswith('```'):
                # Remove markdown code blocks
                response_text = response_text.split('```')[1]
                if response_text.startswith('json'):
                    response_text = response_text[4:]

            question_data = json.loads(response_text.strip())
            return question_data

        except Exception as e:
            logger.error(f"Error generating question: {e}")
            return None

    def analyze_user_progress(self, user_data: Dict) -> Optional[str]:
        """
        Analyze user progress and provide personalized recommendations

        Args:
            user_data: Dictionary with user stats (score, completed modules, etc.)

        Returns:
            Personalized recommendations
        """
        if not self.is_available():
            return None

        try:
            system_prompt = """You are a cybersecurity training coach analyzing student progress."""

            user_prompt = f"""User Statistics:
- Total Score: {user_data.get('total_score', 0)}
- Completed Modules: {user_data.get('completed_modules', 0)}/5
- Current Level: {user_data.get('current_level', 1)}
- Badges Earned: {user_data.get('badges', 0)}

Provide brief, encouraging feedback and 2-3 specific recommendations for
what they should focus on next. Keep it under 100 words."""

            message = self.client.messages.create(
                model=self.model,
                max_tokens=200,
                temperature=0.7,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"Error analyzing progress: {e}")
            return None


# Singleton instance
_claude_assistant = None


def get_claude_assistant() -> ClaudeAssistant:
    """Get or create the Claude assistant instance"""
    global _claude_assistant
    if _claude_assistant is None:
        _claude_assistant = ClaudeAssistant()
    return _claude_assistant


# Convenience functions
def get_hint(question: str, context: str = "") -> Optional[str]:
    """Get a hint for a question"""
    return get_claude_assistant().get_hint(question, context)


def explain_answer(question: str, correct_answer: str,
                   user_answer: str, explanation: str = "") -> Optional[str]:
    """Get enhanced explanation"""
    return get_claude_assistant().explain_answer(
        question, correct_answer, user_answer, explanation
    )


def chat_with_claude(message: str, history: List[Dict] = None) -> Optional[str]:
    """Chat with Claude"""
    return get_claude_assistant().chat(message, history)


def generate_practice_question(topic: str, difficulty: str = "intermediate") -> Optional[Dict]:
    """Generate a practice question"""
    return get_claude_assistant().generate_practice_question(topic, difficulty)


def analyze_progress(user_data: Dict) -> Optional[str]:
    """Analyze user progress"""
    return get_claude_assistant().analyze_user_progress(user_data)


if __name__ == '__main__':
    # Test the integration
    print("Testing Claude Integration...")
    assistant = ClaudeAssistant()

    if assistant.is_available():
        print("✅ Claude is available")

        # Test hint generation
        hint = assistant.get_hint(
            "What should you do if you receive a suspicious email?",
            "This is about phishing detection"
        )
        print(f"\n📝 Hint: {hint}")

        # Test question generation
        question = assistant.generate_practice_question("passwords", "beginner")
        print(f"\n❓ Generated Question: {json.dumps(question, indent=2)}")

    else:
        print("❌ Claude is not available. Install anthropic package and set API key:")
        print("   pip install anthropic")
        print("   export ANTHROPIC_API_KEY='your-key-here'")
