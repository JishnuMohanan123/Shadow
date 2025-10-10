"""
AI Integration for Shadow1834
Supports both Ollama (FREE local AI) and DeepSeek API
Ollama is recommended - 100% FREE, no API key needed!
"""

import os
import json
import logging
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI package not installed. Install with: pip install openai")


class AIAssistant:
    """
    AI Assistant for cybersecurity training platform
    Supports Ollama (FREE, local) and DeepSeek API
    """

    def __init__(self, api_key: Optional[str] = None, use_ollama: bool = True):
        """
        Initialize AI Assistant

        Args:
            api_key: DeepSeek API key (optional if using Ollama)
            use_ollama: Try Ollama first (FREE, local AI)
        """
        self.client = None
        self.model = "llama3.2"  # Default Ollama model
        self.using_ollama = False

        if not OPENAI_AVAILABLE:
            logger.error("OpenAI package not installed. Install with: pip install openai")
            return

        # Try Ollama first (FREE!)
        if use_ollama:
            try:
                self.client = OpenAI(
                    base_url="http://localhost:11434/v1",
                    api_key="ollama"  # Ollama doesn't need real key
                )
                # Test if Ollama is running
                self.client.models.list()
                self.using_ollama = True
                logger.info("✅ Ollama AI initialized successfully (FREE, local)")
                return
            except Exception as e:
                logger.warning(f"Ollama not available, trying DeepSeek API: {e}")

        # Fall back to DeepSeek API
        self.api_key = api_key or os.environ.get('DEEPSEEK_API_KEY', '')
        if not self.api_key:
            logger.error("No DEEPSEEK_API_KEY found and Ollama not running")
            logger.info("Install Ollama for FREE AI: https://ollama.com/download")
            return

        try:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url="https://api.deepseek.com"
            )
            self.model = "deepseek-chat"
            self.using_ollama = False
            logger.info("✅ DeepSeek API initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AI: {e}")

    def is_available(self) -> bool:
        """Check if AI integration is available"""
        return OPENAI_AVAILABLE and self.client is not None

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

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=200,
                temperature=0.7
            )

            return response.choices[0].message.content

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

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=300,
                temperature=0.7
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Error explaining answer: {e}")
            return None

    def chat(self, user_message: str, conversation_history: List[Dict] = None) -> Optional[str]:
        """
        General chat with AI for user assistance

        Args:
            user_message: User's message
            conversation_history: Previous messages in format [{"role": "user"/"assistant", "content": "..."}]

        Returns:
            AI's response or None
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
            messages = [{"role": "system", "content": system_prompt}]

            if conversation_history:
                messages.extend(conversation_history)

            messages.append({"role": "user", "content": user_message})

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=500,
                temperature=0.7
            )

            return response.choices[0].message.content

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

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=400,
                temperature=0.8
            )

            response_text = response.choices[0].message.content.strip()

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

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=200,
                temperature=0.7
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Error analyzing progress: {e}")
            return None


# Singleton instance
_ai_assistant = None


def get_ai_assistant() -> AIAssistant:
    """Get or create the AI assistant instance"""
    global _ai_assistant
    if _ai_assistant is None:
        _ai_assistant = AIAssistant()
    return _ai_assistant


# Convenience functions
def get_hint(question: str, context: str = "") -> Optional[str]:
    """Get a hint for a question"""
    return get_ai_assistant().get_hint(question, context)


def explain_answer(question: str, correct_answer: str,
                   user_answer: str, explanation: str = "") -> Optional[str]:
    """Get enhanced explanation"""
    return get_ai_assistant().explain_answer(
        question, correct_answer, user_answer, explanation
    )


def chat_with_ai(message: str, history: List[Dict] = None) -> Optional[str]:
    """Chat with AI"""
    return get_ai_assistant().chat(message, history)


def generate_practice_question(topic: str, difficulty: str = "intermediate") -> Optional[Dict]:
    """Generate a practice question"""
    return get_ai_assistant().generate_practice_question(topic, difficulty)


def analyze_progress(user_data: Dict) -> Optional[str]:
    """Analyze user progress"""
    return get_ai_assistant().analyze_user_progress(user_data)


if __name__ == '__main__':
    # Test the integration
    import sys

    # Fix encoding for Windows
    if sys.platform == 'win32':
        sys.stdout.reconfigure(encoding='utf-8')

    print("Testing AI Integration...")
    print("=" * 60)
    assistant = AIAssistant()

    if assistant.is_available():
        if assistant.using_ollama:
            print("✅ Using Ollama (FREE, Local AI)")
            print(f"📦 Model: {assistant.model}")
            print("💰 Cost: $0 - FREE Forever!")
        else:
            print("✅ Using DeepSeek API")
            print(f"📦 Model: {assistant.model}")
            print("💰 Cost: Pay per use")

        # Test hint generation
        print("\n" + "=" * 60)
        print("Test 1: Hint Generation")
        print("=" * 60)
        hint = assistant.get_hint(
            "What should you do if you receive a suspicious email?",
            "This is about phishing detection"
        )
        if hint:
            print(f"✅ Hint generated successfully!")
            print(f"📝 {hint[:200]}..." if len(hint) > 200 else f"📝 {hint}")
        else:
            print("❌ Failed to generate hint")

        # Test chat
        print("\n" + "=" * 60)
        print("Test 2: Chat Function")
        print("=" * 60)
        response = assistant.chat("What is phishing in simple terms?")
        if response:
            print(f"✅ Chat response received!")
            print(f"💬 {response[:200]}..." if len(response) > 200 else f"💬 {response}")
        else:
            print("❌ Failed to get chat response")

        print("\n" + "=" * 60)
        print("✅ All tests completed!")
        print("=" * 60)

    else:
        print("❌ AI is not available")
        print("\n📋 Setup Options:")
        print("\n🆓 Option 1: Ollama (FREE - Recommended)")
        print("   1. Download: https://ollama.com/download")
        print("   2. Install OllamaSetup.exe")
        print("   3. Run: ollama pull llama3.2")
        print("   4. Done! No API key needed")
        print("\n💳 Option 2: DeepSeek API")
        print("   1. Get API key: https://platform.deepseek.com")
        print("   2. Set: $env:DEEPSEEK_API_KEY='your-key'")
        print("   3. Add credits to account")
