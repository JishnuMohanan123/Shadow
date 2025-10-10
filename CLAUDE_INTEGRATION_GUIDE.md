# Claude AI Integration Guide
## Shadow1834 Cybersecurity Training Platform

**Date:** October 10, 2025
**Integration:** Anthropic Claude API
**Status:** Ready for Setup

---

## 🤖 What is Claude Integration?

This integration adds AI-powered features to your Shadow1834 platform using Anthropic's Claude AI:

### Features Added:
1. **AI Chat Assistant** - Users can chat with Claude about cybersecurity topics
2. **Smart Hints** - Get AI-generated hints for training questions
3. **Enhanced Explanations** - Detailed explanations for quiz answers
4. **Practice Questions** - AI-generated practice questions on any topic
5. **Progress Analysis** - Personalized recommendations based on user performance

---

## 📦 Files Created

### Core Integration Files:
1. **[claude_integration.py](claude_integration.py)** (425 lines)
   - Main Claude AI integration module
   - ClaudeAssistant class with all AI features
   - Convenience functions for easy use

2. **[claude_routes.py](claude_routes.py)** (179 lines)
   - Flask routes for Claude API endpoints
   - `/api/claude/chat` - Chat with Claude
   - `/api/claude/hint` - Get hints
   - `/api/claude/explain` - Get explanations
   - `/api/claude/practice-question` - Generate questions
   - `/api/claude/analyze-progress` - Analyze user progress
   - `/claude-assistant` - Chat interface page

3. **[templates/claude_assistant.html](templates/claude_assistant.html)** (345 lines)
   - Beautiful chat interface
   - Quick action buttons
   - Real-time messaging
   - Typing indicators
   - Responsive design

4. **requirements.txt** (updated)
   - Added `anthropic>=0.18.0` package

---

## 🚀 Setup Instructions

### Step 1: Install Required Package

```bash
pip install anthropic
```

Or install all requirements:
```bash
pip install -r requirements.txt
```

### Step 2: Get Your Claude API Key

1. Go to **https://console.anthropic.com**
2. Sign up or log in to your account
3. Navigate to **API Keys** section
4. Click **Create Key**
5. Copy your API key (starts with `sk-ant-...`)

### Step 3: Set Environment Variable

#### On Windows:
```powershell
# Temporary (current session only)
$env:ANTHROPIC_API_KEY="your-api-key-here"

# Permanent (user level)
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_API_KEY', 'your-api-key-here', 'User')

# Permanent (system level - requires admin)
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_API_KEY', 'your-api-key-here', 'Machine')
```

#### On Linux/Mac:
```bash
# Temporary (current session)
export ANTHROPIC_API_KEY="your-api-key-here"

# Permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export ANTHROPIC_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

#### Using .env File (Recommended):
Create a `.env` file in your project root:
```
ANTHROPIC_API_KEY=your-api-key-here
```

Then install python-dotenv:
```bash
pip install python-dotenv
```

Add to your app.py (at the top):
```python
from dotenv import load_dotenv
load_dotenv()
```

### Step 4: Integrate Routes into Your App

Open `routes.py` and add at the top:
```python
from claude_routes import register_claude_routes
```

Then after creating the Flask app (after `app = Flask(__name__)`), add:
```python
# Register Claude AI routes
try:
    register_claude_routes(app)
except Exception as e:
    print(f"Warning: Could not register Claude routes: {e}")
```

### Step 5: Add Navigation Link

Open `templates/base.html` and add this menu item in the navigation section:
```html
<li role="none">
    <a href="{{ url_for('claude_assistant_page') }}"
       {% if request.endpoint == 'claude_assistant_page' %}class="active"{% endif %}
       role="menuitem">
        <span class="nav-icon">🤖</span>
        <span class="nav-text">AI ASSISTANT</span>
    </a>
</li>
```

### Step 6: Test the Integration

```bash
# Run the test to verify Claude is working
py claude_integration.py
```

You should see:
```
Testing Claude Integration...
✅ Claude is available
📝 Hint: [Your generated hint]
❓ Generated Question: {...}
```

If you see errors:
```
❌ Claude is not available. Install anthropic package and set API key:
   pip install anthropic
   export ANTHROPIC_API_KEY='your-key-here'
```

### Step 7: Start Your Application

```bash
py app.py
```

Then navigate to:
```
http://localhost:5000/claude-assistant
```

---

## 🎯 Usage Examples

### 1. Chat with Claude

Users can ask questions like:
- "What is phishing?"
- "Explain SQL injection attacks"
- "How do I create a strong password?"
- "What's the difference between malware and ransomware?"

### 2. Get Hints

In your training modules, you can add a hint button:
```javascript
fetch('/api/claude/hint', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        question: "What should you do with a suspicious email?",
        context: "Phishing module"
    })
}).then(r => r.json()).then(data => {
    alert(data.hint);
});
```

### 3. Generate Practice Questions

```javascript
fetch('/api/claude/practice-question', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        topic: "passwords",
        difficulty: "beginner"
    })
}).then(r => r.json()).then(data => {
    console.log(data.question);
});
```

### 4. Analyze Progress

```javascript
fetch('/api/claude/analyze-progress')
    .then(r => r.json())
    .then(data => {
        alert(data.analysis);
    });
```

---

## 💰 API Costs

Claude API pricing (as of 2024):
- **Claude 3.5 Sonnet**
  - Input: $3.00 per million tokens
  - Output: $15.00 per million tokens

**Estimated costs for your platform:**
- Chat message: ~$0.001 - $0.005 per interaction
- Hint generation: ~$0.0005 per hint
- Question generation: ~$0.002 per question
- Progress analysis: ~$0.001 per analysis

**Example monthly costs:**
- 100 users, 10 interactions each = 1000 interactions
- Cost: ~$5-10 per month

Anthropic offers **$5 free credit** for new users!

---

## 🔧 Configuration Options

### Change Claude Model

In `claude_integration.py`, line 34:
```python
self.model = "claude-3-5-sonnet-20241022"  # Latest model
```

Available models:
- `claude-3-5-sonnet-20241022` - Best balance (recommended)
- `claude-3-opus-20240229` - Most powerful, slower, expensive
- `claude-3-haiku-20240307` - Fastest, cheapest

### Adjust Response Length

Modify `max_tokens` in each function:
```python
message = self.client.messages.create(
    model=self.model,
    max_tokens=500,  # Increase for longer responses
    temperature=0.7,
    ...
)
```

### Customize System Prompts

Edit the system prompts in each function to change Claude's behavior:
```python
system_prompt = """You are a cybersecurity expert..."""
```

---

## 🎨 Frontend Integration Examples

### Add Hint Button to Module Questions

In `templates/module.html`, add a hint button:
```html
<button onclick="getHint({{ loop.index0 }})" class="btn btn-secondary">
    💡 Get Hint
</button>

<script>
async function getHint(questionIndex) {
    const question = questions[questionIndex];
    const response = await fetch('/api/claude/hint', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            question: question.text,
            context: "{{ module_data.title }}"
        })
    });
    const data = await response.json();
    if (data.success) {
        alert('💡 Hint: ' + data.hint);
    }
}
</script>
```

### Add Enhanced Explanations to Results

In `templates/results.html`, enhance explanations:
```javascript
async function enhanceExplanation(index) {
    const result = results[index];
    const response = await fetch('/api/claude/explain', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            question: result.question,
            correct_answer: result.options[result.correct_answer],
            user_answer: result.options[result.user_answer],
            explanation: result.explanation
        })
    });
    const data = await response.json();
    document.getElementById(`explanation-${index}`).innerHTML = data.explanation;
}
```

---

## 🔒 Security Considerations

1. **API Key Security**
   - NEVER commit your API key to git
   - Add `.env` to `.gitignore`
   - Use environment variables

2. **Rate Limiting**
   - Consider adding rate limiting to prevent abuse
   - Anthropic has built-in rate limits

3. **User Authentication**
   - All routes require `user_id` in session
   - No anonymous access to AI features

4. **Content Filtering**
   - Claude has built-in safety features
   - Monitor logs for misuse

---

## 📊 Monitoring & Logging

Check logs for Claude usage:
```bash
tail -f shadow1834.log | grep -i claude
```

Log entries include:
- API errors
- Request failures
- Response times
- Usage patterns

---

## 🐛 Troubleshooting

### Error: "Anthropic package not installed"
```bash
pip install anthropic
```

### Error: "No API key provided"
```bash
# Windows
$env:ANTHROPIC_API_KEY="your-key"

# Linux/Mac
export ANTHROPIC_API_KEY="your-key"
```

### Error: "API key invalid"
- Verify your API key at https://console.anthropic.com
- Make sure it starts with `sk-ant-`
- Check for extra spaces or quotes

### Error: "Claude is not available"
Run the test script:
```bash
py claude_integration.py
```

Check the output for specific errors.

### Error: "Rate limit exceeded"
- You've hit Anthropic's rate limits
- Wait a few minutes and try again
- Consider upgrading your API plan

---

## 🎓 API Endpoints Reference

### POST /api/claude/chat
Chat with Claude AI
```json
Request: {
    "message": "What is phishing?",
    "history": [
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi! How can I help?"}
    ]
}

Response: {
    "success": true,
    "response": "Phishing is a type of cyber attack..."
}
```

### POST /api/claude/hint
Get a hint for a question
```json
Request: {
    "question": "What should you do with suspicious emails?",
    "context": "Phishing module"
}

Response: {
    "success": true,
    "hint": "Think about verifying the sender..."
}
```

### POST /api/claude/explain
Get enhanced explanation
```json
Request: {
    "question": "What is 2FA?",
    "correct_answer": "Two-factor authentication",
    "user_answer": "Two-file authentication",
    "explanation": "2FA adds extra security"
}

Response: {
    "success": true,
    "explanation": "Two-factor authentication..."
}
```

### POST /api/claude/practice-question
Generate practice question
```json
Request: {
    "topic": "passwords",
    "difficulty": "beginner"
}

Response: {
    "success": true,
    "question": {
        "question": "Which password is strongest?",
        "options": ["password123", "P@ssw0rd!", ...],
        "correct": 2,
        "explanation": "Long passwords with..."
    }
}
```

### GET /api/claude/analyze-progress
Analyze user progress
```json
Response: {
    "success": true,
    "analysis": "Great progress! You've completed..."
}
```

---

## 📚 Additional Resources

- **Anthropic Documentation:** https://docs.anthropic.com
- **Claude API Reference:** https://docs.anthropic.com/claude/reference
- **Python SDK:** https://github.com/anthropics/anthropic-sdk-python
- **API Console:** https://console.anthropic.com

---

## ✅ Checklist

- [ ] Install anthropic package (`pip install anthropic`)
- [ ] Get API key from https://console.anthropic.com
- [ ] Set ANTHROPIC_API_KEY environment variable
- [ ] Add `register_claude_routes(app)` to routes.py
- [ ] Add navigation link to base.html
- [ ] Test integration (`py claude_integration.py`)
- [ ] Start application and test chat interface
- [ ] (Optional) Add hint buttons to modules
- [ ] (Optional) Add enhanced explanations to results

---

## 🎉 You're All Set!

Once configured, your users will have access to:
- 🤖 AI-powered chat assistant
- 💡 Smart hints for questions
- 🎓 Enhanced explanations
- 📝 Practice question generation
- 📊 Personalized progress analysis

**Need help?** Check the troubleshooting section or review the API documentation.

---

**Created:** October 10, 2025
**Integration Files:** 3 files, ~950 lines of code
**Status:** ✅ Ready for deployment
