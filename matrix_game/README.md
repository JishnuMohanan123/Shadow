# 🎮 SHADOW - Matrix-Themed Cyber Awareness Quiz Game

Welcome to **SHADOW**, an immersive Matrix-themed cybersecurity training platform that tests your knowledge of cyber threats through an interactive quiz game.

## 🌟 Features

- **Matrix Rain Animation** - Authentic falling code background using HTML5 Canvas
- **Terminal-Style Interface** - Classic hacker aesthetic with green-on-black design
- **Typing Effects** - Realistic terminal typing animations
- **Interactive Quiz** - 10 cybersecurity questions with instant feedback
- **Score Tracking** - SQLite database stores all scores and progress
- **Rank System** - From Level 1 Recruit to Cyber Master
- **Sound Effects** - Keyboard clicks and feedback sounds (optional)
- **Responsive Design** - Works on desktop and mobile devices

## 📋 Prerequisites

Before running SHADOW, ensure you have:

- **Python 3.7+** installed
- **pip** (Python package installer)
- **Modern web browser** (Chrome, Firefox, Edge, Safari)

## 🚀 Installation & Setup

### Step 1: Navigate to Project Directory

```bash
cd matrix_game
```

### Step 2: Install Flask

```bash
pip install flask
```

That's it! Flask is the only dependency needed.

### Step 3: Run the Application

```bash
python app.py
```

You should see output like:

```
[SYSTEM] Initializing SHADOW database...
[SYSTEM] Database ready
[SYSTEM] Starting SHADOW Matrix Cyber Quiz...
[ACCESS] Server running on http://127.0.0.1:5000
[MATRIX] The system is ready...
 * Running on http://127.0.0.1:5000
```

### Step 4: Open in Browser

Open your web browser and navigate to:

```
http://127.0.0.1:5000
```

or

```
http://localhost:5000
```

## 🎯 How to Play

1. **Welcome Screen**
   - Enter your agent codename (or use the default "Agent_001")
   - Click "JACK IN" to begin

2. **Quiz Interface**
   - Read each question carefully
   - Click on your answer choice (A, B, C, or D)
   - Immediate feedback: ✅ ACCESS GRANTED or ❌ ACCESS DENIED
   - Click "NEXT MISSION" to continue

3. **Results Screen**
   - View your final score and percentage
   - Earn your rank based on performance:
     - 90%+ : Cyber Master 👑
     - 75%+ : Level 5 Guardian 🛡️
     - 60%+ : Level 3 Operative ⚔️
     - 40%+ : Level 2 Agent 🎯
     - <40% : Level 1 Recruit 🔰
   - Review all answers
   - Try again or exit

## 📁 Project Structure

```
matrix_game/
│
├── app.py                      # Flask backend application
├── shadow.db                   # SQLite database (auto-created)
├── README.md                   # This file
│
├── templates/
│   ├── index.html              # Welcome/start screen
│   ├── quiz.html               # Main quiz interface
│   └── result.html             # Results/score screen
│
└── static/
    ├── css/
    │   └── matrix.css          # Matrix theme styles
    │
    └── js/
        ├── matrix-rain.js      # Matrix rain animation
        ├── terminal-effects.js # Typing effects
        └── quiz-handler.js     # Quiz logic
```

## 🎨 Customization

### Adding More Questions

Edit `app.py` and add questions to the `sample_questions` list in the `init_db()` function:

```python
(
    "Your question text here?",
    "Option A text",
    "Option B text",
    "Option C text",
    "Option D text",
    "B",  # Correct option (A, B, C, or D)
    "medium",  # Difficulty: easy, medium, hard
    "category_name"  # Category name
)
```

### Changing Colors

Edit `static/css/matrix.css` and modify the CSS variables:

```css
:root {
    --matrix-green: #00FF00;      /* Main green color */
    --neon-green: #39FF14;         /* Bright neon green */
    --cyber-blue: #00FFFF;         /* Accent blue */
    --warning-yellow: #FFD700;     /* Warning color */
    --error-red: #FF0000;          /* Error color */
}
```

### Adjusting Matrix Rain

Edit `static/js/matrix-rain.js`:

```javascript
const fontSize = 14;  // Change character size
const chars = 'ABC...'; // Modify characters used
```

## 🔧 Troubleshooting

### Database Issues

If you encounter database errors:

```bash
# Delete the database and restart
rm shadow.db
python app.py
```

### Port Already in Use

If port 5000 is busy, change it in `app.py`:

```python
app.run(debug=True, host='127.0.0.1', port=8000)  # Use port 8000 instead
```

### Static Files Not Loading

Ensure the file structure matches exactly:
- CSS files must be in `static/css/`
- JS files must be in `static/js/`
- Templates must be in `templates/`

## 🎮 Keyboard Shortcuts

- **ESC** - Return to home (from most screens)
- **ENTER** - Submit name/form

## 📊 Database Schema

### Questions Table
```sql
CREATE TABLE questions (
    id INTEGER PRIMARY KEY,
    question_text TEXT,
    option_a TEXT,
    option_b TEXT,
    option_c TEXT,
    option_d TEXT,
    correct_option TEXT,
    difficulty TEXT,
    category TEXT
);
```

### Scores Table
```sql
CREATE TABLE scores (
    id INTEGER PRIMARY KEY,
    player_name TEXT,
    score INTEGER,
    total_questions INTEGER,
    timestamp TEXT
);
```

## 🌐 Browser Compatibility

- ✅ Chrome 80+
- ✅ Firefox 75+
- ✅ Safari 13+
- ✅ Edge 80+

## 🛡️ Security Notes

- This is a **training/demo application**
- Default secret key should be changed for production
- Database has no authentication (local use only)
- Not hardened for public deployment

## 📝 License

This project is open source and available for educational purposes.

## 🤝 Contributing

Feel free to:
- Add more questions
- Improve animations
- Add new features
- Fix bugs

## 📞 Support

Having issues? Check:
1. Python version is 3.7+
2. Flask is installed (`pip list | grep Flask`)
3. You're in the correct directory
4. Port 5000 is available
5. Browser console for JavaScript errors (F12)

## 🎉 Credits

Built with:
- **Flask** - Python web framework
- **SQLite** - Database
- **HTML5 Canvas** - Matrix rain effect
- **Pure CSS** - No frameworks, pure styling
- **Vanilla JavaScript** - No libraries needed

---

**Made for cybersecurity education and Matrix fans 🕶️**

**[SYSTEM] Welcome to SHADOW. The Matrix has you... 🟢**
