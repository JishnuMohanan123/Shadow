# Shadow1834 - File Structure Quick Reference

## Directory Overview

### Root Directory
```
Shadow/
├── app.py                  ⚙️  Core application logic
├── routes.py               🌐 Flask route handlers
├── comprehensive_tests.py  🧪 Test suite (37 tests)
├── requirements.txt        📦 Python dependencies
└── README.md              📖 Main documentation
```

### Static Assets (`static/`)
```
static/
├── css/
│   └── styles.css         🎨 Main stylesheet (28KB)
├── js/
│   └── base.js           ⚡ JavaScript functionality
└── favicon.svg           🔰 Site icon
```

### Templates (`templates/`)
```
templates/
├── base.html              📄 Base template with navigation
├── index.html             🏠 Login/landing page
├── register.html          ✍️  User registration
├── dashboard.html         🎯 Main command center
├── module.html            📚 Training module interface
├── results.html           📊 Module results
├── leaderboard.html       🏆 Rankings page
├── profile.html           👤 User profile
└── admin.html            🔧 Admin control panel
```

### Utility Scripts (`scripts/`)
```
scripts/
├── check_admin.py         ✔️  Verify admin status
├── create_admin.py        ➕ Create admin user
├── migrate_admin.py       🔄 Database migrations
├── set_admin_privileges.py 🔑 Grant admin access
└── test_admin_access.py   🧪 Test admin features
```

### Documentation (`docs/`)
```
docs/
├── ADMIN_CREDENTIALS.txt   🔐 Admin login info
├── QUICK_START_ADMIN.md    🚀 Admin quick start
├── NAVIGATION_IMPROVEMENTS.md 🎨 UI changelog
└── FILE_STRUCTURE_GUIDE.md 📋 This file
```

---

## File Purpose Guide

### Core Files

| File | Purpose | Size | Lines |
|------|---------|------|-------|
| `app.py` | Database logic, user auth, modules | 32KB | 730 |
| `routes.py` | Web routes and handlers | 18KB | 493 |
| `comprehensive_tests.py` | Full test suite | 20KB | 600+ |

### Configuration Files

| File | Purpose |
|------|---------|
| `requirements.txt` | Python dependencies |
| `.gitignore` | Git ignore patterns |
| `PROJECT_STRUCTURE.md` | Detailed structure docs |
| `CLEANUP_SUMMARY.md` | Cleanup process log |

### Generated Files

| File | Purpose | Auto-Generated |
|------|---------|----------------|
| `shadow1834.db` | SQLite database | ✅ Yes |
| `shadow1834.log` | Application logs | ✅ Yes |
| `__pycache__/` | Python cache | ✅ Yes (gitignored) |

---

## Quick Navigation

### Need to...

**Start the app?**
→ `py app.py`

**Run tests?**
→ `py comprehensive_tests.py`

**Create admin?**
→ `py scripts/create_admin.py`

**Check admin status?**
→ `py scripts/check_admin.py`

**Edit styles?**
→ `static/css/styles.css`

**Edit templates?**
→ `templates/*.html`

**Read docs?**
→ `README.md` or `docs/`

---

## File Dependencies

### `app.py` imports:
- `sqlite3` - Database
- `hashlib` - Hashing
- `bcrypt` - Password security
- `json` - Data handling
- `logging` - Logging
- `datetime` - Timestamps

### `routes.py` imports:
- `Flask` - Web framework
- `app` module - Core logic

### Templates extend:
- `base.html` - All templates

---

## File Sizes Reference

| Category | Files | Total Size |
|----------|-------|------------|
| Core Python | 3 | ~70KB |
| Templates | 9 | ~140KB |
| Static CSS | 1 | ~28KB |
| Static JS | 1 | ~5KB |
| Scripts | 5 | ~10KB |
| Docs | 4 | ~20KB |
| **Total** | **23** | **~273KB** |

---

## File Modification Guide

### Never Edit Directly:
- ❌ `shadow1834.db` (use scripts)
- ❌ `shadow1834.log` (auto-generated)
- ❌ `__pycache__/` (auto-generated)

### Edit With Care:
- ⚠️ `app.py` (core logic)
- ⚠️ `.gitignore` (version control)
- ⚠️ `requirements.txt` (dependencies)

### Safe to Edit:
- ✅ `static/css/styles.css`
- ✅ `templates/*.html`
- ✅ `static/js/base.js`
- ✅ `docs/*.md`

---

## Common Paths

### Python Imports
```python
# From root directory
from app import create_user, get_user_by_username
from routes import app
```

### Template Inheritance
```html
{% extends "base.html" %}
{% block content %}
...
{% endblock %}
```

### Static Assets
```html
<!-- CSS -->
<link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">

<!-- JavaScript -->
<script src="{{ url_for('static', filename='js/base.js') }}"></script>

<!-- Images -->
<img src="{{ url_for('static', filename='favicon.svg') }}">
```

---

## Directory Permissions

All directories should be readable and executable:
```bash
drwxr-xr-x  static/
drwxr-xr-x  templates/
drwxr-xr-x  scripts/
drwxr-xr-x  docs/
```

Python files should be executable:
```bash
-rwxr-xr-x  app.py
-rwxr-xr-x  routes.py
-rwxr-xr-x  scripts/*.py
```

---

## Backup Recommendations

### Critical Files to Backup:
1. `shadow1834.db` - User data
2. `app.py` - Core logic
3. `routes.py` - Route handlers
4. `static/css/styles.css` - Custom styles
5. `templates/` - All templates

### Can Skip:
- `shadow1834.log` (logs)
- `__pycache__/` (cache)
- `.venv/` (virtual environment)

---

## Version Control

### Tracked by Git:
✅ All Python files
✅ All templates
✅ All static assets
✅ Documentation
✅ Configuration files

### Ignored by Git:
❌ `__pycache__/`
❌ `*.db`
❌ `*.log`
❌ `.venv/`
❌ IDE files

---

## Quick Reference Commands

```bash
# List all files
ls -la

# List by directory
ls static/
ls templates/
ls scripts/
ls docs/

# Find file
find . -name "*.py"

# Count files
ls -1 | wc -l

# Check file size
du -h app.py

# View structure
tree -L 2
```

---

## Best Practices

### DO:
✅ Keep scripts in `scripts/`
✅ Keep docs in `docs/`
✅ Use descriptive filenames
✅ Follow naming conventions
✅ Document changes

### DON'T:
❌ Mix concerns (scripts in root)
❌ Commit generated files
❌ Edit database directly
❌ Ignore .gitignore
❌ Skip documentation

---

**Last Updated:** October 9, 2025
**Structure Version:** 2.0 (Post-Cleanup)

For detailed information, see [PROJECT_STRUCTURE.md](../PROJECT_STRUCTURE.md)
