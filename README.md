# Shadow1834 - Cybersecurity Training Platform

🎯 **Mission-based cybersecurity training platform with gamification and progressive learning**

![Status](https://img.shields.io/badge/status-active-success)
![Tests](https://img.shields.io/badge/tests-37%20passed-success)
![Python](https://img.shields.io/badge/python-3.13-blue)
![Flask](https://img.shields.io/badge/flask-3.0.0-blue)

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Application
```bash
py app.py
```

### 3. Access Application
Open browser: `http://localhost:5000`

### 4. Create Admin Account (Optional)
```bash
py scripts/create_admin.py
```

## ✨ Features

### 🎓 Training Modules
- **5 Progressive Modules** - Hook the Phish, Hunt the Trojan, Password Bootcamp, Firewall Frenzy, Defend the Net
- **Level-Based Access** - Unlock modules as you progress
- **Multiple Choice Questions** - Interactive learning
- **Real-Time Feedback** - Instant explanations
- **Badge Rewards** - Earn achievements

### 👥 User Management
- **Secure Registration** - Password validation and bcrypt hashing
- **User Profiles** - Track progress and achievements
- **Leaderboard** - Compete with other agents
- **Activity Tracking** - Monitor active players
- **Level Progression** - Unlock higher-level content

### 🔐 Admin Panel
- **User CRUD** - Create, read, update, delete users
- **Privilege Management** - Grant/revoke admin access
- **Badge Management** - Assign achievements
- **Score Control** - Adjust user points
- **Statistics Dashboard** - View system metrics

### 🛡️ Security Features
- ✅ Bcrypt password hashing
- ✅ Account lockout (5 failed attempts)
- ✅ Session timeout (30 minutes)
- ✅ Password strength validation
- ✅ SQL injection prevention
- ✅ XSS protection

### 🎨 UI/UX
- ✅ Cyber-security themed design
- ✅ Responsive layout (mobile-friendly)
- ✅ Animated navigation with glowing effects
- ✅ Real-time progress tracking
- ✅ Interactive dashboards

## 📁 Project Structure

```
Shadow/
├── app.py                  # Core application logic
├── routes.py               # Flask route handlers
├── comprehensive_tests.py  # Test suite (37 tests)
├── static/                 # CSS, JS, images
├── templates/              # HTML templates
├── scripts/                # Utility scripts
├── docs/                   # Documentation
└── PROJECT_STRUCTURE.md    # Detailed structure guide
```

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for complete details.

## 🧪 Testing

Run the complete test suite:
```bash
py comprehensive_tests.py
```

**Test Coverage:**
- 37 tests covering all major functionality
- Database initialization
- User authentication
- Module access control
- Scoring system
- Data integrity
- Edge cases

## 🔧 Admin Tools

Located in `scripts/` directory:

### Check Admin Status
```bash
py scripts/check_admin.py
```

### Create Admin User
```bash
py scripts/create_admin.py
```

### Grant Admin Privileges
```bash
py scripts/set_admin_privileges.py
```

### Test Admin Access
```bash
py scripts/test_admin_access.py
```

## 📚 Documentation

- **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** - Complete project structure guide
- **[docs/ADMIN_CREDENTIALS.txt](docs/ADMIN_CREDENTIALS.txt)** - Admin credentials and capabilities
- **[docs/QUICK_START_ADMIN.md](docs/QUICK_START_ADMIN.md)** - Admin quick reference
- **[docs/NAVIGATION_IMPROVEMENTS.md](docs/NAVIGATION_IMPROVEMENTS.md)** - UI improvements log

## 🎯 Training Modules

### Level 1 - Hook the Phish (100 pts)
Learn to identify phishing attempts and social engineering tactics.

### Level 2 - Hunt the Trojan (120 pts)
Detect and eliminate malware threats before they compromise systems.

### Level 3 - Password Bootcamp (150 pts)
Master the creation and management of ultra-secure passwords.

### Level 4 - Firewall Frenzy (180 pts)
Deploy advanced network security and firewall configurations.

### Level 5 - Defend the Net (250 pts)
Ultimate cybersecurity challenge - prove your mastery.

## 🏆 Achievement System

- **Perfect Score** - Complete module with 100% accuracy (+50 bonus)
- **Streak Master** - Answer 3+ questions correctly in a row (+5 per question)
- **First Mission** - Complete your first training module (+25 bonus)
- **Badge Collection** - Earn badges for each completed module

## 👤 Default Admin Credentials

**Username:** `admin`
**Password:** See `docs/ADMIN_CREDENTIALS.txt`

⚠️ **Change default password after first login!**

## 🔨 Technology Stack

- **Backend:** Python 3.13, Flask 3.0.0
- **Database:** SQLite3
- **Authentication:** bcrypt
- **Frontend:** HTML5, CSS3 (Grid/Flexbox), JavaScript
- **Styling:** Custom cyber-security theme

## 🌐 Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Landing/login page |
| `/register` | GET, POST | User registration |
| `/login` | POST | User authentication |
| `/logout` | GET | Session termination |
| `/dashboard` | GET | Main command center |
| `/module/<id>` | GET | Training module |
| `/submit/<id>` | POST | Module submission |
| `/leaderboard` | GET | User rankings |
| `/profile` | GET | User profile |
| `/admin` | GET | Admin panel (admin only) |
| `/admin/user/<id>/edit` | POST | Edit user (admin only) |
| `/admin/user/<id>/delete` | POST | Delete user (admin only) |

## 📊 Database Schema

### Users Table
- User authentication and profile data
- Score and level tracking
- Badges and achievements
- Admin privileges flag

### User Sessions Table
- Module completion history
- Score records
- Time tracking

### Activity Log Table
- User activity monitoring
- Login/logout tracking
- Module access logs

## 🐛 Troubleshooting

### Database Issues
```bash
# Reinitialize database
py app.py
```

### Admin Access Problems
```bash
# Check admin status
py scripts/check_admin.py

# Reset admin privileges
py scripts/set_admin_privileges.py
```

### Test Failures
```bash
# Run comprehensive tests
py comprehensive_tests.py
```

### Log Files
Check `shadow1834.log` for detailed error messages.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License.

## 🎓 Educational Purpose

Shadow1834 is designed for **educational cybersecurity training** and **security awareness**.

**NOT FOR:** Malicious activities, unauthorized access, or credential harvesting.

## 📧 Support

For issues or questions:
1. Check documentation in `docs/` directory
2. Review `shadow1834.log` for errors
3. Run `py comprehensive_tests.py` for system health check
4. Create GitHub issue with details

## 🌟 Acknowledgments

Built with passion for cybersecurity education and gamified learning.

---

**Made with 💙 by the Shadow1834 Team**

🎮 *Train. Learn. Defend.*
