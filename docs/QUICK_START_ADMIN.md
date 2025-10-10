# Shadow1834 - Admin Quick Start Guide

## 🔐 Admin Credentials

```
Username: admin
Password: kJDaW^0jZ&lIK^2g
```

**⚠️ SAVE THESE CREDENTIALS SECURELY!**

---

## 🚀 Quick Start (3 Steps)

### Step 1: Start the Application
```bash
py app.py
```

### Step 2: Login
1. Open browser: `http://localhost:5000`
2. Enter username: `admin`
3. Enter password: `kJDaW^0jZ&lIK^2g`
4. Click LOGIN

### Step 3: Access Admin Panel
- Click the **"ADMIN"** link in the navigation bar (top right)
- Or navigate directly to: `http://localhost:5000/admin`

---

## ✅ What You Can Do

### User Management
- ✓ **View all users** - Complete list with stats
- ✓ **Edit users** - Change username, email, score, level
- ✓ **Delete users** - Remove accounts (with confirmation)
- ✓ **Grant admin access** - Make other users admins
- ✓ **Manage badges** - Add/remove user achievements

### System Administration
- ✓ **Monitor activity** - Track user logins and actions
- ✓ **View statistics** - Total users, admin count
- ✓ **Manage levels** - Set user access levels
- ✓ **Control scores** - Adjust user points

---

## 📋 Admin Panel Features

When you access `/admin`, you'll see:

1. **Statistics Dashboard**
   - Total user count
   - Number of administrators

2. **User Management Table**
   - All users with full details
   - Edit/Delete actions for each user

3. **Edit User Form**
   - Update username, email, score, level
   - Toggle admin privileges
   - Save changes instantly

---

## 🔒 Security Features

- ✓ Password hashed with bcrypt
- ✓ Admin-only route protection
- ✓ Cannot delete your own account
- ✓ All actions logged
- ✓ Session timeout (30 minutes)
- ✓ Account lockout after 5 failed attempts

---

## 🛠️ Troubleshooting

### Can't see Admin link?
```bash
py check_admin.py
```
Should show: `is_admin: 1`

### Can't login?
- Check password is exactly: `kJDaW^0jZ&lIK^2g`
- Username is: `admin` (lowercase)
- Clear browser cache

### Reset Password?
```bash
py set_admin_privileges.py
```
Generates new password and displays it

### Test Admin Access?
```bash
py test_admin_access.py
```
Verifies all admin functionality

---

## 📁 Important Files

- `ADMIN_CREDENTIALS.txt` - Full admin documentation
- `templates/admin.html` - Admin panel interface
- `app.py` - Admin functions (lines 726-823)
- `routes.py` - Admin routes (lines 403-492)

---

## 🎯 Common Admin Tasks

### Make Another User Admin
1. Go to `/admin`
2. Find the user in the table
3. Click "Edit"
4. Check "Admin Privileges" box
5. Click "Save Changes"

### Adjust User Level
1. Go to `/admin`
2. Click "Edit" on user
3. Change "Level" field
4. Click "Save Changes"

### Delete Inactive User
1. Go to `/admin`
2. Click "Delete" on user
3. Confirm deletion
4. User removed permanently

### View User Details
All visible in the table:
- Username, email, score, level
- Badges earned, join date
- Last login time, admin status

---

## 💡 Tips

- **Admin link** appears only for admin users in navigation
- **Cannot delete self** - safety feature prevents accidents
- **Edit any field** - or leave blank to keep current value
- **Grant admin carefully** - other admins have full access
- **Check logs** - All actions recorded in `shadow1834.log`

---

## 📞 Need Help?

1. Check `shadow1834.log` for errors
2. Run `py check_admin.py` to verify status
3. Run `py test_admin_access.py` to test functionality
4. See `ADMIN_CREDENTIALS.txt` for full documentation

---

**You now have complete administrative access to Shadow1834!** 🎉
