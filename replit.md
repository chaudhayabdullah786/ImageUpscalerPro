# Single-Page Website with Admin Panel

## Overview
A lightweight, responsive single-page website built with pure HTML5 and CSS3, combined with a Flask backend admin panel for managing website content. No CMS or heavy frameworks—just clean, fast code.

## Project Structure
```
/
├── app.py                    # Flask backend with admin functionality
├── templates/
│   ├── index.html           # Main website page
│   ├── admin_login.html     # Admin login page
│   └── admin_dashboard.html # Admin content editor
├── static/
│   ├── styles.css           # Main website styles
│   ├── admin.css            # Admin panel styles
│   └── admin.js             # Admin panel interactivity
├── website.db               # SQLite database (auto-created)
└── replit.md                # Project documentation
```

## Features

### Frontend Website
- Semantic HTML5 with clean structure
- Responsive CSS3 design (mobile, tablet, desktop)
- Smooth scroll navigation
- CSS-only hamburger menu
- No external dependencies
- Fast page load times

### Admin Panel
- Secure login system (default: admin/admin123)
- Real-time content editing (Hero, About, Contact sections)
- Auto-save functionality
- Clean, intuitive admin interface
- SQLite database for persistent storage

## Getting Started

### Running the App
The Flask app automatically starts on port 5000. Just visit the root URL to see your website.

### Accessing the Admin Panel
1. Navigate to `/admin/login`
2. Login with:
   - **Username:** admin
   - **Password:** admin123
3. Edit website content in real-time

## Admin Features

### Content Sections Available
- **Hero Section:** Main banner title and subtitle
- **About Section:** Section title and two paragraphs
- **Contact Section:** Section title and subtitle

### How It Works
1. Edit any field in the admin dashboard
2. Changes auto-save to the database
3. Refresh the website to see updates
4. All changes persist in the SQLite database

## Customization

### Changing Admin Credentials
Edit `app.py` line 49 to change the default admin password:
```python
cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ('admin', generate_password_hash('NEW_PASSWORD_HERE')))
```

### Adding New Content Sections
1. Add new fields in the `default_content` dictionary (line 51-64)
2. Add HTML fields in `templates/admin_dashboard.html`
3. Add corresponding form fields with `data-section` and `data-key` attributes

### Changing Colors
Edit CSS variables in `static/styles.css` `:root` section:
```css
:root {
    --primary-color: #6366f1;    /* Main brand color */
    --primary-dark: #4f46e5;     /* Darker variant */
    --secondary-color: #1e293b;  /* Text color */
}
```

## Database Schema

### Content Table
```sql
- id: Primary key
- section_id: Section name (hero, about, contact)
- content_key: Field name (title, subtitle, text1, etc.)
- content_value: The actual content text
- content_type: Type of content (text, textarea)
- updated_at: Last modification timestamp
```

### Admins Table
```sql
- id: Primary key
- username: Admin username
- password: Hashed password
- created_at: Account creation timestamp
```

## Security Notes
- Default admin credentials should be changed in production
- Use environment variable for SESSION_SECRET
- Database stores passwords hashed with werkzeug security
- Session-based authentication protects admin routes

## Performance
- Pure HTML/CSS with minimal JavaScript
- SQLite database for lightweight storage
- No external API calls
- No framework bloat—just Flask essentials
- Optimized asset delivery with Flask static files

## Recent Changes
- December 2024: Complete website with admin panel built
- Flask backend with SQLite database
- Admin login and content management system
- Real-time content updates on live website

## API Endpoints

### Public Routes
- `GET /` - Main website
- `GET /api/content` - Get all website content as JSON
- `GET /admin/login` - Admin login page
- `POST /admin/login` - Submit admin credentials

### Admin Routes (Requires Authentication)
- `GET /admin` - Admin dashboard
- `GET /admin/logout` - Logout
- `POST /api/admin/content` - Update content (JSON)

## Deployment Notes
When deploying to production:
1. Set `SESSION_SECRET` environment variable
2. Change default admin credentials
3. Use a production WSGI server (gunicorn, etc.)
4. Set Flask `debug=False`
5. Configure proper database backups

