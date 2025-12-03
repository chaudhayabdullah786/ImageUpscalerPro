from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import json
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')
DATABASE = 'website.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS content (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        section_id TEXT NOT NULL,
        content_key TEXT NOT NULL,
        content_value TEXT NOT NULL,
        content_type TEXT DEFAULT 'text',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(section_id, content_key)
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        section_id TEXT NOT NULL,
        image_name TEXT NOT NULL,
        image_path TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    cursor.execute("SELECT * FROM admins WHERE username = 'admin'")
    if not cursor.fetchone():
        default_password = generate_password_hash('admin123')
        cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ('admin', default_password))
    
    default_content = {
        'hero': {
            'title': 'Welcome to Our Website',
            'subtitle': 'We create beautiful, fast, and responsive web experiences'
        },
        'about': {
            'title': 'About Us',
            'text1': 'We are a team of passionate developers dedicated to creating lightweight, high-performance websites. Our focus is on clean code, modern design, and exceptional user experiences.',
            'text2': 'With years of experience in web development, we understand the importance of speed, accessibility, and responsive design. We build websites that work seamlessly across all devices and browsers.'
        },
        'contact': {
            'title': 'Get In Touch',
            'subtitle': 'Ready to start your project? Reach out to us and let\'s create something amazing together.'
        }
    }
    
    for section, fields in default_content.items():
        for key, value in fields.items():
            cursor.execute("SELECT * FROM content WHERE section_id = ? AND content_key = ?", (section, key))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO content (section_id, content_key, content_value, content_type) VALUES (?, ?, ?, ?)",
                    (section, key, value, 'text')
                )
    
    db.commit()
    db.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content")
    content_rows = cursor.fetchall()
    db.close()
    
    content = {}
    for row in content_rows:
        section = row['section_id']
        if section not in content:
            content[section] = {}
        content[section][row['content_key']] = row['content_value']
    
    return render_template('index.html', content=content)

@app.route('/api/content')
def get_content():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content")
    content_rows = cursor.fetchall()
    db.close()
    
    content = {}
    for row in content_rows:
        section = row['section_id']
        if section not in content:
            content[section] = {}
        content[section][row['content_key']] = row['content_value']
    
    return jsonify(content)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid credentials'), 401
    
    return render_template('admin_login.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content ORDER BY section_id")
    content_rows = cursor.fetchall()
    db.close()
    
    content = {}
    for row in content_rows:
        section = row['section_id']
        if section not in content:
            content[section] = {}
        content[section][row['content_key']] = row['content_value']
    
    return render_template('admin_dashboard.html', content=content)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/api/admin/content', methods=['POST'])
@login_required
def update_content():
    data = request.get_json()
    section_id = data.get('section_id')
    content_key = data.get('content_key')
    content_value = data.get('content_value')
    
    if not all([section_id, content_key, content_value]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute(
        "UPDATE content SET content_value = ?, updated_at = CURRENT_TIMESTAMP WHERE section_id = ? AND content_key = ?",
        (content_value, section_id, content_key)
    )
    
    if cursor.rowcount == 0:
        cursor.execute(
            "INSERT INTO content (section_id, content_key, content_value, content_type) VALUES (?, ?, ?, ?)",
            (section_id, content_key, content_value, 'text')
        )
    
    db.commit()
    db.close()
    
    return jsonify({'success': True, 'message': 'Content updated successfully'})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
