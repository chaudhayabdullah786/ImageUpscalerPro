import os
import uuid
import json
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from PIL import Image
import io

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'imageupscaler-dev-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'

DATABASE = 'imageupscaler.db'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'tiff'}
ALLOWED_MIMES = {'image/png', 'image/jpeg', 'image/webp', 'image/tiff'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login_at TEXT,
        is_active INTEGER DEFAULT 1
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS uploads (
        id TEXT PRIMARY KEY,
        owner_id INTEGER,
        original_filename TEXT,
        storage_path TEXT,
        mime_type TEXT,
        size_bytes INTEGER,
        width INTEGER,
        height INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        upload_id TEXT,
        owner_id INTEGER,
        status TEXT DEFAULT 'queued',
        progress INTEGER DEFAULT 0,
        params TEXT,
        model TEXT,
        worker_id TEXT,
        error_message TEXT,
        result_path TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        started_at TEXT,
        finished_at TEXT,
        duration_seconds INTEGER,
        FOREIGN KEY (upload_id) REFERENCES uploads(id),
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS models (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        type TEXT,
        artifact_path TEXT,
        default_params TEXT,
        gpu_required INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        note TEXT
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        entity_type TEXT,
        entity_id TEXT,
        details TEXT,
        ip_address TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    
    cursor.execute("SELECT * FROM users WHERE username = 'abdullah'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ('abdullah', 'admin@imageupscaler.pro', generate_password_hash('231980077'), 'admin')
        )
    
    default_settings = {
        'max_upload_size_bytes': '15728640',
        'allowed_mimes': 'image/png,image/jpeg,image/webp,image/tiff',
        'default_model': 'bicubic',
        'rate_limit_per_minute': '10',
        'retention_days': '30'
    }
    for key, value in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
    
    default_models = [
        ('bicubic', 'builtin', None, '{"quality": "high"}', 0, 'Built-in bicubic interpolation'),
        ('lanczos', 'builtin', None, '{"quality": "high"}', 0, 'Built-in Lanczos resampling'),
    ]
    for model in default_models:
        cursor.execute("INSERT OR IGNORE INTO models (name, type, artifact_path, default_params, gpu_required, note) VALUES (?, ?, ?, ?, ?, ?)", model)
    
    db.commit()
    db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        if session.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def log_audit(user_id, action, entity_type, entity_id, details=None, ip_address=None):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, action, entity_type, entity_id, json.dumps(details) if details else None, ip_address)
    )
    db.commit()
    db.close()

def process_image(job_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("UPDATE jobs SET status = 'running', started_at = ? WHERE job_id = ?", 
                   (datetime.utcnow().isoformat(), job_id))
    db.commit()
    
    cursor.execute('''
        SELECT j.*, u.storage_path, u.original_filename 
        FROM jobs j 
        JOIN uploads u ON j.upload_id = u.id 
        WHERE j.job_id = ?
    ''', (job_id,))
    job = cursor.fetchone()
    
    if not job:
        db.close()
        return
    
    try:
        params = json.loads(job['params']) if job['params'] else {}
        factor = int(params.get('factor', '2').replace('x', ''))
        denoise = params.get('denoise', 'none')
        
        img = Image.open(job['storage_path'])
        
        if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
            img = img.convert('RGBA')
        else:
            img = img.convert('RGB')
        
        new_width = img.width * factor
        new_height = img.height * factor
        
        cursor.execute("UPDATE jobs SET progress = 25 WHERE job_id = ?", (job_id,))
        db.commit()
        
        upscaled = img.resize((new_width, new_height), Image.LANCZOS)
        
        cursor.execute("UPDATE jobs SET progress = 75 WHERE job_id = ?", (job_id,))
        db.commit()
        
        if denoise in ['low', 'med', 'high']:
            from PIL import ImageFilter
            blur_radius = {'low': 0.5, 'med': 1.0, 'high': 1.5}.get(denoise, 0)
            if blur_radius > 0:
                upscaled = upscaled.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                upscaled = upscaled.filter(ImageFilter.UnsharpMask(radius=2, percent=150, threshold=3))
        
        result_filename = f"upscaled_{job_id}.png"
        result_path = os.path.join(app.config['RESULT_FOLDER'], result_filename)
        upscaled.save(result_path, 'PNG', optimize=True)
        
        finished_at = datetime.utcnow()
        started_at = datetime.fromisoformat(job['started_at']) if job['started_at'] else finished_at
        duration = int((finished_at - started_at).total_seconds())
        
        cursor.execute('''
            UPDATE jobs 
            SET status = 'completed', progress = 100, result_path = ?, 
                finished_at = ?, duration_seconds = ?, model = 'lanczos'
            WHERE job_id = ?
        ''', (result_path, finished_at.isoformat(), duration, job_id))
        db.commit()
        
    except Exception as e:
        cursor.execute('''
            UPDATE jobs 
            SET status = 'failed', error_message = ?, finished_at = ?
            WHERE job_id = ?
        ''', (str(e), datetime.utcnow().isoformat(), job_id))
        db.commit()
    
    db.close()

@app.route('/')
def index():
    return render_template('public/index.html')

@app.route('/upload')
def upload_page():
    return render_template('public/upload.html')

@app.route('/job/<job_id>')
def job_status_page(job_id):
    return render_template('public/job_status.html', job_id=job_id)

@app.route('/api/v1/uploads', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    factor = request.form.get('factor', '2x')
    if factor not in ['2x', '4x']:
        return jsonify({'error': 'Invalid upscale factor'}), 400
    
    preset = request.form.get('preset', 'standard')
    denoise = request.form.get('denoise', 'none')
    refine_faces = request.form.get('refine_faces', 'false') == 'true'
    
    upload_id = str(uuid.uuid4())
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'png'
    storage_filename = f"{upload_id}.{ext}"
    storage_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_filename)
    
    file.save(storage_path)
    
    try:
        with Image.open(storage_path) as img:
            width, height = img.size
    except Exception as e:
        os.remove(storage_path)
        return jsonify({'error': 'Invalid image file'}), 400
    
    file_size = os.path.getsize(storage_path)
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        INSERT INTO uploads (id, original_filename, storage_path, mime_type, size_bytes, width, height)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (upload_id, filename, storage_path, file.content_type, file_size, width, height))
    
    params = {
        'factor': factor,
        'preset': preset,
        'denoise': denoise,
        'refine_faces': refine_faces
    }
    
    cursor.execute('''
        INSERT INTO jobs (job_id, upload_id, status, params, created_at)
        VALUES (?, ?, 'queued', ?, ?)
    ''', (job_id, upload_id, json.dumps(params), datetime.utcnow().isoformat()))
    
    db.commit()
    db.close()
    
    thread = threading.Thread(target=process_image, args=(job_id,))
    thread.start()
    
    return jsonify({
        'job_id': job_id,
        'status': 'queued',
        'created_at': datetime.utcnow().isoformat(),
        'estimated_seconds': 10
    }), 202

@app.route('/api/v1/jobs/<job_id>')
def api_job_status(job_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT j.*, u.original_filename, u.storage_path as original_path, u.width as orig_width, u.height as orig_height
        FROM jobs j
        LEFT JOIN uploads u ON j.upload_id = u.id
        WHERE j.job_id = ?
    ''', (job_id,))
    
    job = cursor.fetchone()
    db.close()
    
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    response = {
        'job_id': job['job_id'],
        'status': job['status'],
        'progress': job['progress'],
        'created_at': job['created_at'],
        'started_at': job['started_at'],
        'finished_at': job['finished_at'],
        'duration_seconds': job['duration_seconds'],
        'params': json.loads(job['params']) if job['params'] else {},
        'model': job['model'],
        'error': job['error_message']
    }
    
    if job['status'] == 'completed' and job['result_path']:
        response['result_url'] = f"/results/{os.path.basename(job['result_path'])}"
        response['original_url'] = f"/uploads/{os.path.basename(job['original_path'])}"
    
    return jsonify(response)

@app.route('/api/v1/health')
def api_health():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'")
    queued = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM jobs WHERE status = 'running'")
    running = cursor.fetchone()[0]
    db.close()
    
    return jsonify({
        'status': 'ok',
        'queue_length': queued,
        'jobs_running': running,
        'workers_online': 1
    })

@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/results/<filename>')
def serve_result(filename):
    return send_from_directory(app.config['RESULT_FOLDER'], filename)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            cursor.execute("UPDATE users SET last_login_at = ? WHERE id = ?", 
                          (datetime.utcnow().isoformat(), user['id']))
            db.commit()
            
            log_audit(user['id'], 'login', 'user', str(user['id']), None, request.remote_addr)
            db.close()
            return redirect(url_for('admin_dashboard'))
        
        db.close()
        return render_template('admin/login.html', error='Invalid credentials')
    
    return render_template('admin/login.html')

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'")
    queued_jobs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM jobs WHERE status = 'running'")
    running_jobs = cursor.fetchone()[0]
    
    today = datetime.utcnow().date().isoformat()
    cursor.execute("SELECT COUNT(*) FROM jobs WHERE status = 'completed' AND DATE(created_at) = ?", (today,))
    completed_today = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(duration_seconds) FROM jobs WHERE status = 'completed' AND duration_seconds IS NOT NULL")
    avg_time = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM uploads")
    total_uploads = cursor.fetchone()[0]
    
    cursor.execute("SELECT SUM(size_bytes) FROM uploads")
    total_storage = cursor.fetchone()[0] or 0
    
    cursor.execute('''
        SELECT j.*, u.original_filename 
        FROM jobs j 
        LEFT JOIN uploads u ON j.upload_id = u.id 
        ORDER BY j.created_at DESC LIMIT 10
    ''')
    recent_jobs = cursor.fetchall()
    
    db.close()
    
    return render_template('admin/dashboard.html', 
                          queued_jobs=queued_jobs,
                          running_jobs=running_jobs,
                          completed_today=completed_today,
                          avg_time=round(avg_time, 1),
                          total_uploads=total_uploads,
                          total_storage=round(total_storage / (1024*1024), 2),
                          recent_jobs=recent_jobs)

@app.route('/admin/jobs')
@admin_required
def admin_jobs():
    db = get_db()
    cursor = db.cursor()
    
    status_filter = request.args.get('status', '')
    
    if status_filter:
        cursor.execute('''
            SELECT j.*, u.original_filename 
            FROM jobs j 
            LEFT JOIN uploads u ON j.upload_id = u.id 
            WHERE j.status = ?
            ORDER BY j.created_at DESC
        ''', (status_filter,))
    else:
        cursor.execute('''
            SELECT j.*, u.original_filename 
            FROM jobs j 
            LEFT JOIN uploads u ON j.upload_id = u.id 
            ORDER BY j.created_at DESC
        ''')
    
    jobs = cursor.fetchall()
    db.close()
    
    return render_template('admin/jobs.html', jobs=jobs, status_filter=status_filter)

@app.route('/admin/jobs/<job_id>')
@admin_required
def admin_job_detail(job_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT j.*, u.original_filename, u.storage_path, u.width, u.height, u.size_bytes, u.mime_type
        FROM jobs j
        LEFT JOIN uploads u ON j.upload_id = u.id
        WHERE j.job_id = ?
    ''', (job_id,))
    
    job = cursor.fetchone()
    db.close()
    
    if not job:
        return redirect(url_for('admin_jobs'))
    
    return render_template('admin/job_detail.html', job=job)

@app.route('/api/v1/admin/jobs/<job_id>/cancel', methods=['POST'])
@admin_required
def api_cancel_job(job_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE jobs SET status = 'canceled' WHERE job_id = ? AND status IN ('queued', 'running')", (job_id,))
    db.commit()
    
    log_audit(session.get('user_id'), 'cancel_job', 'job', job_id, None, request.remote_addr)
    db.close()
    
    return jsonify({'success': True})

@app.route('/api/v1/admin/jobs/<job_id>/requeue', methods=['POST'])
@admin_required
def api_requeue_job(job_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
    old_job = cursor.fetchone()
    
    if not old_job:
        db.close()
        return jsonify({'error': 'Job not found'}), 404
    
    new_job_id = f"job_{uuid.uuid4().hex[:12]}"
    cursor.execute('''
        INSERT INTO jobs (job_id, upload_id, owner_id, status, params, created_at)
        VALUES (?, ?, ?, 'queued', ?, ?)
    ''', (new_job_id, old_job['upload_id'], old_job['owner_id'], old_job['params'], datetime.utcnow().isoformat()))
    
    db.commit()
    
    log_audit(session.get('user_id'), 'requeue_job', 'job', job_id, {'new_job_id': new_job_id}, request.remote_addr)
    db.close()
    
    thread = threading.Thread(target=process_image, args=(new_job_id,))
    thread.start()
    
    return jsonify({'success': True, 'new_job_id': new_job_id})

@app.route('/admin/settings')
@admin_required
def admin_settings():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM settings")
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    
    cursor.execute("SELECT * FROM models ORDER BY name")
    models = cursor.fetchall()
    db.close()
    
    return render_template('admin/settings.html', settings=settings, models=models)

@app.route('/api/v1/admin/settings', methods=['POST'])
@admin_required
def api_update_settings():
    data = request.get_json()
    
    db = get_db()
    cursor = db.cursor()
    
    for key, value in data.items():
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    
    db.commit()
    log_audit(session.get('user_id'), 'update_settings', 'settings', None, data, request.remote_addr)
    db.close()
    
    return jsonify({'success': True})

@app.route('/admin/audit')
@admin_required
def admin_audit():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT a.*, u.username 
        FROM audit_logs a 
        LEFT JOIN users u ON a.user_id = u.id 
        ORDER BY a.created_at DESC 
        LIMIT 100
    ''')
    logs = cursor.fetchall()
    db.close()
    
    return render_template('admin/audit.html', logs=logs)

@app.route('/admin/logout')
def admin_logout():
    if 'user_id' in session:
        log_audit(session.get('user_id'), 'logout', 'user', str(session.get('user_id')), None, request.remote_addr)
    session.clear()
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
