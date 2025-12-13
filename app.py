# app.py — Postgres (Neon) merged version with SQLite fallback
import os
import uuid
import json
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image

# DB drivers will be imported dynamically in get_db
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'imageupscaler-dev-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# ---------------- Database configuration (Postgres Neon) ----------------
# Replace / override using DATABASE_URL env var in production
DEFAULT_DATABASE_URL = "postgresql://neondb_owner:npg_usq4SrpaY5BC@ep-blue-field-ah4fge52-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
DATABASE_URL = os.environ.get('DATABASE_URL', DEFAULT_DATABASE_URL)

# driver detection flags
_USE_PG = False
_PG_DRIVER = None  # "psycopg" or "psycopg2"
try:
    import psycopg  # psycopg v3
    _USE_PG = True
    _PG_DRIVER = "psycopg"
    # psycopg rows factory will be used later
except Exception:
    try:
        import psycopg2
        import psycopg2.extras
        _USE_PG = True
        _PG_DRIVER = "psycopg2"
    except Exception:
        _USE_PG = False
        _PG_DRIVER = None

# If Postgres driver not available or DATABASE_URL explicitly set to sqlite://..., fallback to local sqlite file
USE_SQLITE_FALLBACK = False
if not _USE_PG:
    print("[WARNING] No Postgres driver detected (psycopg / psycopg2). Falling back to local SQLite.")
    USE_SQLITE_FALLBACK = True

# If DATABASE_URL begins with sqlite:, force sqlite mode
if DATABASE_URL.startswith("sqlite"):
    USE_SQLITE_FALLBACK = True

# For sqlite local filename (used when fallback)
SQLITE_FILE = 'imageupscaler.db'
# -------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'tiff'}
ALLOWED_MIMES = {'image/png', 'image/jpeg', 'image/webp', 'image/tiff'}


def get_db():
    """
    Returns a DB connection object and a helper cursor factory so that using code can
    fetch rows as mapping (dict-like). Caller must close connection when done.
    This abstracts between psycopg (v3), psycopg2, and sqlite3.
    """
    if USE_SQLITE_FALLBACK:
        conn = sqlite3.connect(SQLITE_FILE, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # Use Postgres via psycopg (v3) or psycopg2
    if _PG_DRIVER == "psycopg":
        # psycopg v3
        conn = psycopg.connect(DATABASE_URL, autocommit=False)
        # Use dict rows
        conn.row_factory = psycopg.rows.dict_row
        return conn
    else:
        # psycopg2 path
        # create connection using URI if provided, else parse
        conn = psycopg2.connect(dsn=DATABASE_URL)
        # use RealDictCursor when creating cursors
        return conn


def dict_fetchone(cursor):
    """Helper to fetch a single row as dict for psycopg2 or sqlite"""
    row = cursor.fetchone()
    if row is None:
        return None
    # For sqlite3.Row or psycopg.rows.dict_row, row behaves as mapping
    try:
        return dict(row)
    except Exception:
        # psycopg2 cursor with RealDictCursor returns dict already
        return row


def dict_fetchall(cursor):
    rows = cursor.fetchall()
    try:
        return [dict(r) for r in rows]
    except Exception:
        return rows


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# decorators same as before
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
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute(
                "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, action, entity_type, entity_id, json.dumps(details) if details else None, ip_address)
            )
        else:
            # psycopg / psycopg2 use %s placeholders
            cur.execute(
                "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address) VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, action, entity_type, entity_id, json.dumps(details) if details else None, ip_address)
            )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def init_db():
    """
    Create tables. Uses SQL adapted for Postgres but also compatible with sqlite in many cases.
    """
    if USE_SQLITE_FALLBACK:
        conn = sqlite3.connect(SQLITE_FILE)
        cur = conn.cursor()
    else:
        if _PG_DRIVER == "psycopg":
            conn = psycopg.connect(DATABASE_URL)
            cur = conn.cursor()
        else:
            conn = psycopg2.connect(dsn=DATABASE_URL)
            cur = conn.cursor()

    # Use SQL that works in Postgres. For sqlite fallback these statements are mostly compatible.
    try:
        # users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
        """)

        # uploads
        cur.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id TEXT PRIMARY KEY,
            owner_id INTEGER,
            original_filename TEXT,
            storage_path TEXT,
            mime_type TEXT,
            size_bytes BIGINT,
            width INTEGER,
            height INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
        """)

        # jobs
        cur.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            finished_at TIMESTAMP,
            duration_seconds INTEGER,
            FOREIGN KEY (upload_id) REFERENCES uploads(id),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
        """)

        # models
        cur.execute("""
        CREATE TABLE IF NOT EXISTS models (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            type TEXT,
            artifact_path TEXT,
            default_params TEXT,
            gpu_required INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            note TEXT
        )
        """)

        # audit_logs
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            entity_type TEXT,
            entity_id TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # settings
        cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)

        # Insert admin user if not exists (driver-specific query)
        if USE_SQLITE_FALLBACK:
            cur.execute("SELECT * FROM users WHERE username = ?", ('abdullah',))
            exists = cur.fetchone()
            if not exists:
                cur.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                    ('abdullah', 'admin@imageupscaler.pro', generate_password_hash('231980077'), 'admin')
                )
        else:
            cur.execute("SELECT * FROM users WHERE username = %s", ('abdullah',))
            exists = cur.fetchone()
            if not exists:
                cur.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                    ('abdullah', 'admin@imageupscaler.pro', generate_password_hash('231980077'), 'admin')
                )

        # default settings
        default_settings = {
            'max_upload_size_bytes': '15728640',
            'allowed_mimes': 'image/png,image/jpeg,image/webp,image/tiff',
            'default_model': 'bicubic',
            'rate_limit_per_minute': '10',
            'retention_days': '30'
        }
        for key, value in default_settings.items():
            if USE_SQLITE_FALLBACK:
                cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
            else:
                cur.execute("INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING", (key, value))

        # default models
        default_models = [
            ('bicubic', 'builtin', None, '{"quality": "high"}', 0, 'Built-in bicubic interpolation'),
            ('lanczos', 'builtin', None, '{"quality": "high"}', 0, 'Built-in Lanczos resampling'),
        ]
        for model in default_models:
            if USE_SQLITE_FALLBACK:
                cur.execute("INSERT OR IGNORE INTO models (name, type, artifact_path, default_params, gpu_required, note) VALUES (?, ?, ?, ?, ?, ?)", model)
            else:
                cur.execute("INSERT INTO models (name, type, artifact_path, default_params, gpu_required, note) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (name) DO NOTHING", model)

        conn.commit()
    finally:
        cur.close()
        conn.close()


# Image processing helper (same as your original logic, but DB calls use get_db())
def process_image(job_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        # Update status -> running
        if USE_SQLITE_FALLBACK:
            cur.execute("UPDATE jobs SET status = 'running', started_at = ? WHERE job_id = ?", (datetime.utcnow().isoformat(), job_id))
        else:
            cur.execute("UPDATE jobs SET status = 'running', started_at = %s WHERE job_id = %s", (datetime.utcnow().isoformat(), job_id))
        conn.commit()

        # fetch job & upload
        if USE_SQLITE_FALLBACK:
            cur.execute('''
                SELECT j.*, u.storage_path, u.original_filename, u.width as orig_width, u.height as orig_height
                FROM jobs j
                JOIN uploads u ON j.upload_id = u.id
                WHERE j.job_id = ?
            ''', (job_id,))
            job = cur.fetchone()
        else:
            cur.execute('''
                SELECT j.*, u.storage_path, u.original_filename, u.width as orig_width, u.height as orig_height
                FROM jobs j
                JOIN uploads u ON j.upload_id = u.id
                WHERE j.job_id = %s
            ''', (job_id,))
            job = cur.fetchone()
            # psycopg row may be mapping (dict) via dict_row; psycopg2 returns tuple unless RealDictCursor used.
            if job is not None and not isinstance(job, dict):
                # attempt to convert row to dict
                desc = [d[0] for d in cur.description]
                job = dict(zip(desc, job))

        if not job:
            return

        params = json.loads(job['params']) if job.get('params') else {}
        factor_raw = params.get('factor', '2x')
        factor = int(str(factor_raw).replace('x', '')) if factor_raw else 2
        denoise = params.get('denoise', 'none')

        img = Image.open(job['storage_path'])

        if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
            img = img.convert('RGBA')
        else:
            img = img.convert('RGB')

        new_width = img.width * factor
        new_height = img.height * factor

        # progress 25
        if USE_SQLITE_FALLBACK:
            cur.execute("UPDATE jobs SET progress = 25 WHERE job_id = ?", (job_id,))
        else:
            cur.execute("UPDATE jobs SET progress = %s WHERE job_id = %s", (25, job_id))
        conn.commit()

        upscaled = img.resize((new_width, new_height), Image.LANCZOS)

        # progress 75
        if USE_SQLITE_FALLBACK:
            cur.execute("UPDATE jobs SET progress = 75 WHERE job_id = ?", (job_id,))
        else:
            cur.execute("UPDATE jobs SET progress = %s WHERE job_id = %s", (75, job_id))
        conn.commit()

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
        started_at = datetime.fromisoformat(job.get('started_at')) if job.get('started_at') else finished_at
        duration = int((finished_at - started_at).total_seconds()) if started_at else 0

        if USE_SQLITE_FALLBACK:
            cur.execute('''
                UPDATE jobs
                SET status = 'completed', progress = 100, result_path = ?, finished_at = ?, duration_seconds = ?, model = 'lanczos'
                WHERE job_id = ?
            ''', (result_path, finished_at.isoformat(), duration, job_id))
        else:
            cur.execute('''
                UPDATE jobs
                SET status = %s, progress = %s, result_path = %s, finished_at = %s, duration_seconds = %s, model = %s
                WHERE job_id = %s
            ''', ('completed', 100, result_path, finished_at.isoformat(), duration, 'lanczos', job_id))
        conn.commit()

    except Exception as e:
        if USE_SQLITE_FALLBACK:
            cur.execute('''UPDATE jobs SET status = 'failed', error_message = ?, finished_at = ? WHERE job_id = ?''', (str(e), datetime.utcnow().isoformat(), job_id))
        else:
            cur.execute('''UPDATE jobs SET status = %s, error_message = %s, finished_at = %s WHERE job_id = %s''', ('failed', str(e), datetime.utcnow().isoformat(), job_id))
        conn.commit()
    finally:
        cur.close()
        conn.close()


# --- Routes (kept same, but DB interactions use get_db()) ---
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
    except Exception:
        os.remove(storage_path)
        return jsonify({'error': 'Invalid image file'}), 400

    file_size = os.path.getsize(storage_path)

    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute('''
                INSERT INTO uploads (id, original_filename, storage_path, mime_type, size_bytes, width, height)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (upload_id, filename, storage_path, file.content_type, file_size, width, height))
            cur.execute('''
                INSERT INTO jobs (job_id, upload_id, status, params, created_at)
                VALUES (?, ?, 'queued', ?, ?)
            ''', (job_id, upload_id, json.dumps({
                'factor': factor, 'preset': preset, 'denoise': denoise, 'refine_faces': refine_faces
            }), datetime.utcnow().isoformat()))
        else:
            cur.execute('''
                INSERT INTO uploads (id, original_filename, storage_path, mime_type, size_bytes, width, height)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (upload_id, filename, storage_path, file.content_type, file_size, width, height))
            cur.execute('''
                INSERT INTO jobs (job_id, upload_id, status, params, created_at)
                VALUES (%s, %s, %s, %s, %s)
            ''', (job_id, upload_id, 'queued', json.dumps({
                'factor': factor, 'preset': preset, 'denoise': denoise, 'refine_faces': refine_faces
            }), datetime.utcnow().isoformat()))
        conn.commit()
    finally:
        cur.close()
        conn.close()

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
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute('''
                SELECT j.*, u.original_filename, u.storage_path as original_path, u.width as orig_width, u.height as orig_height
                FROM jobs j
                LEFT JOIN uploads u ON j.upload_id = u.id
                WHERE j.job_id = ?
            ''', (job_id,))
            job = cur.fetchone()
            job = dict(job) if job else None
        else:
            cur.execute('''
                SELECT j.*, u.original_filename, u.storage_path as original_path, u.width as orig_width, u.height as orig_height
                FROM jobs j
                LEFT JOIN uploads u ON j.upload_id = u.id
                WHERE j.job_id = %s
            ''', (job_id,))
            job = cur.fetchone()
            if job is not None and not isinstance(job, dict):
                desc = [d[0] for d in cur.description]
                job = dict(zip(desc, job))

        if not job:
            return jsonify({'error': 'Job not found'}), 404

        response = {
            'job_id': job['job_id'],
            'status': job['status'],
            'progress': job['progress'],
            'created_at': job['created_at'],
            'started_at': job.get('started_at'),
            'finished_at': job.get('finished_at'),
            'duration_seconds': job.get('duration_seconds'),
            'params': json.loads(job['params']) if job.get('params') else {},
            'model': job.get('model'),
            'error': job.get('error_message')
        }

        if job.get('status') == 'completed' and job.get('result_path'):
            response['result_url'] = f"/results/{os.path.basename(job['result_path'])}"
            response['original_url'] = f"/uploads/{os.path.basename(job['original_path'])}"

        return jsonify(response)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/health')
def api_health():
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'")
            queued = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'running'")
            running = cur.fetchone()[0]
        else:
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = %s", ('queued',))
            queued = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = %s", ('running',))
            running = cur.fetchone()[0]
        return jsonify({
            'status': 'ok',
            'queue_length': queued,
            'jobs_running': running,
            'workers_online': 1
        })
    finally:
        cur.close()
        conn.close()


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

        conn = get_db()
        cur = conn.cursor()
        try:
            if USE_SQLITE_FALLBACK:
                cur.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
                user = cur.fetchone()
                user = dict(user) if user else None
            else:
                cur.execute("SELECT * FROM users WHERE username = %s AND is_active = 1", (username,))
                user = cur.fetchone()
                if user is not None and not isinstance(user, dict):
                    desc = [d[0] for d in cur.description]
                    user = dict(zip(desc, user))

            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']

                if USE_SQLITE_FALLBACK:
                    cur.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (datetime.utcnow().isoformat(), user['id']))
                else:
                    cur.execute("UPDATE users SET last_login_at = %s WHERE id = %s", (datetime.utcnow().isoformat(), user['id']))
                conn.commit()

                log_audit(user['id'], 'login', 'user', str(user['id']), None, request.remote_addr)
                return redirect(url_for('admin_dashboard'))

            return render_template('admin/login.html', error='Invalid credentials')
        finally:
            cur.close()
            conn.close()

    return render_template('admin/login.html')


@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'")
            queued_jobs = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'running'")
            running_jobs = cur.fetchone()[0]
            today = datetime.utcnow().date().isoformat()
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'completed' AND DATE(created_at) = ?", (today,))
            completed_today = cur.fetchone()[0]
            cur.execute("SELECT AVG(duration_seconds) FROM jobs WHERE status = 'completed' AND duration_seconds IS NOT NULL")
            avg_time = cur.fetchone()[0] or 0
            cur.execute("SELECT COUNT(*) FROM uploads")
            total_uploads = cur.fetchone()[0]
            cur.execute("SELECT SUM(size_bytes) FROM uploads")
            total_storage = cur.fetchone()[0] or 0
            cur.execute('''SELECT j.*, u.original_filename FROM jobs j LEFT JOIN uploads u ON j.upload_id = u.id ORDER BY j.created_at DESC LIMIT 10''')
            recent_jobs = cur.fetchall()
            recent_jobs = [dict(r) for r in recent_jobs]
        else:
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = %s", ('queued',))
            queued_jobs = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = %s", ('running',))
            running_jobs = cur.fetchone()[0]
            today = datetime.utcnow().date().isoformat()
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status = %s AND DATE(created_at) = %s", ('completed', today))
            completed_today = cur.fetchone()[0]
            cur.execute("SELECT AVG(duration_seconds) FROM jobs WHERE status = %s AND duration_seconds IS NOT NULL", ('completed',))
            avg_time = cur.fetchone()[0] or 0
            cur.execute("SELECT COUNT(*) FROM uploads")
            total_uploads = cur.fetchone()[0]
            cur.execute("SELECT SUM(size_bytes) FROM uploads")
            total_storage = cur.fetchone()[0] or 0
            cur.execute('''SELECT j.*, u.original_filename FROM jobs j LEFT JOIN uploads u ON j.upload_id = u.id ORDER BY j.created_at DESC LIMIT 10''')
            rows = cur.fetchall()
            # convert to list of dicts
            desc = [d[0] for d in cur.description]
            recent_jobs = [dict(zip(desc, r)) for r in rows]

        return render_template('admin/dashboard.html',
                              queued_jobs=queued_jobs,
                              running_jobs=running_jobs,
                              completed_today=completed_today,
                              avg_time=round(avg_time, 1),
                              total_uploads=total_uploads,
                              total_storage=round(total_storage / (1024*1024), 2),
                              recent_jobs=recent_jobs)
    finally:
        cur.close()
        conn.close()


@app.route('/admin/jobs')
@admin_required
def admin_jobs():
    status_filter = request.args.get('status', '')
    conn = get_db()
    cur = conn.cursor()
    try:
        if status_filter:
            if USE_SQLITE_FALLBACK:
                cur.execute('''
                    SELECT j.*, u.original_filename
                    FROM jobs j
                    LEFT JOIN uploads u ON j.upload_id = u.id
                    WHERE j.status = ?
                    ORDER BY j.created_at DESC
                ''', (status_filter,))
                rows = cur.fetchall()
                jobs = [dict(r) for r in rows]
            else:
                cur.execute('''
                    SELECT j.*, u.original_filename
                    FROM jobs j
                    LEFT JOIN uploads u ON j.upload_id = u.id
                    WHERE j.status = %s
                    ORDER BY j.created_at DESC
                ''', (status_filter,))
                rows = cur.fetchall()
                desc = [d[0] for d in cur.description]
                jobs = [dict(zip(desc, r)) for r in rows]
        else:
            if USE_SQLITE_FALLBACK:
                cur.execute('''SELECT j.*, u.original_filename FROM jobs j LEFT JOIN uploads u ON j.upload_id = u.id ORDER BY j.created_at DESC''')
                rows = cur.fetchall()
                jobs = [dict(r) for r in rows]
            else:
                cur.execute('''SELECT j.*, u.original_filename FROM jobs j LEFT JOIN uploads u ON j.upload_id = u.id ORDER BY j.created_at DESC''')
                rows = cur.fetchall()
                desc = [d[0] for d in cur.description]
                jobs = [dict(zip(desc, r)) for r in rows]

        return render_template('admin/jobs.html', jobs=jobs, status_filter=status_filter)
    finally:
        cur.close()
        conn.close()


@app.route('/admin/jobs/<job_id>')
@admin_required
def admin_job_detail(job_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute('''
                SELECT j.*, u.original_filename, u.storage_path, u.width, u.height, u.size_bytes, u.mime_type
                FROM jobs j
                LEFT JOIN uploads u ON j.upload_id = u.id
                WHERE j.job_id = ?
            ''', (job_id,))
            job = cur.fetchone()
            job = dict(job) if job else None
        else:
            cur.execute('''
                SELECT j.*, u.original_filename, u.storage_path, u.width, u.height, u.size_bytes, u.mime_type
                FROM jobs j
                LEFT JOIN uploads u ON j.upload_id = u.id
                WHERE j.job_id = %s
            ''', (job_id,))
            row = cur.fetchone()
            job = dict(zip([d[0] for d in cur.description], row)) if row else None

        if not job:
            return redirect(url_for('admin_jobs'))

        return render_template('admin/job_detail.html', job=job)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/jobs/<job_id>/cancel', methods=['POST'])
@admin_required
def api_cancel_job(job_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute("UPDATE jobs SET status = 'canceled' WHERE job_id = ? AND status IN ('queued', 'running')", (job_id,))
        else:
            cur.execute("UPDATE jobs SET status = %s WHERE job_id = %s AND status IN (%s, %s)", ('canceled', job_id, 'queued', 'running'))
        conn.commit()
        log_audit(session.get('user_id'), 'cancel_job', 'job', job_id, None, request.remote_addr)
        return jsonify({'success': True})
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/jobs/<job_id>/requeue', methods=['POST'])
@admin_required
def api_requeue_job(job_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
            old_job = cur.fetchone()
            if not old_job:
                return jsonify({'error': 'Job not found'}), 404
            new_job_id = f"job_{uuid.uuid4().hex[:12]}"
            cur.execute('''
                INSERT INTO jobs (job_id, upload_id, owner_id, status, params, created_at)
                VALUES (?, ?, ?, 'queued', ?, ?)
            ''', (new_job_id, old_job['upload_id'], old_job['owner_id'], old_job['params'], datetime.utcnow().isoformat()))
        else:
            cur.execute("SELECT * FROM jobs WHERE job_id = %s", (job_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'Job not found'}), 404
            desc = [d[0] for d in cur.description]
            old_job = dict(zip(desc, row))
            new_job_id = f"job_{uuid.uuid4().hex[:12]}"
            cur.execute('''
                INSERT INTO jobs (job_id, upload_id, owner_id, status, params, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (new_job_id, old_job.get('upload_id'), old_job.get('owner_id'), 'queued', old_job.get('params'), datetime.utcnow().isoformat()))
        conn.commit()
        log_audit(session.get('user_id'), 'requeue_job', 'job', job_id, {'new_job_id': new_job_id}, request.remote_addr)
        thread = threading.Thread(target=process_image, args=(new_job_id,))
        thread.start()
        return jsonify({'success': True, 'new_job_id': new_job_id})
    finally:
        cur.close()
        conn.close()


@app.route('/admin/settings')
@admin_required
def admin_settings():
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute("SELECT * FROM settings")
            settings = {row[0]: row[1] for row in cur.fetchall()}
            cur.execute("SELECT * FROM models ORDER BY name")
            models = [dict(r) for r in cur.fetchall()]
        else:
            cur.execute("SELECT * FROM settings")
            rows = cur.fetchall()
            settings = {r[0]: r[1] for r in rows}
            cur.execute("SELECT * FROM models ORDER BY name")
            rows = cur.fetchall()
            desc = [d[0] for d in cur.description]
            models = [dict(zip(desc, r)) for r in rows]
        return render_template('admin/settings.html', settings=settings, models=models)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/settings', methods=['POST'])
@admin_required
def api_update_settings():
    data = request.get_json()
    conn = get_db()
    cur = conn.cursor()
    try:
        for key, value in data.items():
            if USE_SQLITE_FALLBACK:
                cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
            else:
                cur.execute("INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (key, str(value)))
        conn.commit()
        log_audit(session.get('user_id'), 'update_settings', 'settings', None, data, request.remote_addr)
        return jsonify({'success': True})
    finally:
        cur.close()
        conn.close()


@app.route('/admin/audit')
@admin_required
def admin_audit():
    conn = get_db()
    cur = conn.cursor()
    try:
        if USE_SQLITE_FALLBACK:
            cur.execute('''
                SELECT a.*, u.username
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.created_at DESC
                LIMIT 100
            ''')
            rows = cur.fetchall()
            logs = [dict(r) for r in rows]
        else:
            cur.execute('''
                SELECT a.*, u.username
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.created_at DESC
                LIMIT 100
            ''')
            rows = cur.fetchall()
            desc = [d[0] for d in cur.description]
            logs = [dict(zip(desc, r)) for r in rows]
        return render_template('admin/audit.html', logs=logs)
    finally:
        cur.close()
        conn.close()


@app.route('/admin/logout')
def admin_logout():
    if 'user_id' in session:
        log_audit(session.get('user_id'), 'logout', 'user', str(session.get('user_id')), None, request.remote_addr)
    session.clear()
    return redirect(url_for('admin_login'))


if __name__ == '__main__':
    # Initialize DB (Postgres or sqlite fallback)
    init_db()
    # Run app
    app.run(host='0.0.0.0', port=5000, debug=False)