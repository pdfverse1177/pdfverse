"""
PDFverse - Professional PDF Utility Platform
Backend API with Flask, SQLite, JWT Authentication, and Security Features
"""

import os
import io
import uuid
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread
import time
import re

from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# PDF Processing Libraries
from pypdf import PdfReader, PdfWriter
from PIL import Image
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from openpyxl import load_workbook

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), '..', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'pdfverse.db')

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# CORS Configuration - Update YOUR_NETLIFY_DOMAIN with your actual domain
ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5500',
    'https://pdfverses.netlify.app',  # Your actual Netlify URL
]

# Add FRONTEND_URL from environment if exists
if os.environ.get('FRONTEND_URL'):
    ALLOWED_ORIGINS.append(os.environ.get('FRONTEND_URL'))

CORS(app, origins=ALLOWED_ORIGINS, 
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'])

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff'},
    'pdf': {'pdf'},
    'excel': {'xlsx', 'xls', 'csv'},
    'word': {'docx', 'doc'},
}

def allowed_file(filename, file_type):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

# Database Functions
def get_db():
    """Get database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database tables"""
    db = sqlite3.connect(app.config['DATABASE'])
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        );
        
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            download_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS conversion_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            conversion_type TEXT NOT NULL,
            input_file TEXT,
            output_file TEXT,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at);
        CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
    ''')
    db.commit()
    db.close()

# JWT Token Functions
def generate_token(user_id, email):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = {'user_id': data['user_id'], 'email': data['email']}
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

def optional_auth(f):
    """Decorator for optional authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        g.current_user = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if token:
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                g.current_user = {'user_id': data['user_id'], 'email': data['email']}
            except:
                pass
        
        return f(*args, **kwargs)
    return decorated

# Input Validation
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and other attacks"""
    # Remove any path components
    filename = os.path.basename(filename)
    # Use werkzeug's secure_filename
    filename = secure_filename(filename)
    # Ensure filename is not empty
    if not filename:
        filename = 'unnamed_file'
    return filename

# File Storage Functions
def save_file(file_data, original_filename, user_id=None):
    """Save file securely and return file info"""
    file_id = str(uuid.uuid4())
    safe_filename = sanitize_filename(original_filename)
    ext = safe_filename.rsplit('.', 1)[1].lower() if '.' in safe_filename else 'bin'
    stored_filename = f"{file_id}.{ext}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Save file
    if isinstance(file_data, bytes):
        with open(file_path, 'wb') as f:
            f.write(file_data)
        file_size = len(file_data)
    else:
        file_data.save(file_path)
        file_size = os.path.getsize(file_path)
    
    # Calculate expiry (24 hours from now)
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    # Save to database
    db = get_db()
    db.execute('''
        INSERT INTO files (id, user_id, original_filename, stored_filename, 
                          file_type, file_size, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (file_id, user_id, safe_filename, stored_filename, ext, file_size, expires_at))
    db.commit()
    
    return {
        'file_id': file_id,
        'filename': safe_filename,
        'size': file_size,
        'expires_at': expires_at.isoformat()
    }

def get_file_path(file_id, user_id=None):
    """Get file path securely"""
    db = get_db()
    
    if user_id:
        file_info = db.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            (file_id, user_id)
        ).fetchone()
    else:
        file_info = db.execute(
            'SELECT * FROM files WHERE id = ?',
            (file_id,)
        ).fetchone()
    
    if not file_info:
        return None, None
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_filename'])
    
    if not os.path.exists(file_path):
        return None, None
    
    return file_path, file_info

# Background Cleanup Task
def cleanup_expired_files():
    """Remove expired files from disk and database"""
    while True:
        try:
            db = sqlite3.connect(app.config['DATABASE'])
            cursor = db.execute(
                'SELECT id, stored_filename FROM files WHERE expires_at < ?',
                (datetime.utcnow(),)
            )
            expired_files = cursor.fetchall()
            
            for file_id, stored_filename in expired_files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"Error deleting file {file_path}: {e}")
            
            db.execute('DELETE FROM files WHERE expires_at < ?', (datetime.utcnow(),))
            db.commit()
            db.close()
        except Exception as e:
            print(f"Cleanup error: {e}")
        
        # Run every 5 minutes
        time.sleep(300)

# ================== API ROUTES ==================

# Health Check
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

# ================== AUTH ROUTES ==================

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """Register a new user"""
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400
    
    email = data['email'].strip().lower()
    password = data['password']
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    valid, msg = validate_password(password)
    if not valid:
        return jsonify({'error': msg}), 400
    
    db = get_db()
    
    # Check if user exists
    existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if existing:
        return jsonify({'error': 'Email already registered'}), 409
    
    # Create user
    password_hash = generate_password_hash(password)
    cursor = db.execute(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)',
        (email, password_hash)
    )
    db.commit()
    
    user_id = cursor.lastrowid
    token = generate_token(user_id, email)
    
    return jsonify({
        'message': 'Registration successful',
        'token': token,
        'user': {'id': user_id, 'email': email}
    }), 201

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """Login user"""
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400
    
    email = data['email'].strip().lower()
    password = data['password']
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    if not user['is_active']:
        return jsonify({'error': 'Account is disabled'}), 403
    
    token = generate_token(user['id'], email)
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {'id': user['id'], 'email': email}
    })

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user():
    """Get current user info"""
    return jsonify({'user': g.current_user})

# ================== FILE ROUTES ==================

@app.route('/api/files', methods=['GET'])
@token_required
def list_user_files():
    """List all files for current user"""
    db = get_db()
    files = db.execute('''
        SELECT id, original_filename, file_type, file_size, created_at, 
               expires_at, download_count
        FROM files 
        WHERE user_id = ? AND expires_at > ?
        ORDER BY created_at DESC
    ''', (g.current_user['user_id'], datetime.utcnow())).fetchall()
    
    return jsonify({
        'files': [dict(f) for f in files]
    })

@app.route('/api/files/<file_id>', methods=['GET'])
@optional_auth
def download_file(file_id):
    """Download a file"""
    user_id = g.current_user['user_id'] if g.current_user else None
    file_path, file_info = get_file_path(file_id, user_id)
    
    if not file_path:
        return jsonify({'error': 'File not found or expired'}), 404
    
    # Update download count
    db = get_db()
    db.execute('UPDATE files SET download_count = download_count + 1 WHERE id = ?', (file_id,))
    db.commit()
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_info['original_filename']
    )

@app.route('/api/files/<file_id>', methods=['DELETE'])
@token_required
def delete_file(file_id):
    """Delete a file"""
    file_path, file_info = get_file_path(file_id, g.current_user['user_id'])
    
    if not file_path:
        return jsonify({'error': 'File not found'}), 404
    
    try:
        os.remove(file_path)
    except:
        pass
    
    db = get_db()
    db.execute('DELETE FROM files WHERE id = ?', (file_id,))
    db.commit()
    
    return jsonify({'message': 'File deleted successfully'})

# ================== CONVERSION ROUTES ==================

@app.route('/api/convert/images-to-pdf', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def images_to_pdf():
    """Convert multiple images to a single PDF"""
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files')
    
    if not files or len(files) == 0:
        return jsonify({'error': 'No files selected'}), 400
    
    # Validate all files
    for file in files:
        if not allowed_file(file.filename, 'image'):
            return jsonify({'error': f'Invalid file type: {file.filename}'}), 400
    
    try:
        # Create PDF
        images = []
        for file in files:
            img = Image.open(file.stream)
            if img.mode == 'RGBA':
                img = img.convert('RGB')
            images.append(img)
        
        # Save to PDF
        pdf_buffer = io.BytesIO()
        if len(images) == 1:
            images[0].save(pdf_buffer, 'PDF', resolution=100.0)
        else:
            images[0].save(pdf_buffer, 'PDF', resolution=100.0, 
                          save_all=True, append_images=images[1:])
        
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        # Save file
        user_id = g.current_user['user_id'] if g.current_user else None
        file_info = save_file(pdf_data, 'converted_images.pdf', user_id)
        
        return jsonify({
            'message': 'PDF created successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Conversion failed: {str(e)}'}), 500

@app.route('/api/convert/pdf-to-images', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def pdf_to_images():
    """Convert PDF pages to images"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        # This is a simplified version - for full PDF to image conversion,
        # you'd need pdf2image library with poppler
        # For now, we'll return the PDF info
        reader = PdfReader(file.stream)
        num_pages = len(reader.pages)
        
        return jsonify({
            'message': 'PDF analyzed',
            'pages': num_pages,
            'note': 'Full PDF to image conversion requires additional system dependencies'
        })
    
    except Exception as e:
        return jsonify({'error': f'Processing failed: {str(e)}'}), 500

@app.route('/api/convert/merge-pdfs', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def merge_pdfs():
    """Merge multiple PDFs into one"""
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files')
    
    if len(files) < 2:
        return jsonify({'error': 'At least 2 PDF files are required'}), 400
    
    for file in files:
        if not allowed_file(file.filename, 'pdf'):
            return jsonify({'error': f'Invalid file type: {file.filename}'}), 400
    
    try:
        writer = PdfWriter()
        
        for file in files:
            reader = PdfReader(file.stream)
            for page in reader.pages:
                writer.add_page(page)
        
        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        file_info = save_file(pdf_data, 'merged.pdf', user_id)
        
        return jsonify({
            'message': 'PDFs merged successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Merge failed: {str(e)}'}), 500

@app.route('/api/convert/split-pdf', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def split_pdf():
    """Split PDF into individual pages"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        reader = PdfReader(file.stream)
        user_id = g.current_user['user_id'] if g.current_user else None
        
        files_info = []
        for i, page in enumerate(reader.pages):
            writer = PdfWriter()
            writer.add_page(page)
            
            pdf_buffer = io.BytesIO()
            writer.write(pdf_buffer)
            pdf_buffer.seek(0)
            pdf_data = pdf_buffer.read()
            
            file_info = save_file(pdf_data, f'page_{i+1}.pdf', user_id)
            files_info.append(file_info)
        
        return jsonify({
            'message': f'PDF split into {len(files_info)} pages',
            'files': files_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Split failed: {str(e)}'}), 500

@app.route('/api/convert/compress-pdf', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def compress_pdf():
    """Compress PDF file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        reader = PdfReader(file.stream)
        writer = PdfWriter()
        
        for page in reader.pages:
            page.compress_content_streams()
            writer.add_page(page)
        
        # Remove unused objects
        writer.add_metadata(reader.metadata or {})
        
        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        original_name = sanitize_filename(file.filename)
        compressed_name = f'compressed_{original_name}'
        file_info = save_file(pdf_data, compressed_name, user_id)
        
        return jsonify({
            'message': 'PDF compressed successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Compression failed: {str(e)}'}), 500

@app.route('/api/convert/rotate-pdf', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def rotate_pdf():
    """Rotate PDF pages"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    angle = request.form.get('angle', 90, type=int)
    pages = request.form.get('pages', 'all')  # 'all' or comma-separated page numbers
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    if angle not in [90, 180, 270]:
        return jsonify({'error': 'Angle must be 90, 180, or 270'}), 400
    
    try:
        reader = PdfReader(file.stream)
        writer = PdfWriter()
        
        # Parse pages to rotate
        if pages == 'all':
            pages_to_rotate = set(range(len(reader.pages)))
        else:
            try:
                pages_to_rotate = set(int(p.strip()) - 1 for p in pages.split(','))
            except:
                return jsonify({'error': 'Invalid pages format'}), 400
        
        for i, page in enumerate(reader.pages):
            if i in pages_to_rotate:
                page.rotate(angle)
            writer.add_page(page)
        
        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        original_name = sanitize_filename(file.filename)
        rotated_name = f'rotated_{original_name}'
        file_info = save_file(pdf_data, rotated_name, user_id)
        
        return jsonify({
            'message': 'PDF rotated successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Rotation failed: {str(e)}'}), 500

@app.route('/api/convert/unlock-pdf', methods=['POST'])
@limiter.limit("20 per hour")
@optional_auth
def unlock_pdf():
    """Remove password from PDF"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        reader = PdfReader(file.stream)
        
        if reader.is_encrypted:
            if not reader.decrypt(password):
                return jsonify({'error': 'Incorrect password'}), 400
        
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        
        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        original_name = sanitize_filename(file.filename)
        unlocked_name = f'unlocked_{original_name}'
        file_info = save_file(pdf_data, unlocked_name, user_id)
        
        return jsonify({
            'message': 'PDF unlocked successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Unlock failed: {str(e)}'}), 500

@app.route('/api/convert/protect-pdf', methods=['POST'])
@limiter.limit("20 per hour")
@optional_auth
def protect_pdf():
    """Add password protection to PDF"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    user_password = request.form.get('user_password', '')
    owner_password = request.form.get('owner_password', '')
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    if not user_password:
        return jsonify({'error': 'Password is required'}), 400
    
    try:
        reader = PdfReader(file.stream)
        writer = PdfWriter()
        
        for page in reader.pages:
            writer.add_page(page)
        
        # Encrypt with password
        writer.encrypt(user_password, owner_password or user_password)
        
        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        original_name = sanitize_filename(file.filename)
        protected_name = f'protected_{original_name}'
        file_info = save_file(pdf_data, protected_name, user_id)
        
        return jsonify({
            'message': 'PDF protected successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Protection failed: {str(e)}'}), 500

@app.route('/api/convert/excel-to-pdf', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def excel_to_pdf():
    """Convert Excel file to PDF"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if not allowed_file(file.filename, 'excel'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        # Read Excel file
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file.stream)
        else:
            df = pd.read_excel(file.stream)
        
        # Create PDF with reportlab
        pdf_buffer = io.BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=A4)
        width, height = A4
        
        # Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Excel Data Export")
        
        # Draw table
        c.setFont("Helvetica", 10)
        y = height - 100
        x = 50
        
        # Headers
        cols = list(df.columns)
        col_width = (width - 100) / min(len(cols), 5)
        
        c.setFont("Helvetica-Bold", 9)
        for i, col in enumerate(cols[:5]):  # Limit to 5 columns for readability
            c.drawString(x + i * col_width, y, str(col)[:15])
        
        y -= 20
        c.setFont("Helvetica", 8)
        
        # Data rows
        for _, row in df.head(50).iterrows():  # Limit to 50 rows per page
            if y < 50:
                c.showPage()
                y = height - 50
            
            for i, col in enumerate(cols[:5]):
                value = str(row[col])[:15] if pd.notna(row[col]) else ''
                c.drawString(x + i * col_width, y, value)
            y -= 15
        
        c.save()
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        original_name = sanitize_filename(file.filename)
        pdf_name = original_name.rsplit('.', 1)[0] + '.pdf'
        file_info = save_file(pdf_data, pdf_name, user_id)
        
        return jsonify({
            'message': 'Excel converted to PDF successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Conversion failed: {str(e)}'}), 500

@app.route('/api/convert/add-watermark', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def add_watermark():
    """Add text watermark to PDF"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    watermark_text = request.form.get('text', 'WATERMARK')
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        # Create watermark PDF
        watermark_buffer = io.BytesIO()
        c = canvas.Canvas(watermark_buffer, pagesize=A4)
        width, height = A4
        
        c.setFont("Helvetica", 60)
        c.setFillColorRGB(0.5, 0.5, 0.5, alpha=0.3)
        c.saveState()
        c.translate(width/2, height/2)
        c.rotate(45)
        c.drawCentredString(0, 0, watermark_text)
        c.restoreState()
        c.save()
        
        watermark_buffer.seek(0)
        watermark_reader = PdfReader(watermark_buffer)
        watermark_page = watermark_reader.pages[0]
        
        # Apply watermark to all pages
        reader = PdfReader(file.stream)
        writer = PdfWriter()
        
        for page in reader.pages:
            page.merge_page(watermark_page)
            writer.add_page(page)
        
        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        original_name = sanitize_filename(file.filename)
        watermarked_name = f'watermarked_{original_name}'
        file_info = save_file(pdf_data, watermarked_name, user_id)
        
        return jsonify({
            'message': 'Watermark added successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Watermark failed: {str(e)}'}), 500

@app.route('/api/convert/extract-pages', methods=['POST'])
@limiter.limit("30 per hour")
@optional_auth
def extract_pages():
    """Extract specific pages from PDF"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    pages_str = request.form.get('pages', '')  # Format: "1,3,5-7,9"
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    if not pages_str:
        return jsonify({'error': 'Pages parameter is required'}), 400
    
    try:
        reader = PdfReader(file.stream)
        total_pages = len(reader.pages)
        
        # Parse page ranges
        pages_to_extract = set()
        for part in pages_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= total_pages:
                        pages_to_extract.add(p - 1)
            else:
                p = int(part)
                if 1 <= p <= total_pages:
                    pages_to_extract.add(p - 1)
        
        if not pages_to_extract:
            return jsonify({'error': 'No valid pages specified'}), 400
        
        writer = PdfWriter()
        for page_num in sorted(pages_to_extract):
            writer.add_page(reader.pages[page_num])
        
        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        pdf_buffer.seek(0)
        pdf_data = pdf_buffer.read()
        
        user_id = g.current_user['user_id'] if g.current_user else None
        original_name = sanitize_filename(file.filename)
        extracted_name = f'extracted_{original_name}'
        file_info = save_file(pdf_data, extracted_name, user_id)
        
        return jsonify({
            'message': f'Extracted {len(pages_to_extract)} pages successfully',
            'file': file_info
        })
    
    except Exception as e:
        return jsonify({'error': f'Extraction failed: {str(e)}'}), 500

@app.route('/api/pdf/info', methods=['POST'])
@limiter.limit("60 per hour")
def pdf_info():
    """Get PDF file information"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if not allowed_file(file.filename, 'pdf'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        reader = PdfReader(file.stream)
        metadata = reader.metadata or {}
        
        return jsonify({
            'pages': len(reader.pages),
            'encrypted': reader.is_encrypted,
            'metadata': {
                'title': metadata.get('/Title', ''),
                'author': metadata.get('/Author', ''),
                'subject': metadata.get('/Subject', ''),
                'creator': metadata.get('/Creator', ''),
                'producer': metadata.get('/Producer', ''),
            }
        })
    
    except Exception as e:
        return jsonify({'error': f'Failed to read PDF: {str(e)}'}), 500

# Error Handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 50MB'}), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later'}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# Initialize and Run
if __name__ == '__main__':
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize database
    init_db()
    
    # Start cleanup thread
    cleanup_thread = Thread(target=cleanup_expired_files, daemon=True)
    cleanup_thread.start()
    
    # Run app
    app.run(debug=False, host='0.0.0.0', port=5000)
