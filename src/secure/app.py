import os
from datetime import datetime, timedelta
from flask import Flask, request, session, redirect, url_for, render_template, g, jsonify
import sqlite3
import bcrypt
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError
from functools import wraps
import html
import secrets

#  CONFIG 

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bank.db')
template_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))

app = Flask(__name__, template_folder=template_folder)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production-use-env-var')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False   
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.permanent_session_lifetime = timedelta(minutes=15)

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])
JWT_SECRET = os.environ.get('JWT_SECRET', 'change-jwt-secret-in-production')

#  SCHEMAS 

class LoginSchema(Schema):
    username = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 64)
    password = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 128)

class TransferSchema(Schema):
    to_account = fields.Int(required=True)
    amount     = fields.Float(required=True, validate=lambda x: 0 < x <= 1_000_000)
    note       = fields.Str(load_default='', validate=lambda s: len(s) <= 255)

#  DB 

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            balance   REAL DEFAULT 1000.0,
            is_admin  INTEGER DEFAULT 0,
            is_frozen INTEGER DEFAULT 0
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id        INTEGER PRIMARY KEY,
            from_user INTEGER,
            to_user   INTEGER,
            amount    REAL,
            note      TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        db.commit()

init_db()

#  SECURITY HEADERS 
@app.before_request                              
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)
@app.after_request
def add_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')   
    response.headers['X-Frame-Options']           = 'DENY'
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['Referrer-Policy']           = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy']   = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response

@app.context_processor
def inject_now():
    return {
        'now': datetime.utcnow(),
        'csp_nonce': getattr(g, 'csp_nonce', '')
    }



#  DECORATORS 

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            return 'Access denied', 403
        return f(*args, **kwargs)
    return decorated

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '').strip()
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def api_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

#  PUBLIC ROUTES 

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            error = 'Username and password are required'
        elif len(username) > 64 or len(password) > 128:
            error = 'Input too long'
        else:
            # Bcrypt hash — minimum 12 rounds
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
            db = get_db()
            try:
                db.execute(
                    'INSERT INTO users (username, password) VALUES (?, ?)',
                    (username, password_hash)
                )
                db.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Username already exists'
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        # Parameterized query — no SQL injection possible
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        
        stored_hash = user['password'] if user else None
        if user and isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')
        if user and bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            if user['is_frozen']:
                error = 'Your account is frozen. Contact an administrator.'
            else:
                session.permanent = True
                session['user_id']  = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])
                return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

#  AUTHENTICATED ROUTES 

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    transactions = db.execute(
        'SELECT * FROM transactions WHERE from_user = ? OR to_user = ? ORDER BY timestamp DESC',
        (user_id, user_id)
    ).fetchall()
    return render_template('dashboard.html',
        username=session['username'],
        balance=user['balance'],
        user_id=user_id,
        is_admin=bool(user['is_admin']),
        transactions=transactions
    )

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    error = None
    success = None
    from_user = session['user_id']
    db = get_db()

    if request.method == 'POST':
        try:
            to_account = int(request.form['to_account'])
            amount     = float(request.form['amount'])
            # Sanitize note — strip HTML to prevent XSS
            note = html.escape(request.form.get('note', '').strip())[:255]
        except (ValueError, KeyError):
            error = 'Invalid input'
            to_account = amount = note = None

        if not error:
            if to_account == from_user:
                error = 'Cannot transfer to yourself'
            elif amount <= 0:
                error = 'Amount must be positive'
            else:
                user_status = db.execute(
                    'SELECT is_frozen FROM users WHERE id = ?', (from_user,)
                ).fetchone()
                if user_status and user_status['is_frozen']:
                    error = 'Your account is frozen. Contact an administrator.'
                else:
                    recipient = db.execute(
                        'SELECT id FROM users WHERE id = ?', (to_account,)
                    ).fetchone()
                    if not recipient:
                        error = 'Recipient account not found'
                    else:
                        user = db.execute(
                            'SELECT balance FROM users WHERE id = ?', (from_user,)
                        ).fetchone()
                        if user['balance'] < amount:
                            error = 'Insufficient funds'
                        else:
                            db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, from_user))
                            db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, to_account))
                            db.execute(
                                'INSERT INTO transactions (from_user, to_user, amount, note) VALUES (?, ?, ?, ?)',
                                (from_user, to_account, amount, note)
                            )
                            db.commit()
                            success = 'Transfer successful'

    balance = db.execute('SELECT balance FROM users WHERE id = ?', (from_user,)).fetchone()['balance']
    return render_template('transfer.html', balance=balance, error=error, success=success)

@app.route('/history')
@login_required
def history():
    user_id = session['user_id']
    db = get_db()
    transactions = db.execute(
        'SELECT * FROM transactions WHERE from_user = ? OR to_user = ? ORDER BY timestamp DESC',
        (user_id, user_id)
    ).fetchall()
    return render_template('history.html', transactions=transactions, user_id=user_id)

@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()[:100]  # Limit query length
    results = None
    if q:
        db = get_db()
        user_matches = db.execute(
            'SELECT id, username FROM users WHERE username LIKE ?', (f'%{q}%',)
        ).fetchall()
        note_matches = db.execute(
            'SELECT id, note FROM transactions WHERE note LIKE ?', (f'%{q}%',)
        ).fetchall()
        results = []
        if user_matches:
            results.append('Accounts: ' + ', '.join([f'{u["username"]} (#{u["id"]})' for u in user_matches]))
        if note_matches:
            results.append('Notes: ' + ', '.join([f'#{n["id"]}' for n in note_matches]))
        results = ' | '.join(results) if results else None
    # q is passed to template — template must use {{ q }} (auto-escaped), NOT {{ q | safe }}
    return render_template('search.html', q=q, results=results)

@app.route('/account/<int:account_id>')
@login_required
def account(account_id):
    # Authorization check — users can only view their own account
    if account_id != session['user_id']:
        return 'Access denied', 403
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (account_id,)).fetchone()
    if user:
        return render_template('account.html', id=account_id, username=user['username'], balance=user['balance'])
    return 'Account not found', 404

#  ADMIN ROUTES 

@app.route('/admin')
@admin_required
def admin():
    db = get_db()
    users = db.execute(
        'SELECT id, username, balance, is_admin, is_frozen FROM users'
    ).fetchall()
    transactions = db.execute('''
        SELECT t.id, u1.username AS from_username, u2.username AS to_username,
               t.amount, t.note, t.timestamp
        FROM transactions t
        JOIN users u1 ON t.from_user = u1.id
        JOIN users u2 ON t.to_user   = u2.id
        ORDER BY t.timestamp DESC
        LIMIT 100
    ''').fetchall()
    total_balance = db.execute('SELECT SUM(balance) FROM users').fetchone()[0] or 0
    return render_template('admin.html',
        users=users,
        transactions=transactions,
        total_balance=total_balance
    )

@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/demote/<int:user_id>', methods=['POST'])
@admin_required
def demote_user(user_id):
    # Prevent admin from demoting themselves
    if user_id == session['user_id']:
        return 'Cannot demote yourself', 400
    db = get_db()
    db.execute('UPDATE users SET is_admin = 0 WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        return 'Cannot delete yourself', 400
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.execute('DELETE FROM transactions WHERE from_user = ? OR to_user = ?', (user_id, user_id))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/reset_balance/<int:user_id>', methods=['POST'])
@admin_required
def reset_balance(user_id):
    try:
        amount = float(request.form.get('amount', 1000.0))
        if amount < 0:
            return 'Invalid amount', 400
    except ValueError:
        return 'Invalid amount', 400
    db = get_db()
    db.execute('UPDATE users SET balance = ? WHERE id = ?', (amount, user_id))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/freeze/<int:user_id>', methods=['POST'])
@admin_required
def freeze_user(user_id):
    if user_id == session['user_id']:
        return 'Cannot freeze yourself', 400
    db = get_db()
    db.execute('UPDATE users SET is_frozen = 1 WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/unfreeze/<int:user_id>', methods=['POST'])
@admin_required
def unfreeze_user(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_frozen = 0 WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/delete_transaction/<int:tx_id>', methods=['POST'])
@admin_required
def delete_transaction(tx_id):
    db = get_db()
    db.execute('DELETE FROM transactions WHERE id = ?', (tx_id,))
    db.commit()
    return redirect(url_for('admin'))

#  API ROUTES 

@app.route('/api/auth/token', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def api_login():
    schema = LoginSchema()
    try:
        data = schema.load(request.get_json(force=True) or {})
    except ValidationError as err:
        return jsonify(err.messages), 400

    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?', (data['username'],)
    ).fetchone()
    
    stored_hash = user['password'] if user else None
    if user and isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')

    if user and bcrypt.checkpw(data['password'].encode('utf-8'), stored_hash):
        if user['is_frozen']:
            return jsonify({'error': 'Account is frozen'}), 403
        payload = {
            'user_id':  user['id'],
            'username': user['username'],
            'role':     'admin' if user['is_admin'] else 'user',
            'exp':      datetime.utcnow() + timedelta(minutes=15)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/refresh', methods=['POST'])
@csrf.exempt
@token_required
def api_refresh():
    payload = {
        'user_id':  request.user['user_id'],
        'username': request.user['username'],
        'role':     request.user['role'],
        'exp':      datetime.utcnow() + timedelta(minutes=15)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/api/dashboard')
@csrf.exempt
@token_required
def api_dashboard():
    user_id = request.user['user_id']
    db = get_db()
    user = db.execute(
        'SELECT balance FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    return jsonify({'balance': user['balance']})

@app.route('/api/transfer', methods=['POST'])
@csrf.exempt
@token_required
def api_transfer():
    schema = TransferSchema()
    try:
        data = schema.load(request.get_json(force=True) or {})
    except ValidationError as err:
        return jsonify(err.messages), 422

    from_user  = request.user['user_id']
    to_account = data['to_account']
    amount     = data['amount']
    note       = html.escape(data.get('note', ''))

    if to_account == from_user:
        return jsonify({'error': 'Cannot transfer to yourself'}), 400

    db = get_db()
    user_status = db.execute('SELECT is_frozen FROM users WHERE id = ?', (from_user,)).fetchone()
    if user_status and user_status['is_frozen']:
        return jsonify({'error': 'Account is frozen'}), 403

    recipient = db.execute('SELECT id FROM users WHERE id = ?', (to_account,)).fetchone()
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404

    user = db.execute('SELECT balance FROM users WHERE id = ?', (from_user,)).fetchone()
    if user['balance'] < amount:
        return jsonify({'error': 'Insufficient funds'}), 400

    db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, from_user))
    db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, to_account))
    db.execute(
        'INSERT INTO transactions (from_user, to_user, amount, note) VALUES (?, ?, ?, ?)',
        (from_user, to_account, amount, note)
    )
    db.commit()
    return jsonify({'message': 'Transfer successful'})

@app.route('/api/admin/users')
@csrf.exempt
@token_required
@api_admin_required
def api_admin_users():
    db = get_db()
    users = db.execute(
        'SELECT id, username, balance, is_admin, is_frozen FROM users'
    ).fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/freeze/<int:user_id>', methods=['POST'])
@csrf.exempt
@token_required
@api_admin_required
def api_freeze_user(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_frozen = 1 WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'message': f'User {user_id} frozen'})

@app.route('/api/admin/unfreeze/<int:user_id>', methods=['POST'])
@csrf.exempt
@token_required
@api_admin_required
def api_unfreeze_user(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_frozen = 0 WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'message': f'User {user_id} unfrozen'})

# RUN 

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))  
    app.run(debug=False, host='0.0.0.0', port=port) 