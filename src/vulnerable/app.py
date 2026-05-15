import os
from datetime import datetime
from flask import Flask, request, session, redirect, url_for, render_template, g
import sqlite3

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bank.db')


template_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))

app = Flask(__name__, template_folder=template_folder)
app.secret_key = 'secret'  # [VULN] weak secret key

@app.context_processor
def inject_vulnerability_banner():
    return {'insecure_app': True}

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
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
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            balance REAL DEFAULT 1000.0,
            is_admin INTEGER DEFAULT 0,
            is_frozen INTEGER DEFAULT 0
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            from_user INTEGER,
            to_user INTEGER,
            amount REAL,
            note TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        # Add is_frozen column if it doesn't exist (migration)
        try:
            db.execute('ALTER TABLE users ADD COLUMN is_frozen INTEGER DEFAULT 0')
        except Exception:
            pass
        db.commit()

init_db()

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
        username = request.form['username']
        password = request.form['password']  # [VULN] plaintext password storage
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username already exists'
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        # [VULN] SQL injection — string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        user = db.execute(query).fetchone()
        if user:
            session['user_id']   = user[0]
            session['username']  = user[1]
            session['is_admin']  = bool(user[4])
            return redirect(url_for('dashboard'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

#  AUTHENTICATED ROUTES 

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    balance = user[3]
    transactions = db.execute(
        'SELECT * FROM transactions WHERE from_user=? OR to_user=? ORDER BY timestamp DESC',
        (user_id, user_id)
    ).fetchall()
    return render_template('dashboard.html',
        username=session['username'],
        balance=balance,
        user_id=user_id,
        is_admin=bool(user[4]),
        transactions=transactions
    )

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    error = None
    success = None
    from_user = session['user_id']
    db = get_db()

    if request.method == 'POST':
        # [VULN] No CSRF token validation
        to_account = request.form['to_account']
        amount     = float(request.form['amount'])
        note       = request.form['note']  # [VULN] stored XSS — no sanitization

        # Check if account is frozen
        user_status = db.execute('SELECT is_frozen FROM users WHERE id=?', (from_user,)).fetchone()
        if user_status and user_status[0]:
            error = 'Your account is frozen. Contact an administrator.'
        else:
            user = db.execute('SELECT balance FROM users WHERE id=?', (from_user,)).fetchone()
            if user[0] < amount:
                error = 'Insufficient funds'
            else:
                db.execute('UPDATE users SET balance = balance - ? WHERE id=?', (amount, from_user))
                db.execute('UPDATE users SET balance = balance + ? WHERE id=?', (amount, int(to_account)))
                db.execute(
                    'INSERT INTO transactions (from_user, to_user, amount, note) VALUES (?, ?, ?, ?)',
                    (from_user, int(to_account), amount, note)
                )
                db.commit()
                success = 'Transfer successful'

    balance = db.execute('SELECT balance FROM users WHERE id=?', (from_user,)).fetchone()[0]
    return render_template('transfer.html', balance=balance, error=error, success=success)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    db = get_db()
    transactions = db.execute(
        'SELECT * FROM transactions WHERE from_user=? OR to_user=? ORDER BY timestamp DESC',
        (user_id, user_id)
    ).fetchall()
    return render_template('history.html', transactions=transactions, user_id=user_id)

@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
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
            results.append('Accounts: ' + ', '.join([f'{u[1]} (#{u[0]})' for u in user_matches]))
        if note_matches:
            results.append('Notes: ' + ', '.join([f'#{n[0]}' for n in note_matches]))
        results = ' | '.join(results) if results else None
    return render_template('search.html', q=q, results=results)

@app.route('/account/<int:account_id>')
def account(account_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # [VULN] IDOR — no check that account_id == session['user_id']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (account_id,)).fetchone()
    if user:
        return render_template('account.html', id=account_id, username=user[1], balance=user[3])
    return 'Account not found', 404

#  ADMIN ROUTES  

def admin_required():
    """Returns True if current user is admin, False otherwise."""
    return session.get('is_admin', False)

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not admin_required():
        return 'Access denied', 403
    db = get_db()
    users = db.execute(
        'SELECT id, username, balance, is_admin, is_frozen FROM users'
    ).fetchall()
    transactions = db.execute('''
        SELECT t.id, u1.username, u2.username, t.amount, t.note, t.timestamp
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
def promote_user(user_id):
    if not admin_required():
        return 'Access denied', 403
    db = get_db()
    db.execute('UPDATE users SET is_admin=1 WHERE id=?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/demote/<int:user_id>', methods=['POST'])
def demote_user(user_id):
    if not admin_required():
        return 'Access denied', 403
    db = get_db()
    db.execute('UPDATE users SET is_admin=0 WHERE id=?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not admin_required():
        return 'Access denied', 403
    if user_id == session['user_id']:
        return 'Cannot delete yourself', 400
    db = get_db()
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.execute('DELETE FROM transactions WHERE from_user=? OR to_user=?', (user_id, user_id))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/reset_balance/<int:user_id>', methods=['POST'])
def reset_balance(user_id):
    if not admin_required():
        return 'Access denied', 403
    amount = float(request.form.get('amount', 1000.0))
    db = get_db()
    db.execute('UPDATE users SET balance=? WHERE id=?', (amount, user_id))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/freeze/<int:user_id>', methods=['POST'])
def freeze_user(user_id):
    if not admin_required():
        return 'Access denied', 403
    db = get_db()
    db.execute('UPDATE users SET is_frozen=1 WHERE id=?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/unfreeze/<int:user_id>', methods=['POST'])
def unfreeze_user(user_id):
    if not admin_required():
        return 'Access denied', 403
    db = get_db()
    db.execute('UPDATE users SET is_frozen=0 WHERE id=?', (user_id,))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/admin/delete_transaction/<int:tx_id>', methods=['POST'])
def delete_transaction(tx_id):
    if not admin_required():
        return 'Access denied', 403
    db = get_db()
    db.execute('DELETE FROM transactions WHERE id=?', (tx_id,))
    db.commit()
    return redirect(url_for('admin'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000)) 
    app.run(debug=False, host='0.0.0.0', port=port)