import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            name TEXT NOT NULL,
            link TEXT NOT NULL,
            image TEXT,
            FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS topic_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (topic_id) REFERENCES topics (id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/singup', methods=['GET', 'POST'])
def singup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']

        # Password policy
        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
        if not re.match(password_pattern, password):
            flash('Password must be at least 8 characters, include one uppercase letter, one number, and one special character.')
            return redirect(url_for('singup'))

        if password != confirm:
            flash('Passwords do not match.')
            return redirect(url_for('singup'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            flash('Username already exists.')
            conn.close()
            return redirect(url_for('singup'))
        try:
            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                      (username, generate_password_hash(password)))
            conn.commit()
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))
        finally:
            conn.close()
    return render_template('singup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Handle add topic
    if request.method == 'POST':
        name = request.form['topicName']
        link = request.form['topicLink']
        image_file = request.files.get('topicImage')
        image_path = ''
        if image_file and image_file.filename:
            from werkzeug.utils import secure_filename
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            image_path = os.path.join('static/uploads', filename)
        c.execute('INSERT INTO topics (username, name, link, image) VALUES (?, ?, ?, ?)',
                  (session['username'], name, link, image_path))
        conn.commit()

    # Handle search
    search = request.args.get('search', '')
    if search:
        c.execute('SELECT id, name, link, image FROM topics WHERE username=? AND name LIKE ?', (session['username'], f'%{search}%'))
    else:
        c.execute('SELECT id, name, link, image FROM topics WHERE username=?', (session['username'],))
    topics = c.fetchall()
    conn.close()
    return render_template('dashboard.html', topics=topics, search=search)

@app.route('/delete_topic/<int:topic_id>', methods=['POST'])
def delete_topic(topic_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM topics WHERE id=? AND username=?', (topic_id, session['username']))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/edit_topic/<int:topic_id>', methods=['POST'])
def edit_topic(topic_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    name = request.form['editTopicName']
    link = request.form['editTopicLink']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE topics SET name=?, link=? WHERE id=? AND username=?', (name, link, topic_id, session['username']))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
def topic_view(topic_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Add new data to topic
    if request.method == 'POST':
        content = request.form['content']
        c.execute('INSERT INTO topic_data (topic_id, content) VALUES (?, ?)', (topic_id, content))
        conn.commit()
    # Get topic info
    c.execute('SELECT name FROM topics WHERE id=? AND username=?', (topic_id, session['username']))
    topic = c.fetchone()
    if not topic:
        conn.close()
        flash('Topic not found.')
        return redirect(url_for('dashboard'))
    # Get topic data
    c.execute('SELECT content FROM topic_data WHERE topic_id=?', (topic_id,))
    data = c.fetchall()
    conn.close()
    return render_template('topic_view.html', topic_name=topic[0], topic_id=topic_id, data=data)

@app.route('/topic_suggestions')
def topic_suggestions():
    print('Session username:', session.get('username'))
    if 'username' not in session:
        return jsonify([])
    q = request.args.get('q', '')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT name FROM topics WHERE username=? AND name LIKE ? LIMIT 5', (session['username'], f'{q}%'))
    suggestions = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify(suggestions)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
