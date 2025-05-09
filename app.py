from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
import sqlite3
import html 

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# DB Initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL)''')

    # Hash the password before inserting default user
    # hashed_pwd = bcrypt.generate_password_hash("pwd123").decode('utf-8')
    # c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("Anushree", hashed_pwd))

    conn.commit()
    conn.close()


# Using parameterised query- to avoid SQLi

# @app.route('/', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         user = request.form['username']
#         pwd = request.form['password']

#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("SELECT password FROM users WHERE username = ?", (user,))
#         result = c.fetchone()
#         conn.close()

#         if result and bcrypt.check_password_hash(result[0], pwd):
#             session['username'] = user
#             return redirect(url_for('welcome'))
#         else:
#             return "Invalid credentials! Try again."

#     return render_template('login.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username'].strip()
        pwd = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # ⚠️ SQL Injection VULNERABLE code — do not use in real apps
        query = f"SELECT * FROM users WHERE username = '{user}'"
        print("Executing Query:", query)  # for debugging

        try:
            c.execute(query)
            result = c.fetchone()
        except Exception as e:
            conn.close()
            return f"Error: {e}"

        conn.close()

        if result:
            username_db, hashed_pwd = result
            print("User found:", username_db)
            print("Stored hash:", hashed_pwd)
            print("Password match:", bcrypt.check_password_hash(hashed_pwd, pwd))

            if bcrypt.check_password_hash(hashed_pwd, pwd):
                session['username'] = username_db
                return redirect(url_for('welcome', username=username_db))

        return "Login failed — invalid credentials!"

    # return '''
    #     <form method="POST">
    #         Username: <input type="text" name="username"><br>
    #         Password: <input type="password" name="password"><br>
    #         <input type="submit" value="Login">
    #     </form>
    # '''

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_user = request.form['username']
        new_pwd = request.form['password']

        hashed_pwd = bcrypt.generate_password_hash(new_pwd).decode('utf-8')

        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_user, hashed_pwd))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except:
            return "Username already exists!"

    return render_template('register.html')

@app.route('/welcome')
def welcome():
    # Get username from query parameter (?username=... in URL)
    username = request.args.get('username')
    
    if username:
        # Sanitize the username to prevent XSS
        sanitized_username = html.escape(username)
        return f"Welcome, {sanitized_username}!"  # Display welcome message with sanitized username
    else:
        # If no username in query param, check session or redirect to login
        if 'username' in session:
            sanitized_session_username = html.escape(session['username'])
            return f"Welcome, {sanitized_session_username}!"
        return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
