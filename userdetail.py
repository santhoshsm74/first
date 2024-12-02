from flask import Flask, render_template, request, redirect, flash, url_for, session
import mysql.connector
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flash messages and session management

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',         # Replace with your MySQL username
    'password': 'San_game7',# Replace with your MySQL password
    'database': 'user_db'   # Replace with your database name
}

# Home Route (renders the welcome page)
@app.route('/')
def home():
    return render_template('user.html')  # Render the main page with options for login and sign-up

# Sign Up Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        phone_number = request.form['phone_number']

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            query = "INSERT INTO user1 (email, password, username, phone_number) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (email, hashed_password.decode('utf-8'), username, phone_number))
            conn.commit()

            flash('Sign up successful! You can now log in.', 'success')
            return redirect(url_for('login'))

        except mysql.connector.IntegrityError:
            flash("Email or Username already exists!", "danger")
            return redirect(url_for('signup'))
        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", 'danger')
            return redirect(url_for('signup'))

        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            query = "SELECT password FROM user1 WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                session['username'] = username  # Store the username in the session
                flash('Login successful!', 'success')
                return redirect(url_for('pay'))
            else:
                flash('Invalid username or password.', 'danger')
                return redirect(url_for('login'))

        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", 'danger')
            return redirect(url_for('login'))

        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')

# Payment Page Route
@app.route('/pay')
def pay():
    if 'username' not in session:  # Ensure the user is logged in
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT username FROM user1 ORDER BY username ASC"
        cursor.execute(query)
        users = cursor.fetchall()

        return render_template('pay.html', users=users, current_user=session['username'])

    except mysql.connector.Error as err:
        return f"Database error: {err}"

    finally:
        cursor.close()
        conn.close()

# Password Validation Page
@app.route('/password', methods=['GET', 'POST'])
def password_page():
    if 'username' not in session:  # Ensure the user is logged in
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    current_user = session['username']  # Get the logged-in username

    if request.method == 'POST':
        password = request.form['password']

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            query = "SELECT password FROM user1 WHERE username = %s"
            cursor.execute(query, (current_user,))
            result = cursor.fetchone()

            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                flash('Password validated successfully!', 'success')
                return redirect(url_for('pay'))
            else:
                flash('Invalid password. Try again.', 'danger')
                return redirect(url_for('password_page'))

        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", 'danger')
            return redirect(url_for('pay'))

        finally:
            cursor.close()
            conn.close()

    return render_template('password.html', username=current_user)

# Logout Route
@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
