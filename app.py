from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError, InputRequired, EqualTo
from wtforms.validators import email
from flask_bootstrap import Bootstrap
from flask_mysqldb import MySQL
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from flask import current_app
import random
import string


app = Flask(__name__)
app.secret_key = 'your_secret_key'
Bootstrap(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'kogi_state_tescom'
mysql = MySQL(app)

# All login function.................................................................
class SuperAdmin:
    def __init__(self):
        self.__email = "superadmin@gmail.com"
        self.__password_hash = generate_password_hash("superadmin123")

    def login(self, email, password):
        return email == self.__email and check_password_hash(self.__password_hash, password)

_superadmin = SuperAdmin()

def admin_login(email, password):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, password_hash FROM admins WHERE email = %s", (email,))
    row = cursor.fetchone()
    cursor.close()
    if row and check_password_hash(row[1], password):
        return row[0]  # Return admin id
    return None

# --- Teacher login helper ---
def teacher_login(email, password):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, password_hash FROM teachers WHERE email = %s", (email,))
    row = cursor.fetchone()
    cursor.close()
    if row and check_password_hash(row[1], password):
        return row[0]  # Return teacher id
    return None


# --- Routes -..................................................................................--
@app.route('/')
def landingPage():
    show_login = request.args.get('login') == '1'
    login_error = request.args.get('error') == '1'
    return render_template('landingPage.html', show_login=show_login, login_error=login_error)

@app.route('/login', methods=['POST'])
def login():
    role = request.form.get('role')
    email = request.form.get('email')
    password = request.form.get('password')
    session.clear()

    if role == "superadmin":
        if _superadmin.login(email, password):
            session['role'] = 'superadmin'
            session['user_id'] = 'SA'
            return redirect(url_for('superadmin_dashboard'))
        else:
            flash("Invalid superadmin credentials.", "danger")
            return redirect(url_for('landingPage', login=1, error=1))

    elif role == "admin":
        admin_id = admin_login(email, password)
        if admin_id:
            session['role'] = 'admin'
            session['user_id'] = admin_id
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials.", "danger")
            return redirect(url_for('landingPage', login=1, error=1))

    elif role == "teacher":
        teacher_id = teacher_login(email, password)
        if teacher_id:
            session['role'] = 'teacher'
            session['teacher_id'] = teacher_id
            return redirect(url_for('teacher_dashboard'))
        else:
            flash("Invalid teacher credentials.", "danger")
            return redirect(url_for('landingPage', login=1, error=1))

    else:
        flash("Please select a valid role.", "warning")
        return redirect(url_for('landingPage', login=1, error=1))

# --- Dashboard routes with role protection ---

def role_required(role):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                flash("Unauthorized access.", "danger")
                return redirect(url_for('landingPage', login=1, error=1))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/superadmin_dashboard')
@role_required('superadmin')
def superadmin_dashboard():
    cursor = mysql.connection.cursor()

    # Latest unused password
    cursor.execute("""
        SELECT password FROM superadmin_password
        WHERE used = FALSE ORDER BY created_at DESC LIMIT 1
    """)
    latest_row = cursor.fetchone()
    latest_password = latest_row[0] if latest_row else None

    # Last 10 passwords
    cursor.execute("""
        SELECT password, used, created_at
        FROM superadmin_password ORDER BY created_at DESC LIMIT 10
    """)
    history_rows = cursor.fetchall()
    password_history = [{'password': row[0], 'used': row[1], 'created_at': row[2]} for row in history_rows]

    cursor.close()

    return render_template('superadmin_dashboard.html',
                           latest_password=latest_password,
                           password_history=password_history)


@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, name, email, phone FROM teachers")
    teachers = cursor.fetchall()
    cursor.close()
    return render_template('admin_dashboard.html', teachers=teachers)


@app.route('/teacher_dashboard')
@role_required('teacher')
def teacher_dashboard():
    teacher_id = session.get('teacher_id')
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, message FROM notifications
        WHERE teacher_id = %s AND is_read = FALSE
        ORDER BY created_at DESC
    """, (teacher_id,))
    notifications = cursor.fetchall()
    cursor.close()
    return render_template('teacher_dashboard.html', notifications=notifications)

# ---- universal logout ----------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("landingPage"))


# superadmin.to.create.admin..................................................................................
@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        cursor = None  # Initialize cursor variable
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO admins (email, password_hash) VALUES (%s, %s)", (email, password_hash))
            mysql.connection.commit()
            flash('Admin created successfully.', 'success')
        except Exception as e:
            # print(f"Error: {e}")
            flash('Admin creation failed. Email might already exist.', 'danger')
        finally:
            if cursor:
                cursor.close()
        return redirect(url_for('create_admin'))
    return render_template('create_admin.html')

# admin.to.create.teacher..................................................................................
@app.route('/create_teacher', methods=['GET', 'POST'])
def create_teacher():
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            phone = request.form['phone']
            gender = request.form['gender']
            lga = request.form['lga']
            subject = request.form['subject']
            school_name = request.form['school_name']
            qualification = request.form['qualification']
            address = request.form['address']
            state = request.form['state']
            date_of_birth = request.form['date_of_birth']
            date_joined = request.form['date_joined']
            promotion = request.form['promotion']
            level = request.form['level']
            password = request.form['password']
            password_hash = generate_password_hash(password)
            created_at = datetime.now()

            cursor = mysql.connection.cursor()
            cursor.execute("""
                INSERT INTO teachers (
                    name, email, phone, gender, lga, subject, school_name, qualification,
                    address, state, date_of_birth, date_joined, promotion, level,
                    password_hash, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                name, email, phone, gender, lga, subject, school_name, qualification,
                address, state, date_of_birth, date_joined, promotion, level,
                password_hash, created_at
            ))
            mysql.connection.commit()
            print("Teacher created successfully:", email)
            flash('Teacher created successfully.', 'success')
        except Exception as e:
            print("Error inserting teacher:", e)
            flash('Teacher creation failed.', 'danger')
        finally:
            if cursor:
                cursor.close()

        return redirect(url_for('create_teacher'))

    return render_template('create_teacher.html')

# SMS route................................................................................................
@app.route('/send_message', methods=['GET', 'POST'])
def send_message():
    cursor = mysql.connection.cursor()

    if request.method == 'POST':
        recipient_type = request.form['recipient_type']
        message = request.form['message']

        if recipient_type == 'all':
            cursor.execute("SELECT phone FROM teachers")
            teachers = cursor.fetchall()
            for teacher in teachers:
                phone = teacher[0]
                send_sms(phone, message)
            flash("Message sent to all teachers.", "success")

        elif recipient_type == 'individual':
            teacher_id = request.form['teacher_id']
            cursor.execute("SELECT phone FROM teachers WHERE id = %s", (teacher_id,))
            result = cursor.fetchone()
            if result:
                phone = result[0]
                send_sms(phone, message)
                flash("Message sent to the selected teacher.", "success")
            else:
                flash("Teacher not found.", "danger")

        cursor.close()
        return redirect(url_for('send_message'))

    cursor.execute("SELECT id, name, phone FROM teachers")
    teachers = cursor.fetchall()
    cursor.close()

    return render_template('send_message.html', teachers=teachers)

@app.route('/manage_promotions', methods=['GET', 'POST'])
@role_required('admin')
def manage_promotions():
    cursor = mysql.connection.cursor()

    if request.method == 'POST':
        teacher_id = request.form['teacher_id']
        new_level = int(request.form['level'])
        entered_password = request.form['superadmin_password']

        # Check for matching unused password
        cursor.execute("""
            SELECT id FROM superadmin_password
            WHERE password = %s AND used = FALSE
            ORDER BY created_at DESC LIMIT 1
        """, (entered_password,))
        result = cursor.fetchone()

        if not result:
            flash("Invalid or already-used Superadmin password. Promotion not allowed.", "danger")
            return redirect(url_for('manage_promotions'))

        try:
            # Mark password as used
            cursor.execute("UPDATE superadmin_password SET used = TRUE WHERE id = %s", (result[0],))

            # Update teacher's level
            cursor.execute("""
                UPDATE teachers SET level = %s WHERE id = %s
            """, (new_level, teacher_id))

            # Insert notification
            message = f"You have been promoted to level {new_level}."
            cursor.execute("""
                INSERT INTO notifications (teacher_id, message, is_read)
                VALUES (%s, %s, FALSE)
            """, (teacher_id, message))

            mysql.connection.commit()
            flash("Promotion successful. Superadmin password has been used and invalidated.", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash("Failed to update teacher: " + str(e), 'danger')

    # Fetch all teachers
    cursor.execute("SELECT id, name, email, level, status FROM teachers")
    columns = [col[0] for col in cursor.description]
    teachers = [dict(zip(columns, row)) for row in cursor.fetchall()]
    cursor.close()

    return render_template('manage_promotions.html', teachers=teachers)

# @app.route('/manage_promotions', methods=['GET', 'POST'])
# @role_required('admin')
# def manage_promotions():
#     cursor = mysql.connection.cursor()
#
#     if request.method == 'POST':
#         teacher_id = request.form['teacher_id']
#         new_level = int(request.form['level'])
#
#         try:
#
#             cursor.execute("""
#                 UPDATE teachers
#                 SET level = %s
#                 WHERE id = %s
#             """, (new_level, teacher_id))
#
#
#             message = f"You have been promoted to level {new_level}."
#             cursor.execute("""
#                 INSERT INTO notifications (teacher_id, message, is_read)
#                 VALUES (%s, %s, FALSE)
#             """, (teacher_id, message))
#
#             mysql.connection.commit()
#             flash("Teacher's level updated and notification sent.", 'success')
#         except Exception as e:
#             mysql.connection.rollback()
#             flash("Failed to update teacher: " + str(e), 'danger')
#
#     # Fetch all teachers
#     cursor.execute("SELECT id, name, email, level, status FROM teachers")
#     columns = [col[0] for col in cursor.description]
#     teachers = [dict(zip(columns, row)) for row in cursor.fetchall()]
#     cursor.close()
#
#     return render_template('manage_promotions.html', teachers=teachers)


@app.route('/all_teachers')
@role_required('admin')
def all_teachers():
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, name, email, phone, gender, address, level, status,
               lga, state, subject, school_name, qualification,
               date_of_birth, date_joined, created_at
        FROM teachers
    """)
    columns = [col[0] for col in cursor.description]
    teachers = [dict(zip(columns, row)) for row in cursor.fetchall()]
    cursor.close()

    return render_template('report.html', teachers=teachers)


@app.route('/send_email', methods=['GET', 'POST'])
def send_email():
    render_template("this is email box")


# teachers veiw profile.......................................................................
@app.route('/view_teacher_profile')
@role_required('teacher')
def view_teacher_profile():
    teacher_id = session.get('teacher_id')  # Correct key used during login
    if not teacher_id:
        flash("Unauthorized access", "danger")
        return redirect('/teacher_login')

    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, name, email, phone, gender, address, level, status,
               lga, state, subject, school_name, qualification,
               date_of_birth, date_joined, created_at
        FROM teachers
        WHERE id = %s
    """, (teacher_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    teacher = dict(zip(columns, row)) if row else None
    cursor.close()

    if not teacher:
        flash("Profile not found", "warning")
        return redirect('/teacher_dashboard')

    return render_template('view_teacher_profile.html', teacher=teacher)


# teacher_edit_profile.....................................................................
@app.route('/edit_profile', methods=['GET', 'POST'])
@role_required('teacher')
def edit_teacher_profile():
    teacher_id = session.get('teacher_id')
    if not teacher_id:
        flash("Unauthorized access", "danger")
        return redirect('/teacher_login')

    cursor = mysql.connection.cursor()

    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        address = request.form.get('address')
        password = request.form.get('password')  # Use get() to avoid KeyError

        if password:
            hashed_pw = generate_password_hash(password)
            cursor.execute("""
                UPDATE teachers 
                SET name=%s, phone=%s, email=%s, address=%s, password_hash=%s 
                WHERE id=%s
            """, (name, phone, email, address, hashed_pw, teacher_id))
        else:
            cursor.execute("""
                UPDATE teachers 
                SET name=%s, phone=%s, email=%s, address=%s 
                WHERE id=%s
            """, (name, phone, email, address, teacher_id))

        mysql.connection.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('view_teacher_profile'))

    # GET: fetch current data
    cursor.execute("SELECT name, phone, email, address FROM teachers WHERE id = %s", (teacher_id,))
    row = cursor.fetchone()
    cursor.close()

    if not row:
        flash("Profile not found", "warning")
        return redirect('/teacher_dashboard')

    teacher = {'name': row[0], 'phone': row[1], 'email': row[2], 'address': row[3]}
    return render_template('edit_teacher_profile.html', teacher=teacher)


@app.route('/view_notification/<int:notification_id>')
@role_required('teacher')
def view_notification(notification_id):
    cursor = mysql.connection.cursor()

    # Fetch the notification to display
    cursor.execute("""
        SELECT message, teacher_id FROM notifications WHERE id = %s
    """, (notification_id,))
    notification = cursor.fetchone()

    if not notification:
        flash("Notification not found.", "warning")
        return redirect(url_for('teacher_dashboard'))

    message, teacher_id = notification

    # Make sure the logged-in teacher owns this notification
    if teacher_id != session.get('teacher_id'):
        flash("You do not have permission to view this notification.", "danger")
        return redirect(url_for('teacher_dashboard'))

    # Mark notification as read
    cursor.execute("""
        UPDATE notifications SET is_read = TRUE WHERE id = %s
    """, (notification_id,))
    mysql.connection.commit()
    cursor.close()

    return render_template('view_notification.html', message=message)

# random password...................................................................
@app.route('/generate_superadmin_password', methods=['POST'])
@role_required('superadmin')
def generate_superadmin_password():
    import secrets
    password = secrets.token_urlsafe(8)  # Generates a strong random password
    cursor = mysql.connection.cursor()
    cursor.execute("""
        INSERT INTO superadmin_password (password, used, created_at)
        VALUES (%s, FALSE, NOW())
    """, (password,))
    mysql.connection.commit()
    cursor.close()
    flash("New promotion password generated.", "success")
    return redirect(url_for('superadmin_dashboard'))



# ====== Optional: Test Route ======
# @app.route('/test_sms')
# def test_sms():
#     if send_sms('+2348123456789', 'Hello from TeacherPortal!'):
#         return "✅ Test SMS sent"
#     return "❌ Failed to send test SMS"



if __name__ == '__main__':
    app.run(debug=True)
