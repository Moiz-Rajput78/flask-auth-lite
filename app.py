from flask import Flask, flash, render_template,url_for, request, redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
from datetime import timedelta
import re

db = SQLAlchemy()
login_manager = LoginManager()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @app.route("/health/db")
    def health_check():
        try:
            db.session.execute(text('SELECT 1'))
            return{"db":"ok"}, 200

        except Exception as e:
            return {"db": "error", "detail": str(e)}, 500

    with app.app_context():
        db.create_all()  


    def _is_safe_local_path(target:str)->bool:
        if not target:
            return False
        parts = urlparse(target)
        return parts.scheme == "" and parts.netloc == "" and target.startswith("/")
          

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/dashboard")
    @login_required

    def dashboard():
        return render_template("dashboard.html")

    @app.route("/test")
    @login_required
    def test():
            return "Test Route"

    @app.route("/register", methods=["GET", "POST"])
    def register():

        errors=[]

        if request.method == "POST":
            username = (request.form.get("username")or "").strip()
            email = (request.form.get("email")or "").strip()
            password = request.form.get("password")or ""
            confirm = request.form.get("confirm_password")or ""

            if not(3 <= len(username) <= 150):
                errors.append("Username must be between 3 and 150 characters.")
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                errors.append("Invalid email address.")

            if len(password) < 6:
                errors.append("Password must be at least 6 characters long.")

            if password != confirm:
                errors.append("Passwords do not match.")

            if not errors:
                try:
                    pw_hash = generate_password_hash(password)
                    user = User(username=username, email=email, password=pw_hash)
                    db.session.add(user)
                    db.session.commit()
                    flash("Registration successful! Please log in.", "success")
                    return redirect(url_for('login'))
                except IntegrityError:
                    db.session.rollback()
                    errors.append("Username or email already exists.")
                
        return render_template("register.html", errors=errors)

    @app.route("/login", methods=["GET", "POST"])
    def login():

        errors=[]
        if request.method == "POST":
            email = (request.form.get("email")or "").strip()
            password = request.form.get("password")or ""

            if not email:
             errors.append("Email is required.")
            if not password:
                errors.append("Password is required.")
            if not errors:
                user = User.query.filter_by(email=email).first()
                if not user or not check_password_hash(user.password, password):
                        errors.append("Invalid email or password.")
                else:
                    remember_flag = request.form.get("remember") == "1"
                    login_user(user, remember=remember_flag)
                    flash(f"Login successful! Welcome, {user.username}!", "success")

                    next_url = request.form.get("next") or request.args.get("next") or ""
                    if _is_safe_local_path(next_url):
                        return redirect(next_url)

                    return redirect(url_for('dashboard'))

        return render_template("login.html", errors=errors)

    @app.route("/logout")
    def logout():
         logout_user()
         flash("You have been logged out.", "success")
         return redirect(url_for('index'))

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
            errors=[]
            if request.method == "POST":
                current_pw = request.form.get("current_password")or ""
                new_pw = request.form.get("new_password")or ""
                confirm_pw = request.form.get("confirm_password")or ""

                if not check_password_hash(current_user.password, current_pw):
                    errors.append("Current password is incorrect.")

                if len(new_pw) < 6:
                    errors.append("New password must be at least 6 characters long.")

                if new_pw != confirm_pw:
                    errors.append("New passwords do not match.")

                if not errors:

                    current_user.password = generate_password_hash(new_pw)
                    db.session.commit()
                    flash("Password changed successfully!", "success")
                    return redirect(url_for('dashboard'))

                print(request.form)

            return render_template("change_password.html", errors=errors)

               

    @login_manager.user_loader
    def load_user(user_id):
       return User.query.get(int(user_id))


    return app
   





if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)


app = create_app()