from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
import secrets


app = Flask(__name__)
# app.config['SECRET_KEY'] = 'secret-key-goes-here'
# app.config['SECRET_KEY'] = secrets.token_hex(32)  # random keys three methods
app.config['SECRET_KEY'] = os.urandom(16)

# print(app.config)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# login manager let your app and flask-login work together
login_manager = LoginManager()
login_manager.init_app(app)


# user loader callback that returns the user object given and id
@login_manager.user_loader
def loader_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()


# CREATE TABLE IN DB
#  UserMixin, will help to implement properties such as is_authenticated to the User class.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    print(current_user.is_authenticated)
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        user_name = request.form.get("name")
        user_mail = request.form.get("email")
        selected_user = db.session.execute(db.select(User).where(User.email == user_mail)).scalar()

        if selected_user:   # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        user_password = generate_password_hash(
            password=request.form.get("password"),
            salt_length=8,
            method="pbkdf2:sha256"
        )

        new_user = User()   # adding new user in database
        new_user.name = user_name
        new_user.email = user_mail
        new_user.password = user_password

        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)

        flash("registered successfully, please login.")
        return redirect(url_for("login"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():

    if request.method == 'POST':
        user_email = request.form.get("email")
        user_plain_pass = request.form.get("password")
        selected_user = db.session.execute(db.select(User).where(User.email == user_email)).scalar()

        if selected_user:
            # Check stored password hash against entered password hashed.
            is_password_match = check_password_hash(
                pwhash=selected_user.password,
                password=user_plain_pass
            )
            if is_password_match:
                login_user(selected_user)
                return redirect(url_for('secrets'))
                # return render_template("secrets.html",name=selected_user.name,logged_in=current_user.is_authenticated)
            else:
                flash('Password incorrect, please try again.')
                return render_template("login.html")
        else:
            flash("That email does not exist, please try again.")
            return render_template("login.html")

    # Passing True or False if the user is authenticated.
    return render_template("login.html", logged_in=current_user.is_authenticated)


# Only logged-in users can access secret page
@app.route('/secrets')
@login_required
def secrets():
    # print(current_user.name)
    # Passing the name from the current_user
    return render_template("secrets.html", name=current_user.name, logged_in=True)


# Only logged-in users can log out
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# Only logged-in users can down download the pdf
@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
