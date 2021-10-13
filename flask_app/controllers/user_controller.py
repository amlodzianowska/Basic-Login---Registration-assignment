from flask_app import app
from flask import render_template, redirect, session, request, flash
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
from flask_app.models.user import User

@app.route("/")
def main_page():
    return render_template("index.html")

@app.route("/register", methods=['POST'])
def registration():
    if not User.validate_register(request.form):
        return redirect("/")
    data = {
        "first_name" : request.form['first_name'],
        "last_name" : request.form['last_name'],
        "email" : request.form['email'],
        "password" : bcrypt.generate_password_hash(request.form['password'])
    }
    user_id = User.save_user(data)
    session['user_id'] = user_id
    return redirect("/dashboard")

@app.route("/login", methods = ['POST'])
def login():
    if not User.validate_login(request.form):
        return redirect("/")
    user_from_db = User.get_by_email(request.form)
    session['user_id'] = user_from_db.id

    return redirect("/dashboard")

@app.route("/dashboard")
def show_dashboard():
    if "user_id" not in session:
        flash("Please register/login before continuing!")
        return redirect("/")

    data = {
        "user_id" : session['user_id']
    }
    user = User.get_user_by_id(data)
    return render_template("dashboard.html", user=user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")