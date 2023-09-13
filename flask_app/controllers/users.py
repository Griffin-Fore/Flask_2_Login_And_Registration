from flask_app import app
from flask import Flask, render_template, redirect, request, session
from flask_app.models import user
from flask_bcrypt import Bcrypt

# READ
@app.route('/')
def index():
    return render_template("index.html")


# CREATE
@app.route('/create_user', methods=["POST"])
def create_user():
    user.User.create_user(request.form)
    return redirect('/user')

#show one user route page
@app.route('/user')
def show_one_user():
    if 'user_id' not in session:
        return redirect('/')
    return render_template('one_user.html')

@app.route('/users/login', methods=["POST"])
def login():
    if user.User.login(request.form):
        return redirect('/user')
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
