from flask import Blueprint, render_template, redirect, url_for
from flask import request
from models import db, User
from flask_login import login_user, logout_user, login_required

# Create a blueprint
auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/register', methods=['GET', 'POST'])

# in the same file
@auth_blueprint.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return redirect(url_for('auth.login'))

        # Create a new user
        new_user = User(email=email)
        new_user.set_password(password)

        # Add and commit the user to the database
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('main.todo'))

    return render_template('signup.html')

@auth_blueprint.route('/api/v1/auth/signup', methods=['POST'])
@login_required
def signup():
    data = request.get_json()

    #get email and password
    email = data.get('email')
    password = data.get('password')

    #check if user exists
    existing_user = User.query.filter_by(email).first()
    if existing_user:
        return { "error" : "user already exists. please login"}, 404
    
    new_user = User(email= email)
    new_user.password = password

    db.session.add(new_user)
    db.session.commit()

    return { "user" : new_user.to_dict()}, 201





@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('main.todo'))
        
    return render_template('login.html')


@auth_blueprint.route('/api/v1/auth/login', methods=['POST'])
@login_required
def login():
    data = request.get_json()

    #get email and password
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email).first()
    if user is None or user.check_password(password):
        return {"user not found"}, 401
    
    login_user(user)
    return {"message" : "User logged in successfully", "user": user.to_dict()}, 200





@auth_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth_blueprint.route('/api/v1/auth/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return {"message": "logged out successfully"}, 200

