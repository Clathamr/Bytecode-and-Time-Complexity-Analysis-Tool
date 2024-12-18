from flask import render_template, redirect, url_for, flash, request
from app import app, db
from app.forms import (LoginForm, RegistrationForm, ToDoForm, UploadFileForm)
from app.models import User
from flask_login import current_user, login_user, logout_user, login_required
from urllib.parse import urlsplit
from uuid import uuid4
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import os
from email_validator import validate_email, EmailNotValidError


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


# To do functionality
@login_required
@app.route('/todo', methods=['GET', 'POST'])
def todo():
    form = ToDoForm()
    if current_user.is_authenticated:
        if form.validate_on_submit():
            item = form.item.data
            priority = form.priority.data
            #item_add = ToDoForm(item=item, priority=priority) # this also wouldnt, work, i have no idea why none of these are usable with db.session.add
            #add_item = ToDoForm(item=form.item.data, priority=form.priority.data) #Tried this and the line above for something to add and committ but neither work and cannot see why
            if form.priority: # checks
                priority = form.priority.data
            #     print(priority)
            # print(item_add)
            db.session.add(item) # cannot see why this doesnt work, im adding something with item and priority to a class asking for item then priority
            db.session.commit()

    return render_template('todo.html', title='ToDoList', form=form)


# Here is the upload functionality
@login_required
@app.route('/upload')
def upload():
    form = UploadFileForm()
    if form.validate_on_submit():
        if form.todo_file.data:
            unique_str = str(uuid4())
            filename = secure_filename(f'{unique_str}-{form.todo_file.data.filename}')
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.todo_file.data.save(filepath)
            try:
                with open(filepath, newline='') as txtfile:
                    lines = txtfile.readlines()
                    for line in lines:
                        if line:
                            new_item = ToDoForm.item(item=line)
                            db.session.add(new_item) # here the default value is 5 as is it made so in the models.py
                            db.session.commit()
            except:
                flash('upload failed')
                db.session.rollback()
            finally:
                silent_remove(filepath)

    return render_template('upload.html', title='upload', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash(f'Login for {form.username.data}', 'success')
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data,
                        password_hash=generate_password_hash(form.password.data, salt_length=32))
        db.session.add(new_user)
        try:
            db.session.commit()
            flash(f'Registration for {form.username.data} received', 'success')
            return redirect(url_for('index'))
        except:
            db.session.rollback()
            if User.query.filter_by(username=form.username.data):
                form.username.errors.append('This username is already taken. Please choose another')
            if User.query.filter_by(email=form.email.data):
                form.email.errors.append('This email address is already registered. Please choose another')
            flash(f'Registration failed', 'danger')
    return render_template('registration.html', title='Register', form=form)


def is_valid_email(email):
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError as error:
        return False
    return True


# Attempt to remove a file but silently cancel any exceptions if anything goes wrong
def silent_remove(filepath):
    try:
        os.remove(filepath)
    except:
        pass
    return


# Handler for 413 Error: "RequestEntityTooLarge". This error is caused by a file upload
# exceeding its permitted Capacity
# Note, you should add handlers for:
# 403 Forbidden
# 404 Not Found
# 500 Internal Server Error
# See: https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
@app.errorhandler(413)
def error_413(error):
    return render_template('errors/413.html'), 413
