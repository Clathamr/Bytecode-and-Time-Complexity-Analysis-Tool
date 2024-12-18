from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, IntegerField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Email, ValidationError


class ToDoForm(FlaskForm):
    item = StringField('Thing To Do', validators=[DataRequired()])
    priority = IntegerField('Item Priority')
    submit = SubmitField('Add')


class UploadFileForm(FlaskForm):
    todo_file = FileField('Choose To Do .txt File', validators=[FileAllowed(['txt'])])
    submit = SubmitField('Upload')


class DeleteButton(FlaskForm):
    submit = SubmitField('Delete Item')


class IncrementButton(FlaskForm):  # increment here because increasing number lowers priority
    submit = SubmitField('Decrease Priority')


class DecrementButton(FlaskForm):
    submit = SubmitField('Increase Priority') # Decrement as lowing number increases priority


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmpassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


