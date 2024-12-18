from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin


class ToDo(db.Model):
    __tablename__ = 'todo'
    item_id = db.Column(db.Integer(), primary_key=True, unique=True, nullable=False)
    item = db.Column(db.String(64), nullable=False, unique=False)
    priority = db.Column(db.Integer(), nullable=False, unique=False, default=5)
    #user = db.relationship('User', backref='item', lazy='dynamic') trial
    user = db.Column(db.Integer, db.ForeignKey('users.user_id'))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    username = db.Column(db.String(20), nullable=False, unique=True, index=True)
    email = db.Column(db.String(64), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    #user = db.Column(db.Integer, db.ForeignKey('user.item_id'), nullable=True) # also trial
    todo = db.relationship('ToDo', backref='todoitem', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, salt_length=32)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Since we named our primary key "user_id", instead of "id", we have to override the
    # get_id() from the UserMixin to return the id, and it has to be returned as a string
    def get_id(self):
        return str(self.user_id)

    def __repr__(self):
        return f"user(id='{self.user_id}', '{self.username}', '{self.email}')"


@login.user_loader
def load_user(id):
    return User.query.get(int(id))
