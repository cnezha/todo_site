from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)  # Убрал unique=True
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def get_id(self):
        return str(self.id)  # Явное указание метода get_id

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserManager:
    @staticmethod
    def create_user(username, email, password):
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e
        return user

    @staticmethod
    def get_user_by_email(email):
        return User.query.filter_by(email=email).first()