# models.py
import datetime
from app import db
import sqlalchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
#
# class Post(db.Model):
#
#     __tablename__ = 'posts'
#
#     id = db.Column(db.Integer, primary_key=True)
#     text = db.Column(db.String, nullable=False)
#     date_posted = db.Column(db.DateTime, nullable=False)
#
#     def __init__(self, text):
#         self.text = text
#         self.date_posted = datetime.datetime.now()

class Gifs(db.Model):
    __tablename__ = 'gifs'

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, nullable=False)
    gifid = db.Column(db.String(64))
    slug = db.Column(db.String(2048))
    #embed_url = db.Column(db.String(2048))

    def __init__(self, userid, gifid, slug):
        self.userid = userid
        self.gifid = gifid
        self.slug = slug


class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)