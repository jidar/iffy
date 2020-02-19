# app.py
import logging
import os
import sys
from config import BaseConfig
from giphylib.client import Giphy as GAPI
from flask import Flask
from flask import request, render_template, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo

app = Flask(__name__)
app.config.from_object(BaseConfig)
login = LoginManager(app)
login.login_view = 'login'
db = SQLAlchemy(app)

from giphylib.client import API_KEY
from models import *

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
@login_required
def index():
    return render_template('index.html')

@app.route('/search', methods=['GET', 'POST', 'PUT'])
@login_required
def search():
    if request.method == 'POST':
        query = request.form['query']
        gapi = GAPI(API_KEY)
        results = gapi.search(query=query)
        return render_template('search.html', results=results.data)
    return render_template('search.html', results=[])

@app.route('/manage', methods=['GET', 'POST'])
@login_required
def manage():
    if request.method == 'POST':
        saved_gifs = request.form.getlist('saved')
        for sg in saved_gifs:
            id, slug = sg.split('::')
            gif = Gifs(session.get('_user_id'), id, slug)
            matches = (
                Gifs.query.filter_by(userid=1)
                    .filter_by(gifid=id)
                    .filter_by(slug=slug)
                    .first()
            )
            if matches is None:
                db.session.add(gif)
                db.session.commit()

    gifs = Gifs.query.filter_by(userid=session.get('_user_id')).all()
    return render_template('manage.html', gifs=gifs)

@app.route('/delete', methods=['POST'])
def delete():
    deletable_gifs = request.form.getlist('deleted')
    for gifid in deletable_gifs:
        gifs = (
            Gifs.query
                .filter_by(gifid=gifid)
                .filter_by(userid=session.get('_user_id'))
                .delete()
        )
        db.session.commit()
    return redirect(url_for('manage'))

if __name__ == '__main__':
    app.run()
