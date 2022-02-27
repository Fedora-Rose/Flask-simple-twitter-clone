from distutils.log import debug
from enum import unique
from flask import Flask, redirect, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, logout_user, login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask('app')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app) 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.loginview = '/login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    display_name = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(200))
    posts = db.relationship('Post', backref='owner')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    title = db.Column(db.String(20))
    text = db.Column(db.String(250))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@app.route('/', methods=['POST', 'GET'])
def home():
    if request.method == 'POST':
        title = request.form['title']
        text = request.form['text']

        new_post = Post(title=title, text=text, owner=current_user)
        db.session.add(new_post)
        db.session.commit()
    return render_template('home.html', current_user=current_user)

@app.route('/user/<name>')
def user(name):
    user = User.query.filter_by(display_name=name).first()

    if user: 
        posts = user.posts
        return render_template('user.html', user=user, posts=posts)
    else:
        return '404'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        user = User.query.filter_by(display_name=name).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect('/')
            else:
                return render_template('login.html', error='Wrong username or password')

        else:
            return render_template('login.html', error='Wrong username or password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']

        existing_user_name = User.query.filter_by(display_name=name).first()
        if existing_user_name:
            return render_template('register.html', error='User allready exists')
        else:
            hashed_password = generate_password_hash(password, method="sha256")
            new_user = User(display_name=name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)