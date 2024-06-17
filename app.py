from flask import Flask, render_template, request, session, url_for, redirect, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, login_user, LoginManager, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os
# from sql_models import UserClass, LoginForm, RegisterForm

#app and db settings
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)
#db.init_app(app)

#LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#SQL models
#user database model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class FileClass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    owner = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)

#this funckton creates tables in database
with app.app_context():
    db.create_all()
    
#register form with validation
class FileForm(FlaskForm):
    file = FileField('File', validators=[FileRequired()])
    submit = SubmitField('Upload')

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": 'username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": 'password'})
    submit = SubmitField("Register")
    def validate_username(self, username):
        existing_user_name = User.query.filter_by(
            username = username.data).first()
        if existing_user_name:
            raise ValidationError("User already exists")
        
#login form with validation    
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": 'username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": 'password'})
    submit = SubmitField("Login")

@login_manager.user_loader
def laod_user(user_id):
    return User.query.get(int(user_id))

#index page
@app.route("/")
def index():
    return render_template('index.html')

#login function with LoginManager
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form = form)

#register function with hashing password
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username = form.username.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form = form)

#dashboard page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    files = FileClass.query.all()
    return render_template('dashboard.html', data = files)

#logout function
@app.route('/logout') 
@login_required       
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    form = FileForm()
    if current_user.is_authenticated:
        user = current_user.username
    if form.validate_on_submit():
        file = form.file.data
        filenamee = file.filename
        file.save(os.path.join('uploads', filenamee))
        new_file = FileClass(filename = filenamee, owner = user, filepath = os.path.join('uploads', filenamee))
        db.session.add(new_file)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    return render_template('upload.html', form = form)

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory('uploads', filename, as_attachment = True)

if __name__ == "__main__":
    app.run(debug=True)