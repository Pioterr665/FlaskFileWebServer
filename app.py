from flask import Flask, render_template, request, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, login_user, LoginManager, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
# from sql_models import UserClass, LoginForm, RegisterForm

#app and db settings
app = Flask(__name__)
bcrypt = Bcrypt(app)
db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'
db.init_app(app)

#LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#SQL models

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": 'username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": 'password'})
    submit = SubmitField("Register")
    def validate_username(self, username):
        existing_user_name = User.query.filter_by(
            username=username.data).first()
        if existing_user_name:
            raise ValidationError("User already exists")
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": 'username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": 'password'})
    submit = SubmitField("Login")

@login_manager.user_loader
def user_loader(username):
    if User.query.filter_by(username = form.username):
        sda

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
                return redirect('dashboard')
    return render_template('login.html', form=form)

#register function with hashing password
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username = form.username.data, pasword = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form = form)

#dashboard page
@login_required
@app.route('/dashboard')
def dashboard():
        return render_template('dashboard')

#logout function
@app.route('/logout')        
def logout():
    logout_user()
    return redirect('index')
    
            
if __name__ == "__main__":
    app.run(debug=True)