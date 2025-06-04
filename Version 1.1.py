from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    @classmethod
    def create(cls, username, email, password):
        """
        Factory method to create a new User instance.
        This method handles hashing the password before creating the user.
        """
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = cls(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    def check_password(self, password):
        """Helper method to verify the user's password."""
        return check_password_hash(self.password_hash, password)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    reviews = Review.query.all()
    return render_template('home.html', reviews=reviews)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if user already exists (Optional but recommended)
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        try:
            User.create(username=username, email=email, password=password)
            flash('Registration successful! Please log in.', 'success')
        except Exception as e:
            # Log the exception in a production scenario
            flash('An error occurred during registration. Please try again.', 'danger')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/review', methods=['GET', 'POST'])
@login_required
def review():
    if request.method == 'POST':
        title = request.form['title']
        rating = request.form['rating']
        text = request.form['text']
        new_review = Review(title=title, user_id=current_user.id, rating=rating, text=text)
        db.session.add(new_review)
        db.session.commit()
        flash('Review posted successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('review.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if not already created
    app.run(debug=True)
