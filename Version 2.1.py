from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dateutil import tz
from sqlalchemy import or_

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def date_now():
    local_zone = tz.tzlocal()
    return datetime.now(local_zone)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=date_now())
    reviews = db.relationship('Review', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

    @classmethod
    def create(cls, username, email, password):
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = cls(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    film_title = db.Column(db.String(150), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=date_now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='review', cascade='all, delete-orphan', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    local_zone = tz.tzlocal()
    date = db.Column(db.DateTime, default=date_now())
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----- ROUTES -----
@app.route('/')
def home():
    reviews = Review.query.order_by(Review.date.desc()).all()

    reviews_grouped = {}
    for review in reviews:
        title = review.film_title
        if title not in reviews_grouped:
            reviews_grouped[title] = []
        reviews_grouped[title].append(review)

    return render_template('home.html', reviews_grouped=reviews_grouped)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter(or_(User.username == username, User.email == email)).first():
            flash('Username or email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        try:
            User.create(username=username, email=email, password=password)
            flash('Registration successful! Please log in.', 'success')
        except Exception as e:
            print(f"Registration Error: {e}")
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
        film_title = request.form['film_title']
        rating = int(request.form['rating'])
        text = request.form['text']
        new_review = Review(film_title=film_title, rating=rating, text=text, user_id=current_user.id)
        db.session.add(new_review)
        db.session.commit()
        flash('Review posted successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('review.html')


@app.route('/comment/<int:review_id>', methods=['POST'])
@login_required
def comment(review_id):
    text = request.form['comment_text']
    review = Review.query.get_or_404(review_id)
    new_comment = Comment(text=text, review_id=review.id, user_id=current_user.id)
    db.session.add(new_comment)
    db.session.commit()
    flash('Comment added!', 'success')
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
