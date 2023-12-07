from flask import Flask, render_template, flash, request, redirect, url_for
from sqlalchemy import desc
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from webforms import LoginForm, PostForm, UserForm, SearchForm
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import uuid as uuid
from flask_mail import Mail, Message
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://name:pass@host/db'
app.config['SECRET_KEY'] = "mysecret"


app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mailname'
app.config['MAIL_PASSWORD'] = 'pass'

mail = Mail(app)

UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))


@app.context_processor
def base():
	form = SearchForm()
	return dict(form=form)


@app.route('/search', methods=["POST"])
def search():
	form = SearchForm()
	posts = Posts.query
	if form.validate_on_submit():
		post.search = form.search.data

		posts = posts.filter(Posts.tags.like('%' + post.search + '%'))
		posts = posts.order_by(desc(Posts.date_posted)).all()

		return render_template("search.html",
		 form=form,
		 search = post.search,
		 posts = posts)


@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password_hash, form.password.data):
				login_user(user)
				flash("Login Succesfull!")
				return redirect(url_for('posts'))
			else:
				flash("Wrong Password - Try Again!")
		else:
			flash("That User Doesn't Exist! Try Again...")


	return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You Have Been Logged Out!  Thanks For Stopping By...")
	return redirect(url_for('login'))




@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
	post_to_delete = Posts.query.get_or_404(id)
	id = current_user.id
	if id == post_to_delete.poster.id:
		try:
		    PostLikes.query.filter_by(post_id=post_to_delete.id).delete()
			db.session.delete(post_to_delete)
			db.session.commit()
			flash("Blog Post Was Deleted!")

		    posts = Posts.query.order_by(desc(Posts.date_posted)).all()
		    return render_template("posts.html", posts=posts)


		except:
			flash("Whoops! There was a problem deleting post, try again...")

			posts = Posts.query.order_by(desc(Posts.date_posted)).all()
			return render_template("posts.html", posts=posts)
	else:
		flash("You Aren't Authorized To Delete That Post!")

		posts = Posts.query.order_by(desc(Posts.date_posted)).all()
		return render_template("posts.html", posts=posts)

@app.route('/')
def index():
	posts = Posts.query.order_by(desc(Posts.date_posted)).all()
	return render_template("posts.html", posts=posts)


@app.route('/my_posts')
def my_posts():
	posts = Posts.query.order_by(desc(Posts.date_posted)).all()
	return render_template("my_posts.html", posts=posts)

@app.route('/posts')
def posts():
	posts = Posts.query.order_by(desc(Posts.date_posted)).all()
	return render_template("posts.html", posts=posts)

@app.route('/posts/<int:id>')
def post(id):
	post = Posts.query.get_or_404(id)
	return render_template('post.html', post=post)

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
	post = Posts.query.get_or_404(id)
	form = PostForm()
	if form.validate_on_submit():
		post.title = form.title.data
		post.tags = form.tags.data
		post.content = form.content.data

		db.session.add(post)
		db.session.commit()
		flash("Post Has Been Updated!")
		return redirect(url_for('post', id=post.id))

	if current_user.id == post.poster_id:
		form.title.data = post.title
		form.tags.data = post.tags
		form.content.data = post.content
		return render_template('edit_post.html', form=form)
	else:
		flash("You Aren't Authorized To Edit This Post...")
		posts = Posts.query.order_by(desc(Posts.date_posted)).all()
		return render_template("posts.html", posts=posts)



@app.route('/add-post', methods=['GET', 'POST'])
#@login_required
def add_post():
	form = PostForm()

	if form.validate_on_submit():
		poster = current_user.id
		post = Posts(title=form.title.data, content=form.content.data, poster_id=poster, tags=form.tags.data)

		form.title.data = ''
		form.content.data = ''
		form.tags.data = ''

		db.session.add(post)
		db.session.commit()

		users = Users.query.with_entities(Users.email).all()
		sender = "mailsender"
		for user in users:
		    try:
		        msg = Message("New Blog Post Alert", sender=sender, recipients=[user.email])
		        msg.body = f"A new post has been added to the blog. Check it out at {url_for('post', id=post.id, _external=True)}"
		        mail.send(msg)
		    except Exception as e:
		        print(str(e))
		flash("Blog Post Submitted Successfully!")

	return render_template("add_post.html", form=form)


@app.route('/posts/like/<int:post_id>')
@login_required
def like_post(post_id):
    post_like = PostLikes.query.filter_by(post_id=post_id, user_id=current_user.id).first()
    if post_like:
        if post_like.like_status:
            db.session.delete(post_like)
            flash('You have unliked the post.')
        else:
            post_like.like_status = True
            flash('You have changed your reaction to like.')
    else:
        new_like = PostLikes(post_id=post_id, user_id=current_user.id, like_status=True)
        db.session.add(new_like)
        flash('You liked the post.')
    db.session.commit()
    return redirect(url_for('posts'))

@app.route('/posts/dislike/<int:post_id>')
@login_required
def dislike_post(post_id):
    post_dislike = PostLikes.query.filter_by(post_id=post_id, user_id=current_user.id).first()
    if post_dislike:
        if not post_dislike.like_status:
            db.session.delete(post_dislike)
            flash('You have undisliked the post.')
        else:
            post_dislike.like_status = False
            flash('You have changed your reaction to dislike.')
    else:
        new_dislike = PostLikes(post_id=post_id, user_id=current_user.id, like_status=False)
        db.session.add(new_dislike)
        flash('You disliked the post.')
    db.session.commit()
    return redirect(url_for('posts'))





@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
	name = None
	form = UserForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user is None:
			hashed_pw = generate_password_hash(form.password_hash.data, method='pbkdf2:sha256')
			user = Users(username=form.username.data, name=form.name.data, email=form.email.data, password_hash=hashed_pw)
			db.session.add(user)
			db.session.commit()
		name = form.name.data
		form.name.data = ''
		form.username.data = ''
		form.email.data = ''
		form.password_hash.data = ''

		flash("User Added Successfully!")
	return render_template("add_user.html",
		form=form,
		name=name)


@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500

class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255), nullable=False)
	content = db.Column(db.Text)
	date_posted = db.Column(db.DateTime, default=datetime.utcnow)
	tags = db.Column(db.String(255), nullable=False)
	poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	likes = db.relationship('PostLikes', backref='post', lazy='dynamic')

class PostLikes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    like_status = db.Column(db.Boolean, nullable=False)


class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable=False, unique=True)
	date_added = db.Column(db.DateTime, default=datetime.utcnow)

	password_hash = db.Column(db.String(128))
	posts = db.relationship('Posts', backref='poster')
	liked_posts = db.relationship('PostLikes', backref='user', lazy='dynamic')


	@property
	def password(self):
		raise AttributeError('password is not a readable attribute!')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	def __repr__(self):
		return '<Name %r>' % self.name