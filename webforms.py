from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, Email
from wtforms.widgets import TextArea
from flask_wtf.file import FileField

class SearchForm(FlaskForm):
	search = StringField("Search", validators=[DataRequired()])
	submit = SubmitField("Submit")

class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = TextAreaField("Content", validators=[DataRequired()])
	tags = StringField("Tags (comma-seperated)", validators=[DataRequired()])
	submit = SubmitField("Submit")

class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired(), Email()])
	password_hash = PasswordField('Password', validators=[DataRequired(),  Length(min=8, message='Password must be at least 8 characters long.'), EqualTo('password_hash2', message='Passwords Must Match!')])
	password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
	submit = SubmitField("Submit")
