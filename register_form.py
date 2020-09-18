from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField
from wtforms.validators import ValidationError, DataRequired, Length, Email, number_range, EqualTo


class registerForm(FlaskForm):
    name = StringField('First Name', render_kw={"placeholder": "First Name"}, validators=[DataRequired(message="This field cannot be empty"), Length(max=50, message="Cannot be over 50 characters")])
    email = StringField('Email Address:', render_kw={"placeholder": "Email Address"}, validators=[DataRequired(message="This field cannot be empty"), Email(message="Please enter a valid email address"), Length(max=320, message="Cannot be over 320 characters")])
    password = PasswordField('Password:', render_kw={"placeholder": "Password"}, validators=[DataRequired(message="This field cannot be empty"), Length(min=6, message="Password must be over 6 characters"), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password:', render_kw={"placeholder": "Confirm Password"}, validators=[DataRequired(message="This field cannot be empty"), Length(min=6, message="Password must over 6 characters")])

