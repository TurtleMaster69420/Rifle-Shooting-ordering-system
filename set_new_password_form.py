from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import ValidationError, DataRequired, Length, Email, EqualTo


class set_new_password_form(FlaskForm):
    new_password = PasswordField('Password:', render_kw={"placeholder": "Password"}, validators=[DataRequired(message="This field cannot be empty"), Length(min=6, message="Password must be over 6 characters")])
    confirm_new_password = PasswordField('Confirm Password:', render_kw={"placeholder": "Confirm Password"}, validators=[DataRequired(message="This field cannot be empty"), EqualTo('password', message='Passwords must match')])
