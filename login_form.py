from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import ValidationError, DataRequired, Length, Email


class loginForm(FlaskForm):
    email = StringField('Email Address:', render_kw={"placeholder": "Email Address"},
                        validators=[DataRequired(message="This field cannot be empty"),
                                                      Email(message="Please enter a valid email address")])
    password = PasswordField('Password:', render_kw={"placeholder": "Password"},
                             validators=[DataRequired(message="This field cannot be empty"),
                                                      Length(min=6,
                                                             message="Password must be greater than 6 characters")])

