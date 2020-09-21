from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import ValidationError, DataRequired, Length, Email


class forgot_password_form(FlaskForm):
    email = StringField('Email Address:', render_kw={"placeholder": "Email Address"},
                        validators=[DataRequired(message="This field cannot be empty"),
                                                      Email(message="Please enter a valid email address")])

