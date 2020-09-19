from flask import Flask, session, redirect, render_template, request
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from login_form import loginForm
from register_form import registerForm
import datetime

app = Flask(__name__)
# TODO: Keep email password as environment variable
# TODO: Implement register functionality
# TODO: Fix Kalaish's validator logic
# TODO: Fix Tarun's css
# TODO: Polish/explore HTML
# TODO: Implement forgot_password.html
# TODO: Push all changes

app.config.update(
    SECRET_KEY="YNeGB;aX+5Pu6(}>?T?xs0sn3a{PZ0r7z|-K",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_DATABASE_URI="sqlite:///site.db",
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=465,
    MAIL_USERNAME="dstackordering@gmail.com",
    MAIL_PASSWORD="kalaishisreallystupid39429iidoPSIIOCNH)(SOH((@OInNKLFNAIOjiojIOA",
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=True
)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
mail = Mail(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=False, nullable=False)
    type = db.Column(db.String(50), unique=False, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.datetime.now)
    pwHash = db.Column(db.String(60), unique=False, nullable=False)
    orders = db.relationship("Order", backref="orderer", lazy=True)

    def __repr__(self):
        return f"<User {self.name}, {self.email}>"


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=True)

    def __repr(self):
        return f"<Order {self.id}>, {self.quantity} of {self.item_id}"


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orders = db.relationship("Order", backref="group", lazy=True)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orders = db.relationship("Order", backref="item", lazy=True)


def authenticate(page_type=None):
    """
    :param page_type: either orderer, staff, manager or a NoneType
    :return: a tuple, the first value being a boolean indicating whether the user should be on the current page and the
    second being a string (None if the boolean was set to true) indicating the path the user should be redirected to
    """
    pages = {None: "/login",
             "orderer": "/orderer/home",
             "staff": "/staff/home",
             "manager": "/manager/home"}
    if "user" not in session:
        return not page_type, pages[None]
    user = User.query.get(session["user"])
    return user.type == page_type, user.pages[user.type]


def create_user(name, email, password):
    """
    :param name: The user's real name
    :param email: The user's email address (used to contact them)
    :param password: The password the user set
    :return: A tuple (`result`, `message`), where `result` is a boolean indicating whether the user was created or not, and
    `message` is the message that will be displayed to the user
    """
    if User.query.filter_by(email=email).first():
        return False, "That email is already in use"
    pwHash = bcrypt.generate_password_hash(password, 10)
    db.session.add(User(name=name, email=email, pwHash=pwHash, type="orderer"))
    db.session.commit()
    return True, "Your account was created!"


def verify_login(email, password):
    """
    :param email: The user's email
    :param password: The password which will be checked
    :return: `result`, which is a boolean indicating whether the login credentials were correct or not
    """
    user = User.query.filter_by(email=email).first()
    if not user:
        return False

    if bcrypt.check_password_hash(user.pwHash, password):
        return True
    else:
        return False


def find_user(email):
    #returns True if emails in email is already in database
    return False


@app.route('/')
def index():  # NOTE: session is cleared when the BROWSER is closed, not the last window of the page
    allowed, new_page = authenticate()
    if allowed:
        return redirect("/login")
    else:
        return redirect(new_page)


@app.route('/login', methods=["GET", "POST"])
def login():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = loginForm()
    if not form.validate_on_submit():
        return render_template('login.html', form=form, location="Login")
    login_info = request.form
    if verify_login(login_info['email'], login_info['password']):
        return 'Successfully logged in, happy days'
    else:
        return render_template('login.html', form=form, invalid=True, location="Login")


@app.route('/register', methods=["GET", "POST"])
def register():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = registerForm()
    if not form.validate_on_submit():
        return render_template('register.html', form=form, location="Register")
    register_info = request.form
    if not find_user(register_info['email']):
        #function to add guy to database
        return 'Successfully registered, happy days'
    else:
        return render_template("register.html", form=form, invalid=True, location="Register")


@app.route('/forgot_password')
def forgot_password():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    return render_template("forgot_password.html")


if __name__ == '__main__':
    app.run()
