from flask import Flask, session, redirect, render_template, request, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from login_form import loginForm
from forgot_password_form import forgot_password_form
from set_new_password_form import set_new_password_form
from dotenv import load_dotenv
from register_form import registerForm
import datetime
import os


load_dotenv()


app = Flask(__name__)
# TODO: Implement register functionality
# TODO: Fix Tarun's css
# TODO: Polish/explore HTML
# TODO: Implement forgot_password.html
# TODO: Push all changes

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY"),
    SECURITY_PASSWORD_SALT=os.environ.get("SECURITY_PASSWORD_SALT"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_DATABASE_URI="sqlite:///site.db",
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=465,
    MAIL_USERNAME="dstackordering@gmail.com",
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=True
)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
mail = Mail(app)
serialiser = URLSafeTimedSerializer(app.config.get("SECRET_KEY"))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=False, nullable=False)
    type = db.Column(db.String(50), unique=False, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.datetime.now)
    pwHash = db.Column(db.String(60), unique=False, nullable=False)
    confirmed = db.Column(db.Boolean)
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
    return user.type == page_type, pages[user.type]


def create_user(name, email, password, user_type="orderer"):
    """
    :param name: The user's real name
    :param email: The user's email address (used to contact them)
    :param password: The password the user set
    :param user_type: The permission level of the user (orderer, staff, manager, or None)
    :return: A string called `token`, which is the serialised token the server will use for the verification email
    """

    if User.query.filter_by(email=email).first():
        return None
    pwd_hash = bcrypt.generate_password_hash(password, 10)
    db.session.add(User(name=name, email=email, pwHash=pwd_hash, type=user_type, confirmed=False))
    db.session.commit()
    return serialiser.dumps(email, salt=app.config.get("SECURITY_PASSWORD_SALT"))


def verify_login(email, password):
    """
    :param email: The user's email
    :param password: The password which will be checked
    :return: `result`, which is a boolean indicating whether the login credentials were correct or not
    """
    user = User.query.filter_by(email=email).first()
    if not user or not user.confirmed:
        return False

    if bcrypt.check_password_hash(user.pwHash, password):
        session["user"] = user.id
        return True
    else:
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
    if form.validate_on_submit():
        login_info = request.form
        if verify_login(login_info['email'], login_info['password']):
            return redirect("/")
        else:
            flash("Either the email doesn't exist or the password is incorrect", "text-danger")
    return render_template('login.html', form=form)


@app.route('/register', methods=["GET", "POST"])
def register():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = registerForm()
    if form.validate_on_submit():
        register_info = request.form
        token = create_user(register_info.get("name"), register_info.get("email"), register_info.get("password"))
        if not token:
            form.email.errors.append("This email has already been used, try a different one")
        else:
            msg = Message("Confirm account", sender="dstackordering@gmail.com", recipients=[register_info.get("email")])
            msg.body = f"""
Here is the link to confirm your account: 127.0.0.1:5000/confirm?token={token}
            """
            mail.send(msg)
            flash("A confirmation email has been sent to your account! Please check both your inbox and spam folder", "text-success")
    return render_template('register.html', form=form)


@app.route("/confirm")
def confirm():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    try:
        # verify that the token is valid and hasn't expired
        email = serialiser.loads(
            request.args.get("token"),
            salt=app.config.get("SECURITY_PASSWORD_SALT"),
            max_age=28800  # 8 hours
        )
        user = User.query.filter_by(email=email).first()
        assert user
    except:
        return render_template("error.html")
    user.confirmed = True
    db.session.commit()
    session["user"] = user.id
    return redirect("/")


@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = forgot_password_form()
    if form.validate_on_submit():
        email = request.form["email"]
        if not User.query.filter_by(email=email).first():
            form.email.errors.append("There is no account with the provided email")
        else:
            msg = Message("Reset password", sender="dstackordering@gmail.com", recipients=[email])
            token = serialiser.dumps(email+"resetpwd", salt=app.config.get("SECURITY_PASSWORD_SALT"))
            msg.body = f"""
Here is the link to reset your password: 127.0.0.1:5000/set_new_password?token={token}
            """
            mail.send(msg)
            flash("We have sent an email to change your password, please check both your inbox and spam folder", "text-success")
    return render_template("forgot_password.html", form=form)


@app.route('/set_new_password', methods=["GET", "POST"])
def set_new_password():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = set_new_password_form()
    if request.method == "GET" or form.validate_on_submit():
        try:
            payload = serialiser.loads(
                request.args.get("token"),
                salt=app.config.get("SECURITY_PASSWORD_SALT"),
                max_age=28800
            )
            assert payload.endswith("resetpwd")
            email = payload[:-8]
            user = User.query.filter_by(email=email).first()

            assert user
        except:
            return render_template("error.html")
        if form.validate_on_submit():
            user.pwHash = bcrypt.generate_password_hash(request.form["new_password"], 10)
            print(request.form["new_password"])
            db.session.commit()
            flash("Your password has been successfully updated!", "text-success")
            return redirect("/login")
    return render_template("set_new_password.html", form=form)

@app.route('/orderer/home', methods=["GET", "POST"])
def orderer_home():
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)
    return render_template("orderer_home.html")

@app.route('/orderer/join', methods=["GET", "POST"])
def join_group():
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)
    return render_template("join_group.html")


@app.route('/orderer/create', methods=["GET", "POST"])
def create_group():
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)
    return render_template("create_group.html")

if __name__ == '__main__':
    app.run()
