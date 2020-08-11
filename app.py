from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import datetime

app = Flask(__name__)
app.config["SECRET_KEY"] = "YNeGB;aX+5Pu6(}>?T?xs0sn3a{PZ0r7z|-K"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=False, nullable=False)
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


def create_user(name, email, password):
    '''
    :param name: The user's real name
    :param email: The user's email address (used to contact them)
    :param password: The password the user set
    :return: A tuple (`result`, `message`), where `result` is a boolean indicating whether the user was created or not, and
    `message` is the message that will be displayed to the user
    '''
    if User.query.filter_by(email=email).first():
        return False, "That email is already in use"
    pwHash = bcrypt.generate_password_hash(password, 10)
    db.session.add(User(name=name, email=email, pwHash=pwHash))
    db.session.commit()
    return True, "Your account was created!"


def verify_login(username, password):
    '''
    :param username: Either the name or email of the user. Both will checked in the database
    :param password: The password which will be checked
    :return: `result`, which is a boolean indicating whether the login credentials were correct or not
    '''
    user = User.query.filter_by(name=username).first()
    if not user:
        user = User.query.filter_by(email=username).first()
        if not user:
            return False

    if bcrypt.check_password_hash(user.pwHash, password):
        return True
    else:
        return False


@app.route('/')
def index():
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
