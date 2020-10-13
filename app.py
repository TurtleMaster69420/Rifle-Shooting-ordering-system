from flask import Flask, session, redirect, render_template, request, flash, make_response
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
from werkzeug.utils import secure_filename
from bokeh.plotting import figure, show, output_file
from bokeh.embed import components
from bokeh.models import DatetimeTickFormatter, Panel, Tabs, ColumnDataSource, HoverTool, FactorRange
from bokeh.palettes import Dark2
from bokeh.plotting import figure
from bokeh.transform import cumsum
from bokeh.transform import dodge
from math import pi
from bokeh.palettes import Turbo256
from random import randint
from datetime import timedelta
import datetime
import os
import time
import random

load_dotenv()

UPLOAD_FOLDER = 'static\\menu'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(app.instance_path, 'uploads')
print(UPLOAD_FOLDER)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
print(UPLOAD_FOLDER)

# load certain config variables from an env file
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
    MAIL_USE_SSL=True,
    UPLOAD_FOLDER=UPLOAD_FOLDER
)

# instantiate all the flask classes we'll need
bcrypt = Bcrypt(app)
base64Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/"
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
mail = Mail(app)
serialiser = URLSafeTimedSerializer(app.config.get("SECRET_KEY"))

group_members = db.Table("group_members",
                         db.Column("user_id", db.Integer, db.ForeignKey("user.user_id")),
                         db.Column("group_id", db.Integer, db.ForeignKey("group.group_id"))
                         )

def new():
    orders = {'Chicken Burgers': randint(10, 20),
              'Beef Burgers': randint(10, 15),
              'Fish Burgers': randint(1, 5),
              'Small chips': randint(25, 30),
              'Large Chips': randint(15, 20),
              'Family chicken pack': randint(5, 10),
              'Coke': randint(5, 15),
              'Sprite': randint(5, 12)}
    return orders

def generate_data_for_vis():
    orders = new()
    food = []
    number = []
    for i in orders:
        food.append(i)
        number.append(orders[i])


    data = []
    date_list = []
    cb = []
    beef = []
    fish = []
    small = []
    large = []
    family = []
    coke = []
    sprite = []
    current = (datetime.datetime.now())
    for week in range(4):
        data.append([])
        for day in range(1):
            data[week].append({})
            data[week][day]['date'] = {}
            data[week][day]['orders'] = {}
            x = new()
            current += timedelta(days=7)
            data[week][day]['date'] = current.strftime('%d-%m-%Y')
            date_list.append(data[week][day]['date'])
            for order in x:
                data[week][day]['orders'][order] = x[order]
                cb.append(data[week][day]['orders']['Chicken Burgers'])
                chicken_burgers = [cb[i] for i in range(0, len(cb), 8)]
            for order in x:
                data[week][day]['orders'][order] = x[order]
                beef.append(data[week][day]['orders']['Beef Burgers'])
                beef_burgers = [beef[i] for i in range(0, len(beef), 8)]
            for order in x:
                data[week][day]['orders'][order] = x[order]
                fish.append(data[week][day]['orders']['Fish Burgers'])
                fish_burgers = [fish[i] for i in range(0, len(fish), 8)]
            for order in x:
                data[week][day]['orders'][order] = x[order]
                small.append(data[week][day]['orders']['Small chips'])
                small_chips = [small[i] for i in range(0, len(small), 8)]
            for order in x:
                data[week][day]['orders'][order] = x[order]
                large.append(data[week][day]['orders']['Large Chips'])
                large_chips = [large[i] for i in range(0, len(large), 8)]
            for order in x:
                data[week][day]['orders'][order] = x[order]
                family.append(data[week][day]['orders']['Family chicken pack'])
                family_chicken_pack = [family[i] for i in range(0, len(family), 8)]
            for order in x:
                data[week][day]['orders'][order] = x[order]
                coke.append(data[week][day]['orders']['Coke'])
                cokee = [coke[i] for i in range(0, len(coke), 8)]
            for order in x:
                data[week][day]['orders'][order] = x[order]
                sprite.append(data[week][day]['orders']['Sprite'])
                spritee = [sprite[i] for i in range(0, len(sprite), 8)]

    week1 = []
    add = chicken_burgers[0], beef_burgers[0], fish_burgers[0], small_chips[0], large_chips[0], family_chicken_pack[0], \
          cokee[0], spritee[0]
    week1.extend(add)


    week2 = []
    add2 = chicken_burgers[1], beef_burgers[1], fish_burgers[1], small_chips[1], large_chips[1], family_chicken_pack[1], \
           cokee[1], spritee[1]
    week2.extend(add2)

    week3 = []
    add3 = chicken_burgers[2], beef_burgers[2], fish_burgers[2], small_chips[2], large_chips[2], family_chicken_pack[2], \
           cokee[2], spritee[2]
    week3.extend(add3)


    week4 = []
    add4 = chicken_burgers[3], beef_burgers[3], fish_burgers[3], small_chips[3], large_chips[3], family_chicken_pack[3], \
           cokee[3], spritee[3]
    week4.extend(add4)

    #week1date = date_list[0]

    week1_sum = sum(week1)

    week2_sum = sum(week2) + week1_sum

    week3_sum = sum(week3) + week2_sum

    week4_sum = sum(week4) + week3_sum

    total_sums = [week1_sum, week2_sum, week3_sum, week4_sum]

    return food, week1, week2, week3, week4, date_list, total_sums

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_gid():
    now = time.time()
    return int(now * 105.2) + 100000564023


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=False, nullable=False)
    type = db.Column(db.String(50), unique=False, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.datetime.now)
    pwHash = db.Column(db.String(60), unique=False, nullable=False)
    confirmed = db.Column(db.Boolean)
    groups_owned = db.relationship("Group", backref="organiser")
    groups_in = db.relationship("Group", secondary=group_members, backref=db.backref("members", lazy="dynamic"))
    orders = db.relationship("Order", backref="orderer")

    def __repr__(self):
        return f"<User {self.name}, {self.email}>"


class Group(db.Model):
    group_id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    gid = db.Column(db.Integer, default=get_gid, unique=True, nullable=False)
    name = db.Column(db.Integer, unique=True, nullable=False)
    invite_code = db.Column(db.String, unique=True, nullable=True)
    timeframe_end = db.Column(db.DateTime, nullable=True, unique=False)
    organiser_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
    orders = db.relationship("Order", backref="group_in", lazy=True)


class Order(db.Model):
    order_id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.group_id"))
    orderer_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
    item_info = db.relationship("Info", backref="order")
    total_cost = db.Column(db.Float, nullable=False)


class Info(db.Model):
    info_id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("order.order_id"))
    item = db.relationship("Item", backref="info")
    quantity = db.Column(db.Integer, unique=False, nullable=False)


class Item(db.Model):
    item_id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(128), nullable=False)
    info_id = db.Column(db.Integer, db.ForeignKey("info.info_id"))


# this function checks whether the user is allowed on the current page, taking in the parameter of the page type
# (e.g. manager, orderer, staff or someone who hasn't logged in (NoneType object)
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
    user = User.query.get(session.get("user"))
    if not user or not user.confirmed:
        return not page_type, pages[None]
    return user.type == page_type, pages[user.type]


# this function will add a user to the database but mark them as unconfirmed and generate a secure token for email
# verification
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
    pwd_hash = bcrypt.generate_password_hash(password, 10)  # generates bcrypt password hash (very secure)
    db.session.add(User(name=name, email=email, pwHash=pwd_hash, type=user_type, confirmed=user_type != "orderer"))
    db.session.commit()
    if user_type == "orderer":
        return serialiser.dumps(email, salt=app.config.get("SECURITY_PASSWORD_SALT"))


# this function checks whether the provided email and password combination exists in the database
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
        session["user"] = user.user_id
        return True
    else:
        return False


# create group
def create_group(name, oid):
    """
    :param name: the name of the new group
    :param oid: the id of the organiser
    :return: the group id of the new group
    """
    new_group = Group(name=name, organiser=User.query.get(oid))
    db.session.add(new_group)
    db.session.commit()

    return new_group.gid


# "main page" which will always redirect users to the appropriate part of the page
@app.route('/')
def index():
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

    # verify whether the form is valid or not
    if form.validate_on_submit():
        login_info = request.form

        # verify the login details
        if verify_login(login_info['email'], login_info['password']):
            return redirect("/")
        else:
            flash("Either the email doesn't exist or the password is incorrect", "text-danger")
    return render_template('login.html', form=form)


@app.route('/logout', methods=["GET"])
def logout():
    if session.get("user"):
        del session["user"]
    return redirect("/")


@app.route('/register', methods=["GET", "POST"])
def register():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = registerForm()

    # verify whether the form is valid or not
    if form.validate_on_submit():
        register_info = request.form

        # create token
        token = create_user(register_info.get("name"), register_info.get("email"), register_info.get("password"))
        if not token:
            form.email.errors.append("This email has already been used, try a different one")
        else:

            # send confirmation email to confirm the user's account
            msg = Message("Confirm account", sender="dstackordering@gmail.com", recipients=[register_info.get("email")])
            msg.body = f"""
Here is the link to confirm your account: 127.0.0.1:5000/confirm?token={token}
            """
            mail.send(msg)
            flash("A confirmation email has been sent to your account! Please check both your inbox and spam folder",
                  "text-success")
    return render_template('register.html', form=form)


@app.route("/confirm", methods=["GET"])
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

    # confirm the user and set their session cookie as their user id (indicating they are now logged in)
    user.confirmed = True
    db.session.commit()
    session["user"] = user.user_id
    flash("Your account has been created! Enjoy your experience.", "success")
    return redirect("/")


@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = forgot_password_form()

    # verify whether the form is valid or not
    if form.validate_on_submit():
        email = request.form["email"]
        if not User.query.filter_by(email=email).first():
            form.email.errors.append("There is no account with the provided email")
        else:

            # send confirmation email to reset the user's password
            msg = Message("Reset password", sender="dstackordering@gmail.com", recipients=[email])
            token = serialiser.dumps(email + "resetpwd", salt=app.config.get("SECURITY_PASSWORD_SALT"))
            msg.body = f"""
Here is the link to reset your password: 127.0.0.1:5000/set_new_password?token={token}
            """
            mail.send(msg)
            flash("We have sent an email to change your password, please check both your inbox and spam folder",
                  "text-success")
    return render_template("forgot_password.html", form=form)


@app.route('/set_new_password', methods=["GET", "POST"])
def set_new_password():
    allowed, new_page = authenticate()
    if not allowed:
        return redirect(new_page)
    form = set_new_password_form()

    # if the request is valid or a GET request is made to the page
    if request.method == "GET" or form.validate_on_submit():
        try:
            # verify that the token is in the correct format and hasn't expired
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

        # if the user is resetting their password
        if form.validate_on_submit():
            # overwrite existing password
            user.pwHash = bcrypt.generate_password_hash(request.form["new_password"], 10)
            db.session.commit()
            flash("Your password has been successfully reset! Log in with the new password", "text-success")
            return redirect("/login")
    return render_template("set_new_password.html", form=form)


@app.route("/orderer/home", methods=["GET"])
def orderer_home():
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)

    user = User.query.get(session["user"])
    return render_template("orderer_home.html", groups_in=user.groups_in, groups_owned=user.groups_owned)


@app.route("/orderer/about", methods=["GET"])
def orderer_about():
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)

    user = User.query.get(session["user"])
    return render_template("orderer_about.html", groups_in=user.groups_in, groups_owned=user.groups_owned)


@app.route("/orderer/create", methods=["POST"])
def orderer_create():
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)

    # if no name is provided
    name = request.form.get("name")
    if not name:
        return make_response('{"error": "No name was supplied"}', 401)

    # if the group name already exists
    group_wanted = Group.query.filter_by(name=name).first()
    if group_wanted:
        return make_response('{"error": "This group already exists"}', 401)

    gid = create_group(name, session["user"])
    flash("Welcome to the new group you have created!", "success")
    return f'{{"url": "/orderer/group/{gid}"}}'


@app.route("/orderer/join", methods=["POST"])
def orderer_join():
    print(request.form.get("invite_code"))
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)

    # if no invite code is provided
    invite_code = request.form.get("invite_code")
    if not invite_code:
        return make_response('{"error": "No invite code was supplied"}', 401)

    group_wanted = Group.query.filter_by(invite_code=invite_code).first()

    # if no group exists with the specified invite code
    if not group_wanted:
        return make_response('{"error": "No group was found to have the provided invite code"}', 401)

    # if the user is the organiser of the group
    if group_wanted.organiser_id == session["user"]:
        return make_response('{"error": "You are already the organiser of this group"}', 401)

    # if the user is a member of the group
    if group_wanted.members.filter_by(user_id=session["user"]).first():
        return make_response('{"error": "You are already a member of this group"}', 401)

    flash("Welcome to the new group!", "success")
    group_wanted.members.append(User.query.get(session["user"]))
    db.session.commit()
    return f'{{"url": "/orderer/group/{group_wanted.gid}"}}'


@app.route("/orderer/group/<gid>/invite", methods=["GET"])
def group_invite(gid):
    allowed, new_page = authenticate("orderer")
    if not allowed:
        print("ujfisdjjdsf")
        return redirect(new_page)

    group_wanted = Group.query.filter_by(gid=gid).first()

    # if the gid does not exist
    if not group_wanted:
        print("yeehoo")
        return redirect("/orderer/home")

    # if the user is not the organiser of the group
    if group_wanted.organiser_id != session["user"]:
        print("yoeoey")
        return redirect("/orderer/home")

    # assign the group invite code as a 24 character, random readable string and redirect organiser back to their group
    group_wanted.invite_code = "".join([random.choice(base64Chars) for _ in range(24)])
    db.session.commit()

    return redirect(f"/orderer/group/{gid}")


@app.route('/orderer/group/<gid>/setTimeFrame', methods=["GET"])
def set_time_frame(gid):
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)

    # check if group exists
    group_wanted = Group.query.filter_by(gid=gid).first()

    if not group_wanted:
        return redirect("/orderer/home")

    # check if the user is the organiser of the group
    if group_wanted.organiser_id != session["user"]:
        return redirect("/orderer/home")

    end_date = request.args.get("date")

    # check if date is provided
    if not end_date:
        flash("No date was provided", "danger")
        return redirect(f"/orderer/group/{gid}")

    end_time = request.args.get("time")

    # check if time was provided
    if not end_time:
        flash("No time was provided", "danger")
        return redirect(f"/orderer/group/{gid}")

    # convert to datetime object and set timeframe in database
    timeframe_end = datetime.datetime.strptime(f"{end_date} - {end_time}", "%Y-%m-%d - %H:%M")
    group_wanted.timeframe_end = timeframe_end
    print(timeframe_end)
    db.session.commit()
    print(group_wanted.timeframe_end)
    print("WHAT", Group.query.all()[0].timeframe_end)


    flash("The timeframe has been set!", "success")

    return redirect(f"/orderer/group/{gid}")


@app.route('/orderer/group/<gid>', methods=["GET"])
def group(gid):
    allowed, new_page = authenticate("orderer")
    if not allowed:
        return redirect(new_page)

    group_wanted = Group.query.filter_by(gid=gid).first()

    # if the provided gid does not exist
    if not group_wanted:
        return redirect("/orderer/home")

    # remove time frame if it has finished
    if group_wanted.timeframe_end and group_wanted.timeframe_end < datetime.datetime.today():
        group_wanted.timeframe_end = None
        db.session.commit()

    user = User.query.get(session["user"])

    order = None
    for o in group_wanted.orders:
        if o.orderer_id == session["user"]:
            order = o
            break

    print(group_wanted.timeframe_end)

    # if the user is the organiser, display the organiser page
    if group_wanted.organiser_id == session["user"]:
        return render_template("organiser_group.html", groups_in=user.groups_in,
                               groups_owned=user.groups_owned, group=group_wanted, order=order)

    # if the user is a normal member, display the default orderer page
    if group_wanted.members.filter_by(user_id=session["user"]).first():
        return render_template("orderer_group.html", groups_in=user.groups_in,
                               groups_owned=user.groups_owned, group=group_wanted, order=order, user_db=User)

    # otherwise, redirect the user back the their home page (they are unauthenticated)
    return redirect("/orderer/home")


@app.route('/staff/home', methods=["GET"])
def staff_home():
    allowed, new_page = authenticate("staff")
    if not allowed:
        return redirect(new_page)
    return render_template("staff_home.html")


@app.route('/manager/home')
def manager_home():
    print(123)
    allowed, new_page = authenticate("manager")
    if not allowed:
        return redirect(new_page)
    food, week1, week2, week3, week4, date_list, total_sums = generate_data_for_vis()

    data = {'food': food,
            'week1': week1,
            'week2': week2,
            'week3': week3,
            'week4': week4}

    source = ColumnDataSource(data=data)
    plot = figure(x_range=food, y_range=(0, 35), plot_height=500, plot_width=1000, title="Order Counts by Week",
                  toolbar_location=None, tools="", x_axis_label="Food",
                  y_axis_label="Number of orders")
    plot.vbar(x=dodge('food', -0.15, range=plot.x_range), top='week1', width=0.1, source=source,
              color="#ff8533", legend_label=date_list[0])

    plot.vbar(x=dodge('food', -0.05, range=plot.x_range), top='week2', width=0.1, source=source,
              color="#80dfff", legend_label=date_list[1])

    plot.vbar(x=dodge('food', 0.05, range=plot.x_range), top='week3', width=0.1, source=source,
              color="#6fdc6f", legend_label=date_list[2])

    plot.vbar(x=dodge('food', 0.15, range=plot.x_range), top='week4', width=0.1, source=source,
              color="#ff4d4d", legend_label=date_list[3])

    plot.x_range.range_padding = 0
    plot.xgrid.grid_line_color = None
    plot.xaxis.major_label_text_font_size = "11pt"
    plot.yaxis.major_label_text_font_size = "11pt"
    plot.legend.location = "top_left"
    plot.legend.orientation = "horizontal"
    tab2 = Panel(child = plot, title = "Weekly Orders")
    plot1 = figure(plot_width = 800, title="Total Orders", x_axis_label="Date",
                      y_axis_label="Total Food Orders", plot_height = 600, x_range=date_list)
    plot1.line(x = date_list, y = total_sums, line_width = 4)
    plot1.circle(x = date_list, y = total_sums, fill_color = "white", size = 9)
    plot1.xaxis.major_label_text_font_size = "11pt"
    plot1.yaxis.major_label_text_font_size = "11pt"
    tab1 = Panel(child=plot1, title="Total Orders")
    tabs = Tabs(tabs=[tab1, tab2])
    script, div = components(tabs)
    return render_template("manager_home.html", script=script, div=div)



@app.route('/manager/menu', methods=["GET", "POST"])
def manager_menu():
    allowed, new_page = authenticate("manager")
    if not allowed:
        return redirect(new_page)

    valid = True
    if request.method == "POST":
        form = request.form
        print(form)

        if 'new-name' in form:
            if not (form.get('new-name') and form.get('price')):
                valid = False
            else:
                print([x[0] for x in os.walk("..")])
                print(os.getcwd())
                print(request.files)
                file = request.files['item-image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    print(filename)
                    print(app.config['UPLOAD_FOLDER'])
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_item = Item(name=form.get('new-name'), price=form.get('price'), image=('/static/menu/' + secure_filename(form.get('item-image'))), description=form.get('name'))
                db.session.add(new_item)
                db.session.commit()
        else:
            for item in Item.query.all():
                item.name = form.get(str(item.item_id) + 'name')
                item.price = form.get(str(item.item_id) + 'price')
                if form.get(str(item.item_id) + 'remove', 'off') == 'on':
                    Item.query.filter_by(item_id=item.item_id).delete()
            db.session.commit()

    menu = []
    menu_raw = Item.query.all()
    for item in menu_raw:
        menu.append({"id": item.item_id, "name": item.name, "image": item.image, "price": item.price, "description": item.description})

    filter = request.args.get('filter', 'name')
    reverse = (request.args.get('reverse', 'false') == 'true')
    mode = (request.args.get('mode', 'normal'))
    if not valid:
        mode = 'add'

    menu = sorted(menu, key=lambda i: i[filter])
    if reverse:
        menu.reverse()


    return render_template("manager_menu.html", menu=menu, reverse=reverse, edit=(mode == 'edit'), add=(mode == 'add'), normal=(mode == 'normal'), valid=valid)

@app.route('/manager/add_item', methods=["POST"])
def manager_add_item():
    print(123)
    allowed, new_page = authenticate("manager")
    if not allowed:
        return redirect(new_page)
    if request.method == "POST":
        form = request.form
        print(form)

@app.route('/manager/staff')
def manager_staff():
    allowed, new_page = authenticate("manager")
    if not allowed:
        return redirect(new_page)
    staff = [{'name':'Bob', 'email': 'bob@gmail.com'},
             {'name':'Rob', 'email': 'rob42@gmail.com'},
             {'name':'Cob', 'email': 'cob@gmail.com'},
             {'name':'Nob', 'email': 'nob@gmail.com'},
    ]
    return render_template("manager_staff.html", staff=staff)


if __name__ == '__main__':
    app.run()