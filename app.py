from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_pymongo import PyMongo
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt


app = Flask(__name__)

# <-- DATABASE CONFIG -->

#change this to your mlab.com information.
app.config['MONGO_DBNAME'] = 'DBNAME'
app.config['MONGO_URI'] = 'mongodb://USER:LOGIN@MLAB/DBNAME'
mongo = PyMongo(app) #don't touch this line

# <-- END DATABASE CONFIG -->


# <-- HELPER FUNCTIONS -->

#DO NOT TOUCH THIS, THESE ARE THE SACRED TEXTS.
def is_logged_in(f):
    """Checks if a user is logged in"""
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'is_logged_in' in session:
            return f(*args, **kwargs)
        flash('Unauthorized, please login.', 'danger')
        return redirect(url_for('login'))
    return wrap

# <-- END HELPER FUNCTIONS -->


# <-- ROUTES -->

#registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles a visit to the registration page"""
    form = RegisterForm(request.form) #we store our form object in a variable of type RegisterForm
    if request.method == 'POST' and form.validate(): #if we're giving data to the server and the form is all good
        #fetching the fields from our form and storing them
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data) #we encrypt the password before storing it

        users = mongo.db.users #storing the users collection in the database
        existing_user = users.find_one({'email' : email}) #a user matching the email we received from the user

        if not existing_user: #if a user wasn't found
            users.insert({
                'username' : username,
                'email' : email,
                'password' : password
            }) #we shove the user trying to register into the database
            flash('You are now registered and can log in', 'success') #we tell the user they're cool in a pretty color.
            return redirect(url_for('login')) #send them to the login
    return render_template('register.html', form=form) #if they didn't give data to the server we just go straight here and serve them the form.

#login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles a visit to the login page"""
    form = LoginForm(request.form) #we store our form object in a variable of type LoginForm
    if request.method == 'POST': #if we're giving data to the server
        #fetching the fields from our form and storing them
        email = form.email.data
        password_candidate = form.password.data

        users = mongo.db.users #storing the users collection in the database
        user = users.find_one({'email' : email}) #a user matching the email we received from the user

        if user: #if we found a user with a matching email
            password = user['password'] #the password hash of said user
            if sha256_crypt.verify(password_candidate, password): #if the two passwords match
                session['logged_in'] = True #we say that a user is logged in, therefore a session is opened.
                session['email'] = email #we store the email as the identifier of the session.
                session['username'] = user['username'] #we store the username of the user

                flash('You are now logged in', 'success') #we give the user a pretty banner.
                return redirect(url_for('feed')) #we redirect them to the feed
        flash('Invalid login', 'danger') #shows a red banner to the user if we didn't find a user with a matching email or if the password didn't match.
    return render_template('login.html', form=form) #if they didn't give data to the server we just go straight here and serve them the form.

# <-- END ROUTES -->


# <-- MODELS -->

#Defining the model for the registration form.
class RegisterForm(Form):
    """Defines the model for a registration form"""
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password', [validators.DataRequired()])

#Defining the model for the login form
class LoginForm(Form):
    """Defines the model for a login form"""
    email = StringField('Email')
    password = PasswordField('Password')

# <-- END MODELS -->


# <-- APPLICATION CONFIG -->

if __name__ == '__main__':
    app.config['SECRET_KEY'] = 'CHANGE-ME' #change to whatever key you like
    app.run(host="0.0.0.0", port=2000, debug=True)

# <-- END APPLICATION CONFIG -->
