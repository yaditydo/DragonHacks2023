from flask import Flask, render_template, request, redirect, url_for, got_request_exception
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, gen_salt, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO
import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

"""Initial plan was a flask framework. Ignore this file, I'm just leaving it for later use."""











app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

#users
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(24), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.Integer(17), unique=True, nullable=False)
    password = db.Column(db.String(32), unique=True, nullable=False)
    pubkey = db.Column(db.String(255), nullable=False)
    privkey = db.Column(db.String(255), nullable=False)
@app.route('/') 
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        # Perform any necessary actions, such as creating the user or generating the key pair

        # Redirect to the chat room upon successful login
        return redirect(url_for('chat'))

    return render_template('login.html')


    
    
if __name__ =='__main__':
    app.run(debug=True)
    
    
    
    