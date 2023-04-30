from flask import Flask, render_template, request, redirect, url_for, got_request_exception
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///daroom.db'
db = SQLAlchemy(app)



@app.route('/', methods=['GET'])
def login():
    render_template('login.html')
    
    
if __name__ =='__main__':
    app.run(debug=True)
