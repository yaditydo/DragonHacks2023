#structure-preserving map between two algebraic structures of same type (groups, rings, vector spaces.)
import rsa
import socket
import threading
from flask import Flask, render_template, request, session, redirect
from flask_socketio import SocketIO, send, join_room, leave_room
import random
import string


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app)

@app.route('/, methods=["POST", "GET"]')
def home():
    return render_template(home.html)


        















if __name__ == '__main__':
    socketio.run(debug=True)