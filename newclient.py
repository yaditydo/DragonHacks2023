import os
import sys
import socket
import threading
import sqlite3
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import tkinter as tk
from tkinter import messagebox, simpledialog

DB_NAME = 'user_info.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       name TEXT UNIQUE NOT NULL,
                       phone INTEGER UNIQUE NOT NULL,
                       email TEXT NOT NULL UNIQUE,
                       password TEXT UNIQUE NOT NULL,
                       private_key TEXT,
                       public_key TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS contacts
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       user_email TEXT,
                       name TEXT,
                       email TEXT,
                       FOREIGN KEY (user_email) REFERENCES users (email))''')
    conn.commit()
    conn.close()

init_db()

def hash_password(password, salt):
    return scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

class Client:

    def __init__(self, host, port, email, password, update_message_display):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None
        self.private_key = None
        self.shared_key = None
        self.email = email
        self.password = password
        self.update_message_display = update_message_display

    def start(self):
        try:
            print('Trying to connect to {}:{}...'.format(self.host, self.port))
            self.sock.connect((self.host, self.port))
            print('Successfully connected to {}:{}'.format(self.host, self.port))
        except Exception as e:
            print("Error connecting to the server. Double check your configuration.")
        self.register_user()
        self.perform_key_exchange()

        print('Welcome, {}! Getting ready to send and receive messages...'.format(self.name))
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

    def register_user(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email=?', (self.email,))
        user = cursor.fetchone()

        if user:
            stored_password = user[4]
            salt = user[5][:16]  #  stored the salt as the first 16 bytes of the password field
            hashed_password = hash_password(self.password, salt)
            if stored_password != hashed_password:
                messagebox.showerror("Error", "Incorrect password, please try again")
                sys.exit(1)
            else:
                self.name = user[1]
        else:
            messagebox.showerror("Error", "User not found, please register first")
            sys.exit(1)

        self.private_key = ECC.generate(curve='P-256')
        public_key = self.private_key.public_key()
        cursor.execute('UPDATE users SET private_key=?, public_key=? WHERE email=?',
                       (self.private_key.export_key(format='PEM'), public_key.export_key(format='PEM'), self.email))
        conn.commit()
        conn.close()

    def perform_key_exchange(self):
            self.sock.sendall(self.private_key.public_key().export_key(format='PEM').encode('ascii'))
            server_public_key_pem = self.sock.recv(1024).decode('ascii')
            server_public_key = ECC.import_key(server_public_key_pem)
            self.shared_key = self.private_key.d * server_public_key.pointQ
            
def pad_message(self, message):
    while len(message) % 16 != 0:
        message += ' '
    return message

def send_messages(self, recipient, message):
    full_message = '{} -> {}: {}'.format(self.name, recipient, message)
    padded_message = self.pad_message(full_message)
    cipher = AES.new(self.shared_key.x.to_bytes(32, 'big'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(padded_message.encode('ascii'))
    self.sock.sendall(cipher.nonce + tag + ciphertext)

def receive_messages(self):
    while True:
        data = self.sock.recv(1024)
        if data:
            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]
            cipher = AES.new(self.shared_key.x.to_bytes(32, 'big'), AES.MODE_EAX, nonce)
            message = cipher.decrypt_and_verify(ciphertext, tag).decode('ascii').rstrip()
            self.update_message_display(message)
        else:
            print('\nOh no, we have lost connection to the server!')
            print('\nQuitting...')
            self.sock.close()
            os._exit(0)
            
    
class MessagingWindow(tk.Tk):
    def __init__(self, host, port, email, password):
        super().__init__()
        self.title("Messaging")
        self.height = 600
        self.width = 600

        self.client = Client(host, port, email, password, self.update_message_display)
        self.client.start()

        self.contacts_listbox = tk.Listbox(self, width=30)
        self.contacts_listbox.grid(row=0, column=0, rowspan=4, padx=5, pady=5, sticky=tk.N+tk.S)
        self.refresh_contacts()

        self.message_display = tk.Text(self, wrap=tk.WORD)
        self.message_display.grid(row=0, column=1, columnspan=3, padx=5, pady=5)

        self.recipient_label = tk.Label(self, text="Recipient:")
        self.recipient_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.recipient_entry = tk.Entry(self)
        self.recipient_entry.grid(row=1, column=2, sticky=tk.W+tk.E, padx=5, pady=5)

        self.message_label = tk.Label(self, text="Message:")
        self.message_label.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        self.message_entry = tk.Entry(self)
        self.message_entry.grid(row=2, column=2, sticky=tk.W+tk.E, padx=5, pady=5)

        self.send_button = tk.Button(self, text="Send", command=self.send_message)
        self.send_button.grid(row=3, column=2, sticky=tk.E, padx=5, pady=5)

        self.add_contact_button = tk.Button(self, text="Add Contact", command=self.add_contact)
        self.add_contact_button.grid(row=0, column=4, padx=5, pady=5)

        self.remove_contact_button = tk.Button(self, text="Remove Contact", command=self.remove_contact)
        self.remove_contact_button.grid(row=1, column=4, padx=5, pady=5)

        self.refresh_contacts_button = tk.Button(self, text="Refresh Contacts", command=self.refresh_contacts)
        self.refresh_contacts_button.grid(row=2, column=4, padx=5, pady=5)
def update_message_display(self, message):
    self.message_display.insert(tk.END, message + '\n')

def send_message(self):
    recipient = self.recipient_entry.get()
    message = self.message_entry.get()
    self.client.send_messages(recipient, message)
    self.message_entry.delete(0, tk.END)

def refresh_contacts(self):
    self.contacts_listbox.delete(0, tk.END)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM contacts WHERE user_email = ?', (self.client.email,))
    contacts = cursor.fetchall()
    for contact in contacts:
        self.contacts_listbox.insert(tk.END, contact[0])

def add_contact(self):
    name = simpledialog.askstring("Name", "Enter the name of the contact:")
    if name:
        email = simpledialog.askstring("Email", "Enter the email of the contact:")
        if email:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO contacts (user_email, name, email) VALUES (?, ?, ?)',
                           (self.client.email, name, email))
            conn.commit()
            conn.close()
            self.refresh_contacts()

def remove_contact(self):
    selected_index = self.contacts_listbox.curselection()
    if selected_index:
        selected_name = self.contacts_listbox.get(selected_index)
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE name=?', (selected_name,))
        contact = cursor.fetchone()
        if contact:
            cursor.execute('DELETE FROM contacts WHERE user_email=? AND contact_email=?',
                    (self.client.email, contact[0]))
            conn.commit()
            self.refresh_contacts()
        else:
            messagebox.showerror("Error", "Could not find email address for contact")
        conn.close()
        
def sign_up():
    new_email = simpledialog.askstring("Email", "Enter your email:")
    if new_email:
        new_name = simpledialog.askstring("Name", "Enter your name:")
        if new_name:
            new_password = simpledialog.askstring("Password", "Enter your password:", show="*")
            if new_password:
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                salt = get_random_bytes(16)
                hashed_password = hash_password(new_password, salt)
                try:
                    cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                                   (new_name, new_email, salt + hashed_password))
                    conn.commit()
                    messagebox.showinfo("Success", "Account created successfully.")
                except sqlite3.IntegrityError:
                    messagebox.showerror("Error", "Email already exists.")
                conn.close()
                
                
def login():
    host = 'localhost'
    port = 1060

    identifier = email_entry.get()
    password = password_entry.get()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email=? OR name=?', (identifier, identifier))
    user = cursor.fetchone()
    conn.close()

    if user:
        stored_password = user[4]
        salt = stored_password[:16]  # The salt is stored as the first 16 bytes of the password field
        hashed_password = hash_password(password, salt)
        if stored_password != hashed_password:
            messagebox.showerror("Error", "Incorrect password, please try again")
        else:
            messaging_window = MessagingWindow(host, port, user[3], password)
            messaging_window.mainloop()
    else:
        messagebox.showerror("Error", "User not found, please register first")

if __name__ == '__main__':
    login_window = tk.Tk()
    login_window.title("Login ~ Simple SecureChat")
    login_window.geometry("600x600")

    bg_image_path = "img/bgtg.png"  # Provide the path to the background image
    bg_image = tk.PhotoImage(file=bg_image_path)
    bg_label = tk.Label(login_window, image=bg_image)
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    email_label = tk.Label(login_window, text="Email or Username:")
    email_label.grid(row=0, column=0, padx=5, pady=5)
    email_entry = tk.Entry(login_window)
    email_entry.grid(row=0, column=1, padx=5, pady=5)

    password_label = tk.Label(login_window, text="Password:")
    password_label.grid(row=1, column=0, padx=5, pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.grid(row=1, column=1, padx=5, pady=5)

    login_button = tk.Button(login_window, text="Login", command=login)
    login_button.grid(row=2, column=1, padx=5, pady=5)

    signup_button = tk.Button(login_window, text="Sign Up", command=sign_up)
    signup_button.grid(row=3, column=1, padx=5, pady=5)
    login_window.mainloop()


            


