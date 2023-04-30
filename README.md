# Simple SecureChat /~~~\ Program Documentation
## Overview
### This encrypted chat program provides end-to-end encrypted communication between users through a server. The application is built using Python and the Tkinter library for the graphical user interface. It uses a combination of asymmetric and symmetric encryption for secure communication. The program also provides user authentication and contact management features to user profiles.

## Libraries and Protocols
~Original plan was to implement the Signal Open-Source Library however due to time constraints decided against (for now)
- Plan to implement in future along with OpenPGP tools!
The following libraries are used in the program:

- os, sys, and socket - For socket-based communication between the client and the server.
- threading - For running` send and receive operations concurrently in separate threads.
- sqlite3 - For storing user information and contacts in a local SQLite database.
- Crypto - A cryptography library that provides various encryption algorithms and key generation methods.
- Crypto.Cipher.AES: Provides AES symmetric encryption for message encryption.
- Crypto.PublicKey.ECC: Provides Elliptic Curve Cryptography (ECC) for key generation and key exchange.
- Crypto.Random: Generates random bytes for various purposes (e.g., salt in password hashing).
- Crypto.Protocol.KDF.scrypt: Provides the scrypt key derivation function for password hashing.
- tkinter, tkinter.messagebox, and tkinter.simpledialog - For creating the graphical user interface and displaying dialog boxes.
## Encryption and Key Exchange
## The program uses a combination of asymmetric and symmetric encryption techniques:

### Asymmetric Encryption (ECC): Elliptic Curve Cryptography (ECC) is used to generate public-private key pairs for each user. During the key exchange process, the client sends its public key to the server, and the server sends its public key to the client. The client and the server then use their respective private keys to compute a shared secret, which is used as the symmetric encryption key.

### Symmetric Encryption (AES): AES encryption is used to encrypt messages between users. AES is a symmetric encryption algorithm, which means that the same key is used for both encryption and decryption. The shared secret generated during the key exchange process is used as the symmetric key for AES encryption.

### User Authentication and Contact Management
User authentication is performed using email and password. Passwords are hashed using the scrypt key derivation function with a random salt, and the resulting hash is stored in the local SQLite database. When a user logs in, their password is hashed with the stored salt, and the hash is compared to the stored hash to verify their identity.

### Contacts are managed through a SQLite database that stores contact information such as name, phone number, email, and public key. Users can add, remove, and refresh their contacts through the graphical interface.

### Graphical User Interface (GUI)
- The program uses the Tkinter library to create a GUI that includes:

- A login window that prompts the user for their email and password.
- A messaging window that displays the following components:
- A listbox showing the user's contacts.
- A text box for displaying messages.
- An entry box for entering the recipient's name.
- An entry box for typing messages.
- Buttons for sending messages, adding contacts, removing contacts, and refreshing the contacts list.
- The messaging window also handles window close events, prompting the user for confirmation before exiting and closing the connection to the server.


