# (server.py)
import os
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import sys
def server_commands(server):
    while True:
        cmd = input("Enter a command (start, stop, exit): ")
        if cmd.lower() == "start":
            if not server.running:
                server.running = True
                server.start()
            else:
                print("Server is already running.")
        elif cmd.lower() == "stop":
            if server.running:
                server.running = False
                server.stop()
            else:
                print("Server is not running.")
        elif cmd.lower() == "exit":
            if server.running:
                server.stop()
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid command.")
class Server(threading.Thread):

    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(f"Server listening on {self.host}:{self.port}")

            while True:
                client_socket, client_addr = sock.accept()
                print(f"Accepted connection from {client_addr}")
                conn = ServerConnection(client_socket, client_addr, self)
                conn.start()
                self.connections.append(conn)

    def broadcast(self, message, source):
        for connection in self.connections:
            if connection.sockname != source:
                connection.send(message)

    def remove_connection(self, connection):
        self.connections.remove(connection)


class ServerConnection(threading.Thread):

    def __init__(self, sc, sockname, server):
        super().__init__()
        self.sc = sc
        self.sockname = sockname
        self.server = server
        self.key = None

    def run(self):
        self.key = self.receive_key()
        try:
            while True:
                encrypted_message = self.sc.recv(1024)
                if encrypted_message:
                    message = self.decrypt_message(encrypted_message)
                    print('{} says {!r}'.format(self.sockname, message))
                    self.server.broadcast(encrypted_message, self.sockname)
                else:
                    print('{} has closed the connection'.format(self.sockname))
                    break
        finally:
            self.sc.close()
            self.server.remove_connection(self)

    def receive_key(self):
        key = self.sc.recv(32)
        return key

    def send(self, message):
        self.sc.sendall(message)

    def decrypt_message(self, encrypted_message):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=encrypted_message[:16])
        message = cipher.decrypt(encrypted_message[16:]).decode('utf-8')
        return message


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 1060
    server = Server(host, port)
    server.start()
    cmd_thread = threading.Thread(target=server_commands, args=(server,))
    cmd_thread.start()
    # this will keep the main thread running indefinitely
    while True:
        pass