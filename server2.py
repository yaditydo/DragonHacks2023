import os
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import sys

class ServerSocket(threading.Thread):

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
        finally:
                    self.sc.close()
                    self.server.remove_connection(self)
                    return

    def receive_key(self):
        key = self.sc.recv(32)
        return key

    def send(self, message):
        self.sc.sendall(message)

    def decrypt_message(self, encrypted_message):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=encrypted_message[:16])
        message = cipher.decrypt(encrypted_message[16:]).decode('utf-8')
        return message

    def broadcast(self, message, source):
        for connection in self.server.connections:
            if connection.sockname != source:
                connection.send(message)

    def remove_connection(self, connection):
        self.server.connections.remove(connection)


def exit(server):
    while True:
        ipt = input('')
        if ipt == 'q':
            print('Closing all connections...')
            for connection in server.connections:
                connection.sc.close()
            print('Shutting down the server...')
            sys.exit(0)


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 1060
    server = ServerSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), host, port)
    server.sc.bind((server.sockname, server.port))
    server.sc.listen(1)

    print('Listening on {}:{}...'.format(server.sockname, server.port))
    while True:
        sc, sockname = server.sc.accept()
        print('Accepted a new connection from {}:{}...'.format(sockname[0], sockname[1]))
        server_socket = ServerSocket(sc, sockname, server)
        server.connections.append(server_socket)
        server_socket.start()

exit = threading.Thread(target=exit, args=server)
exit.start()
