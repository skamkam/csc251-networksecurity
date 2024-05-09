# Sarah Kam
# Reference: https://www.youtube.com/watch?v=3QiPPX-KeSc

import socket
import threading # allows parallel processing of code

HEADER = 64 # bytes, 1st msg to server every time is going to be a header len 64 that tells us len of msg that comes next
PORT = 5050
# pick a port that isn't being used for something else; >4000 good bet

SERVER = socket.gethostbyname(socket.gethostname())
# gethostbyname says host name will be the IPv4 in paren
# gethostname is this computer's IPv4

ADDR = (SERVER, PORT)
# creates address of tuple server, port

FORMAT = 'utf-8' # decode msg from bytes format to utf-8
DISCONNECT_MESSAGE = "done"

# make a socket to open up this device to other connections
# pick a socket and bind socket to that address
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# lowercase server is the server we're making
# socket.socket creates a new socket
# family AF_INET is IPv4
# type SOCK_STREAM is streaming data through the socket

# need to bind server to address
server.bind(ADDR)

def handle_client(conn, addr):
    # runs concurrently for each client
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        msg_len = conn.recv(HEADER).decode(FORMAT)
        # receive a certain num of bytes from client
        # "blocking" line of code; conn.recv and server.accept wait for client to do smth 
        if msg_len: # check msg_len has Something (first msg is null)
            msg_len = int(msg_len)

            msg = conn.recv(msg_len).decode(FORMAT)
            print(f"[{addr}] {msg}")

            conn.send(msg.encode(FORMAT)) # server echoes client's msg back to them

            if msg == DISCONNECT_MESSAGE:
                connected = False

    conn.close() # cleanly close current connection

def start():
    # handle new connections and distribute them where they should go
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        # waits on this line of code to store info abt a new connection, then conn object to send info back to the thing that connected
        thread = threading.Thread(target = handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")
        # num of active conns is num threads - 1 bc start thread is 1 thread

print("[STARTING] server is starting...")
start()