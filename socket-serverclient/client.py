# Sarah Kam
# Reference: https://www.youtube.com/watch?v=3QiPPX-KeSc

import socket

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "done"
SERVER = socket.gethostbyname(socket.gethostname())
# client runs on same machine as server!
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    message = msg.encode(FORMAT)
    msg_len = len(message)
    send_len = str(msg_len).encode(FORMAT)
    send_len += b' ' * (HEADER - len(send_len))
    # pad the byte-formatted str of msg len to make sure it's 64 bytes long
    # b' ' is byte repr. of space char, find len of send_len, subtract from HEADER len, then pad ' '
    client.send(send_len)
    client.send(message)

    print(client.recv(2048).decode(FORMAT)) # receieve message back from server - CLEAN UP CODE TO INCLUDE LENGTH PROCESSING

msg = input()
while(msg != "done"):
    send(msg)
    msg = input()
send(DISCONNECT_MESSAGE)
