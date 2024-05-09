# Sarah Kam
# IP Spoofing with Scapy
# References:
#   https://youtu.be/yD8qrP8sCDs
#   https://null-byte.wonderhowto.com/how-to/create-packets-from-scratch-with-scapy-for-scanning-dosing-0159231/
#   https://stackoverflow.com/a/23275930

from scapy.all import send, IP
# allows coding exactly as in scapy console


x = IP(ttl=64)
x.src = "127.0.0.1"         # this is the src we were assigned
x.dst = "192.168.9.14"      # made-up dst IP
send(x)
