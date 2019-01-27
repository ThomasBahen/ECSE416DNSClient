import socket 
import sys
import argparse


DNS_IP = "132.206.44.21"
PORT = 53 

parser = argparse.ArgumentParser()

parser.add_argument("-t", default = 5)
parser.add_argument("-r", default = 3)
parser.add_argument("-p", default = 53)
parser.add_argument("-mx",  action='store_const', dest='type', default=0x0001, const=0x000F)
parser.add_argument("-ns",  action='store_const', dest='type', default=0x0001, const=0x0002)
parser.add_argument("serverName", nargs=2)
args= parser.parse_args()

print(args.serverName)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((DNS_IP, PORT))
s.sendall("www.mcgill.ca")
data = s.recv(16)
counter = 0


key = bytes([3,ord('w'),ord('w'),6,ord('m'),ord('c'),ord('g'),ord('i'),ord('l'),ord('l'),2,ord('c'),ord('a'), 0, 1, 0, 1])
