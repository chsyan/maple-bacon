#!/usr/bin/env python3
from pwn import *
import base64

HOST = 'encode-me.ctf.maplebacon.org'
PORT = 32016
LEVELS = 1337

def encode_bytes(n):
    return n.to_bytes(8, 'little')

def encode_base64(n):
    return base64.b64encode(n.to_bytes(8, 'big'))

def encode_hex(n):
    return hex(n).encode()

def encode_binary(n):
    return bin(n).encode()

def encode(n, f):
    match f:
        case 'bytes':
            return encode_bytes(n)
        case 'base64':
            return encode_base64(n)
        case 'hexadecimal':
            return encode_hex(n)
        case _:
            return encode_binary(n)

conn = remote(HOST, PORT)
for i in range(LEVELS):
    print('Score: ', i, end='\r', flush=True)
    conn.recvuntil(b'Return ')
    data = conn.recvline()
    data = data.decode().split()
    input = int(data[0])
    format = data[2]
    output = encode(input, format)
    conn.sendline(output)
print(conn.recvall().decode())
conn.close()
