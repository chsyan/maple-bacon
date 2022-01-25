#!/usr/bin/env python3
from pwn import *
import base64

HOST = 'encode-me.ctf.maplebacon.org'
PORT = 32015
LEVELS = 1337

def decode_bytes(n):
    return int.from_bytes(n, byteorder='little')

def decode_base64(n):
    # Convert to binary first.
    # https://stackoverflow.com/questions/43207978/python-converting-from-base64-to-binary
    return decode_binary("".join(["{:08b}".format(x) for x in base64.b64decode(n)]))

def decode_hex(n):
    return int(n, 16)

def decode_binary(n):
    return int(n, 2)

def decode(n, f):
    match f:
        case 'bytes':
            return decode_bytes(n)
        case 'base64':
            return decode_base64(n)
        case 'hexadecimal':
            return decode_hex(n)
        case _:
            return decode_binary(n)

conn = remote(HOST, PORT)
for i in range(LEVELS):
    print('Score: ', i, end='\r', flush=True)
    format = conn.recvline_contains(b'BEGIN ').decode().split()[1].lower()
    input = conn.recvuntil(b'-----')
    input = input[:input.rfind(b'\n')]
    output = decode(input, format)
    conn.sendline(str(output).encode())
print(conn.recvall().decode())
conn.close()
