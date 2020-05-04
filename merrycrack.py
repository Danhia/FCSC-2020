from pwn import *
from base64 import b64encode
from base64 import b64decode
from zlib import *
import numpy as np
import itertools

q = 2**11
n = 280
n_bar = 4
m_bar = 4

conn = remote('challenges1.france-cybersecurity-challenge.fr',2001)
res = conn.recvline() 
res = conn.recvline() 
A = res[4:]
A = np.reshape(np.frombuffer(decompress(b64decode(A)), dtype = np.int64), (n,n))
res = conn.recvline()
B = res[4:]
B = np.reshape(np.frombuffer(decompress(b64decode(B)), dtype = np.int64), (n,n_bar))
C = np.zeros(shape=(m_bar,n_bar),dtype=np.int64)
S = np.zeros(shape=(n,n_bar),dtype=np.int64)

values = [p for p in itertools.product([-1, 0, 1], repeat=4)]

for k in range(0, 280):
	found = False
	U = np.zeros(shape=(m_bar,n),dtype=np.int64)
	U[0][k] = 515
	for i in range(0, 81):
		key = np.zeros(shape=(m_bar,n_bar),dtype=np.int64)
		for j in range(0, 4):
			key[0][j] = values[i][j]
		conn.recvuntil(b'>>>')
		conn.send(b'1\n')
		conn.recvuntil(b'=')
		out = b64encode(compress(U.tobytes())).decode() + '\n'
		conn.send(out.encode())
		conn.recvuntil(b'=')
		out = b64encode(compress(C.tobytes())).decode() + '\n'
		conn.send(out.encode())
		conn.recvuntil(b'=')
		out = b64encode(compress(key.tobytes())).decode() + '\n'
		conn.send(out.encode())
		res = conn.recvline()
		if (res != b' Failure.\n'):
			print(res)
			found = True
			break
	if (found == True):
		for i in range(0,4):
			S[k][i] = -1 * key[0][i]
	else:
		print('ERROR')
		break

E = np.mod(B - np.dot(A,S), q)

for i in range(0, n):
    for j in range(0, n_bar):
        if E[i][j] == 2047:
            E[i][j] = -1

conn.recvuntil(b'>>>')
conn.send(b'2\n')
print(conn.recvuntil(b'='))
out = b64encode(compress(S.tobytes())).decode() + '\n'
conn.send(out.encode())
print(conn.recvuntil(b'='))
out = b64encode(compress(E.tobytes())).decode() + '\n'
conn.send(out.encode())
print(conn.recvline())
print(conn.recvline())

conn.close()