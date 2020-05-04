import sys
import numpy as np
from zlib import compress, decompress
from base64 import b64encode as b64e, b64decode as b64d
from pwn import *
import itertools

q     = 2 ** 11
n     = 280
n_bar = 4
m_bar = 4

conn = remote('challenges1.france-cybersecurity-challenge.fr',2002)
res = conn.recvline() 
print(res)
res = conn.recvline() 
Ab = res[4:]
Ab = np.reshape(np.frombuffer(decompress(b64d(Ab)), dtype = np.int64), (n,n))
res = conn.recvline()
Bb = res[4:]
Bb = np.reshape(np.frombuffer(decompress(b64d(Bb)), dtype = np.int64), (n,n_bar))

count = 0
values = [0, 1]
S = np.zeros(shape=(n,n_bar),dtype=np.int64)
for k in range (0, 4):
	key = np.zeros(shape=(m_bar,n_bar),dtype=np.int64)
	V = np.zeros(shape=(m_bar,n_bar),dtype=np.int64)
	V[0][k] = 256
	for j in range (0, n):
		U = np.zeros(shape=(m_bar,n),dtype=np.int64)
		U[0][j] = -1
		for i in range (0, 2):
			count += 1
			found = False
			key[0][k] = values[i]
			conn.recvuntil(b'>>>')
			conn.send(b'1\n')
			conn.recvuntil(b'=')
			out = b64e(compress(U.tobytes())) + '\n'
			conn.send(out.encode())
			conn.recvuntil(b'=')
			out = b64e(compress(V.tobytes())) + '\n'
			conn.send(out.encode())
			conn.recvuntil(b'=')
			out = b64e(compress(key.tobytes())) + '\n'
			conn.send(out.encode())
			res = conn.recvline()
			if (res != b' Failure.\n'):
				print(res, count)
				found = True
				break
		if found == True:
			S[j][k] = key[0][k]
		else:
			print('ERROR')
			break

print('PART 2')

C = np.zeros(shape=(m_bar,n_bar),dtype=np.int64)
key = np.zeros(shape=(m_bar,n_bar),dtype=np.int64)
for k in range(0, 280):
	found = False
	U = np.zeros(shape=(m_bar,n),dtype=np.int64)
	U[0][k] = 515
	z = 0
	for elem in S[k]:
		z = z + elem
	values = [p for p in itertools.product([1, 0], repeat=4-z)]
	for i in range(0, len(values)):
		for w in range(0, 4):
			key[0][w] = S[k][w] * -1
		m = 0
		for w in range(0, 4):
			if key[0][w] == 0:
				key[0][w] = values[i][m]
				m += 1
		count += 1
		conn.recvuntil(b'>>>')
		conn.send(b'1\n')
		conn.recvuntil(b'=')
		out = b64e(compress(U.tobytes())) + '\n'
		conn.send(out.encode())
		conn.recvuntil(b'=')
		out = b64e(compress(C.tobytes())) + '\n'
		conn.send(out.encode())
		conn.recvuntil(b'=')
		out = b64e(compress(key.tobytes())) + '\n'
		conn.send(out.encode())
		res = conn.recvline()
		if (res != b' Failure.\n'):
			found = True
			print(res, count)
			break
	if (found == True):
		for w in range(0, 4):
			S[k][w] = key[0][w] * -1
		print(S[k])
	else:
		print ('ERROR')
		break

print(count)
E = np.mod(Bb - np.dot(Ab,S), q)

for i in range(0, n):
    for j in range(0, n_bar):
        if E[i][j] == 2047:
            E[i][j] = -1

conn.recvuntil(b'>>>')
conn.send(b'2\n')
print(conn.recvuntil(b'='))
out = b64e(compress(S.tobytes())) + '\n'
conn.send(out.encode())
print(conn.recvuntil(b'='))
out = b64e(compress(E.tobytes())) + '\n'
conn.send(out.encode())
print(conn.recvline())
print(conn.recvline())

conn.close()