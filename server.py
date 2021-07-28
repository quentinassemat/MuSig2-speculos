from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from random import getrandbits as rnd, randbytes, randint
from binascii import hexlify, unhexlify

from time import sleep
from tools import *

randint1 = int.from_bytes(randbytes(4), 'big') // 2
randint2 = int.from_bytes(randbytes(4), 'big') // 2
rand_msg1 = hexlify(randint1.to_bytes(4, 'big')).decode()
rand_msg2 = hexlify(randint2.to_bytes(4, 'big')).decode()
l1 = hexlify((8).to_bytes(2, 'little')).decode()
print(l1)

randfield1 = sct.randbelow(n)
randfield2 = sct.randbelow(n)
rand_msg3 = hexlify(randfield1.to_bytes(N_bytes, 'big')).decode()
rand_msg4 = hexlify(randfield2.to_bytes(N_bytes, 'big')).decode()
l2 = hexlify((2 * N_bytes).to_bytes(2, 'little')).decode()
print(l2)

randpoint1 = randfield1 * G
randpoint2 = randfield2 * G
rand_msg5 = hexlify(point_to_bytes(randpoint1)).decode()
rand_msg6 = hexlify(point_to_bytes(randpoint2)).decode()
l3 = hexlify((2 * (2 * N_bytes + 1)).to_bytes(2, 'little')).decode()
print(l3)

CMDS = [
    "8003"+ l1 + rand_msg1 + rand_msg2, # envoie de deux entier de type u32 
    "8004" + l2 + rand_msg3 + rand_msg4, # envoie deux field element
    "8005" + l3 + rand_msg5 + rand_msg6 # envoie deux point secp256k1
]

d = getDongleTCP(port=40000)

print(
    f"Nous essayons de faire l'addition suivante {randint1} + {randint2} = {randint1 + randint2} ")

print(
    f"Nous essayons de faire l'addition suivante {randfield1} + {randfield2} = {(randfield1 + randfield2 ) % n} ")

print(
    f"Nous essayons de faire l'addition suivante {randpoint1.to_affine()} + {randpoint2.to_affine()} = {(randpoint1 + randpoint2).to_affine()} ")

ANSWER = []
for i in range(len(CMDS)):
    cmd = unhexlify(CMDS[i])
    # print(cmd)
    r = None
    try:
        r = d.exchange(cmd)
        sleep(1)
    except Exception as e:
        print("test")
        print(e)
    if r is not None:
        # print("Response hex : ", hexlify(r))
        # ANSWER.append(int.from_bytes(r, 'big'))
        if (i == len(CMDS) - 1):
            ANSWER.append(bytes_to_point(r))
        else:
            if r == None:
                ANSWER.append("cancelled")
            else :
                ANSWER.append(int.from_bytes(r, 'big') % n)
    sleep(2)

print(f"On obtient le résultat suivant : {ANSWER}")
d.close()
