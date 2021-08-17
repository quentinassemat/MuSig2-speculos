from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from random import getrandbits as rnd, randbytes, randint
from binascii import hexlify, unhexlify

from time import sleep
from tools import *

# # on parcours 

# private_key1 = int.from_bytes(unhexlify(b'04aa797eac3cae3e4965fffb81a0b713cee34fc8eca574f9aa0c493cb4f589b9'), 'big')
# public_key1 = G * private_key1
# print("public_key 1 :")
# print(public_key1)

# private_nonces1 = [int.from_bytes(unhexlify(b'1d9d11e85620fd99b2df0580a1686c918b6356e25e9a78a8980334db3ca36659'), 'big'), int.from_bytes(unhexlify(b'd3f21c70728f2c28cca87b3e74f848e8814a9e8dea2d215e727949d3edecc6c0'), 'big'), int.from_bytes(unhexlify(b'76c4db49fca72228ef7442fb29cb16df4f2ac2f196462aa23ee63c6fe743bc5e'), 'big')]
# public_nonces1 = [G * pn for pn in private_nonces1]
# print("public_nonces1 :")
# print(public_nonces1)

# private_key2 = int.from_bytes(unhexlify(b'aa5af357588330428ba1ecdce2a834f2504acc608fad3e0bfb7d6134e7839d91'), 'big')
# public_key2 = G * private_key2
# print("public_key2 :")
# print(public_key2)

# private_nonces2 = [int.from_bytes(unhexlify(b'29a9311bad4bc716e0118b24e95c611dea265a737e9a73cc13d3926223ae184c'), 'big'), int.from_bytes(unhexlify(b'ed85b998a7d5826f89963937f0f105ea087020f346a48517d9e093d75011e93d'), 'big'), int.from_bytes(unhexlify(b'1a79cc0daa0cefc083aeae38367b9aa71befa4135006434fa6fbfe6b7af3f994'), 'big')]
# public_nonces2 = [G * pn for pn in private_nonces2]
# print("public_nonces2 :")
# print(public_nonces2)

# r_nonces = [(public_nonces1[i] + public_nonces2[i]).to_affine() for i in range(nb_nonces)]
# print("r_nonces : ")
# print(r_nonces)

# a = [int.from_bytes(unhexlify(b'df4ed489056da38aafa1fcde62c1de7e139fb2d6cac6757cd83d24a8dfa4f7ef'), 'big'), int.from_bytes(unhexlify(b'c5a061df57a4bc75bdb6e8b3947ce6b68d2795b274b2c911a5ace7117b91c846'), 'big')]
# xtilde = ((a[0] * public_key1 ) + (a[1] * public_key2)).to_affine()
# print("xtilde : ")
# print(xtilde)

# b = int.from_bytes(unhexlify(b'dd04b79667da8911c300d357168120b4bdb04890c92e93c4a149fbcb8c3b77ce'), 'big')

# rsign = (r_nonces[0] + (r_nonces[1] * b ) + (r_nonces[2] * (b * b))).to_affine()
# print("rsign : ")
# print(rsign)

# c = int.from_bytes(unhexlify(b'bfc809687974ce9a0c0bc774e474ebf59019716b5406060b6ee25202d6c06bc1'), 'big')

# selfsign1 = ((c * a[0] * private_key1) + (private_nonces1[0] + (private_nonces1[1] * b ) + (private_nonces1[2] * (b * b)))) % n

# print("selfsign1 : ")
# print(hexlify(selfsign1.to_bytes(32, 'big')))

# selfsign2 = ((c * a[1] * private_key2) + (private_nonces2[0] + (private_nonces2[1] * b ) + (private_nonces2[2] * (b * b)))) % n

# print("selfsign2 : ")
# print(hexlify(selfsign2.to_bytes(32, 'big')))

# sign = selfsign1 + selfsign2 % n

# left = (G * sign).to_affine()
# print("left : ")
# print(left)

# right  = (rsign + (xtilde * c)).to_affine()
# print("right : ")
# print(right)



# # on debug juste 
# sys.exit(1)
#Paramètres pour la signature
nb_participant = 2 # pour l'instant on fait avec 2 participants
# try: 
#     nb_participant = int(sys.argv[1])
# except ValueError:
#     print("Unvalid number of signers")
#     sys.exit(1)

nb_nonces = 3
M = "Alice donne 1 Bitcoin à Bob"

#Données de communication serveur 
ADRESSE = 'localhost'
PORTS = [40000 + i for i in range(nb_participant)]
MEM = 16496 # mémoire nécessaire pour communiquer les infos durant les étapes de communications

# #Construction des clefs publiques 
# # public key 1 : 0423cdc4924412d491d0ed13272372e945ddd9886c32592f8ac9b7b37dcd8adc7d20d88572e9fdbe872c1dbfbdb9921cb8d17af04a63b65646aa7bc29f42d16f41
# # public key 2 : 0479717b8ad6bd8efa41af00e682d97004be32738b54a30d2a0141eb2c2590baa0bffee15e85c9be9478e34e251baa3a2e11aef8269d8b1a695ceb7ff177185fd8

# PUBKEYS_BIN = [unhexlify(b'0423cdc4924412d491d0ed13272372e945ddd9886c32592f8ac9b7b37dcd8adc7d20d88572e9fdbe872c1dbfbdb9921cb8d17af04a63b65646aa7bc29f42d16f41'), unhexlify(b'0479717b8ad6bd8efa41af00e682d97004be32738b54a30d2a0141eb2c2590baa0bffee15e85c9be9478e34e251baa3a2e11aef8269d8b1a695ceb7ff177185fd8')]
# PUBKEYS = [bytes_to_point(b) for b in PUBKEYS_BIN]

# print(PUBKEYS)

SOCKETS  = [getDongleTCP(port=PORTS[i]) for i in range(nb_participant)]

print("Les sockets est bind, nous pouvons commencer")


CMDS = [
    "80ff", # demande de quitter la signature
    "8001", # demande de clef publique
    "8002", # demande de signature 
    "8003", # demande des publiques nonces 
    "8004" + "c400", # +<indice du joueur> + <nonce1> + <nonce2>  + <nonce3>   envoie de nonce + taille (Taille de 3 nonces plus 1 bytes de préfixe qui indique de quelle joueur ça vient)
    "8005", # demande des signatures
    "8006" + "4000", # <sign1> <sign2> <sign3> renvoie des signatures
    "8007" + "9200" # + <clef publique 1> + <clef publique 2> 
]

# demande des clefs publiques 
PUBKEYS = []

for i in range(nb_participant):
    cmd = unhexlify(CMDS[1])
    try:
        r = SOCKETS[i].exchange(cmd)
        sleep(0.5)
    except Exception as e:
        print(e)
        print("Echec envoie mode signature : signature abandonnée")
        cmd = unhexlify(CMDS[0])
        for k in range(nb_participant):
            SOCKETS[k].exchange(cmd)
        sys.exit(1)
    if r is not None:
        PUBKEYS.append(bytes_to_point(r))

print(PUBKEYS)

# mise en mode signature des clients rust 

for i in range(nb_participant):
    cmd = unhexlify(CMDS[2])
    try:
        r = SOCKETS[i].exchange(cmd)
        sleep(0.5)
    except Exception as e:
        print(e)
        print("Echec envoie mode signature : signature abandonnée")
        cmd = unhexlify(CMDS[0])
        for k in range(nb_participant):
            SOCKETS[k].exchange(cmd)
        sys.exit(1)
    

# envoie des clefs publiques 

for i in range(nb_participant):
    signs_to_send_bytes = bytearray()
    for j in range(nb_participant):
        signs_to_send_bytes += point_to_bytes(PUBKEYS[j])
    cmd = unhexlify(CMDS[7]) + signs_to_send_bytes # demande des publics nonces
    r = None
    try: 
        r = SOCKETS[i].exchange(cmd)
        sleep(0.5)
    except Exception as e:
        print(e)
        print("Echec reception : signature abandonnée")
        cmd = unhexlify(CMDS[0])
        for k in range(nb_participant):
            try:
                SOCKETS[k].exchange(cmd)
            except Exception as e:
                print(e)
        sys.exit(1)
    


R = [[] for i in range(nb_participant)] #on remplit à la première étape
count_nonce = 0

for i in range(nb_participant):
    cmd = unhexlify(CMDS[3]) # demande des publics nonces
    for j in range(nb_nonces):
        r = None
        try: 
            r = SOCKETS[i].exchange(cmd)
            sleep(0.5)
        except Exception as e:
            print(e)
        if r is not None:
            R[i].append(bytes_to_point(r))
        else:
            print("Echec reception : signature abandonnée")
            cmd = unhexlify(CMDS[0])
            for k in range(nb_participant):
                SOCKETS[k].exchange(cmd)
            sys.exit(1)
print(R)

# envoie des public nonces 

for i in range(nb_participant):
    for j in range(nb_participant):
        nonces_to_send_bytes = bytearray()
        for v in range(nb_nonces):
            nonces_to_send_bytes += point_to_bytes(R[j][v])
        cmd = unhexlify(CMDS[4]) + (j).to_bytes(1, 'big') + nonces_to_send_bytes # demande des publics nonces
        r = None
        try: 
            r = SOCKETS[i].exchange(cmd)
            sleep(0.5)
        except Exception as e:
            print(e)
            print("Echec reception : signature abandonnée")
            cmd = unhexlify(CMDS[0])
            for k in range(nb_participant):
                SOCKETS[k].exchange(cmd)
            sys.exit(1)


S = [] #on remplit à la première étape
count_nonce = 0

# reception des signatures

for i in range(nb_participant):
    cmd = unhexlify(CMDS[5]) # demande des signatures
    r = None
    try: 
        r = SOCKETS[i].exchange(cmd)
        sleep(0.5)
    except Exception as e:
        print(e)
    if r is not None:
        S.append(int.from_bytes(r, 'big'))
    else:
        print("Echec reception : signature abandonnée")
        cmd = unhexlify(CMDS[0])
        for k in range(nb_participant):
            SOCKETS[k].exchange(cmd)
        sys.exit(1)
print(S)

# envoie des signatures
for i in range(nb_participant):
    signs_to_send_bytes = bytearray()
    for v in range(nb_participant):
        signs_to_send_bytes += S[v].to_bytes(32, 'big')
    cmd = unhexlify(CMDS[6]) + signs_to_send_bytes # demande des publics nonces
    r = None
    try: 
        r = SOCKETS[i].exchange(cmd)
        sleep(0.5)
    except Exception as e:
        print(e)
        print("Echec reception : signature abandonnée")
        cmd = unhexlify(CMDS[0])
        for k in range(nb_participant):
            SOCKETS[k].exchange(cmd)
        sys.exit(1)

print("ok")

# for i in range(nb_participant):
#     SOCKETS[i].close()

