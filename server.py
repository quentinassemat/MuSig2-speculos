from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from random import getrandbits as rnd, randbytes, randint
from binascii import hexlify, unhexlify

from time import sleep
from tools import *

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

# #Collecte des id (clé publiques) des signeurs:
# PUBKEYS = [E] * nb_participant

#Construction des clefs publiques 
# public key 1 : 0423cdc4924412d491d0ed13272372e945ddd9886c32592f8ac9b7b37dcd8adc7d20d88572e9fdbe872c1dbfbdb9921cb8d17af04a63b65646aa7bc29f42d16f41
# public key 2 : 0479717b8ad6bd8efa41af00e682d97004be32738b54a30d2a0141eb2c2590baa0bffee15e85c9be9478e34e251baa3a2e11aef8269d8b1a695ceb7ff177185fd8

PUBKEYS_BIN = [unhexlify(b'0423cdc4924412d491d0ed13272372e945ddd9886c32592f8ac9b7b37dcd8adc7d20d88572e9fdbe872c1dbfbdb9921cb8d17af04a63b65646aa7bc29f42d16f41'), unhexlify(b'0479717b8ad6bd8efa41af00e682d97004be32738b54a30d2a0141eb2c2590baa0bffee15e85c9be9478e34e251baa3a2e11aef8269d8b1a695ceb7ff177185fd8')]
PUBKEYS = [bytes_to_point(b) for b in PUBKEYS_BIN]

print(PUBKEYS)

SOCKETS  = [getDongleTCP(port=PORTS[i]) for i in range(nb_participant)]

print("Les sockets est bind, nous pouvons commencer")


CMDS = [
    "80ff", # demande de quitter la signature
    "8001", # demande de clef publique
    "8002", # demande de signature 
    "8003", # demande des publiques nonces 
    "8004" + "c400" # +<indice du joueur> + <nonce1> + <nonce2>  + <nonce3>   envoie de nonce + taille (Taille de 3 nonces plus 1 bytes de préfixe qui indique de quelle joueur ça vient)
]

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

print("ok")

# for i in range(nb_participant):
#     SOCKETS[i].close()

