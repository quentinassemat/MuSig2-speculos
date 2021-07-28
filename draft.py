#Importation des librairies

from operator import truediv
from sympy import isprime

#On prend secrets car random n'est pas fiable pour la cryptographie
import secrets as sct

#pour les fonctions de hash
import hashlib as hl

#pour gérer les courbes elliptiques
from arithm.ecc.curves import secp256k1
from arithm.ecc.ecc import Point
from arithm.field import Field, FieldElement

#pour gérer speculos
from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from random import getrandbits as rnd, randbytes, randint
from binascii import hexlify, unhexlify

from time import sleep

#pour la communication tcp
import socket

#pour les interactions utilisateurs
import sys

#on travaille avec secp256K1 : voici quelques constantes :
#G est le générateur de notre groupe
G = secp256k1.G

#ordre du groupe
n = secp256k1.order

#F est le corps de définition de la courbe
F = secp256k1.a.field

#nombre de bytes necessaire pour stocker en byte les entiers
N_bytes = 32

#E est le neutre du groupe
E = Point(F(0), F(1), F(0), secp256k1)

#Paramètres pour la signature
nb_participant = 0
try: 
    nb_participant = int(sys.argv[1])
except ValueError:
    print("Unvalid number of signers")
    sys.exit(1)

nb_nonces = 3
M = "Alice donne 1 Bitcoin à Bob"

#Données de communication serveur 
ADRESSE = 'localhost'
PORTS = [40000 + i for i in range(nb_participant)]
MEM = 16496 #mémoire nécessaire pour communiquer les infos durant les étapes de communications


#Class signer à sa clef publique (self.KEY), sa clef prive (self.key), une fonction de generation aleatoire
class Signer:
    #constructeurs
    def __init__(self, nb_nonces):
        self.key = sct.randbelow(n - 1) + 1
        self.KEY = self.key * G
        self.list_r = [0]*nb_nonces
        self.selfa = 0

    def gen_r(self):
        for i in range(len(self.list_r)):
            self.list_r[i] = sct.randbelow(n)

def point_to_bytes(p : Point, compress = False): # TODO : on pourrait checker le premier bit et choisir si c'est compressé en fonction
    #d'après sec1
    if compress:
        p.to_affine()
        res = bytearray()
        if p.is_at_infinity():
            res.extend(0).to_bytes(N_bytes + 1, 'big')
        else :
            res.extend(((p.y.val % 2) + 2).to_bytes(1, 'big'))
            res.extend((p.x.val).to_bytes(N_bytes, 'big'))
        return bytes(res)
    else:
        p.to_affine()
        res = bytearray()
        res.extend(((4).to_bytes(1, 'big')))
        res.extend((p.x.val).to_bytes(N_bytes, 'big'))
        res.extend((p.y.val).to_bytes(N_bytes, 'big'))   
        return bytes(res)


def bytes_to_point(bytes_point : bytes, compress = False):
    #d'après sec1
    if compress:
        if (bytes == (0).to_bytes(N_bytes + 1, 'big')):
            return E
        x = FieldElement(int.from_bytes(bytes_point[1:len(bytes_point)], 'big'), F)
        y_squared = x ** 3 + x * secp256k1.a + secp256k1.b
        y = FieldElement.sqrt(y_squared)
        ytilde = int.from_bytes(bytes_point[0:1], 'big') % 2
        if ytilde == y.val % 2:
            return Point(x,y)
        else:
            return Point(x,-y)
    else :
        valid = int.from_bytes(bytes_point[0:1], 'big')
        if valid != 4:
            raise Exception("Unvalid encoding")
        else :
            x = FieldElement(int.from_bytes(bytes_point[1:N_bytes + 1], 'big'), F)
            y = FieldElement(int.from_bytes(bytes_point[N_bytes + 1:len(bytes_point)], 'big'), F)
            if (y**2 == x ** 3 + x * secp256k1.a + secp256k1.b):
                return Point(x,y)
            raise Exception("Point pas sur la courbe")


def bytesrep_to_messagePoint(bytesrep):
    bytesrep_list = bytesrep.split(b' ] ')
    str_id = bytesrep_list[0][5:]
    str_point = bytesrep_list[1]
    return messagePoint(bytes_to_point(str_id),bytes_to_point(str_point))

def bytesrep_to_messageSign(bytesrep):
    bytesrep_list = bytesrep.split(b' ] ')
    str_id = bytesrep_list[0][5:]
    str_sign = bytesrep_list[1]
    return messagePoint(bytes_to_point(str_id),int.from_bytes(str_sign, 'big'))

def matPoint_to_bytes(R): #pour envoyer matrice de point 
    n = len(R) #censé être nb_participant
    m = len(R[0]) #censé être nb_nonces
    L = []
    for i in range(n-1):
        L.append(listPoint_to_bytes(R[i]))
        L.append(b' \n ')
    L.append(listPoint_to_bytes(R[n-1]))
    return b''.join(L)

def bytes_to_matPoint(bytes):
    R = [[E]*nb_nonces for i in range(nb_participant)]
    list1 = bytes.split(b' \n ')
    for i in range(nb_participant):
        L = list1[i].split(b' ; ')
        for j in range(nb_nonces):
            R[i][j] = bytes_to_point(L[j])
    return R
        
def listPoint_to_bytes(L):
    n = len(L)
    res = []
    for i in range(n-1):
        res.append(point_to_bytes(L[i]))
        res.append(b' ; ')
    res.append(point_to_bytes(L[n-1]))
    return b''.join(res)

def listint_to_bytes(L):
    n = len(L)
    res = bytearray(b"")
    for i in range(n-1):
        res.extend(L[i].to_bytes(N_bytes, 'big'))
        res.extend(b' ; ')
    res.extend(L[n-1].to_bytes(N_bytes, 'big'))
    return res

def bytes_to_list(bytes): #pour communiquer la liste des clefs publiques (même si censé déjà les avoir)
    L = [E] * nb_participant
    temp = bytes.split(b' ; ')
    assert len(temp) == nb_participant
    for i in range(nb_participant):
        L[i] = bytes_to_point(temp[i])
    return L

def bytes_to_listint(bytes):
    L = [0] * nb_participant
    temp = bytes.split(b' ; ')
    assert len(temp) == nb_participant
    for i in range(nb_participant):
        L[i] = int.from_bytes(temp[i], 'big')
    return L


#class pour wrapper l'envoie de message en ayant l'information de où vient le message
class messagePoint:
    def __init__(self, _id, _point):
        self.point = _point
        self.id = _id

    def __bytes__(self):
        return b''.join(["[ID :".encode('utf-8') ,point_to_bytes(self.id)," ] ".encode('utf-8') , point_to_bytes(self.point)])

def bytesrep_to_messageSign(bytes):
    str_list = bytes.split(b' ] ')
    str_id = str_list[0][5:]
    str_sign = str_list[1]
    return messageSign(bytes_to_point(str_id),int.from_bytes(str_sign, 'big'))

#class pour wrapper l'envoie de message en ayant l'information de où vient le message
class messageSign:
    def __init__(self, _id, _sign):
        self.sign = _sign
        self.id = _id

    def __bytes__(self):
        return b''.join(["[ID :".encode('utf-8') ,point_to_bytes(self.id)," ] ".encode('utf-8') , self.sign.to_bytes(N_bytes, 'big')])

#Génération de signature aléatoire
def FakeKey(G):
    return (sct.randbelow(n) * G, sct.randbelow(n))

def input_yes_no():
    while True:
        str = input("")
        if str == "yes":
            return True
        elif str == "no":
            return False
        else:
            print("Please enter a valid input (yes/no)")


### truc du ADD

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
            ANSWER.append(int.from_bytes(r, 'big') % n)
    sleep(2)

print(f"On obtient le résultat suivant : {ANSWER}")
d.close()

###fin truc du add


def cmd(nb_bytes: int, bytes):
    return "8002" + hexlify(nb_bytes.to_bytes(2, 'little')).decode() + hexlify(bytes).decode()

# On débute la signature : 

#Collecte des id (clé publiques) des signeurs:
PUBKEYS = [E] * nb_participant

SOCKETS  = [getDongleTCP(port=PORTS[i]) for i in range(nb_participant)]

print("Las sockets est bind, nous pouvons commencer")

count_pubkeys = 0

while count_pubkeys < nb_participant:
    cmd = unhexlify(CMDS[0])
    r = None 
    for i in range(nb_participant):
        try:
            r = SOCKETS[i].exchange(cmd, 20)
        except Exception as e:
            print(e)
        if r is not None: 
            PUBKEYS[i] = bytes_to_point(r, False)
            count_pubkeys += 1
            print("Response : ", hexlify(r))

print(f"On a reçu les clefs publiques")
print(PUBKEYS)


# envoie de la liste des clefs publiques aux signeurs

count_pubkeys = 0

while count_pubkeys < nb_participant:
    cmd = 
    for i in range(nb_participant):
        try:
            r = SOCKETS[i].exchange(cmd(2))

    try:
        for i in range(nb_participant):
            cmd = CMDS
            r = SOCKETS
        client, adresseClient = serveur.accept()
        client.sendall(listPoint_to_bytes(PUBKEYS))
        count_pubkeys += 1
    finally:
        client.close()

print(f"On a envoyé les clefs publiques")





### FIN DES FONCTIONS : DÉBUT DE L'ALGO DE SIGNATURES AVEC SPECULOS ###
