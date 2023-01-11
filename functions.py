import basicCalc as bc
import base58 as b58
import hashlib
import json

from random import randint
from justpy.kfuncs import removeData, checkHx

def walletGenerateSingle():
    name= input("Walltet Name: ")
    dA = randint(3, bc.curve.n-2)
    pK0 = bc.scalar_mult(dA, bc.curve.g)
    pK = pubKeypre(pK0)
    checksum = IpsoHasher(pK)
    pKn = b58.b58encode(bytes.fromhex("80"+checkHx(removeData("0x", hex(dA)), 64))).decode()
    addr = (b58.b58encode(bytes.fromhex(checksum))).decode()
    wallet_dict = {"wallet: ": name,
    "dA: ": pKn,
    "pub: ": pK,
    "address: ": addr}
    #file generation
    with open(name+".json", 'w') as outfile:
        json.dump(wallet_dict, outfile)
    print("wallet file created")

def walletGenerateMulti():
    users = int(input("Enter number of users: "))
    name = input("Enter base name for wallet generation: ")
    usr_keys_basic =[randint(3, bc.curve.n-2) for i in range(0, users)]
    usr_keys_priv = []
    dump = []
    usr_keys_pub = []
    # Loops for private wif formation and public key calculations
    for i in usr_keys_basic:
        usr_keys_priv.append(b58.b58encode(bytes.fromhex("80"+checkHx(removeData("0x", hex(i)), 64))).decode())
    for i in usr_keys_basic:
        a = bc.scalar_mult(i, bc.curve.g)
        dump.append(a)
        usr_keys_pub.append(pubKeypre(a))
    # Code Continues
    master_pub_key = pubKeypre(keyAdd(dump))
    checksum = IpsoHasher(master_pub_key)
    addr = b58.b58encode(bytes.fromhex(checksum)).decode()
    usr_wallets = []
    # Creates Multiple File
    for usr in range(0, users):
        usr_wallets.append({"wallet: ": name+" "+str(usr), "dA: ": usr_keys_priv[usr], "pub: ": master_pub_key, "address: ": addr})
    for usr in range(0, len(usr_wallets)):
        with open(name+" "+str(usr)+".json", 'w') as outfile:
            json.dump(usr_wallets[usr], outfile)
    print("Wallet files created")

def pubKeypre(pK):
    if pK[1] % 2 == 0:
        pK = "02"+checkHx(removeData("0x", (hex(pK[0]))), 64)
    else:
        pK = "03"+checkHx(removeData("0x", (hex(pK[0]))), 64)
    return pK

def keyAdd(keylist):
    ne = []
    for n in keylist:
        if len(ne) == 0:
            ne.append(n)
        else:
            ne.append(bc.point_add(ne.pop(), n))
    return ne[-1]

def IpsoHasher(pK):
    pubh1 = hashlib.sha256(pK.encode()).hexdigest()
    pubh2 = "66"+hashlib.new('ripemd160', pubh1.encode()).hexdigest()
    pubh3 = hashlib.sha256((hashlib.sha256(pubh2.encode()).hexdigest()).encode()).hexdigest()
    pubh4 = pubh3[8:16]
    pub = pubh2+pubh4
    return pub
