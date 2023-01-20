import basicCalc as bc
import base58 as b58
import hashlib
import json

from random import randint
from justpy.kfuncs import removeData, checkHx


def walletGenerateSingle():
    name = input("Walltet Name: ")
    dA = randint(3, bc.curve.n - 2)
    pK0 = bc.scalar_mult(dA, bc.curve.g)
    pK = pubKeypre(pK0)
    checksum = IpsoHasher(pK)
    pKn = b58.b58encode(bytes.fromhex(
        "80" + checkHx(removeData("0x", hex(dA)), 64))).decode()
    addr = (b58.b58encode(bytes.fromhex(checksum))).decode()
    wallet_dict = {"wallet: ": name,
                   "dA: ": pKn,
                   "pub: ": pK,
                   "address: ": addr}
    # file generation
    with open(name + ".json", 'w') as outfile:
        json.dump(wallet_dict, outfile)
    print("wallet file created")


def walletGenerateMulti():
    users = int(input("Enter number of users: "))
    name = input("Enter base name for wallet generation: ")
    usr_keys_basic = [randint(3, bc.curve.n - 2) for i in range(0, users)]
    usr_keys_priv = []
    dump = []
    usr_keys_pub = []
    # Loops for private wif formation and public key calculations
    for i in usr_keys_basic:
        usr_keys_priv.append(b58.b58encode(bytes.fromhex(
            "80" + checkHx(removeData("0x", hex(i)), 64))).decode())
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
        usr_wallets.append({"wallet: ": name + " " + str(usr),
                           "dA: ": usr_keys_priv[usr], "pub: ": master_pub_key, "address: ": addr})
    for usr in range(0, len(usr_wallets)):
        with open(name + " " + str(usr) + ".json", 'w') as outfile:
            json.dump(usr_wallets[usr], outfile)
    print("Wallet files created")


def sigGenerate(dA, pK, dat):
    dA = int(dA, 16)
    # checks
    dat_c = int(dat, 16)
    pubK_c = int(pK, 16)
    if pairCheck(dA, pK) is False:
        raise Exception("PrivPubError: Private and public key are not pairs")
    # main
    det = str(dA) + str(dat)
    K = int(hashlib.sha256(det.encode()).hexdigest(), 16)
    r_xy = bc.scalar_mult(K, bc.curve.g)
    r = r_xy[0]
    conc = removeData("0x", hex(r)) + str(dat)
    e = int(hashlib.sha256(conc.encode()).hexdigest(), 16)
    s = (K - (dA * e)) % bc.curve.n
    z = {"s: ": s, "r: ": pubKeypre(r_xy), "pK": pK, "message: ": dat}
    return z


def sigVerify(pK, r, s, dat):
    if type(pK) is tuple:
        pK = pK
    else:
        pK = ucompress(pK)
        x = pK[2:66]
        y = pK[66:]
        pK = (int(x, 16), int(y, 16))
    if len(r) > 64:
        r = r[2:]
    else:
        r = r
    conc = r + dat
    e = int(hashlib.sha256(conc.encode()).hexdigest(), 16)
    pt = bc.point_add(bc.scalar_mult(e, pK), bc.scalar_mult(s, bc.curve.g))
    if int(r, 16) == pt[0]:
        return True
    else:
        return False


def ucompress(pK):
    y_par = int(pK[:2]) - 2
    x = int(pK[2:], 16)
    y2 = (pow(x, 3, bc.curve.p) + 7) % bc.curve.p
    y = pow(y2, (bc.curve.p + 1) // 4, bc.curve.p)
    if y % 2 == y_par:
        return "04" + pK[2:] + checkHx(removeData("0x", hex(y)), 64)
    else:
        y = -y % bc.curve.p
        return "04" + pK[2:] + checkHx(removeData("0x", hex(y)), 64)


def pubKeypre(pK):
    if pK[1] % 2 == 0:
        pK = "02" + checkHx(removeData("0x", (hex(pK[0]))), 64)
    else:
        pK = "03" + checkHx(removeData("0x", (hex(pK[0]))), 64)
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
    pubh2 = "66" + hashlib.new('ripemd160', pubh1.encode()).hexdigest()
    pubh3 = hashlib.sha256(
        (hashlib.sha256(pubh2.encode()).hexdigest()).encode()).hexdigest()
    pubh4 = pubh3[8:16]
    pub = pubh2 + pubh4
    return pub


def pairCheck(priv, pub):
    pub = "0x" + pub[2:]
    if hex((bc.scalar_mult(priv, bc.curve.g)[0])) != hex(int(pub, 16)):
        print(hex((bc.scalar_mult(priv, bc.curve.g)[0])))
        print(pub)
        return False
    else:
        return True


def generateRand():
    print("Generationg Random Pub-Priv pairs")
    dA = (randint(0, bc.curve.n))
    pKn = bc.scalar_mult(dA, bc.curve.g)
    pK = (hex(pKn[1]))
    pKs = pubKeypre(pKn)
    dA = hex(dA)
    z = {"dA: ": dA, "pK: ": pK, "pKs: ": pKs}
    return z
