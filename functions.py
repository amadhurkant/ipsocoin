import basicCalc as bc
import base58 as b58
import hashlib
import json
import random

def walletGenerateSingle():
    name= input("Walltet Name: ")
    dA = random.randint(3, bc.curve.n-2)
    pK = bc.scalar_mult(dA, bc.curve.g)
    pk0 = bc.scalar_mult(dA, bc.curve.g)[1]
    if pK[1] % 2 == 0:
        pK = "02"+removeData("0x", str(hex(pK[0])))
    else:
        pK = "03"+removeData("0x", str(hex(pK[0])))
    pubh1 = hashlib.sha256(pK.encode()).hexdigest()
    pubh2 = "66"+hashlib.new('ripemd160', pubh1.encode()).hexdigest()
    pubh3 = hashlib.sha256((hashlib.sha256(pubh2.encode()).hexdigest()).encode()).hexdigest()
    pubh4 = pubh3[8:16]
    pub = pubh2+pubh4
    pKn = b58.b58encode(bytes.fromhex("80"+removeData("0x", hex(dA)))).decode()
    addr = (b58.b58encode(bytes.fromhex(pub))).decode()
    wallet_dict = {"wallet: ": name,
    "dA: ": pKn,
    "pub: ": pK,
    "address: ": addr}
    #file generation
    with open(name+".json", 'w') as outfile:
        json.dump(wallet_dict, outfile)
    print("wallet file created - pls check")

def removeData(remove, data):
    if remove not in data:
        raise Exception(f"RemoveNotError: Data to be removed- {remove} -not found in provided data")
    occurence = data.count(remove)
    if remove in data:
        data0 =  data.split("0x", occurence)
    data2 = ''
    for i in data0:
        data2 = data2+i
    return data2
print(walletGenerateSingle())
