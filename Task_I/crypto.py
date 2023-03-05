from Cryptodome.Cipher import AES
import os

    
def pkcs7_pad(plain,blocksize):
    BLOCKSIZE = blocksize #in bytes

    padbyte = BLOCKSIZE - len(plain)%BLOCKSIZE
    plain += chr(padbyte) * padbyte
    return plain

def pkcs7_strip(plain,blocksize):
    BLOCKSIZE = blocksize #in bytes

    numblocks = int(len(plain)/(BLOCKSIZE) + (1 if len(plain)%BLOCKSIZE else 0))

    newplain = plain[0:(numblocks-1)*BLOCKSIZE]
    padblock = plain[(numblocks-1)*BLOCKSIZE:]
    padbytes = ord(padblock[-1:])
    #Validate padding - we should never see a pad end in zero
    if padbytes == 0 or padbytes > BLOCKSIZE:
        raise Exception("PaddingError")
        return ""
    #make sure all the pad bytes make sense
    for b in padblock[BLOCKSIZE-padbytes:BLOCKSIZE]:
        if b != padbytes:
            raise Exception("PaddingError")
            return ""

    newplain += padblock[:-padbytes]

    return newplain


def cbc_encrypt(plain, key):

    iv = os.urandom(AES.block_size)
    aes_obj = AES.new(bytes(key), AES.MODE_CBC, iv)
    return iv + aes_obj.encrypt(bytes(pkcs7_pad(plain, AES.block_size), "UTF-8"))

def cbc_decrypt(enc, key):

    iv = enc[:AES.block_size]
    aes_obj = AES.new(bytes(key), AES.MODE_CBC, iv)
    enc_pad = aes_obj.decrypt(enc[AES.block_size:])
    return  pkcs7_strip(enc_pad, AES.block_size)
