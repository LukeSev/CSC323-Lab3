import requests
import re
from Crypto.Cipher import AES
import os
import crypto
import pkcs7

BLOCKSIZE = 16

base_url = "http://127.0.0.1:8080"
eavesdrop_url = base_url + "/eavesdrop"
submit_url = base_url + "/submit"

def eavesdrop():
    # Reads in ciphertext from web server and returns it as string
    text = requests.get(eavesdrop_url).text
    lines = re.sub('<.+?>', '', text).split("\n")
    output = []
    for line in lines:
        if(len(line.lstrip()) > 0):
            output.append(line.lstrip())
    # Ciphertext appears on second line
    return output[1]

def test_ciphertext(ciphertext):
    # Takes in ciphertext as hex string and returns 1 if valid and 0 otherwise
    # First word in request's text is either 404 (valid decryption) or 403 (invalid decryption)
    r = requests.get(base_url + "/?enc=" + ciphertext).text.split(' ')
    val = int(r[0])
    if((val != 403) and (val != 404)):
        print("Bad server output")
    return val - 403

def test_one_byte_pad(ciphertext):
    # Takes ciphertext as bytearray that should have only one padding byte in the resulting plaintext (0x01)
    # Verifies that it's actually just 0x01 and didn't incidentally create a valid padding of another number
    # Tests by changing second to last byte in the IV, which should still return valid padding if padding is 0x01
    ctext = ciphertext
    ctext[BLOCKSIZE-2] = ctext[BLOCKSIZE-2] ^ 255 
    return test_ciphertext(bytes(ctext).hex())

def decrypt_block(cblock1, cblock2):
    # Given ciphertext as bytes, decrypts the last block of the ciphertext
    # This is achieved by repeatedly finding the last unkown byte in the block by testing padding
    # For example, for the last byte in the block, change the last byte in the prev block til you get a result that changes the last byte to 0x01
    prev_block = bytearray(cblock1)
    ctext = bytearray(cblock2)
    ptext = bytearray(BLOCKSIZE) # Initialize empty block for our plaintext
    last_byte = len(ctext)-1 # Index for last byte in ciphertext, save for easier byte manipulation later
    input = bytearray(2*BLOCKSIZE) # Will send this to oracle, first block is an IV thats created, second is ciphertext block in question
    fake_IV = bytearray(BLOCKSIZE)

    # Basic Idea: During decryption, for any plaintext byte P[i], P[i] = C[i] XOR Decryption(C[i+BLOCKSIZE])
    # Brute-forcing every possible C[i] will eventually give us valid padding
    # Once this is done, we can calculate what our plaintext will be and update our fake_IV using XOR logic
    # For a more detailed, though somewhat hard-to-read explanation, I uploaded my written/drawn out work
    #   on my github at https://github.com/LukeSev/CSC323-Lab3/blob/master/Task_I/Lab3_PaddingOracleAttack_Rationale.pdf 

    # Solve for first 15 padding bytes, last one is special case (all 0's)
    for target in range(1, BLOCKSIZE+1): # target pad value we want to set
        found = 0
        for guess in range(256): # Test each possible byte value
            # If we XOR ctext byte with our test byte and the target padding, it'll be valid padding if test is plaintext byte

            fake_IV[-target] = guess
            input = fill_bytes(input, fake_IV, BLOCKSIZE, 0)
            input = fill_bytes(input, ctext, BLOCKSIZE, BLOCKSIZE)
            if(test_ciphertext(bytes(input).hex())):
                if((target > 1) or (test_one_byte_pad(input)) == 1):
                    # Found valid padding, now find what that would give in plaintext
                    ptext[-target] = prev_block[-target] ^ fake_IV[-target] ^ target

                    # Prep for next round of padding by setting fake_IV to create padding blocks for next target
                    for i in range(1,target+1):
                        fake_IV[-i] = fake_IV[-i] ^ target ^ (target+1)
                    found = 1
                    break
        if(found == 0):
            print("FAILED TO FIND PLAINTEXT BYTE")
            return
    return bytes(ptext)


def fill_bytes(plaintext, block, numbytes, start):
    # Given index to start at, fills plaintext with bytes from block
    # plaintext and block are bytearray, start is int
    for i in range(numbytes):
        plaintext[start+i] = block[i]
    return plaintext

def decrypt_ciphertext(ciphertext):
    # Takes in ciphertext as hex string, returns plaintext as bytes
    ctext = bytearray(bytes.fromhex(ciphertext))
    num_blocks = int((len(ctext) / BLOCKSIZE) - 1)   # Don't decrypt IV
    plaintext = bytearray(BLOCKSIZE*num_blocks)
    for i in range(num_blocks):
        decrypted = decrypt_block(bytes(ctext[-(2*BLOCKSIZE):-BLOCKSIZE]), bytes(ctext[-BLOCKSIZE:]))
        if(decrypted == None):
            print("Decryption failed :(")
            return
        print("Block {} Successfully decrypted".format(num_blocks-i))
        block = bytearray(decrypted)
        plaintext = fill_bytes(plaintext, block, BLOCKSIZE, len(plaintext)-1-(BLOCKSIZE*(1+i)))
        ctext = ctext[:-BLOCKSIZE]
    return bytes(plaintext)

def main():
    ciphertext = eavesdrop().rstrip()
    plaintext = decrypt_ciphertext(ciphertext)
    print(plaintext)
    print(bytearray(plaintext))
    pStr = re.sub("[)(]", "", plaintext.decode())
    print(crypto.pkcs7_strip(pStr.encode(), BLOCKSIZE).decode())

    # block = b'\xBE\xEF\xBE\xEF' * 4
    # plaintext = bytearray(BLOCKSIZE*3)
    # print(fill_bytes(plaintext, block, BLOCKSIZE, BLOCKSIZE*2))

    # # Basic testing
    # print("Testing ciphertext: {}".format(ciphertext))
    # if(test_ciphertext(ciphertext)):
    #     print("Valid decryption! Length: {} bytes\n".format(len(bytes.fromhex(ciphertext))))
    # else:
    #     print("Invalid decryption :(\n")

    
    # altered = bytearray(bytes.fromhex(ciphertext))
    # for i in range(BLOCKSIZE):
    #     altered[len(altered)-1-(BLOCKSIZE+i)] = i
    # print("Testing ALTERED ciphertext: {}".format(ciphertext))
    # if(test_ciphertext(bytes(altered).hex())):
    #     print("Valid decryption! Length: {} bytes\n".format(len(bytes.fromhex(ciphertext))))
    # else:
    #     print("Invalid decryption :(\n")

    # invalid_ctext = "A" * 15
    # print("Testing ciphertext: {}".format(invalid_ctext))
    # if(test_ciphertext(invalid_ctext)):
    #     print("Valid decryption!\n")
    # else:
    #     print("Invalid decryption :(\n")


if __name__ == '__main__':
    main()