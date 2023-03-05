import requests
import re
from Crypto.Cipher import AES
import os
import crypto

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
    return int(r[0]) - 403

def decrypt_block(ciphertext):
    # Given ciphertext as bytes, decrypts the last block of the ciphertext
    # This is achieved by repeatedly finding the last unkown byte in the block by testing padding
    # For example, for the last byte in the block, change the last byte in the prev block til you get a result that changes the last byte to 0x01
    reference = bytearray(ciphertext)
    ctext = reference
    ptext = bytearray(BLOCKSIZE) # Initialize empty block for our plaintext
    last_byte = len(ctext)-1 # Index for last byte in ciphertext, save for easier byte manipulation later
    
    # Solve for first 15 padding bytes, last one is special case (all 0's)
    for distance in range(15): # distance away from last byte in ciphertext block
        c_index = last_byte-(BLOCKSIZE+distance)
        p_index = BLOCKSIZE-(1+distance)
        target = distance+1 # If solving for distance = 0, want to set padding byte to 0+1 = 0x01, if 1, set to 0x02, etc
        curr_byte = reference[c_index] # Go to previous block
        for test in range(256): # Test each possible byte
            # If we XOR ctext byte with our test byte and the target padding, it'll be successful for if test is plaintext byte
            ctext[c_index] = curr_byte ^ test ^ target 
            if(test_ciphertext(bytes(ctext).hex())):
                ptext[p_index] = test
                # Now prepare block by filling in padding for next iteration
                for i in range(distance):
                    ctext[last_byte-i] = (target+1) ^ reference[last_byte-(BLOCKSIZE+i)] ^ ptext[BLOCKSIZE-(i+1)]
                break
    # Now do final padding byte, which should be all 0's
    c_index = last_byte - (BLOCKSIZE+(BLOCKSIZE-1))
    p_index = 0
    target = 0
    curr_byte = reference[last_byte-((2*BLOCKSIZE)+1)]
    for test in range(256):
        ctext[c_index] = curr_byte ^ test ^ target
        if(test_ciphertext(bytes(ctext).hex())):
            ptext[p_index] = test
            return bytes(ptext)
    return bytes(ptext)

def fill_plaintext(plaintext, block, start):
    # Given index to start at, fills plaintext with bytes from block
    # plaintext and block are bytearray, start is int
    for i in range(BLOCKSIZE):
        plaintext[start+i] = block[i]
    return plaintext

def decrypt_ciphertext(ciphertext):
    # Takes in ciphertext as hex string, returns plaintext as bytes
    ctext = bytearray(bytes.fromhex(ciphertext))
    num_blocks = int((len(ctext) / BLOCKSIZE) - 1)   # Don't decrypt IV
    plaintext = bytearray(BLOCKSIZE*num_blocks)
    for i in range(num_blocks):
        block = bytearray(decrypt_block(bytes(ctext)))
        plaintext = fill_plaintext(plaintext, block, len(plaintext)-1-(BLOCKSIZE*(1+i)))
        ctext = ctext[:-BLOCKSIZE]
    return bytes(plaintext)


# def test_decryption():
#     key = os.urandom(16)
#     plaintext = "Hello there pal my name is John Dark Souls and I am the titular dude from the critically-acclaimed videogame series Dark Souls. I suck nuts."
#     ciphertext = crypto.cbc_encrypt(plaintext, key).hex()
#     print("Length of ciphertext in bytes: {}".format(len(bytes.fromhex(ciphertext))))
#     plaintext = decrypt_ciphertext(ciphertext)
#     print(plaintext.decode('ascii'))

def main():
    #ciphertext = eavesdrop()


    # Basic testing
    # print("Testing ciphertext: {}".format(ciphertext))
    # if(test_ciphertext(ciphertext)):
    #     print("Valid decryption!\n")
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