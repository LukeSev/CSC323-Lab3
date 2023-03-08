import math

int_size = 2**32


def rotl(num, amt):
    # Given an 32-bit int and a shift amount, rotates left by 'amt' bits
    shifted = num
    for i in range(amt):
        temp = (shifted << 1) % int_size
        if(0x80000000 & shifted):
            # MSB is 1, add to end
            temp = temp | 0x0001
        shifted = temp
    return shifted

def parse_block(block):
    # Takes in 64-byte (512 bit) block as bytearray
    # Returns list of 32-bit ints for every 4 bytes in block
    words = [0] * 80
    for i in range(16):
        words[i] = int.from_bytes(bytes(block[i*4:(i*4)+4]), byteorder='big')
    return words

def sha1_hash(message):
    # Given message in bytes, create hash using SHA1 method

    # Initialize variables
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Calculate message length in bits
    msg = bytearray(message)
    ml = len(msg) * 8 # 8 bits per byte

    # Pre-processing
    # Need to pad msg with a '1' bit then k 0's until length is 448 % 512
    msg.append(0x80)

    # Now pad with 0's
    while(len(msg) % 64 != 56):
        msg.append(0x00)

    
    # Now append ml as 64-bits to make overall msg a multiple of 512
    length = ml.to_bytes(8, byteorder='big')
    for byt in length:
        msg.append(byt)

    if(len(msg) % 64 != 0):
        print("ERROR: PRE-PROCESSED MESSAGE IS NOT MULTIPLE OF 512 BITS")

    N = int(len(msg)/64) # Number of blocks

    # Parse the message into 512-bit (64 byte) blocks
    blocks = [0] * N
    for i in range(N):
        block = bytearray(64)
        for j in range(64):
            block[j] = msg[(i*64)+j]
        blocks[i] = block

    # Main Processing / Hash Computation
    for block in blocks:
        # Break up each block into sixteen 32-bit words
        w = parse_block(block)
        
        # Extend 16 words into 80 words
        for i in range(16, 80):
            w[i] = rotl((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        # Initialize hash value for chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main Loop
        for i in range(80):
            if((i >= 0) and (i <=19)):
                f = (b & c) ^ ((~b) & d)
                k = 0x5A827999
            elif((i >= 20) and (i <= 39)):
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif((i >= 40) and (i <= 59)):
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC
            elif((i >= 60) and (i <= 79)):
                f = b ^ c ^ d
                k = 0xCA62C1D6
            else:
                print("ERROR: SOMETHING WENT WRONG")

            temp = (rotl(a, 5) + f + e + k + w[i]) % int_size
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) % int_size
        h1 = (h1 + b) % int_size
        h2 = (h2 + c) % int_size
        h3 = (h3 + d) % int_size
        h4 = (h4 + e) % int_size

    digest = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return digest

def find_sha1_collision():
    # Looking for collision on any 50 bits of sha1 output
    # We'll look for collision in first (least significant) 50 bits
    go = True
    i = 0
    hashes = {}
    while(go):
        msg = i.to_bytes(math.ceil(i/255), 'big')
        digest = sha1_hash(msg) & 0x03FFFFFFFFFFFF
        # digest = ((int.from_bytes(msg, byteorder='big')**2)%3) & 0x03FFFFFFFFFFFF
        # print(type(digest))
        if digest in hashes:
            print("50 bit collision found!\n")
            return (digest, (msg, hashes[digest]))
        hashes[digest] = msg
        i+=1

def test_sha1():
    # Tests sha1 against four test vectors
    test_vectors = ["abc", 
                    "", 
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
                    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 
                    "a" * (10**6)]
    for vector in test_vectors:
        name = vector
        if(name[:2] == "aa"):
            # Don't repeat the 1,000,000 a's
            name = "1,000,000 a's"
        digest = sha1_hash(vector.encode())
        print("\nMessage: {}\nHash: {}".format(name, hex(digest)))
    print()

def main():
    #test_sha1()
    msgs = find_sha1_collision()
    print(msgs)
   

if __name__ == '__main__':
    main()