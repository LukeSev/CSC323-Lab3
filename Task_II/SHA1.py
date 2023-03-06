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
    ml = len(msg) * 8       # 8 bits per byte

    # Pre-processing
    # Need to pad msg with a '1' bit then k 0's until length is 448 % 512
    msg.append(0x80)
    num_pad_bytes = int(448/8) - int(((ml+8) % 512)/8)

    # Now pad with 0's
    for i in range(num_pad_bytes):
        msg.append(0x00)
    
    # Now append ml as 64-bits to make overall msg a multiple of 512
    length = ml.to_bytes(8, byteorder='big')
    for byt in length:
        msg.append(byt)

    # Parse the message into 512-bit (64 byte) blocks
    temp = msg
    blocks = []
    for i in range(int(len(msg)/64)):
        block = bytearray()
        for j in range(64):
            block.append(temp[j])
        blocks.append(block)
        temp = temp[64:]

    # Main Processing / Hash Computation
    for block in blocks:
        # Break up each block into sixteen 32-bit words
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(bytes(block[j*4:(j*4)+4]), "big")
        
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
                f = (b & c) ^ ((not b) & d)
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
            
            temp = rotl(a, 5) + f + e + k + w[i]
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = temp

        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e

    digest = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return digest


def main():
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

    # shift_amt = 1
    # unshifted = 0xFFFFFFFE
    # shifted = rotl(unshifted, shift_amt)
    # print("Shift Amount: {}\nUnshifted: {}\nShifted:   {}".format(shift_amt, bin(unshifted), bin(shifted)))

if __name__ == '__main__':
    main()