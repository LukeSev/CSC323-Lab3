def pad(message, blocksize):
    # Takes in message as bytes and blocksize as int
    # Returns padded message as bytes
    msg_arr = bytearray(message)
    pad_size = blocksize - (len(msg_arr) % blocksize)
    if(pad_size == blocksize):
        # Pad with zero block
        pad_bytes = bytearray(blocksize)
    else:
        pad_bytes = bytearray()
        for i in range(pad_size):
            pad_bytes.append(pad_size)
    for byte in pad_bytes:
        msg_arr.append(byte)
    return bytes(msg_arr)

def unpad(message, blocksize):
    # Takes in (potentially) padded message as bytes and blocksize as int
    # Returns unpadded message as bytes
    msg_arr = bytearray(message)

    # First check if it's a valid, padded message
    if((len(msg_arr) % blocksize) != 0):
        raise Exception("Invalid message size for padding")

    # If padding by full block, last byte should be 0x00 not block size
    if(msg_arr[len(msg_arr)-1] == blocksize):
        raise Exception("Invalid padding bytes")
    
    # Determine how many bytes to remove from end of message
    pad_amt = int(msg_arr[len(msg_arr)-1])
    pad_val = pad_amt

    # Account for zero block
    # if(pad_val == 0):
    #     # Padded with '0' block
    #     pad_amt = blocksize
    
    # Check if padding is valid
    for i in range(pad_amt):
        if(msg_arr[len(msg_arr)-1-i] != pad_val):
            raise Exception("Invalid padding bytes")

    # Return message with specified amount of bytes removed
    return bytes(msg_arr[:-pad_amt])


def main():
    foundation = bytearray()
    for i in range(11):
        foundation.append(i)
    blocksize = 4

    wrong_size = b'\x00\x01\x02\x03\x05'
    pad_amt_too_big = b'\x00\x01\x02\x03\x04\x05\x03\x03'
    no_padding = b'\x00\x01\x02\x03'
    zero_block = pad(b'\x00\x01\x02\x03', blocksize) # Expect: b'\x00\x01\x02\x03\x00\x00\x00\x00'
    just_right = pad(b'\x00\x01\x02\x03\x04\x02', blocksize) # Expect: b'\x00\x01\x02\x03\x04\x02\x02\x02'



    tests = [wrong_size, pad_amt_too_big, no_padding, zero_block, just_right]
    print("BEGIN TEST\nBLOCKSIZE: {}\n".format(blocksize))
    for test in tests:
        try:
            print("TEST INPUT: {}".format(test))
            unpadded = unpad(test, blocksize)
            print("UNPADDING SUCCESSFUL: {}\n".format(unpadded))
        except Exception as e:
            print("UNPADDING FAILED: {}\n".format(str(e)))

if __name__ == '__main__':
    main()
        