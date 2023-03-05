import requests
import re

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

def main():
    ciphertext = eavesdrop()
    print("Testing ciphertext: {}".format(ciphertext))
    if(test_ciphertext(ciphertext)):
        print("Valid decryption!\n")
    else:
        print("Invalid decryption :(\n")
    invalid_ctext = "A" * 15
    print("Testing ciphertext: {}".format(invalid_ctext))
    if(test_ciphertext(invalid_ctext)):
        print("Valid decryption!\n")
    else:
        print("Invalid decryption :(\n")


if __name__ == '__main__':
    main()