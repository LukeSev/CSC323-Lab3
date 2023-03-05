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

def main():
    ciphertext = eavesdrop()
    print(ciphertext)

if __name__ == '__main__':
    main()