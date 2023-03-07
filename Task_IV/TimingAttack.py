import requests
import re
import os
import crypto
import time

BLOCKSIZE = 16

base_url = "http://127.0.0.1:8080/?q="
mac_url_addon = "&mac="

def timeSubmit(url, precision):
    # Submits a URL and times how long it takes to get response
    start = time.time()
    requests.get(url)
    finish = time.time()
    return round(finish-start, precision)

def timingAttack():
    precision = 10

    # First set a baseline for the time an invalid mac should take
    q1 = "testo"
    mac1 = "5F4D5F"
    url1 = base_url + q1 + mac_url_addon + mac1

    q2 = "hello"
    mac2 = "89032D"
    url2 = base_url + q2 + mac_url_addon + mac2

    t1 = timeSubmit(url1, precision)
    t2 = timeSubmit(url2, precision)

    if(abs(t1-t2) > (t1/100)):
        # If significant difference in the two times, then one is a correct guess, otherwise set a baseline
        print("Found a valid byte")
        valid_byte = max(t1, t2)
    baseline = min(t1, t2)

    print(baseline)
    print(valid_byte)

def main():
    timingAttack()

if __name__ == '__main__':
    main()