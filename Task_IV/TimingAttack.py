import requests
import re
import os
import crypto
import time

BLOCKSIZE = 16

base_url = "http://127.0.0.1:8080/?q="
mac_url_addon = "&mac="
invalid_msg = 'Invalid signature. '

def BoxTest(i, j, X, Y):
    # Performs box test, as described by Crosby et al. in Opportunities and Limits of Remote Timing Attacks
    # i and j are two quantiles, X and Y are two random subsets of N total measurements
    # X and Y are both lists of response times stored as floats
    # To test if significant difference, quantiles i-->j for both data sets are calculated
    # If there's no overlap between the sets and X < Y for all x and y, then there's a significant difference in response times
    # note: Size of X and Y must be equal and be divisible by 100
    if((len(X) != len(Y)) or (len(X) % 100 != 0)):
        raise Exception("Invalid dataset(s)")
    
    N = len(X)
    # Sort and determine quantiles of x and y
    X_sorted = sorted(X, key = lambda x:float(x))
    x1 = X_sorted[int(N*i)]
    x2 = X_sorted[int(N*j)]

    Y_sorted = sorted(Y, key = lambda y:float(y))
    y1 = Y_sorted[int(N*i)]
    y2 = Y_sorted[int(N*j)]
    
    if(x2 < y1):
        print("Significant difference found with Y having higher process time")
        return 'y'
    elif(y2 < x1):
        print("Significant difference found with X having higher process time")
        return 'x'
    else:
        #print("No significant difference found")
        return '0'
    


def get_HTML_text(text):
    lines = re.sub('<.+?>', '', text).split("\n")
    output = []
    for line in lines:
        if(len(line.lstrip()) > 0):
            output.append(line.lstrip())
    return output

def timeSubmit(url, precision):
    # Submits a URL and times how long it takes to get response
    start = time.time()
    r = requests.get(url)
    finish = time.time()
    return (round(finish-start, precision), get_HTML_text(r.text)[0])

def get_baseline(precision):
    # Submits a few test URLs to the server to set a baseline for waiting time
    q1 = "testo"
    mac1 = "5F4D5F"
    url1 = base_url + q1 + mac_url_addon + mac1

    q2 = "hello"
    mac2 = "89032D"
    url2 = base_url + q2 + mac_url_addon + mac2

    t1 = timeSubmit(url1, precision)
    t2 = timeSubmit(url2, precision)

    if(max(t1[0],t2[0]) > (10*min(t1[0],t2[0]))):
        # If significant difference in the two times, then one is a correct guess, otherwise set a baseline
        print("Found a valid byte")
        print((t1,t2))
        valid_byte = max(t1[0], t2[0])
    return min(t1[0], t2[0])

def populate_dataset(url, N, precision):
    # Measure N values for a given url that's being tested
    U = []
    for i in range(N):
        U.append(timeSubmit(url, precision)[0])
    return U


def timingAttack():
    # First set a baseline for the time an invalid mac should take
    q = "easy"
    N = 100
    precision = 10
    percentile = 0.15
    sensitivity = 0.1

    url = base_url + q + mac_url_addon
    base_len = len(url)
    found = 0
    while(found == 0):
        # Find next char
        for i in range(0,255,2):
            url1 = url + hex(i)[2:]
            url1 += "0" * (40-(len(url1)-base_len)) # pad with 0's to get full mac length
            X = populate_dataset(url1, N, precision)
            url2 = url + hex(i+1)[2:]
            url2 += "0" * (40-(len(url2)-base_len)) # pad with 0's to get full mac length
            Y = populate_dataset(url2, N, precision)
            result = BoxTest(percentile-sensitivity, percentile+sensitivity, X, Y)
            if(result == 'x'):
                url = url1
                break
            elif(result == 'y'):
                url = url2
                break
        print(url)
        if(timeSubmit(url, precision)[1] == invalid_msg):
            print("Invalid signature")
        else:
            print(timeSubmit(url, precision)[1])
            found = 1
    return url



def main():
    url = timingAttack()
    print(url)

if __name__ == '__main__':
    main()