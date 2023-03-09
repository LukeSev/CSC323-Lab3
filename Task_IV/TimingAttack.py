import requests
import re
import os
import crypto
import time
import random
import math

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
    
def process(t):
    # Used for calibrating Hypothesis Testing, waits t amount of seconds
    start = time.time()
    time.sleep(t+((random.random()-0.5) *t))
    return time.time()-start

def calc_ij(tau):
    best = (10000,10000, 0, 0)
    for p in range(0, 100, 1):
        FP = 0
        FN = 0
        i = (p/1000) * (1 + random.random())
        j = (p/1000) * (1 + random.random())

        for x in range(200):
            print("i: {}, j: {}".format(i,j))
            results = test_ij(i,j,tau)
            FP += results[0]
            FN += results[1]
        
        if(((FP) < best[0]) and ((FN) < best[1])):
            best = (FP, FN, i,j)
    return best 


def test_ij(i,j, tau):
    # Tests for false positives and false negatives by generating X and Y and seeing how many false positives you get
    N = 1000
    X = []
    Y1 = []
    Y2 = []
    for i in range(N):
        X.append(process(0.01))
        Y1.append(process(0.01))
        Y2.append(process(0.01 + tau))
    
    FN = 0
    FP = 0
    # First look for false positives between X and Y1
    if(BoxTest(i,j,X,Y1) != '0'):
        FP = 1
    if(BoxTest(i,j,X,Y2) == '0'):
        FN = 1
    return (FP, FN)

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


def populate_dataset(url, N, precision):
    # Measure N values for a given url that's being tested
    U = []
    for i in range(N):
        U.append(timeSubmit(url, precision)[0])
    return U

def filter(U, mode, precision, p=None, window=None, i=None, j=None):
    # Applies filter to a dataset to compute the process time
    # Modes include: percentile ('pl'), peak ('pk'), average range ('avg'), and percentile smoothing ('ps')
    match mode:
        case 'pl':
            return sorted(U)[int(p)*len(U)]
        case 'pk':
            # window = proportion of sample to be considered at once (i.e. 0.1 = 10% of values)
            windowsize = int(len(U)*window)
            U = sorted(U, key = lambda u:float(u))
            #print(U)
            min_diff = 10000000.0
            med = 0.0
            for i in range(0, len(U)-windowsize+1, 1):
                diff = U[i+windowsize-1] - U[i]
                if(diff < min_diff):
                    med = U[int(windowsize/2)+i]
                    min_diff = diff
            return med
        case 'avg':
            return
        case 'ps':
            return

def getNoise(url, precision, N):
    # Perform N repetitions of submitting a mac and find the min, max, and avg variation from the mean
    data = []
    min = 100000
    max = 0
    avg = 0
    for i in range(N):
        datapt = timeSubmit(url,precision)[0]
        data.append(datapt)
        avg += datapt
        if(datapt < min):
            min = datapt
        if(datapt > max):
            max = datapt
    avg = avg/N
    var = 0
    for i in range(N):
        var += abs(data[i] - avg)**2
    var = math.sqrt(var/N)
    return (min, max, avg, var)

def test_url(url, N, precision, mode, sensitivity, noise, window=None):
    for i in range(sensitivity):
        u = filter(populate_dataset(url, N, precision), mode, precision, window=window)
        if(u < (noise[1] + noise[2])/2):
            return 0
        print("success")
    return 1

def timingAttack():
    q = "easy"
    N = 10
    precision = 50
    sensitivity = 4

    url = base_url + q + mac_url_addon
    base_len = len(url)
    mac_len = 0
    while(mac_len < 40):
        # Find next char
        found = 0

        # Get noise to determine what threshold to shoot for
        noise = getNoise(url + "0"*(74-len(url)), precision, 250) # (min, max, avg, var)
        print(noise)

        for i in range(256):
            potential_url = url + hex(i)[2:]
            potential_url += "0" * (38-mac_len)

            results = test_url(potential_url, N, precision, 'pk', sensitivity, noise, window=0.1)

            if(results):
                mac_len += 2
                url = potential_url[:base_len+mac_len]
                found = 1
                break

        # for i in range(0,255,2):
        #     url1 = url + hex(i)[2:]
        #     url1 += "0" * (38-mac_len) # pad with 0's to get full mac length
        #     X = populate_dataset(url1, N, precision)
        #     url2 = url + hex(i+1)[2:]
        #     url2 += "0" * (38-mac_len) # pad with 0's to get full mac length
        #     Y = populate_dataset(url2, N, precision)

        #     ptX = filter(X, 'pk', precision, window=0.1)
        #     ptY = filter(Y, 'pk', precision, window=0.1)
        #     #print("New X,Y pair: {} || {}".format(ptX, ptY))

        #     threshold_multiplier = 1 + ((1+int(mac_len/2)) * sensitivity)
        #     if((max(ptX, ptY) > (min(ptX, ptY) + 0.01 + (0.001*threshold_multiplier)))):
        #         if(ptX > ptY):
        #             print("Found new byte in X dataset.")
        #             mac_len += 2
        #             url = url1[:base_len+mac_len]
        #             found = 1
        #             break
        #         elif(ptX < ptY):
        #             mac_len += 2
        #             url = url2[:base_len+mac_len]
        #             found = 1
        #             break    

        if(found == 0):
            print("Failed to find byte #{}".format(int(mac_len/2)))
            return
        print("New URL: {}".format(url))
    if(timeSubmit(url, precision)[1] == invalid_msg):
        print("Invalid signature")
    else:
        print(timeSubmit(url, precision)[1])
        found = 1
    return url


def simpleTimingAttack():
    q = "easy"
    N = 100
    precision = 50
    base_percentile = 0.5
    sensitivity = 0.25

    url = base_url + q + mac_url_addon
    base_len = len(url)
    mac_len = 0
    while(mac_len < 40):
        # Find next char
        found = 0
        for i in range(255):
            url1 = url + hex(i)[2:]
            url1 += "0" * (38-(mac_len*2)) # pad with 0's to get full mac length
            url2 = url + hex(i+1)[2:]
            url2 += "0" * (38-(mac_len*2)) # pad with 0's to get full mac length

            
            ptX = timeSubmit(url1, precision)[0]
            ptY = timeSubmit(url2, precision)[0]

            delay = 0.01*(1+mac_len)
            if(max(ptX,ptY) > (min(ptX, ptY) + delay)):
                    print("Found new byte")
                    print("X,Y pair: {} || {}".format(ptX, ptY))
                    mac_len += 1
                    if(ptX > ptY):
                        url = url1[:base_len+(mac_len*2)]
                    else:
                        url = url2[:base_len+(mac_len*2)]
                    found = 1
                    break

        if(found == 0):
            print("Failed to find byte #{}".format(mac_len+1))
            return
        print("New URL: {}".format(url))

    if(timeSubmit(url, precision)[1] == invalid_msg):
        print("Invalid signature")
    else:
        print(timeSubmit(url, precision)[1])
        found = 1

    return url

def test():
    url1 = base_url + "easy" + mac_url_addon + "ff" + 38*"0"
    url2 = base_url + "easy" + mac_url_addon + "9a" + 38*"0"

    print(timeSubmit(url1, 10))
    print(timeSubmit(url2, 10))


def main():
    url = timingAttack()
    #url = simpleTimingAttack()
    print(url)
    #test()



if __name__ == '__main__':
    main()