# cryptanalysistools.py
#
# Simple tools for analyzing classical ciphers.

import json

def get_count(ciphertext, blacklist=[], caselower=True):
    # get the count of characters in a ciphertext.
    # will ignore blacklist symbols
    # will convert all to lower case if set to true
    charbank = {}
    if(caselower):
        ciphertext = ciphertext.lower()
    
    for c in ciphertext:
        if(c not in blacklist):
            if(c not in charbank):
                charbank[c] = 1
            else:
                charbank[c] += 1

    return charbank

def get_freq(charbank, ciphertextlen):
    # normalize a dictionary of counts with a given length
    for c in charbank:
        charbank[c] = charbank[c]/ciphertextlen
    return charbank

def ngram_count(text, blacklist=[], n=2, caselower=True):
    # get the count of n-grams in the text
    if(caselower):
        text = text.lower()
    for blacklisted in blacklist:
        text = text.replace(blacklisted, "")
    print(f"cleaned up text = {text}")
    
    textlen = len(text)
    nfreq = {}
    for i in range(0, textlen-n+1):
        subtext = text[i:i+n]
        if(subtext not in nfreq):
            nfreq[subtext] = 1
        else:
            nfreq[subtext] += 1
    return nfreq

def ngram_freq(ngrambank):
    # get the frequency of n-grams in the text
    gramcount = len(ngrambank)
    nfreq = {}
    for f in ngrambank:
        nfreq[f] = ngrambank[f]/gramcount
    return nfreq

def ctlen(ciphertext, blacklist=[]):
    # counts the length of the ciphertext, excluding banned characters
    count = 0
    for c in ciphertext:
        if(c not in blacklist):
            count += 1
    return count

def connect_leads(d, r, depth=2):
    # matches up likely candidates for char from freq analysis
    
    # d is the frequency count of the ciphertext
    # r is the frequency reference of the main text
    # depth is the number n-greatest match to frequency
    def cmpfrq(e):
        return e[1]
    
    matches = {}
    # c:char, f:freq, rc:refchar, rf:reffreq
    d_items = d.items()
    r_items = r.items()
    for c, f in d_items:
        candidates = list()

        for rc, rf in r_items:
            # get the absolute freq difference for each ref character
            # smallest difference implies it's a candidate for decryption
            candidates.append((rc, abs(f-rf)))

        candidates.sort(key=cmpfrq)
        matches[c] = [can[0] for can in candidates[0:depth]]
    return matches

def egcd(a, b):
    # calculate the gcd such that r = gcd(a, b) and sa + tb = r
    a0 = a
    b0 = b
    t0 = 0
    t = 1
    s0 = 1
    s = 0
    q = a0//b0
    r = a0 - q*b0
    while r > 0:
        tmp = t0 - q*t
        t0 = t
        t =  tmp
        tmp = s0 - q*s
        s0 = s
        s = tmp
        a0 = b0
        b0 = r
        q = a0//b0
        r = a0 - q*b0
    r = b0
    return (r, s, t)


def load_json(path):
    # load a frequency dictionary from json
    file = open(path, "r")
    data = json.load(file)
    file.close()
    return data

def load_dictionary(path):
    # load a wordlist dictionary from file
    file = open(path, "r")
    wordlist = file.read().split()
    file.close()
    return wordlist

def write_json(d, path):
    # write a frequency dictionary to json
    file = open(path, "w")
    json.dump(d, file)
    file.close()

def disp_dict(d):
    # print out a dictionary
    for k in d:
        print(f"{k}:{d[k]}")

