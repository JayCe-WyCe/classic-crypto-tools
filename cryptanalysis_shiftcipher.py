# Shift ciphers are quite simple, and can be automated.

from cryptanalysistools import *

# grab the ciphertext
ciphertext = input(f"Enter your ciphertext here: ").lower()
ctextlen = len(ciphertext)

offset = ord('a')
key = 0
mod = 26

english = load_dictionary(".\\dictionary.txt")
blacklist = [" ", ",", "."]

# perform the shift
results = list()
for k in range(0, mod-10):
    ctext = list(ciphertext)
    validcount = 0
    wordcount = 0
    for i in range(0, ctextlen):
        c = ctext[i]
        if(c not in blacklist):
            ctext[i] = chr(((ord(c)-offset)+k)%mod + offset)
    result = "".join(ctext)
    
    # see how many valid words
    lonewords = result.split()
    for word in lonewords:
        wordcount += 1
        if(word in english):
            validcount += 1

    if(validcount/wordcount > 0.75):
        results.append((k, result))

print(results)

