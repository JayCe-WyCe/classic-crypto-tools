# Analyze affine ciphers.
import numpy as np
import sympy as sp
from cryptanalysistools import *

def aff_decrypt(ciphertext, key, banned=[]):
    # ax + b = y
    # x = ainv*(y - b)
    a, b = key
    # recall c1*x = 1 - c2*26 => c1*x = 1 since 26 mod 26 = 0
    ainv = int(egcd(a, 26)[1])
    ctext = list(ciphertext)
    ptext = []
    offset = ord('a')

    for c in ctext:
        if(c not in banned):
            cnum = ord(c)-offset
            c = chr((ainv*(cnum - b))%26+offset)
        ptext.append(c)

    plaintext = "".join([p for p in ptext])

    return plaintext
    

# grab the ciphertext
ciphertext = input(f"Enter your ciphertext here: ").lower()
blacklist = [" ", ",", ".", "-", "'", "\""]
ctextlen = ctlen(ciphertext, blacklist)

count_table = get_count(ciphertext, blacklist)
freq_table = get_freq(count_table, ctextlen)

ref_table = load_json("freqreference.json")

print(f"freqtable =\n{freq_table}\n")
print(f"\nreftable =\n{ref_table}\n")

match_table = connect_leads(freq_table, ref_table)

print(f"matches = {match_table}")

matches = match_table.items()
offset = ord('a')

english = load_dictionary(".\\dictionary.txt")
dec_results = []

# look at pairs, like (i, f) and postulate enc(a) = i, enc(u) = f
for i, c1 in matches:
    for j, c2 in matches:
        if(i==j):
            # trim the run-time
            continue      
        Y = np.array([ord(i)-offset, ord(j)-offset])
        for c1e in c1:
            for c2e in c2:
                M = np.matrix(f"{ord(c1e)-offset} {1};"\
                              f"{ord(c2e)-offset} {1}")

                determinant = int(round(np.linalg.det(M)))
                if(determinant):
                    gcdtup = egcd(determinant, 26)
                    if(gcdtup[0]==1):
                        wordcount = 0
                        validcount = 0
                        Minv = sp.Matrix(M).inv_mod(26)
                        C = Minv*Y
                        a = (C[0][0]+C[0][1])%26
                        b = (C[1][0]+C[1][1])%26
                        enckey = (a, b)

                        ptext_candidate = aff_decrypt(ciphertext, enckey, blacklist)
                        
                        lonewords = ptext_candidate.split()
                        for word in lonewords:
                            wordcount += 1
                            if(word in english):
                                validcount +=1

                        if(validcount/wordcount > 0.5):
                            dec_results.append((enckey, ptext_candidate))
                    

                        
print(f"Done.\n")
for i in range(0, 10):
    print(dec_results[i])

    
    
        
