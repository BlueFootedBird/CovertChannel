#!/usr/bin/env python

import socket 
import sys
from random import random
from random import randint
from random import seed
import time
import timeout_decorator
from random import shuffle 
from pebble import concurrent
from concurrent.futures import TimeoutError


#Convert decimal character to a hexadecimal character
def decimalToHex(value):
    switch = randint(0,1) #Generate a number, zero or one

    if(value < 10):
        return str(value)
    if(value == 10):
        return "a"
    if(value == 11):
        return "b"
    if(value == 12):
        return "c"
    if(value == 13):
        return "d"
    if(value == 14):
        return "e"
    if(value == 15):
        if(switch == 0):
            return "f"
        if(switch == 1):
            return "."

#Generates 'random' ascii
def generateAscii():
    randomAsciiList = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',':',';','!','>','<','/','(',')','@','=']
    if(randint(1,10) < 7):
        return '.'
    else:
        return randomAsciiList[randint(0,len(randomAsciiList)-1)]

#Embeds the key/nonce into the a random byte 
#inside of the "Data" portion of our UDP datagram
def EmbedKey(message, nonce, count):
    #Break the string into a list
    tempList = list(message) 

    #This is a SECRET algorithm shared between the server and the client
    #calculate where the key is hidden inside the "Data" of the UDP datagram
    #to encrypt/decrypt characters 
    index =  (7 + int(((len(message))/5))) % len(message)

    #Returns an ascii string from an int of 0-15
    tempList[index] = decimalToHex(nonce)

    #This is a switch to sync the server with the client!
    if(count == 0):
        tempList[0] = '{'
        #print(str(tempList[0]))
    tempString = ""
    embededString = tempString.join(tempList) 
    return embededString

#Listen for a server responde for 10ish seconds
#If we do not hear beack from the server, retransmit 
#the data to the server
@concurrent.process(timeout=5)
def listenForServerAck():
    #If(we get a response from the server):
    #   //Stop re-transmission and continue sending the rest of the message
    #If(we don't get a response from the server):
    #   //Keep on re-transmitting until we hear back from the server
    datagrams = sock.recvfrom(1024)
    print("Recieved server ACK")
    return True

@timeout_decorator.timeout(2)
def getInput():
    return list(sys.stdin.read())

#Shuffles duplicate messages
def myshuffle(key, myindex, message):
    #Break the message into array of chars
    msg = list(message)          

    #Isolate the First byte of the message
    #We must preserve this byte as the first byte
    a = [msg[0]]

    #Grab substring from after the first byte,
    #and up to the index of the key (EXCLUDING the key)
    b = msg[1:myindex]
    shuffle(b)

    #Isolate the key
    c = [str(decimalToHex(key))]

    #Grab substring from AFTER the key,
    #and up the rest of the message
    d = msg[(myindex+1):]
    shuffle(d)

    #Combine the 1st byte + shuffled characters + key + shuffled characters
    return ''.join(a + b + c + d)

def getUserInput():
    #Makes sure the operator inputs the right arguments
    #Also includes a --help description of how to use this tool
    try:
        #Grab input from pipe to file
        inputs = getInput()
        inputs = inputs[:-1]
    except:
        print("\nError running the command. Too few arguments.\n\nSee for more details:\n\n     >  echo 'help' | ./client.py\n\n")
        quit()

    # HELPER FUNCTION
    # Aids the operators to use the client correctly
    helper = list("help")
    if(len(helper) == len(inputs)):
        checker = True
        for x in range(len(helper)):
            if(inputs[x] != helper[x]):
                #print(inputs[x], " ",helper[x])
                checker = False
        if(checker == True):
            print("\nThe syntax for the command is as follows:\n\n")
            print("     > [Message] | ./client.py\n\n")
            print("Examples:\n\n")
            print("     > ls -l | ./client.py\n")
            print("     > cat myfile.txt | ./client.py\n")
            print("     > echo ''ILoveMyDog'' | ./client.py\n")
            sys.exit()

    inputs = ''.join(inputs)
    inputs = ['&' if i=='\n' else i for i in inputs] #Replace '\n' with periods
    inputs = ['.' if i==' ' else i for i in inputs] #Replace spaces with periods

    return inputs



SERVER_PORT = 50000
SERVER_IP = "10.65.91.162"

CLIENT_PORT = 60000
CLIENT_IP = "10.65.91.162"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((CLIENT_IP, CLIENT_PORT))



#Get User Input and Filter Out Unreadable Characters
inputs = getUserInput()
inputs = ''.join(inputs)
inputs = ['&' if i=='\n' else i for i in inputs] #Replace '\n' with periods
inputs = ['.' if i==' ' else i for i in inputs]  #Replace spaces with periods


#Change our Message into an Ascii list
myAsciiList = list(inputs)
print("\n                  ", myAsciiList, "\n")

#Change our Ascii list into a Decimal list
myDecimalList = myAsciiList
for i in range(len(myAsciiList)):
    myDecimalList[i] = ord(myAsciiList[i])
print("                  ", myDecimalList, "\n")


# Send Our Message (Covertly) 
#
#
# Because we are using the "Length" field of our packets to
# communicate data, we can only send a single ascii character per UDP datagram
#
#
# We encrypt our message over the network via a homemade polyalphabetic cipher.
# Each character is "increased" or "shifted" by a random value (aka, a key/nonce)
# This key/nonce ranges from the values 0-15. Every character we send over the network
# will be individually offset between 0 to 15 decimal places. 
#
#
# The randomly chosen key is assigned as the one of the bytes in 
# the "Data" section of our UDP packets. Our server parses that specifc byte 
# in the "Data" section to retrieve the key of a trasnmitted character.
# The key is then subtracted from the total length of the UDP packet, leaving 
# behind the original plaintext. 
#
#
# Example: 
#
#----------------------------------------------------------
# ~Original Message~  |         |  ~Over the Wire~         |
# Plaintext           |   Key   |  Cipertext               | 
# -------------------------------------------------------- |
#    I          (73)  |    3    |    (76)          L       |
#    L          (76)  |    a    |    (86)          V       |
#    o         (111)  |    0    |   (111)          o       |
#    v         (118)  |    3    |   (121)          y       |
#    e         (101)  |    9    |   (110)          n       |
#    M          (77)  |    1    |    (78)          N       |
#    y         (121)  |    8    |   (129)          ?       |
#    D          (68)  |    5    |    (73)          I       |
#    o         (111)  |    f    |   (126)          ~       |
#    G         (103)  |    5    |   (108)          l       |
#-----------------------------------------------------------
#
# Plaintext:    "ILoveMyDog"
# Ciphertext:   "LVoynN?I~l"


#For each character in our message:
for x in range(len(myAsciiList)):
    received = False

    #Generate a key for spice/entropy
    #Adds a random hexadecimal value to the length
    key = randint(0,15)


    #Generate random ascii (fluff) to achieve proper message length. 
    #Encrypts the DATA length by adding extra chracters
    #from the value of our key
    fluff = ""
    for y in range((myDecimalList[x]) + key):  
        fluff += generateAscii() 

    # !!! GUARENTEED DELIVERY FOR UDP !!!
    #
    #
    #Initilaize setting up to hear a resposne from the server 
    #
    #
    #We are going to send our data to the server. If the server does not
    #anwser us within a couple of seconds, we will send the same data 
    #over and over until we hear back from the server
    #
    #This is a while-loop for re-transmitting UDP packets until they are recieved
    while (received != True):
        #Embeds a nonce into the message
        fluff = EmbedKey(fluff, key, x)
        
        #SHUFFLE any duplicate messages
        index =  (7 + int(((len(fluff))/5))) % len(fluff)
        shuffledMessage = myshuffle(key, index, fluff)
        shuffledMessage = bytes(shuffledMessage, 'utf-8')

        #Attempt to send our message to the server
        print("Datagram", x, "data:  %s \n" % shuffledMessage.decode('utf-8'))
        sock.sendto(shuffledMessage, (SERVER_IP, SERVER_PORT))

        try:
            print("Listening for ACK:")
            received = listenForServerAck().result()
        except TimeoutError as error:   
            print("function took longer than %d seconds" % error.args[1])
