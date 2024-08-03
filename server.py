#!/usr/bin/env python
import socket
from random import random
from random import randint
import hashlib
import string
from time import sleep



#This makes ascii that mimics regular UDP traffic
def makeAscii():
    randomAsciiList = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',':',';','!','>','<','/','(',')','@','=']
    #Generate a character from "randomAsciiList"
    if(randint(1,10) < 7):
        return '.'
    else:
        return randomAsciiList[randint(0,len(randomAsciiList)-1)]

#Take in hexadecimal values and spit out their int values
def hexToDecimal(value):
    if(value == 'a'):
        return 10
    if(value == 'b'):
        return 11
    if(value == 'c'):
        return 12
    if(value == 'd'):
        return 13
    if(value == 'e'):
        return 14
    if(value == 'f' ):
        return 15
    if(value == '.'):
        return 15
    else:
        return value

#Returns a hash of a string
def getHash(message):
    listOfChars = list(message)
    listOfChars.sort()
    sortedBytes = bytes(''.join(listOfChars),"utf-8")
    return str(hashlib.sha256(sortedBytes).hexdigest())

#Checks to see if a UDP Datagram has
#already been logged by the server. 
#This prevents out-of-order delivery
def ID_Exists(DataID, DataIDs):
    for x in range(len(DataIDs)): #List of all the IDS
        if(DataID == DataIDs[x]):
            print("Duplicate ID recieved. Dropping: ", DataID,"\n")
            return True

    #print("Server accepts this packet: Adding ", DataID, "To the server")      
    return False



#This variable, server_count, is a sequential time tracker for our algoithem used to determine where the key is
server_count = 0
DatagramIDs = []
DatagramID = [] 
drop_count = 0

SERVER_PORT = 50000
#SERVER_IP = "10.65.91.138"
SERVER_IP = "10.65.91.162"

CLIENT_PORT = 60000
CLIENT_IP = "10.65.91.162"

while True:

    #Socket Stuff
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.bind((SERVER_IP, SERVER_PORT))

    #Listen and grab the UDP plaintextChar
    udpDatagram, addr = sock.recvfrom(1024)
    
    #Decode the UDP Datagram bytes and write it to a string
    message = udpDatagram.decode('utf-8')

    #Break the string up into parsable characters
    chunks = list(message)

    #Sync our counter with the client when the client sends the server another message
    #WARNING:
    #  If we do not resync our counter with the client,
    #  our server will break because we will not be able
    #  to retrieve the key from the DATA section. Without the key, 
    #  the server cannot decrypt messages. 
    #
    #  When the client sends a new message, the client will
    #  send the first byte as a RESET chracter we denote as "{"
    #  Therefore, if the client sends a message with the first
    #  byte as a "{", we must reset our datagram counter to zero
    
    #
    # TODO We can change this if we want*
    switch = chunks[0]
    if(switch == '{'): 
        server_count = 0
        DatagramIDs.clear()

    #Parse the UDP Datagram at our INDEX for the KEY value
    #  The server and the client have a shared, secret algorithm to determine
    #  the index of the key. The server parses the UDP datagram's "DATA" section at 
    #  our calculated index to retrieve the key. 
    index =  (7 + int(((len(message))/5))) % len(message)
    key = int((hexToDecimal(chunks[index])))
    #print("Server count: ",server_count)
    #print("Server index: ",index)
    #print("Server key: ",key)

    #Create a unique ID for a UDP Datagram
    #  Background:
    #    We have re-transmission functionality for UDP. But 
    #    what happens if the client's second message arrives faster than
    #    the first? The server will break. How we do we prevent the 
    #    server from accepting duplicate messages?
    #  
    #  Answer:
    #     To ensure correct-order delivery, we must generate
    #     unique datagram IDs for every distinct datagram the
    #     server recieves. 
    #     
    #     These unique IDs are composed of three parts: Datagram Length, Index of the Key, 
    #     and the Value of the Key. We believe these three values are enough to distinguish
    #     between duplicate packets. 

    #Create a hash of the message
    DatagramID = str(getHash(message))
    #Check to see if this is a duplicate packet or not
    if(ID_Exists(str(DatagramID), DatagramIDs) == False): 
        drop_count = 0
        DatagramIDs.append(DatagramID)
        #plaintextChar retrieved from the the UDP datagram "DATA" field
        #Decypts the ciphertext by subtracting the key from the length of our DATA section
        plaintextChar = len(udpDatagram) - key

        #Print Ascii characters in "Data" section for value randomization
        MESSAGE = ""
        for x in range(randint(100,150)):
            MESSAGE += makeAscii()
        MESSAGE = bytes(MESSAGE,"utf-8")

        #There are two print statements here because of the formatting
        print("Plaintext: ", chr(plaintextChar), " ", (plaintextChar), "     Ciphertext: ", chr(len(udpDatagram)), " ", (plaintextChar+key), "   Index: ", index,"\n")
        print("Sending ACK")
        sock.sendto(MESSAGE, (CLIENT_IP, CLIENT_PORT))

        #KEEP THIS IN FFS
        #DO NOT ACCIDENTALLY DELETE THIS
        server_count = server_count +1
    
    else: #PREVENTS OUT OF ORDER DELIVERY 
       drop_count += 1
       if(drop_count > 2):
            print("\nResending ACK to Client\n")
            sleep(0.5)
            print("Sending ACK")
            sock.sendto(MESSAGE, (CLIENT_IP, CLIENT_PORT))

