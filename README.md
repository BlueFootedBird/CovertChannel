# UDP Size Modulation Covert Channel
This covert channel transmits UDP datagrams from a client written in python to a server written in python. We are in the process of rewriting the python client to a C client. We communite data via modulating the size of the data section of the UDP datagrams we send. 


# High Level Overview of How the Channel Works
**The client:**
1. Accepts user input
2. Converts each individual character of the user input into its ASCII decimal equivalent
2. Creates a key between values 0 and 15 for each character in the message
3. Encrypts each plaintext ASCII decimal value by adding the randomly generated key 
4. Generates the UDP datagram's "Data" field to be the length of the encrypted ASCII decimal value 
5. Inserts they key into the "Data" field 
6. Sends the crafted UDP datagram to the server

**The server:**
1. Recieves the UDP datagram from the client
2. Parses the data for the value of the key used to encrypt a given character
3. Subtracts the key's value from the length of the datagram's "Data" field
4. Prints out the plaintext ASCII character value 
