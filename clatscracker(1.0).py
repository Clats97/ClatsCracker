import hashlib
import sys
import os
import time
import bcrypt
import itertools
import string
import threading
from concurrent.futures import ThreadPoolExecutor
from argon2 import PasswordHasher, Type

passwords_tried = 0
total_passwords = 0
found_password = None
threads_count = 1
progress_lock = threading.Lock()
found_lock = threading.Lock()

def print_header():
    title = r"""
   ██████╗██╗        █████╗ ████████╗███████╗
   ██╔════╝██║       ██╔══██╗╚══██╔══╝██╔════╝
   ██║     ██║       ███████║   ██║   ███████╗
   ██║     ██║       ██╔══██║   ██║   ╚════██║
   ██████╗ ███████╗  ██║  ██║   ██║   ███████║
   ╚═════╝ ╚══════╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝

        C       L      A       T       S
    """
    print("\033[1;31m" + title + "\033[0m")

    author = "🛡️ By Josh Clatney - Ethical Pentesting Enthusiast 🛡️"
    print("\033[1;36m" + author + "\033[0m")

    quote = """
    --------------------------------------------------------------------------------------------------------------------
    The best hash cracking tool available. Cracks 8 algorithms and supports dictionary based or automatic cracking.
    --------------------------------------------------------------------------------------------------------------------
    """
    print("\033[1;37m" + quote + "\033[0m")

def print_menu():
    print("\nMenu:")
    print("1.Crack Password")
    print("2.Exit")

def hash_password(password, hash_algorithm):
    password_bytes = password.encode('utf-8')
    if hash_algorithm == 'md5':
        return hashlib.md5(password_bytes).hexdigest()
    elif hash_algorithm == 'sha1':
        return hashlib.sha1(password_bytes).hexdigest()
    elif hash_algorithm == 'sha256':
        return hashlib.sha256(password_bytes).hexdigest()
    elif hash_algorithm == 'sha512':
        return hashlib.sha512(password_bytes).hexdigest()
    elif hash_algorithm == 'sha3_256':
        return hashlib.sha3_256(password_bytes).hexdigest()
    elif hash_algorithm == 'scrypt':
        return hashlib.scrypt(password_bytes, salt=b'', n=16384, r=8, p=1, dklen=64).hex()
    else:
        return None

def validate_hash_length(hash_algorithm, hash_value):
    expected_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128,
        'sha3_256': 64,
        'scrypt': 128
    }
    if hash_algorithm == 'bcrypt':
        return True
    if hash_algorithm == 'argon2id':
        return True
    expected_length = expected_lengths.get(hash_algorithm)
    if expected_length and len(hash_value) != expected_length:
        print(f"🚫 The provided hash does not match the expected length for {hash_algorithm}.")
        return False
    return True

def check_password(password, hash_to_decrypt, hash_algorithm):
    global passwords_tried, found_password
    with found_lock:
        if found_password is not None:
            return
    if hash_algorithm == 'bcrypt':
        try:
            if bcrypt.checkpw(password.encode('utf-8'), hash_to_decrypt.encode('utf-8')):
                with found_lock:
                    found_password = password
                return
        except Exception:
            pass
    elif hash_algorithm == 'argon2id':
        ph = PasswordHasher(type=Type.ID)
        try:
            ph.verify(hash_to_decrypt, password)
            with found_lock:
                found_password = password
            return
        except Exception:
            pass
    else:
        hashed_word = hash_password(password, hash_algorithm)
        if hashed_word == hash_to_decrypt:
            with found_lock:
                found_password = password
            return
    with progress_lock:
        passwords_tried += 1
        progress = (passwords_tried / total_passwords) * 100
        print(f"\rProgress: {progress:.2f}%", end='', flush=True)

def chunk_list(lst, n):
    k, m = divmod(len(lst), n)
    return (lst[i*k+min(i,m):(i+1)*k+min(i+1,m)] for i in range(n))

def dictionary_crack_worker(passwords_chunk, hash_to_decrypt, hash_algorithm):
    for pwd in passwords_chunk:
        with found_lock:
            if found_password is not None:
                return
        check_password(pwd, hash_to_decrypt, hash_algorithm)
        with found_lock:
            if found_password is not None:
                return

def concurrent_hash_cracker(dictionary, hash_to_decrypt, hash_algorithm):
    global total_passwords, passwords_tried, found_password
    found_password = None
    passwords_tried = 0
    all_passwords = []

    for dictionary_path in dictionary:
        if os.path.exists(dictionary_path):
            with open(dictionary_path, 'r', encoding='utf-8') as f:
                for line in f:
                    p = line.strip()
                    if p:
                        all_passwords.append(p)
        else:
            print(f"\n🔍 Dictionary file '{dictionary_path}' not found.\n")

    all_passwords = list(set(all_passwords))
    total_passwords = len(all_passwords)

    if total_passwords == 0:
        print("Sorry, no password was found in the dictionary.")
        return None

    chunks = list(chunk_list(all_passwords, threads_count))

    with ThreadPoolExecutor(max_workers=threads_count) as executor:
        futures = [executor.submit(dictionary_crack_worker, chunk, hash_to_decrypt, hash_algorithm) for chunk in chunks]
        for future in futures:
            future.result()

    return found_password

def brute_force_crack(hash_to_decrypt, hash_algorithm, charset, length):
    global found_password, total_passwords, passwords_tried
    found_password = None
    passwords_tried = 0
    attempts = [''.join(p) for p in itertools.product(charset, repeat=length)]
    total_passwords = len(attempts)

    chunks = list(chunk_list(attempts, threads_count))

    def brute_force_worker(pwd_chunk, htd, algo):
        for pwd in pwd_chunk:
            with found_lock:
                if found_password is not None:
                    return
            check_password(pwd, htd, algo)
            with found_lock:
                if found_password is not None:
                    return

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=threads_count) as executor:
        futures = [executor.submit(brute_force_worker, chunk, hash_to_decrypt, hash_algorithm) for chunk in chunks]
        for future in futures:
            future.result()

    if found_password:
        print(f"\n\n\033[1;32m🔓 Found Password: {found_password}\033[0m\n")
        print(f"⏱️ Amount of time it took to crack the password: {time.time() - start_time:.2f} seconds")
        return True
    else:
        print("\n\033[1;31m🛑 Sorry, no password was found.\033[0m\n")
        print(f"⏱️ Amount of time it took: {time.time() - start_time:.2f} seconds")
        return False

def choose_resource_usage():
    global threads_count
    print("\nChoose the resource usage level (number of threads):")
    print("1. Low (1 thread)")
    print("2. Medium (4 threads)")
    print("3. High (8 threads)")
    print("4. Custom")
    choice = input("\nEnter your choice: ").strip()

    if choice == '1':
        threads_count = 1
    elif choice == '2':
        threads_count = 4
    elif choice == '3':
        threads_count = 8
    elif choice == '4':
        custom_threads = input("Enter the number of threads (1-1000): ").strip()
        if custom_threads.isdigit():
            custom_threads = int(custom_threads)
            if 1 <= custom_threads <= 1000:
                threads_count = custom_threads
            else:
                print("⛔ Invalid number. Defaulting to Medium usage.")
                threads_count = 4
        else:
            print("⛔ Invalid input. Defaulting to Medium usage.")
            threads_count = 4
    else:
        print("⛔ Invalid choice. Defaulting to Medium usage.")
        threads_count = 4

def main():
    attention_message = "⚠️ This tool is for ethical use or pentesting only. Do not misuse it or break the law with it. ⚠️"
    print("\033[1;33m" + attention_message + "\033[0m")

    print_header()
    choose_resource_usage()

    while True:
        print_menu()
        choice = input("\nEnter your choice: ").strip()

        if choice == '1':
            print("\n🔐  Password Cracker  🔐\n")
            hash_algorithm = input("Which hashing algorithm do you want to crack? (Options: md5, sha1, sha256, sha3_256, sha512, bcrypt, argon2id, scrypt): ").lower()

            if hash_algorithm not in ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'sha3_256', 'argon2id', 'scrypt']:
                print("🚫 Invalid hash algorithm.")
                continue

            hash_to_decrypt = input("Enter the unsalted hash value: ").strip()
            if not hash_to_decrypt:
                print("🚫 No hash provided.")
                continue

            if hash_algorithm == 'bcrypt':
                if not hash_to_decrypt.startswith("$2"):
                    print("🚫 This does not look like a bcrypt hash. Bcrypt hashes typically start with $2a$, $2b$, or $2y$.")
                    continue
            else:
                if not validate_hash_length(hash_algorithm, hash_to_decrypt):
                    continue

            print("\nChoose your cracking method:")
            print("1. Dictionary-Based Cracking")
            print("2. Automatic Brute Force Cracking")
            method_choice = input("\nEnter your choice: ").strip()

            if method_choice == '1':
                num_dictionary = input("Enter how many dictionaries you want to use: ").strip()
                if not num_dictionary.isdigit() or int(num_dictionary) <= 0:
                    print("❌ Invalid number of dictionaries.")
                    continue
                num_dictionary = int(num_dictionary)

                dictionary = []
                for i in range(num_dictionary):
                    dictionary_path = input(f"Enter path for the dictionary file {i+1}: ").strip()
                    dictionary.append(dictionary_path)

                start_time = time.time()
                cracked_password = concurrent_hash_cracker(dictionary, hash_to_decrypt, hash_algorithm)
                end_time = time.time()

                if cracked_password:
                    print(f"\n\n\033[1;32m🔓 Password Successfully Cracked!: {cracked_password}\033[0m\n")
                else:
                    print("\n\033[1;31m🛑 Cracking uncussessful. Password is not in the dictionary file.\033[0m\n")

                print(f"⏱️ Amount of time to crack the password: {end_time - start_time:.2f} seconds")

            elif method_choice == '2':
                if hash_algorithm not in ['md5', 'sha1', 'sha256', 'sha3_256']:
                    print("🚫 Automatic brute force only supports md5, sha1, sha256, or sha3_256.")
                    continue
                charset = string.ascii_letters + string.digits
                length_input = input("Enter password length: ").strip()
                if not length_input.isdigit() or int(length_input) <= 0:
                    print("❌ Invalid length.")
                    continue
                length = int(length_input)
                brute_force_crack(hash_to_decrypt, hash_algorithm, charset, length)
            else:
                print("\n⛔ Invalid choice. Please select a valid option.")

        elif choice == '2':
            print("\n🚪 Exiting...")
            sys.exit()
        else:
            print("\n⛔ Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()