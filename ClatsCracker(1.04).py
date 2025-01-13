import hashlib
import sys
import os
import time
import bcrypt
import itertools
import string
import threading
import signal
import zlib
from concurrent.futures import ThreadPoolExecutor, Future
from argon2 import PasswordHasher, Type
import psutil
import mmap
from typing import List, Optional

CPU_USAGE_THRESHOLD = 90.0
LOG_FILE = "cracking.log"

class CrackerState:
    """
    Holds shared state for the cracking operations, minimizing the use of global variables.
    """
    def __init__(self) -> None:
        self.passwords_tried = 0
        self.total_passwords = 0
        self.found_password: Optional[str] = None
        self.threads_count = 1
        self.start_time: Optional[float] = None
        self.abort_requested = False

        self.progress_lock = threading.Lock()
        self.found_lock = threading.Lock()

def write_log(message: str) -> None:
    """
    Append a log entry to the specified LOG_FILE.
    Ignores exceptions to avoid interfering with main cracking loop.
    """
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{time.ctime()} - {message}\n")
    except Exception:
        pass

def signal_handler(sig, frame, state: CrackerState) -> None:
    """
    Graceful interruption handler for SIGINT (Ctrl + C).
    """
    state.abort_requested = True
    print("\n\nCaught interruption signal. Attempting to stop gracefully...")

def register_signal_handler(state: CrackerState) -> None:
    """
    Registers the signal handler with access to the shared CrackerState.
    """
    def handler(sig, frame):
        signal_handler(sig, frame, state)
    signal.signal(signal.SIGINT, handler)

hash_lengths = {
    'crc32': 8,
    'md4': 32,
    'md5': 32,
    'ripemd160': 40,
    'sha1': 40,
    'sha1_v2': 40,
    'sha224': 56,
    'sha256': 64,
    'sha3_224': 56,
    'sha3_256': 64,
    'sha3_384': 96,
    'sha3_512': 128,
    'sha512': 128,
    'blake2_224': 56
}

def print_header() -> None:
    """
    Prints a stylized header for the program.
    """
    title_art = r"""
   ██████╗██╗        █████╗ ████████╗███████╗
   ██╔════╝██║       ██╔══██╗╚══██╔══╝██╔════╝
   ██║     ██║       ███████║   ██║   ███████╗
   ██║     ██║       ██╔══██║   ██║   ╚════██║
   ██████╗ ███████╗  ██║  ██║   ██║   ███████║
   ╚═════╝ ╚══════╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝
"""
    title_version = "        C       L      A       T       S       C      R       A       C       K       E       R   (Version 1.05)"
    author = "🛡️ By Josh Clatney - Ethical Pentesting Enthusiast 🛡️"
    quote = """
    --------------------------------------------------------------------------------------------------------------------
    A top-tier hash cracking tool that supports numerous algorithms and has unique capabilities and functionality. 
    --------------------------------------------------------------------------------------------------------------------
    """

    print("\033[1;31m" + title_art + "\033[0m")
    print("\033[1;34m" + title_version + "\033[0m")
    print("\033[1;37m" + author + "\033[0m")
    print("\033[1;37m" + quote + "\033[0m")

def print_menu() -> None:
    """
    Displays the main menu options.
    """
    print("\nMenu:")
    print("1.Crack Password")
    print("2.Exit")

def guess_hash_algorithm(hash_value: str) -> Optional[List[str]]:
    """
    Attempt to guess the hash algorithm(s) based on length and format.
    Returns a list of possible candidates or None if undetectable.
    """
    if hash_value.startswith("$2"):
        return ['bcrypt']
    if hash_value.startswith("$argon2id$"):
        return ['argon2id']

    length = len(hash_value)
    candidates = []
    for algo, algo_len in hash_lengths.items():
        if length == algo_len:
            candidates.append(algo)

    # Possible scrypt detection: 128 hex characters
    if length == 128 and all(c in '0123456789abcdef' for c in hash_value.lower()):
        candidates.append('scrypt')

    candidates = list(set(candidates))
    return candidates if candidates else None

def hash_password(password: str, hash_algorithm: str) -> Optional[str]:
    """
    Hash a given password string using the specified algorithm 
    and return its hex digest or None if unsupported.
    """
    password_bytes = password.encode('utf-8')

    if hash_algorithm == 'crc32':
        return format(zlib.crc32(password_bytes) & 0xffffffff, '08x')
    elif hash_algorithm == 'md4':
        return hashlib.new('md4', password_bytes).hexdigest()
    elif hash_algorithm == 'md5':
        return hashlib.md5(password_bytes).hexdigest()
    elif hash_algorithm == 'ripemd160':
        return hashlib.new('ripemd160', password_bytes).hexdigest()
    elif hash_algorithm == 'blake2_224':
        return hashlib.blake2b(password_bytes, digest_size=28).hexdigest()
    elif hash_algorithm == 'sha224':
        return hashlib.sha224(password_bytes).hexdigest()
    elif hash_algorithm == 'sha3_224':
        return hashlib.sha3_224(password_bytes).hexdigest()
    elif hash_algorithm == 'sha3_256':
        return hashlib.sha3_256(password_bytes).hexdigest()
    elif hash_algorithm == 'sha3_384':
        return hashlib.sha3_384(password_bytes).hexdigest()
    elif hash_algorithm == 'sha3_512':
        return hashlib.sha3_512(password_bytes).hexdigest()
    elif hash_algorithm == 'sha1':
        return hashlib.sha1(password_bytes).hexdigest()
    elif hash_algorithm == 'sha1_v2':
        first_pass = hashlib.sha1(password_bytes).digest()
        return hashlib.sha1(first_pass).hexdigest()
    elif hash_algorithm == 'sha256':
        return hashlib.sha256(password_bytes).hexdigest()
    elif hash_algorithm == 'sha512':
        return hashlib.sha512(password_bytes).hexdigest()
    elif hash_algorithm == 'scrypt':
        return hashlib.scrypt(password_bytes, salt=b'', n=16384, r=8, p=1, dklen=64).hex()

    return None

def validate_hash_length(hash_algorithm: str, hash_value: str) -> bool:
    """
    Validate that the provided hash string matches the expected length 
    for the specified algorithm, ignoring variable-length algorithms.
    """
    if hash_algorithm in ['bcrypt', 'argon2id', 'scrypt']:
        return True
    expected_length = hash_lengths.get(hash_algorithm)
    if expected_length and len(hash_value) != expected_length:
        print(f"🚫 The provided hash does not match the expected length for {hash_algorithm}.")
        return False
    return True

def print_stats(state: CrackerState) -> None:
    """
    Print attempts per second and estimated time remaining.
    """
    if state.start_time is None:
        return
    elapsed = time.time() - state.start_time
    if elapsed > 0 and state.passwords_tried > 0:
        aps = state.passwords_tried / elapsed
        remaining = state.total_passwords - state.passwords_tried
        eta = remaining / aps if aps > 0 else 99999
        print(f" APS: {aps:.2f}/s ETA: {eta:.1f}s", end='', flush=True)

def throttle_cpu_usage() -> None:
    """
    Throttle execution if CPU usage exceeds CPU_USAGE_THRESHOLD.
    """
    cpu_usage = psutil.cpu_percent(interval=0.0)
    if cpu_usage > CPU_USAGE_THRESHOLD:
        time.sleep(0.5)

def check_password(password: str, hash_to_decrypt: str, hash_algorithm: str, state: CrackerState) -> None:
    """
    Check if a given password matches the target hash using the specified algorithm.
    If a match is found, store it in state.found_password.
    """
    with state.found_lock:
        if state.found_password is not None or state.abort_requested:
            return

    if hash_algorithm == 'bcrypt':
        try:
            if bcrypt.checkpw(password.encode('utf-8'), hash_to_decrypt.encode('utf-8')):
                with state.found_lock:
                    state.found_password = password
            return
        except Exception:
            return
    elif hash_algorithm == 'argon2id':
        ph = PasswordHasher(type=Type.ID)
        try:
            ph.verify(hash_to_decrypt, password)
            with state.found_lock:
                state.found_password = password
            return
        except Exception:
            return
    else:
        hashed_word = hash_password(password, hash_algorithm)
        if hashed_word == hash_to_decrypt:
            with state.found_lock:
                state.found_password = password

def get_line_count(file_path: str) -> int:
    """
    Count the number of lines in a file. Returns 0 if file not found or empty.
    """
    count = 0
    try:
        with open(file_path, 'rb') as f:
            for _ in f:
                count += 1
    except Exception:
        return 0
    return count

def dictionary_crack_chunk(
    lines_chunk: List[str],
    hash_to_decrypt: str,
    hash_algorithm: str,
    progress_interval: int,
    state: CrackerState
) -> None:
    """
    Sub-task for dictionary-based cracking of a chunk of lines.
    """
    local_counter = 0

    for pwd in lines_chunk:
        if state.abort_requested or state.found_password is not None:
            return
        check_password(pwd, hash_to_decrypt, hash_algorithm, state)
        local_counter += 1

        if local_counter >= progress_interval:
            with state.progress_lock:
                state.passwords_tried += local_counter
                local_counter = 0
                if not state.abort_requested and state.found_password is None and state.total_passwords > 0:
                    progress = (state.passwords_tried / state.total_passwords) * 100
                    print(f"\rProgress: {progress:.2f}%", end='', flush=True)
                    print_stats(state)
            throttle_cpu_usage()
            if state.abort_requested or state.found_password is not None:
                return

    if local_counter > 0:
        with state.progress_lock:
            state.passwords_tried += local_counter
            if not state.abort_requested and state.found_password is None and state.total_passwords > 0:
                progress = (state.passwords_tried / state.total_passwords) * 100
                print(f"\rProgress: {progress:.2f}%", end='', flush=True)
                print_stats(state)
        throttle_cpu_usage()

def lines_in_chunks(file_path: str, chunk_size: int = 100000) -> List[str]:
    """
    Generator that yields chunks of lines from a file using memory mapping.
    """
    try:
        with open(file_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                batch = []
                while True:
                    line = mm.readline()
                    if not line:
                        if batch:
                            yield batch
                        break
                    line_decoded = line.decode('utf-8', errors='replace').rstrip('\n')
                    batch.append(line_decoded)
                    if len(batch) >= chunk_size:
                        yield batch
                        batch = []
    except Exception:
        return

def dictionary_crack_worker(
    dictionary_path: str,
    hash_to_decrypt: str,
    hash_algorithm: str,
    state: CrackerState,
    progress_interval: int = 5_000_000
) -> None:
    """
    Primary worker function for cracking a hash using a single dictionary file.
    """
    if not os.path.exists(dictionary_path):
        print(f"\n🔍 Dictionary file '{dictionary_path}' not found.\n")
        return

    line_count = get_line_count(dictionary_path)
    if line_count == 0:
        return

    local_threads = state.threads_count if state.threads_count > 1 else 1

    with ThreadPoolExecutor(max_workers=local_threads) as executor:
        futures: List[Future] = []
        for chunk in lines_in_chunks(dictionary_path):
            if state.abort_requested or state.found_password is not None:
                break
            futures.append(
                executor.submit(
                    dictionary_crack_chunk,
                    chunk,
                    hash_to_decrypt,
                    hash_algorithm,
                    progress_interval,
                    state
                )
            )

        while True:
            if state.found_password is not None or state.abort_requested:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            if all(f.done() for f in futures):
                break
            time.sleep(0.01)

def concurrent_hash_cracker(
    dictionaries: List[str],
    hash_to_decrypt: str,
    hash_algorithm: str,
    state: CrackerState
) -> Optional[str]:
    """
    Orchestrates dictionary-based cracking using multiple dictionaries concurrently.
    Returns the found password or None if not found / aborted.
    """
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    write_log(f"Starting dictionary cracking. Hash: {hash_to_decrypt}, Algo: {hash_algorithm}, Dicts: {dictionaries}")

    state.start_time = time.time()
    state.total_passwords = 0

    for dictionary_path in dictionaries:
        if os.path.exists(dictionary_path):
            state.total_passwords += get_line_count(dictionary_path)

    if state.total_passwords == 0:
        print("Sorry, no password was found in the dictionary (no valid lines).")
        write_log("No passwords found in dictionary files.")
        return None

    with ThreadPoolExecutor(max_workers=min(state.threads_count, len(dictionaries))) as executor:
        futures: List[Future] = []
        for dictionary_path in dictionaries:
            if os.path.exists(dictionary_path):
                futures.append(
                    executor.submit(
                        dictionary_crack_worker,
                        dictionary_path,
                        hash_to_decrypt,
                        hash_algorithm,
                        state
                    )
                )

        while True:
            if state.found_password is not None:
                state.abort_requested = True
                executor.shutdown(wait=False, cancel_futures=True)
                print(f"\n\n\033[1;32m🔓 Password Successfully Cracked!: {state.found_password}\033[0m")
                write_log(f"Password found: {state.found_password}")
                input("Press Enter to continue...")
                break
            if all(f.done() for f in futures):
                break
            time.sleep(0.01)

        for future in futures:
            future.result()  # Raise any exceptions

    if not state.found_password and not state.abort_requested:
        print("\n\033[1;31m🛑 Cracking unsuccessful. Password not found.\033[0m\n")
        write_log("Cracking completed, password not found.")

    return state.found_password

def generate_passwords(cset: str, plen: int, chunk_size: int = 1_000_000):
    """
    Generator that yields batches (chunks) of password permutations 
    for a given character set and length.
    """
    batch = []
    for combo in itertools.product(cset, repeat=plen):
        batch.append(''.join(combo))
        if len(batch) >= chunk_size:
            yield batch
            batch = []
    if batch:
        yield batch

def brute_force_worker(
    pwd_list: List[str],
    hash_to_decrypt: str,
    hash_algorithm: str,
    state: CrackerState,
    progress_interval: int
) -> None:
    """
    Worker function for brute force chunk processing.
    """
    local_counter = 0
    for pwd in pwd_list:
        with state.found_lock:
            if state.found_password is not None or state.abort_requested:
                return
        check_password(pwd, hash_to_decrypt, hash_algorithm, state)
        local_counter += 1

        if local_counter >= progress_interval:
            with state.progress_lock:
                state.passwords_tried += local_counter
                local_counter = 0
                if not state.abort_requested and state.found_password is None and state.total_passwords > 0:
                    progress = (state.passwords_tried / state.total_passwords) * 100
                    print(f"\rProgress: {progress:.2f}%", end='', flush=True)
                    print_stats(state)
            throttle_cpu_usage()
            if state.abort_requested or state.found_password is not None:
                return

    if local_counter > 0:
        with state.progress_lock:
            state.passwords_tried += local_counter
            if not state.abort_requested and state.found_password is None and state.total_passwords > 0:
                progress = (state.passwords_tried / state.total_passwords) * 100
                print(f"\rProgress: {progress:.2f}%", end='', flush=True)
                print_stats(state)
        throttle_cpu_usage()

def brute_force_crack(
    hash_to_decrypt: str,
    hash_algorithm: str,
    charset: str,
    length: int,
    state: CrackerState,
    progress_interval: int = 5_000_000
) -> bool:
    """
    Brute force a hash by trying all combinations of a given charset and length.
    Returns True if a password is found, False otherwise.
    """
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    write_log(f"Starting brute force. Hash: {hash_to_decrypt}, Algo: {hash_algorithm}, Length: {length}")
    state.start_time = time.time()

    state.total_passwords = len(charset) ** length
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=state.threads_count) as executor:
        for chunk in generate_passwords(charset, length):
            if state.found_password or state.abort_requested:
                break
            chunk_size = len(chunk)
            if chunk_size == 0:
                continue

            def split_chunk(lst: List[str], n: int):
                k, m = divmod(len(lst), n)
                start = 0
                for i in range(n):
                    end = start + k + (1 if i < m else 0)
                    yield lst[start:end]
                    start = end

            sub_chunks = list(split_chunk(chunk, min(state.threads_count, chunk_size)))
            futures: List[Future] = []
            for sc in sub_chunks:
                futures.append(
                    executor.submit(
                        brute_force_worker,
                        sc,
                        hash_to_decrypt,
                        hash_algorithm,
                        state,
                        progress_interval
                    )
                )

            while True:
                if state.found_password or state.abort_requested:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                if all(f.done() for f in futures):
                    break
                time.sleep(0.01)

            if state.found_password or state.abort_requested:
                break

    if state.found_password:
        state.abort_requested = True
        print(f"\n\n\033[1;32m🔓 Found Password: {state.found_password}\033[0m\n")
        print(f"⏱️ Amount of time it took to crack the password: {time.time() - start_time:.2f} seconds")
        write_log(f"Brute force success. Password: {state.found_password}")
        input("Press Enter to continue...")
        return True
    else:
        if not state.abort_requested:
            write_log("Brute force completed, no password found.")
            print("\n\033[1;31m🛑 Sorry, no password was found.\033[0m\n")
            print(f"⏱️ Amount of time it took: {time.time() - start_time:.2f} seconds")
        return False

def choose_resource_usage(state: CrackerState) -> None:
    """
    Allows user to set concurrency level (threads).
    """
    print("\nChoose the amount of threads used:")
    print("1. Low (1 thread)")
    print("2. Medium (4 threads)")
    print("3. High (8 threads)")
    print("4. Custom (1-1000 threads)")

    choice = input("\nEnter your choice: ").strip()
    if choice == '1':
        state.threads_count = 1
    elif choice == '2':
        state.threads_count = 4
    elif choice == '3':
        state.threads_count = 8
    elif choice == '4':
        custom_threads = input("Enter the number of threads (1-1000): ").strip()
        if custom_threads.isdigit():
            custom_threads = int(custom_threads)
            if 1 <= custom_threads <= 1000:
                state.threads_count = custom_threads
            else:
                print("⛔ Invalid number. Defaulting to Medium usage.")
                state.threads_count = 4
        else:
            print("⛔ Invalid input. Defaulting to Medium usage.")
            state.threads_count = 4
    else:
        print("⛔ Invalid choice. Defaulting to Medium usage.")
        state.threads_count = 4

def main() -> None:
    """
    Main entry point for the script.
    """
    state = CrackerState()
    register_signal_handler(state)

    attention_message = "⚠️ This tool is for ethical use or pentesting only. Do not misuse it or break the law with it. ⚠️"
    print("\033[1;33m" + attention_message + "\033[0m")

    print_header()
    choose_resource_usage(state)

    valid_algorithms = [
        'md4', 'md5', 'crc32', 'ripemd160', 'blake2_224', 'sha1', 'sha1_v2',
        'sha224', 'sha256', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384',
        'sha3_512', 'bcrypt', 'scrypt', 'argon2id', 'auto'
    ]

    brute_force_supported = [
        'md4', 'md5', 'crc32', 'ripemd160', 'blake2_224', 'sha1', 'sha1_v2',
        'sha224', 'sha256', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'
    ]

    while True:
        print_menu()
        choice = input("\nEnter your choice: ").strip()
        if choice == '1':
            print("\n🔐  Password Cracker  🔐\n")
            print("Supported algorithms: md4, md5, crc32, ripemd160, blake2_224, sha1, sha1_v2, sha224, sha256, sha512, sha3_224, sha3_256, sha3_384, sha3_512, bcrypt, scrypt, argon2id, or auto")

            hash_algorithm = input("Which hashing algorithm do you want to crack? (or 'auto' to guess): ").lower()
            hash_to_decrypt = input("Enter the unsalted hash value: ").strip()
            if not hash_to_decrypt:
                print("🚫 No hash provided.")
                continue

            # Auto-detect or validate user-supplied algorithm
            if hash_algorithm == 'auto':
                candidates = guess_hash_algorithm(hash_to_decrypt)
                if not candidates:
                    print("🚫 Could not auto-detect hash algorithm.")
                    continue
                if len(candidates) == 1:
                    hash_algorithm = candidates[0]
                    print(f"Guessed algorithm: {hash_algorithm}")
                else:
                    print("Multiple possible algorithms found:")
                    for i, c in enumerate(candidates, 1):
                        print(f"{i}. {c}")
                    sel = input("Select the algorithm number: ").strip()
                    if sel.isdigit() and 1 <= int(sel) <= len(candidates):
                        hash_algorithm = candidates[int(sel) - 1]
                        print(f"Selected algorithm: {hash_algorithm}")
                    else:
                        print("⛔ Invalid choice.")
                        continue
            else:
                if hash_algorithm not in valid_algorithms:
                    print("🚫 Invalid hash algorithm.")
                    continue

            # Quick format checks for bcrypt or argon2id
            if hash_algorithm == 'bcrypt':
                if not hash_to_decrypt.startswith("$2"):
                    print("🚫 This does not look like a bcrypt hash.")
                    continue
            elif hash_algorithm == 'argon2id':
                if not hash_to_decrypt.startswith("$argon2id$"):
                    print("🚫 This does not look like a valid Argon2id hash.")
                    continue

            # Validate length for known fixed-length algorithms
            if hash_algorithm not in ['bcrypt', 'argon2id', 'scrypt']:
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
                dictionaries = []
                for i in range(num_dictionary):
                    dictionary_path = input(f"Enter path for the dictionary file {i+1}: ").strip()
                    dictionaries.append(dictionary_path)

                start_time = time.time()
                _ = concurrent_hash_cracker(dictionaries, hash_to_decrypt, hash_algorithm, state)
                end_time = time.time()
                print(f"⏱️ Total time: {end_time - start_time:.2f} seconds")

            elif method_choice == '2':
                if hash_algorithm not in brute_force_supported:
                    print("🚫 Automatic brute force is not supported for this algorithm.")
                    continue
                charset = string.ascii_letters + string.digits
                length_input = input("Enter password length: ").strip()
                if not length_input.isdigit() or int(length_input) <= 0:
                    print("❌ Invalid length.")
                    continue
                length = int(length_input)

                start_time = time.time()
                _ = brute_force_crack(hash_to_decrypt, hash_algorithm, charset, length, state)
                end_time = time.time()
                print(f"⏱️ Total time: {end_time - start_time:.2f} seconds")
            else:
                print("\n⛔ Invalid choice. Please select a valid option.")
        elif choice == '2':
            print("\n🚪 Exiting...")
            sys.exit()
        else:
            print("\n⛔ Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()