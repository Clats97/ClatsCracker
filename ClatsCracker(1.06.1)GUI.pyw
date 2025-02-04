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
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, Future
from argon2 import PasswordHasher, Type
import psutil
from typing import List, Optional
from passlib.hash import nthash
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext

# Try importing chardet for encoding detection.
try:
    import chardet
except ImportError:
    chardet = None

# Global Constants
CPU_USAGE_THRESHOLD = 95.0
LOG_FILE = "Hash_Cracking_Results_ClatScope"  # Updated log file name

# -----------------------------------------------------
# Shared State Class for Cracking Operations
# -----------------------------------------------------
class CrackerState:
    """
    Holds shared state for the cracking operations.
    """
    def __init__(self) -> None:
        self.passwords_tried = 0
        self.total_passwords = 0
        self.found_password: Optional[str] = None
        self.threads_count = 1
        self.start_time: Optional[float] = None
        self.abort_requested = False
        self.cracking_complete = False

        self.progress_lock = threading.Lock()
        self.found_lock = threading.Lock()

def write_log(message: str) -> None:
    """Append a log entry to the specified LOG_FILE."""
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{time.ctime()} - {message}\n")
    except Exception:
        pass

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
    'blake2_224': 56,
    'sha512_224': 56,
    'sha512_256': 64,
    'blake2b': 128,
    'blake2s': 64,
    'sha384': 96,
    'shake128': 64,
    'shake256': 128
}

# -----------------------------------------------------
# Password Verification and Hashing Helpers
# -----------------------------------------------------
def phpass_verify(password: str, phpass_hash: str) -> bool:
    itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    if not (phpass_hash.startswith('$P$') or phpass_hash.startswith('$H$')):
        return False
    if len(phpass_hash) != 34:
        return False

    count_log2 = itoa64.index(phpass_hash[3])
    count = 1 << count_log2
    salt = phpass_hash[4:12]
    if len(salt) != 8:
        return False

    hash_val = hashlib.md5((salt + password).encode('utf-8')).digest()
    for _ in range(count):
        hash_val = hashlib.md5(hash_val + password.encode('utf-8')).digest()

    def _encode_64(inp: bytes) -> str:
        outp = []
        value = 0
        bits = 0
        for byte in inp:
            value |= (byte << bits)
            bits += 8
            while bits >= 6:
                outp.append(itoa64[value & 0x3f])
                value >>= 6
                bits -= 6
        if bits > 0:
            outp.append(itoa64[value & 0x3f])
        return ''.join(outp)

    output = phpass_hash[0:12]
    encoded = _encode_64(hash_val)
    encoded = encoded[:22]
    output += encoded
    return output == phpass_hash

def guess_hash_algorithm(hash_value: str) -> Optional[List[str]]:
    if hash_value.startswith("$2"):
        return ['bcrypt']
    if hash_value.startswith("$argon2id$"):
        return ['argon2id']
    if (hash_value.startswith("$P$") or hash_value.startswith("$H$")) and len(hash_value) == 34:
        return ['phpass_md5']

    length = len(hash_value)
    if length == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
        return ['md5', 'ntlm']

    candidates = []
    for algo, algo_len in hash_lengths.items():
        if length == algo_len:
            candidates.append(algo)

    if length == 128 and all(c in '0123456789abcdef' for c in hash_value.lower()):
        candidates.append('scrypt')

    candidates = list(set(candidates))
    return candidates if candidates else None

def hash_password(password: str, hash_algorithm: str) -> Optional[str]:
    """Hash the password using the specified algorithm."""
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
    elif hash_algorithm == 'sha512_224':
        return hashlib.new('sha512_224', password_bytes).hexdigest()
    elif hash_algorithm == 'sha512_256':
        return hashlib.new('sha512_256', password_bytes).hexdigest()
    elif hash_algorithm == 'blake2b':
        return hashlib.blake2b(password_bytes).hexdigest()
    elif hash_algorithm == 'blake2s':
        return hashlib.blake2s(password_bytes).hexdigest()
    elif hash_algorithm == 'sha384':
        return hashlib.sha384(password_bytes).hexdigest()
    elif hash_algorithm == 'shake128':
        shake = hashlib.shake_128(password_bytes)
        return shake.hexdigest(32)
    elif hash_algorithm == 'shake256':
        shake = hashlib.shake_256(password_bytes)
        return shake.hexdigest(64)
    return None

def validate_hash_length(hash_algorithm: str, hash_value: str) -> bool:
    if hash_algorithm in ['bcrypt', 'argon2id', 'scrypt', 'phpass_md5', 'ntlm']:
        return True
    expected_length = hash_lengths.get(hash_algorithm)
    if expected_length and len(hash_value) != expected_length:
        return False
    return True

def throttle_cpu_usage() -> None:
    cpu_usage = psutil.cpu_percent(interval=0.1)  # Slight interval for smoother reading
    if cpu_usage > CPU_USAGE_THRESHOLD:
        time.sleep(0.5)

# -----------------------------------------------------
# Encoding Detection Helper for File I/O
# -----------------------------------------------------
def detect_file_encoding(file_path: str, sample_size: int = 10000) -> str:
    """
    Detect the encoding of a text file by reading a sample of bytes.
    Falls back to 'utf-8' if detection fails or chardet is not available.
    """
    if chardet is None:
        return 'utf-8'
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
        detection = chardet.detect(sample)
        encoding = detection.get('encoding')
        if encoding is None:
            encoding = 'utf-8'
        return encoding
    except Exception:
        return 'utf-8'

# -----------------------------------------------------
# Updated File I/O Helpers using Detected Encoding
# -----------------------------------------------------
def get_line_count(file_path: str) -> int:
    """Count the number of lines in a file using the detected encoding."""
    try:
        encoding = detect_file_encoding(file_path)
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def lines_in_chunks(file_path: str, chunk_size: int = 100000):
    """Yield batches of lines from a file using the detected encoding."""
    try:
        encoding = detect_file_encoding(file_path)
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            batch = []
            for line in f:
                batch.append(line.rstrip('\n'))
                if len(batch) >= chunk_size:
                    yield batch
                    batch = []
            if batch:
                yield batch
    except Exception:
        return

# ====================================================
# CPU-Intensive Functions (Stateless, To Be Run in Processes)
# ====================================================
def check_password_cpu(password: str, hash_to_decrypt: str, hash_algorithm: str) -> (bool, Optional[str]):
    """Check if the password matches the hash; return (True, password) if so."""
    if hash_algorithm == 'bcrypt':
        try:
            if bcrypt.checkpw(password.encode('utf-8'), hash_to_decrypt.encode('utf-8')):
                return True, password
        except Exception:
            return False, None
        return False, None
    elif hash_algorithm == 'argon2id':
        ph = PasswordHasher(type=Type.ID)
        try:
            ph.verify(hash_to_decrypt, password)
            return True, password
        except Exception:
            return False, None
    elif hash_algorithm == 'phpass_md5':
        if phpass_verify(password, hash_to_decrypt):
            return True, password
        return False, None
    elif hash_algorithm == 'ntlm':
        try:
            if nthash.verify(password, hash_to_decrypt):
                return True, password
        except Exception:
            return False, None
        return False, None
    else:
        hashed_word = hash_password(password, hash_algorithm)
        if hashed_word == hash_to_decrypt:
            return True, password
        return False, None

def process_dictionary_chunk(chunk: List[str], hash_to_decrypt: str, hash_algorithm: str, progress_interval: int) -> (int, Optional[str]):
    """Process a chunk of dictionary passwords in a process."""
    processed = 0
    found_password = None
    local_counter = 0
    for pwd in chunk:
        match, candidate = check_password_cpu(pwd, hash_to_decrypt, hash_algorithm)
        processed += 1
        local_counter += 1
        if match:
            found_password = candidate
            break
        if local_counter >= progress_interval:
            local_counter = 0
            throttle_cpu_usage()
    return processed, found_password

def process_brute_force_chunk(chunk: List[str], hash_to_decrypt: str, hash_algorithm: str, progress_interval: int) -> (int, Optional[str]):
    """Process a chunk of brute-force candidates in a process."""
    processed = 0
    found_password = None
    local_counter = 0
    for pwd in chunk:
        match, candidate = check_password_cpu(pwd, hash_to_decrypt, hash_algorithm)
        processed += 1
        local_counter += 1
        if match:
            found_password = candidate
            break
        if local_counter >= progress_interval:
            local_counter = 0
            throttle_cpu_usage()
    return processed, found_password

# ====================================================
# Dictionary-Based Cracking Worker (Runs in a Thread)
# ====================================================
def dictionary_crack_worker(dictionary_path: str, hash_to_decrypt: str, hash_algorithm: str,
                            state: CrackerState, progress_interval: int, update_progress_callback) -> None:
    if not os.path.exists(dictionary_path):
        write_log(f"Dictionary file '{dictionary_path}' not found.")
        return

    line_count = get_line_count(dictionary_path)
    if line_count == 0:
        return

    # For each chunk read via file reading with detected encoding, offload CPU work to processes.
    with ProcessPoolExecutor(max_workers=state.threads_count) as proc_executor:
        for chunk in lines_in_chunks(dictionary_path):
            if state.abort_requested or state.found_password is not None:
                break
            future = proc_executor.submit(process_dictionary_chunk, chunk, hash_to_decrypt, hash_algorithm, progress_interval)
            try:
                processed, found = future.result()
                # Batch update of state with minimal lock holding.
                with state.progress_lock:
                    state.passwords_tried += processed
                    progress = (state.passwords_tried / state.total_passwords) * 100 if state.total_passwords > 0 else 0
                update_progress_callback(progress, state)
                if found is not None:
                    with state.found_lock:
                        state.found_password = found
                        state.abort_requested = True
                    break
            except Exception:
                continue

# ====================================================
# Concurrent Cracker for Dictionary-Based Method Using Threads
# ====================================================
def concurrent_hash_cracker(dictionaries: List[str], hash_to_decrypt: str, hash_algorithm: str,
                              state: CrackerState, update_progress_callback, on_complete_callback) -> None:
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    state.cracking_complete = False
    write_log(f"Starting dictionary cracking. Hash: {hash_to_decrypt}, Algo: {hash_algorithm}, Dicts: {dictionaries}")

    state.start_time = time.time()
    state.total_passwords = 0
    for dictionary_path in dictionaries:
        if os.path.exists(dictionary_path):
            state.total_passwords += get_line_count(dictionary_path)

    if state.total_passwords == 0:
        write_log("No passwords found in dictionary files.")
        on_complete_callback(None)
        return

    # Run one dictionary worker per dictionary in a thread.
    with ThreadPoolExecutor(max_workers=min(state.threads_count, len(dictionaries))) as executor:
        futures: List[Future] = []
        for dictionary_path in dictionaries:
            if os.path.exists(dictionary_path):
                futures.append(
                    executor.submit(dictionary_crack_worker, dictionary_path, hash_to_decrypt,
                                    hash_algorithm, state, 5000000, update_progress_callback)
                )

        # Poll until a password is found or all workers finish.
        while True:
            if state.found_password is not None:
                state.abort_requested = True
                for f in futures:
                    f.cancel()
                write_log(f"Password found: {state.found_password}")
                on_complete_callback(state.found_password)
                break
            if all(f.done() for f in futures):
                break
            time.sleep(0.01)

        for future in futures:
            try:
                future.result()
            except Exception:
                pass

    if not state.found_password and not state.abort_requested:
        write_log("Cracking completed, password not found.")
        on_complete_callback(None)

# ====================================================
# Brute-Force Cracking Using Processes (Similar to Before)
# ====================================================
def generate_passwords(cset: str, plen: int, chunk_size: int = 1000000):
    batch = []
    for combo in itertools.product(cset, repeat=plen):
        batch.append(''.join(combo))
        if len(batch) >= chunk_size:
            yield batch
            batch = []
    if batch:
        yield batch

def brute_force_crack(hash_to_decrypt: str, hash_algorithm: str, charset: str, length: int,
                      state: CrackerState, update_progress_callback, on_complete_callback) -> None:
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    state.cracking_complete = False
    write_log(f"Starting brute force. Hash: {hash_to_decrypt}, Algo: {hash_algorithm}, Length: {length}")
    state.start_time = time.time()

    state.total_passwords = len(charset) ** length

    with ProcessPoolExecutor(max_workers=state.threads_count) as executor:
        futures: List[Future] = []
        for chunk in generate_passwords(charset, length):
            if state.found_password or state.abort_requested:
                break

            def split_chunk(lst: List[str], n: int):
                k, m = divmod(len(lst), n)
                start = 0
                for i in range(n):
                    end = start + k + (1 if i < m else 0)
                    yield lst[start:end]
                    start = end

            sub_chunks = list(split_chunk(chunk, min(state.threads_count, len(chunk))))
            for sub in sub_chunks:
                futures.append(
                    executor.submit(process_brute_force_chunk, sub, hash_to_decrypt, hash_algorithm, 5000000)
                )

            for future in futures:
                if state.found_password or state.abort_requested:
                    break
                try:
                    processed, found = future.result()
                    with state.progress_lock:
                        state.passwords_tried += processed
                        progress = (state.passwords_tried / state.total_passwords) * 100 if state.total_passwords > 0 else 0
                    update_progress_callback(progress, state)
                    if found is not None:
                        with state.found_lock:
                            state.found_password = found
                            state.abort_requested = True
                        break
                except Exception:
                    continue
            if state.found_password or state.abort_requested:
                break

    if state.found_password:
        write_log(f"Brute force success. Password: {state.found_password}")
        on_complete_callback(state.found_password)
    else:
        if not state.abort_requested:
            write_log("Brute force completed, no password found.")
            on_complete_callback(None)

# ====================================================
# GUI Code (Largely Unchanged)
# ====================================================
class HashCrackerGUI:
    def __init__(self, master):
        self.master = master
        master.title("ClatsCracker Hash Tool v1.06.1")
        master.geometry("800x800")
        master.resizable(False, False)

        self.state = CrackerState()

        # Main Frame
        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Branding Section
        branding_text = """
██████╗██╗      █████╗ ████████╗███████╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║     ██║     ███████║   ██║   ███████╗██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║     ██║     ██╔══██║   ██║   ╚════██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
           C L A T S C R A C K E R     H A S H     T O O L   (Version 1.06.1)
          Multi-algorithm hash cracking tool. Ethical use only.
         🛡️By Josh Clatney - Ethical Pentesting Enthusiast  🛡️
        """
        self.branding_label = tk.Label(
            self.main_frame,
            text=branding_text,
            font=("Courier", 10, "bold"),
            justify="center",
            fg="blue",
            bg="lightgrey",
            anchor="center"
        )
        self.branding_label.grid(row=0, column=0, columnspan=5, pady=(0, 10), sticky="n")

        # Hash Input Section
        self.hash_label = ttk.Label(self.main_frame, text="Hash Value:")
        self.hash_label.grid(row=1, column=0, sticky=tk.W, pady=5)

        self.hash_entry = ttk.Entry(self.main_frame, width=60)
        self.hash_entry.grid(row=1, column=1, pady=5, sticky=tk.W)

        # Paste Button
        self.paste_button = ttk.Button(self.main_frame, text="Paste", command=self.paste_hash)
        self.paste_button.grid(row=1, column=2, sticky=tk.W, padx=(5, 2), pady=5)

        # Algorithm Selection
        self.algo_label = ttk.Label(self.main_frame, text="Hash Algorithm:")
        self.algo_label.grid(row=2, column=0, sticky=tk.W, pady=5)

        self.algo_var = tk.StringVar()
        self.algo_combobox = ttk.Combobox(
            self.main_frame, textvariable=self.algo_var, state="readonly",
            values=[
                'auto', 'md4', 'md5', 'crc32', 'ripemd160', 'blake2_224',
                'sha1', 'sha1_v2', 'sha224', 'sha256', 'sha512', 'sha3_224',
                'sha3_256', 'sha3_384', 'sha3_512', 'bcrypt', 'scrypt',
                'argon2id', 'phpass_md5', 'sha512_224', 'sha512_256',
                'ntlm', 'blake2b', 'blake2s', 'sha384', 'shake128', 'shake256'
            ]
        )
        self.algo_combobox.current(0)
        self.algo_combobox.grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=5)

        # Cracking Method
        self.method_label = ttk.Label(self.main_frame, text="Cracking Method:")
        self.method_label.grid(row=3, column=0, sticky=tk.W, pady=5)

        self.method_var = tk.StringVar(value="dictionary")
        self.dict_radio = ttk.Radiobutton(
            self.main_frame, text="Dictionary-Based", variable=self.method_var,
            value="dictionary", command=self.toggle_method
        )
        self.dict_radio.grid(row=3, column=1, sticky=tk.W, pady=5)

        self.brute_radio = ttk.Radiobutton(
            self.main_frame, text="Brute-Force", variable=self.method_var,
            value="brute", command=self.toggle_method
        )
        self.brute_radio.grid(row=3, column=2, sticky=tk.W, pady=5)

        # Dictionary Selection
        self.dict_label = ttk.Label(self.main_frame, text="Dictionary Files:")
        self.dict_label.grid(row=4, column=0, sticky=tk.W, pady=5)

        self.dict_listbox = tk.Listbox(self.main_frame, selectmode=tk.MULTIPLE, width=60, height=4)
        self.dict_listbox.grid(row=4, column=1, columnspan=1, sticky=tk.W, pady=5)

        # Add and Remove Buttons for Dictionary Files
        self.add_dict_button = ttk.Button(self.main_frame, text="Add", command=self.add_dictionary)
        self.add_dict_button.grid(row=4, column=2, sticky=tk.W, padx=(5, 2), pady=5)

        self.remove_dict_button = ttk.Button(self.main_frame, text="Remove", command=self.remove_dictionary)
        self.remove_dict_button.grid(row=4, column=3, sticky=tk.W, padx=(2, 5), pady=5)

        # Brute-Force Parameters
        self.charset_label = ttk.Label(self.main_frame, text="Character Set:")
        self.charset_label.grid(row=5, column=0, sticky=tk.W, pady=5)

        self.charset_var = tk.StringVar()
        self.charset_combobox = ttk.Combobox(
            self.main_frame, textvariable=self.charset_var, state="readonly",
            values=[
                'Alphanumeric (A-Z, a-z, 0-9)',
                'Hexadecimal (0-9, a-f)',
                'ASCII Printable (!-~)',
                'Custom'
            ]
        )
        self.charset_combobox.current(0)
        self.charset_combobox.grid(row=5, column=1, sticky=tk.W, pady=5)
        self.charset_combobox.bind("<<ComboboxSelected>>", self.update_charset_entry)

        self.custom_charset_entry = ttk.Entry(self.main_frame, width=40, state='disabled')
        self.custom_charset_entry.grid(row=5, column=2, sticky=tk.W, pady=5)

        self.length_label = ttk.Label(self.main_frame, text="Password Length:")
        self.length_label.grid(row=6, column=0, sticky=tk.W, pady=5)

        self.length_entry = ttk.Entry(self.main_frame, width=10)
        self.length_entry.grid(row=6, column=1, sticky=tk.W, pady=5)
        self.length_entry.insert(0, "1")

        # Threads Selection
        self.threads_label = ttk.Label(self.main_frame, text="Threads:")
        self.threads_label.grid(row=7, column=0, sticky=tk.W, pady=5)

        self.threads_var = tk.StringVar(value="4")
        self.threads_combobox = ttk.Combobox(
            self.main_frame, textvariable=self.threads_var, state="readonly",
            values=['1 (Low)', '4 (Medium)', '8 (High)', 'Custom']
        )
        self.threads_combobox.current(1)
        self.threads_combobox.grid(row=7, column=1, sticky=tk.W, pady=5)
        self.threads_combobox.bind("<<ComboboxSelected>>", self.update_threads_entry)

        self.custom_threads_entry = ttk.Entry(self.main_frame, width=10, state='disabled')
        self.custom_threads_entry.grid(row=7, column=2, sticky=tk.W, pady=5)

        # Start and Abort Buttons
        self.start_button = ttk.Button(self.main_frame, text="Start Cracking", command=self.start_cracking)
        self.start_button.grid(row=8, column=1, sticky=tk.W, pady=20)

        self.abort_button = ttk.Button(self.main_frame, text="Abort", command=self.abort_cracking, state='disabled')
        self.abort_button.grid(row=8, column=2, sticky=tk.W, pady=20)

        # Progress Bar
        self.progress = ttk.Progressbar(self.main_frame, orient='horizontal', length=600, mode='determinate')
        self.progress.grid(row=9, column=0, columnspan=5, pady=10)

        # Metrics Section
        self.metrics_frame = ttk.Frame(self.main_frame)
        self.metrics_frame.grid(row=10, column=0, columnspan=5, pady=10, sticky="w")

        self.passwords_tried_var = tk.StringVar(value="Passwords Tried: 0")
        self.progress_var = tk.StringVar(value="Progress: 0.00%")
        self.eta_var = tk.StringVar(value="ETA: N/A")
        self.aps_var = tk.StringVar(value="Attempts Per Second: 0.00")

        self.passwords_tried_label = ttk.Label(self.metrics_frame, textvariable=self.passwords_tried_var)
        self.passwords_tried_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 20))

        self.progress_label = ttk.Label(self.metrics_frame, textvariable=self.progress_var)
        self.progress_label.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))

        self.eta_label = ttk.Label(self.metrics_frame, textvariable=self.eta_var)
        self.eta_label.grid(row=0, column=2, sticky=tk.W, padx=(0, 20))

        self.aps_label = ttk.Label(self.metrics_frame, textvariable=self.aps_var)
        self.aps_label.grid(row=0, column=3, sticky=tk.W, padx=(0, 20))

        # Status Display
        self.status_display = scrolledtext.ScrolledText(self.main_frame, width=90, height=10, state='disabled')
        self.status_display.grid(row=11, column=0, columnspan=5, pady=10)

        self.toggle_method()

        # Start periodic live metrics update.
        self.update_live_metrics()

    def update_live_metrics(self):
        if self.state.start_time is not None:
            elapsed = time.time() - self.state.start_time
            aps = self.state.passwords_tried / elapsed if elapsed > 0 else 0
        else:
            aps = 0.0
        self.passwords_tried_var.set(f"Passwords Tried: {self.state.passwords_tried}")
        self.aps_var.set(f"Attempts Per Second: {aps:.2f}")
        if not self.state.cracking_complete:
            self.master.after(500, self.update_live_metrics)

    def add_dictionary(self):
        files = filedialog.askopenfilenames(title="Select Dictionary Files",
                                            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        for file in files:
            if file not in self.dict_listbox.get(0, tk.END):
                self.dict_listbox.insert(tk.END, file)

    def remove_dictionary(self):
        selected_indices = self.dict_listbox.curselection()
        for index in reversed(selected_indices):
            self.dict_listbox.delete(index)

    def update_charset_entry(self, event=None):
        if self.charset_combobox.get() == 'Custom':
            self.custom_charset_entry.configure(state='normal')
        else:
            self.custom_charset_entry.delete(0, tk.END)
            self.custom_charset_entry.configure(state='disabled')

    def update_threads_entry(self, event=None):
        if self.threads_combobox.get() == 'Custom':
            self.custom_threads_entry.configure(state='normal')
        else:
            self.custom_threads_entry.delete(0, tk.END)
            self.custom_threads_entry.configure(state='disabled')

    def toggle_method(self):
        method = self.method_var.get()
        if method == "dictionary":
            self.dict_label.configure(state='normal')
            self.dict_listbox.configure(state='normal')
            self.add_dict_button.configure(state='normal')
            self.remove_dict_button.configure(state='normal')
            self.charset_label.configure(state='disabled')
            self.charset_combobox.configure(state='disabled')
            self.custom_charset_entry.configure(state='disabled')
            self.length_label.configure(state='disabled')
            self.length_entry.configure(state='disabled')
        else:
            self.dict_label.configure(state='disabled')
            self.dict_listbox.configure(state='disabled')
            self.add_dict_button.configure(state='disabled')
            self.remove_dict_button.configure(state='disabled')
            self.charset_label.configure(state='normal')
            self.charset_combobox.configure(state='readonly')
            self.update_charset_entry()
            self.length_label.configure(state='normal')
            self.length_entry.configure(state='normal')

    def get_selected_charset(self):
        choice = self.charset_combobox.get()
        if choice == 'Alphanumeric (A-Z, a-z, 0-9)':
            return string.ascii_letters + string.digits
        elif choice == 'Hexadecimal (0-9, a-f)':
            return string.hexdigits.lower()
        elif choice == 'ASCII Printable (!-~)':
            return ''.join(chr(i) for i in range(33, 127))
        elif choice == 'Custom':
            return self.custom_charset_entry.get()
        else:
            return string.ascii_letters + string.digits

    def get_selected_threads(self):
        choice = self.threads_combobox.get()
        if choice.startswith('1'):
            return 1
        elif choice.startswith('4'):
            return 4
        elif choice.startswith('8'):
            return 8
        elif choice == 'Custom':
            custom = self.custom_threads_entry.get()
            if custom.isdigit():
                custom = int(custom)
                if 1 <= custom <= 1000:
                    return custom
            return 4
        else:
            return 4

    def paste_hash(self):
        try:
            clipboard = self.master.clipboard_get()
            self.hash_entry.delete(0, tk.END)
            self.hash_entry.insert(0, clipboard)
        except tk.TclError:
            messagebox.showerror("Paste Error", "No text in clipboard to paste.")

    def start_cracking(self):
        hash_to_decrypt = self.hash_entry.get().strip()
        if not hash_to_decrypt:
            messagebox.showerror("Input Error", "Please enter the hash value.")
            return

        hash_algorithm = self.algo_var.get()
        if hash_algorithm == 'auto':
            candidates = guess_hash_algorithm(hash_to_decrypt)
            if not candidates:
                messagebox.showerror("Algorithm Error", "Could not auto-detect hash algorithm.")
                return
            elif len(candidates) == 1:
                hash_algorithm = candidates[0]
                self.log_status(f"Auto-detected algorithm: {hash_algorithm}")
            else:
                selected = self.select_from_candidates(candidates)
                if selected is None:
                    return
                hash_algorithm = selected
                self.log_status(f"Selected algorithm: {hash_algorithm}")
        else:
            if hash_algorithm not in hash_lengths and hash_algorithm not in ['bcrypt', 'argon2id', 'scrypt', 'phpass_md5', 'ntlm', 'blake2b', 'blake2s', 'sha384', 'shake128', 'shake256']:
                messagebox.showerror("Algorithm Error", "Invalid hash algorithm selected.")
                return

        if not validate_hash_length(hash_algorithm, hash_to_decrypt):
            messagebox.showerror("Hash Length Error", f"The provided hash does not match the expected length for {hash_algorithm}.")
            return

        method = self.method_var.get()
        if method == "dictionary":
            dictionaries = self.dict_listbox.get(0, tk.END)
            if not dictionaries:
                messagebox.showerror("Input Error", "Please add at least one dictionary file.")
                return
            self.state.threads_count = self.get_selected_threads()
            self.start_button.configure(state='disabled')
            self.abort_button.configure(state='normal')
            self.progress['value'] = 0
            self.log_status("Starting dictionary-based cracking...")
            threading.Thread(
                target=concurrent_hash_cracker,
                args=(list(dictionaries), hash_to_decrypt, hash_algorithm, self.state,
                      self.update_progress, self.on_cracking_complete),
                daemon=True
            ).start()
        else:
            if hash_algorithm not in [
                'md4', 'md5', 'crc32', 'ripemd160', 'blake2_224',
                'sha1', 'sha1_v2', 'sha224', 'sha256', 'sha3_224',
                'sha3_256', 'sha3_384', 'sha3_512', 'ntlm',
                'sha512_224', 'sha512_256', 'blake2b', 'blake2s', 'sha384', 'shake128', 'shake256'
            ]:
                messagebox.showerror("Unsupported Algorithm", "Automatic brute force is not supported for this algorithm.")
                return
            charset = self.get_selected_charset()
            if not charset:
                messagebox.showerror("Input Error", "Character set cannot be empty.")
                return
            length_str = self.length_entry.get().strip()
            if not length_str.isdigit() or int(length_str) <= 0:
                messagebox.showerror("Input Error", "Please enter a valid password length.")
                return
            length = int(length_str)
            self.state.threads_count = self.get_selected_threads()
            self.start_button.configure(state='disabled')
            self.abort_button.configure(state='normal')
            self.progress['value'] = 0
            self.log_status("Starting brute-force cracking...")
            threading.Thread(
                target=brute_force_crack,
                args=(hash_to_decrypt, hash_algorithm, charset, length, self.state,
                      self.update_progress, self.on_cracking_complete),
                daemon=True
            ).start()

    def abort_cracking(self):
        if messagebox.askyesno("Abort", "Are you sure you want to abort the cracking process?"):
            self.state.abort_requested = True
            self.log_status("Aborting cracking process...")
            self.abort_button.configure(state='disabled')

    def update_progress(self, progress, state):
        if self.state.cracking_complete:
            return
        self.progress['value'] = min(progress, 100)
        eta = self.calculate_eta(state)
        if state.start_time is not None and time.time() > state.start_time:
            elapsed = time.time() - state.start_time
            aps = state.passwords_tried / elapsed if elapsed > 0 else 0
        else:
            aps = 0.0
        self.progress_var.set(f"Progress: {progress:.2f}%")
        self.eta_var.set(f"ETA: {eta}")
        self.aps_var.set(f"Attempts Per Second: {aps:.2f}")

    def calculate_eta(self, state):
        if state.start_time is None:
            return "N/A"
        elapsed = time.time() - state.start_time
        if elapsed > 0 and state.passwords_tried > 0:
            aps = state.passwords_tried / elapsed
            remaining = state.total_passwords - state.passwords_tried
            eta = remaining / aps if aps > 0 else 99999
            return f"{eta:.1f} seconds"
        return "N/A"

    def on_cracking_complete(self, result):
        self.state.cracking_complete = True
        if result:
            self.log_status(f"Password Successfully Cracked!: {result}")
            messagebox.showinfo("Success", f"Password Successfully Cracked!: {result}")
        else:
            if self.state.abort_requested:
                self.log_status("Cracking process was aborted.")
                messagebox.showwarning("Aborted", "Cracking process was aborted.")
            else:
                self.log_status("Cracking unsuccessful. Password not found.")
                messagebox.showinfo("Unsuccessful", "Cracking unsuccessful. Password not found.")
        self.start_button.configure(state='normal')
        self.abort_button.configure(state='disabled')

    def log_status(self, message):
        self.status_display.configure(state='normal')
        self.status_display.insert(tk.END, f"{message}\n")
        self.status_display.see(tk.END)
        self.status_display.configure(state='disabled')

    def select_from_candidates(self, candidates):
        selection_window = tk.Toplevel(self.master)
        selection_window.title("Select Hash Algorithm")
        selection_window.geometry("300x200")
        selection_window.grab_set()

        label = ttk.Label(selection_window, text="Multiple algorithms detected:")
        label.pack(pady=10)

        listbox = tk.Listbox(selection_window)
        for algo in candidates:
            listbox.insert(tk.END, algo)
        listbox.pack(pady=10, fill=tk.BOTH, expand=True)

        selected_algo = []

        def select():
            selection = listbox.curselection()
            if selection:
                selected_algo.append(listbox.get(selection[0]))
                selection_window.destroy()
            else:
                messagebox.showerror("Selection Error", "Please select an algorithm.")
        
        select_button = ttk.Button(selection_window, text="Select", command=select)
        select_button.pack(pady=10)

        self.master.wait_window(selection_window)
        return selected_algo[0] if selected_algo else None

def main():
    root = tk.Tk()
    gui = HashCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()