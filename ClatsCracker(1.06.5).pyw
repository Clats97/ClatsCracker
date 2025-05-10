from __future__ import annotations
import hashlib, os, time, bcrypt, itertools, string, threading, zlib, logging, sys
import concurrent.futures as cf
import tkinter as tk, multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import List, Optional, Tuple, Dict
from argon2 import PasswordHasher, Type
from passlib.hash import nthash
from tkinter import filedialog, messagebox, ttk, scrolledtext
try:
    from Crypto.Hash import MD4 as _MD4, RIPEMD160 as _RIPEMD160
    _HAS_FAST_HASHES = True
except ImportError:
    _HAS_FAST_HASHES = False
try:
    import chardet
except ImportError:
    chardet = None
CPU_USAGE_THRESHOLD = 99.5
if getattr(sys, 'frozen', False):                       
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(_SCRIPT_DIR, "Hash_Cracking_Results_ClatsCracker.txt")
ALIAS_MAP = {'shakeke128': 'shake128', 'sha1v2': 'sha1_v2', 'ntplm': 'ntlm'}
_DEFAULT_THREADS = max(1, (os.cpu_count() or 1) // 2)
_ENC_CACHE: Dict[str, str] = {}
SCRIPT_NAME = os.path.basename(sys.argv[0] if sys.argv and sys.argv[0] else '')
logger = logging.getLogger("clatscracker")
logger.setLevel(logging.INFO)
_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(filename)s — %(message)s"))
_fh.flush = lambda: None
logger.addHandler(_fh)
write_log = logger.info
_POOL: Optional[ProcessPoolExecutor] = None
_ARGON2_PH = PasswordHasher(type=Type.ID)

hash_lengths = {
    'crc32': 8, 'md4': 32, 'md5': 32, 'ripemd160': 40, 'sha1': 40, 'sha1_v2': 40,
    'sha224': 56, 'sha256': 64, 'sha3_224': 56, 'sha3_256': 64, 'sha3_384': 96,
    'sha3_512': 128, 'sha512': 128, 'blake2_224': 56, 'sha512_224': 56,
    'sha512_256': 64, 'blake2b': 128, 'blake2s': 64, 'sha384': 96,
    'shake128': 64, 'shake256': 128, 'shakeke128': 64, 'scrypt': 128
}

_HASH_FUNCS = {
    'crc32':        lambda b: format(zlib.crc32(b) & 0xffffffff, '08x'),
    'md4':          (lambda b: _MD4.new(data=b).hexdigest())       if _HAS_FAST_HASHES else
                    (lambda b: hashlib.new('md4', b).hexdigest()),
    'md5':          lambda b: hashlib.md5(b).hexdigest(),
    'ripemd160':    (lambda b: _RIPEMD160.new(data=b).hexdigest()) if _HAS_FAST_HASHES else
                    (lambda b: hashlib.new('ripemd160', b).hexdigest()),
    'blake2_224':   lambda b: hashlib.blake2b(b, digest_size=28).hexdigest(),
    'sha224':       lambda b: hashlib.sha224(b).hexdigest(),
    'sha256':       lambda b: hashlib.sha256(b).hexdigest(),
    'sha512':       lambda b: hashlib.sha512(b).hexdigest(),
    'sha3_224':     lambda b: hashlib.sha3_224(b).hexdigest(),
    'sha3_256':     lambda b: hashlib.sha3_256(b).hexdigest(),
    'sha3_384':     lambda b: hashlib.sha3_384(b).hexdigest(),
    'sha3_512':     lambda b: hashlib.sha3_512(b).hexdigest(),
    'sha1':         lambda b: hashlib.sha1(b).hexdigest(),
    'sha512_224':   lambda b: hashlib.new('sha512_224', b).hexdigest(),
    'sha512_256':   lambda b: hashlib.new('sha512_256', b).hexdigest(),
    'blake2b':      lambda b: hashlib.blake2b(b).hexdigest(),
    'blake2s':      lambda b: hashlib.blake2s(b).hexdigest(),
    'sha384':       lambda b: hashlib.sha384(b).hexdigest(),
}

def canonical_algo(name: str) -> str:
    return ALIAS_MAP.get(name.lower(), name.lower())

class CrackerState:
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

def phpass_verify(password: str, phpass_hash: str) -> bool:
    it = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    if not (phpass_hash.startswith('$P$') or phpass_hash.startswith('$H$')) or len(phpass_hash) != 34:
        return False
    cl = it.index(phpass_hash[3])
    cnt = 1 << cl
    salt = phpass_hash[4:12]
    if len(salt) != 8:
        return False
    h = hashlib.md5((salt + password).encode()).digest()
    for _ in range(cnt):
        h = hashlib.md5(h + password.encode()).digest()
    def e(inp: bytes):
        out, val, bits = [], 0, 0
        for byte in inp:
            val |= byte << bits
            bits += 8
            while bits >= 6:
                out.append(it[val & 0x3f])
                val >>= 6
                bits -= 6
        if bits:
            out.append(it[val & 0x3f])
        return ''.join(out)
    return phpass_hash[:12] + e(h)[:22] == phpass_hash

def guess_hash_algorithm(h: str) -> Optional[List[str]]:
    if h.startswith("$2"):
        return ['bcrypt']
    if h.startswith("$argon2id$"):
        return ['argon2id']
    if (h.startswith("$P$") or h.startswith("$H$")) and len(h) == 34:
        return ['phpass_md5']
    hl, l = h.lower(), len(h)
    if l == 32 and all(c in '0123456789abcdef' for c in hl):
        return ['md5', 'ntlm']
    cand = [k for k, v in hash_lengths.items() if l == v]
    if l == 128 and all(c in '0123456789abcdef' for c in hl):
        cand.append('scrypt')
    return list(dict.fromkeys(cand)) or None

def hash_password(p: str, a: str) -> Optional[str]:
    b = p.encode()
    if a == 'sha1_v2':
        return hashlib.sha1(hashlib.sha1(b).digest()).hexdigest()
    if a == 'scrypt':
        return hashlib.scrypt(b, salt=b'', n=16384, r=8, p=1, dklen=64).hex()
    if a in ('shake128', 'shakeke128'):
        return hashlib.shake_128(b).hexdigest(32)
    if a == 'shake256':
        return hashlib.shake_256(b).hexdigest(64)
    fn = _HASH_FUNCS.get(a)
    return fn(b) if fn else None

def validate_hash_length(a: str, h: str) -> bool:
    if a in {'bcrypt', 'argon2id', 'scrypt', 'phpass_md5', 'ntlm'}:
        return True
    exp = hash_lengths.get(a)
    return False if exp and len(h) != exp else True

_cpu_last = 0.0
def throttle_cpu():
    global _cpu_last
    if _cpu_last > CPU_USAGE_THRESHOLD:
        time.sleep(0.2)

def check_password_cpu(p: str, d: str, a: str) -> Tuple[bool, Optional[str]]:
    b = p.encode()
    if a == 'bcrypt':
        try:
            if bcrypt.checkpw(b, d.encode()):
                return True, p
        except Exception:
            pass
        return False, None
    if a == 'argon2id':
        try:
            _ARGON2_PH.verify(d, p)
            return True, p
        except Exception:
            return False, None
    if a == 'phpass_md5':
        return (phpass_verify(p, d), p) if phpass_verify(p, d) else (False, None)
    if a == 'ntlm':
        try:
            if nthash.verify(p, d):
                return True, p
        except Exception:
            return False, None
        return False, None
    matched = hash_password(p, a) == d
    return (matched, p) if matched else (False, None)

def _process_chunk(chunk: List[str], d: str, a: str, step: int) -> Tuple[int, Optional[str]]:
    processed = 0
    for idx in range(len(chunk)):
        pwd = chunk[idx]
        ok, found = check_password_cpu(pwd, d, a)
        processed += 1
        if ok:
            return processed, found
        if processed % step == 0:
            throttle_cpu()
    return processed, None

def detect_file_encoding(path: str, sample: int = 10000) -> str:
    if chardet is None:
        return 'utf-8'
    try:
        with open(path, 'rb') as f:
            return chardet.detect(f.read(sample)).get('encoding') or 'utf-8'
    except Exception:
        return 'utf-8'

def get_line_count(path: str) -> int:
    try:
        enc = _ENC_CACHE.get(path) or detect_file_encoding(path)
        _ENC_CACHE[path] = enc
        with open(path, 'r', encoding=enc, errors='replace') as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def lines_in_chunks(path: str, chunk: int = 300_000):
    try:
        enc = _ENC_CACHE.get(path) or detect_file_encoding(path)
        _ENC_CACHE[path] = enc
        with open(path, 'r', encoding=enc, errors='replace') as f:
            batch = []
            for line in f:
                batch.append(line.rstrip('\n'))
                if len(batch) >= chunk:
                    yield batch
                    batch = []
            if batch:
                yield batch
    except Exception:
        return

def _generate_passwords(chars: str, length: int, chunk: int = 100000):
    batch = []
    for tup in itertools.product(chars, repeat=length):
        batch.append(''.join(tup))
        if len(batch) >= chunk:
            yield batch
            batch = []
    if batch:
        yield batch

def dictionary_crack_worker(path: str, d: str, a: str, state: CrackerState,
                             step: int, cb) -> None:
    if not os.path.exists(path):
        write_log(f"Dictionary {path} not found")
        return
    for chunk in lines_in_chunks(path):
        if state.abort_requested or state.found_password:
            break
        fut = _POOL.submit(_process_chunk, chunk, d, a, step)
        try:
            processed, found = fut.result()
        except Exception:
            continue
        with state.progress_lock:
            state.passwords_tried += processed
            pct = (state.passwords_tried / state.total_passwords * 100) if state.total_passwords else 0
        cb(pct, state)
        if found:
            with state.found_lock:
                state.found_password = found
                state.abort_requested = True
            break

def concurrent_hash_cracker(dicts: List[str], d: str, a: str,
                            state: CrackerState, cb, done) -> None:
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    state.cracking_complete = False
    write_log("Dictionary cracking started")
    state.start_time = time.time()
    state.total_passwords = sum(get_line_count(p) for p in dicts if os.path.exists(p))
    if not state.total_passwords:
        write_log("Empty dictionaries")
        done(None)
        return
    max_workers = min(state.threads_count, len(dicts))
    with ThreadPoolExecutor(max_workers=max_workers) as tpe:
        futs = [tpe.submit(dictionary_crack_worker, p, d, a, state, 5_000_000, cb)
                for p in dicts if os.path.exists(p)]
        while True:
            if state.found_password:
                state.abort_requested = True
                for f in futs:
                    f.cancel()
                break
            if all(f.done() for f in futs):
                break
            time.sleep(0.05)
    write_log("Dictionary cracking complete")
    done(state.found_password)

def brute_force_crack(d: str, a: str, chars: str, length: int,
                      state: CrackerState, cb, done) -> None:
    state.found_password   = None
    state.passwords_tried  = 0
    state.abort_requested  = False
    state.cracking_complete = False
    state.start_time       = time.time()
    state.total_passwords  = len(chars) ** length
    write_log("Bruteforce started")
    for chunk in _generate_passwords(chars, length):
        if state.abort_requested or state.found_password:
            break
        size = max(1, len(chunk) // state.threads_count)
        subs = [chunk[i:i + size] for i in range(0, len(chunk), size)]
        futs = [_POOL.submit(_process_chunk, s, d, a, 5_000_000) for s in subs]
        for fut in cf.as_completed(futs):
            if state.abort_requested:
                break
            try:
                proc, found = fut.result()
            except Exception:
                continue
            with state.progress_lock:
                state.passwords_tried += proc
                pct = (state.passwords_tried / state.total_passwords * 100) if state.total_passwords else 0
            cb(pct, state)
            if found:
                with state.found_lock:
                    state.found_password = found
                    state.abort_requested = True
                break
        if state.found_password or state.abort_requested:
            break
    write_log("Bruteforce complete")
    done(state.found_password)
class HashCrackerGUI:
    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("ClatsCracker Hash Tool GUI v1.06.5")
        master.geometry("800x800")
        master.resizable(False, False)

        self.state = CrackerState()
        self.current_hash = ""
        self.current_algo = ""
        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        branding_text = r"""
 ██████╗██╗      █████╗ ████████╗███████╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║     ██║     ███████║   ██║   ███████╗██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║     ██║     ██╔══██║   ██║   ╚════██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
           C L A T S C R A C K E R     H A S H     T O O L   (Version 1.06.5)
          Multi-algorithm hash cracking tool. Ethical use only.
         🛡️By Josh Clatney - Ethical Pentesting Enthusiast  🛡️
"""
        self.branding_label = tk.Label(self.main_frame, text=branding_text,
                                       font=("Courier", 10, "bold"),
                                       justify="center", fg="blue",
                                       bg="lightgrey", anchor="center")
        self.branding_label.grid(row=0, column=0, columnspan=5, pady=(0, 10), sticky="n")
        ttk.Label(self.main_frame, text="Hash Value:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.hash_entry = ttk.Entry(self.main_frame, width=60)
        self.hash_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Button(self.main_frame, text="Paste", command=self._paste).grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        ttk.Label(self.main_frame, text="Algorithm:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.algo_var = tk.StringVar()
        self.algo_box = ttk.Combobox(
            self.main_frame, textvariable=self.algo_var, state="readonly",
            values=['auto'] + sorted(hash_lengths) +
                   ['bcrypt', 'scrypt', 'argon2id', 'phpass_md5', 'ntlm',
                    'ntplm', 'shake128', 'shake256', 'shakeke128']
        )
        self.algo_box.current(0)
        self.algo_box.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Label(self.main_frame, text="Method:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.method_var = tk.StringVar(value='dictionary')
        ttk.Radiobutton(self.main_frame, text="Dictionary",
                        variable=self.method_var, value='dictionary',
                        command=self._toggle).grid(row=3, column=1, sticky=tk.W)
        ttk.Radiobutton(self.main_frame, text="Bruteforce",
                        variable=self.method_var, value='brute',
                        command=self._toggle).grid(row=3, column=2, sticky=tk.W)
        ttk.Label(self.main_frame, text="Dictionaries:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.dict_list = tk.Listbox(self.main_frame, width=60, height=4, selectmode=tk.MULTIPLE)
        self.dict_list.grid(row=4, column=1, sticky=tk.W)
        ttk.Button(self.main_frame, text="Add", command=self._add_dict).grid(row=4, column=2, sticky=tk.W, padx=5)
        ttk.Button(self.main_frame, text="Remove", command=self._rem_dict).grid(row=4, column=3, sticky=tk.W, padx=5)
        ttk.Label(self.main_frame, text="Charset:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.charset_var = tk.StringVar()
        self.charset_box = ttk.Combobox(self.main_frame, textvariable=self.charset_var,
                                        state="readonly",
                                        values=['Alphanumeric', 'Hex', 'ASCII', 'Custom'])
        self.charset_box.current(0)
        self.charset_box.grid(row=5, column=1, sticky=tk.W)
        self.charset_box.bind("<<ComboboxSelected>>", self._charset_toggle)
        self.charset_custom = ttk.Entry(self.main_frame, width=40, state='disabled')
        self.charset_custom.grid(row=5, column=2, sticky=tk.W)
        ttk.Label(self.main_frame, text="Length:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.len_entry = ttk.Entry(self.main_frame, width=10)
        self.len_entry.insert(0, "1")
        self.len_entry.grid(row=6, column=1, sticky=tk.W)
        ttk.Label(self.main_frame, text="Threads:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.thr_var = tk.StringVar(value=str(_DEFAULT_THREADS))
        self.thr_box = ttk.Combobox(self.main_frame, textvariable=self.thr_var,
                                    state="readonly",
                                    values=['1 (Low)', f'{_DEFAULT_THREADS} (Medium)',
                                            f'{os.cpu_count() or 1} (High)', 'Custom'])
        self.thr_box.current(1)
        self.thr_box.grid(row=7, column=1, sticky=tk.W)
        self.thr_box.bind("<<ComboboxSelected>>", self._thr_toggle)
        self.thr_custom = ttk.Entry(self.main_frame, width=10, state='disabled')
        self.thr_custom.grid(row=7, column=2, sticky=tk.W)
        ttk.Button(self.main_frame, text="Start", command=self._start).grid(row=8, column=1, sticky=tk.W, pady=15)
        self.abort_btn = ttk.Button(self.main_frame, text="Abort",
                                    command=self._abort, state='disabled')
        self.abort_btn.grid(row=8, column=2, sticky=tk.W, pady=15)
        self.progress = ttk.Progressbar(self.main_frame, orient='horizontal',
                                        length=600, mode='determinate')
        self.progress.grid(row=9, column=0, columnspan=4, pady=10)
        self.tried_var = tk.StringVar(value="Tried:0")
        self.pct_var   = tk.StringVar(value="0%")
        self.eta_var   = tk.StringVar(value="ETA:N/A")
        self.aps_var   = tk.StringVar(value="APS:0")
        m = ttk.Frame(self.main_frame); m.grid(row=10, column=0, columnspan=4, sticky='w')
        ttk.Label(m, textvariable=self.tried_var).grid(row=0, column=0, padx=5)
        ttk.Label(m, textvariable=self.pct_var  ).grid(row=0, column=1, padx=5)
        ttk.Label(m, textvariable=self.eta_var  ).grid(row=0, column=2, padx=5)
        ttk.Label(m, textvariable=self.aps_var  ).grid(row=0, column=3, padx=5)
        self.log = scrolledtext.ScrolledText(self.main_frame, width=90, height=10, state='disabled')
        self.log.grid(row=11, column=0, columnspan=4, pady=10)
        self._toggle()
        self._metrics()

    def _gui(self, f, *a, **k):
        self.master.after(0, f, *a, **k)

    def _add_dict(self):
        for f in filedialog.askopenfilenames(title="Select Dictionaries",
                                             filetypes=[("Text", "*.txt"), ("All", "*.*")]):
            if f not in self.dict_list.get(0, tk.END):
                self.dict_list.insert(tk.END, f)

    def _rem_dict(self):
        for i in reversed(self.dict_list.curselection()):
            self.dict_list.delete(i)

    def _charset_toggle(self, _=None):
        if self.charset_box.get() == 'Custom':
            self.charset_custom.config(state='normal')
        else:
            self.charset_custom.delete(0, tk.END)
            self.charset_custom.config(state='disabled')

    def _thr_toggle(self, _=None):
        if self.thr_box.get() == 'Custom':
            self.thr_custom.config(state='normal')
        else:
            self.thr_custom.delete(0, tk.END)
            self.thr_custom.config(state='disabled')

    def _toggle(self):
        dic = self.method_var.get() == 'dictionary'
        st  = 'normal' if dic else 'disabled'
        self.dict_list.config(state=st)
        for widget in (self.charset_box, self.charset_custom, self.len_entry):
            widget.config(state='disabled' if dic else 'normal')

    def _paste(self):
        try:
            self.hash_entry.delete(0, tk.END)
            self.hash_entry.insert(0, self.master.clipboard_get())
        except tk.TclError:
            messagebox.showerror("Clipboard", "Empty")

    def _charset(self) -> str:
        c = self.charset_box.get()
        if c == 'Alphanumeric':
            return string.ascii_letters + string.digits
        if c == 'Hex':
            return string.hexdigits.lower()
        if c == 'ASCII':
            return ''.join(chr(i) for i in range(33, 127))
        if c == 'Custom':
            return self.charset_custom.get()
        return string.ascii_letters + string.digits

    def _threads(self) -> int:
        t = self.thr_box.get()
        if t.isdigit():
            return int(t)
        if t == 'Custom' and self.thr_custom.get().isdigit():
            return int(self.thr_custom.get())
        return _DEFAULT_THREADS

    def _metrics(self):
        if self.state.start_time:
            elapsed = max(1e-3, time.time() - self.state.start_time)
            aps     = self.state.passwords_tried / elapsed
        else:
            aps = 0.0
        self.tried_var.set(f"Tried:{self.state.passwords_tried}")
        self.aps_var.set(f"APS:{aps:.2f}")
        if not self.state.cracking_complete:
            self.master.after(500, self._metrics)

    def _log(self, msg: str):
        def append():
            self.log.config(state='normal')
            self.log.insert(tk.END, msg + "\n")
            self.log.see(tk.END)
            self.log.config(state='disabled')
        self._gui(append)

    def _progress(self, pct: float, state: CrackerState):
        self._gui(self._progress_ui, pct, state)

    def _progress_ui(self, pct: float, state: CrackerState):
        self.progress['value'] = pct
        self.pct_var.set(f"{pct:.2f}%")
        if state.start_time and state.passwords_tried:
            elapsed = time.time() - state.start_time
            aps     = state.passwords_tried / elapsed
            remaining = max(0, state.total_passwords - state.passwords_tried)
            eta     = remaining / aps if aps else float('inf')
            self.eta_var.set(f"ETA:{eta:.1f}s")
        else:
            self.eta_var.set("ETA:N/A")

    def _done(self, pwd: Optional[str]):
        self._gui(self._done_ui, pwd)

    def _done_ui(self, pwd: Optional[str]):
        self.state.cracking_complete = True
        self.abort_btn.config(state='disabled')
        logger.handlers[0].flush()
        elapsed = time.time() - self.state.start_time if self.state.start_time else 0
        if pwd:
            write_log(f"SessionEnd | Script:{SCRIPT_NAME} | Hash:{self.current_hash} | "
                      f"Algorithm:{self.current_algo} | Cracked:Yes | Password:{pwd} | "
                      f"Duration:{elapsed:.2f}s")
            self._log("Found:" + pwd)
            messagebox.showinfo("Cracked", pwd)
        else:
            if self.state.abort_requested:
                write_log(f"SessionEnd | Script:{SCRIPT_NAME} | Hash:{self.current_hash} | "
                          f"Algorithm:{self.current_algo} | Cracked:Aborted | "
                          f"Duration:{elapsed:.2f}s")
                self._log("Aborted")
                messagebox.showwarning("Aborted", "Process aborted")
            else:
                write_log(f"SessionEnd | Script:{SCRIPT_NAME} | Hash:{self.current_hash} | "
                          f"Algorithm:{self.current_algo} | Cracked:No | "
                          f"Duration:{elapsed:.2f}s")
                self._log("Not found")
                messagebox.showinfo("Done", "Password not found")
        self.progress['value'] = 0

    def _abort(self):
        if messagebox.askyesno("Abort", "Abort process?"):
            self.state.abort_requested = True
            self.abort_btn.config(state='disabled')

    def _start(self):
        d = self.hash_entry.get().strip()
        if not d:
            messagebox.showerror("Input", "Enter hash")
            return
        a_raw = self.algo_box.get()
        a     = canonical_algo(a_raw)
        if a == 'auto':
            cand = guess_hash_algorithm(d)
            if not cand:
                messagebox.showerror("Algorithm", "Unknown")
                return
            if len(cand) == 1:
                a = cand[0]
                self._log("Detected:" + a)
            else:
                sel = self._choose(cand)
                if not sel:
                    return
                a = sel
        if not validate_hash_length(a, d):
            messagebox.showerror("Length", "Mismatch")
            return
        self.state.threads_count = self._threads()
        self.state.cracking_complete = False
        self.progress['value'] = 0
        self.abort_btn.config(state='normal')
        self._log("Starting")
        self.current_hash = d
        self.current_algo = a
        write_log(f"SessionStart | Script:{SCRIPT_NAME} | Hash:{d} | "
                  f"Algorithm:{a} | StartTime:{time.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.method_var.get() == 'dictionary':
            dicts = self.dict_list.get(0, tk.END)
            if not dicts:
                messagebox.showerror("Dictionary", "Add files")
                return
            threading.Thread(target=concurrent_hash_cracker,
                             args=(list(dicts), d, a, self.state,
                                   self._progress, self._done),
                             daemon=True).start()
        else:
            if a not in _HASH_FUNCS and a not in {'sha1_v2', 'scrypt', 'ntlm',
                                                  'ntplm', 'sha512_224', 'sha512_256',
                                                  'shake128', 'shake256', 'shakeke128'}:
                messagebox.showerror("Unsupported", "Bruteforcing not supported")
                return
            cs = self._charset()
            if not cs:
                messagebox.showerror("Charset", "Empty")
                return
            l_str = self.len_entry.get().strip()
            if not (l_str.isdigit() and int(l_str) > 0):
                messagebox.showerror("Length", "Invalid")
                return
            threading.Thread(target=brute_force_crack,
                             args=(d, a, cs, int(l_str), self.state,
                                   self._progress, self._done),
                             daemon=True).start()

    def _choose(self, cands: List[str]) -> Optional[str]:
        w = tk.Toplevel(self.master)
        w.title("Select")
        w.geometry("200x200")
        w.grab_set()
        lb = tk.Listbox(w)
        for c in cands:
            lb.insert(tk.END, c)
        lb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        sel = []
        def ok():
            if lb.curselection():
                sel.append(lb.get(lb.curselection()[0]))
                w.destroy()
            else:
                messagebox.showerror("Select", "Choose")
        ttk.Button(w, text="Select", command=ok).pack(pady=5)
        self.master.wait_window(w)
        return sel[0] if sel else None

def _worker_init(nice_val: int):
    try:
        os.nice(nice_val)
    except AttributeError:
        pass

def main() -> None:
    mp.freeze_support()
    try:
        mp.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    global _POOL
    _POOL = ProcessPoolExecutor(max_workers=os.cpu_count() or 1,
                                initializer=_worker_init, initargs=(5,))
    root = tk.Tk()
    HashCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()