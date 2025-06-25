from __future__ import annotations
from tkinter import filedialog, messagebox, scrolledtext, ttk
import hashlib, hmac, os, sys, time, itertools, string, logging, zlib, threading, concurrent.futures as cf, tkinter as tk, multiprocessing as mp, mmap, subprocess
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from logging.handlers import RotatingFileHandler
from typing import List, Optional, Tuple, Dict

def _pip_install(pkg: str) -> None:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])
    except Exception:
        pass

try:
    from argon2 import PasswordHasher, Type
except ImportError:
    _pip_install("argon2-cffi")
    from argon2 import PasswordHasher, Type

try:
    from passlib.hash import nthash
except ImportError:
    _pip_install("passlib")
    from passlib.hash import nthash

_HAS_FAST_HASHES = False
try:
    from Crypto.Hash import MD4 as _MD4, RIPEMD160 as _RIPEMD160
    _HAS_FAST_HASHES = True
except ImportError:
    _pip_install("pycryptodome")
    try:
        from Crypto.Hash import MD4 as _MD4, RIPEMD160 as _RIPEMD160
        _HAS_FAST_HASHES = True
    except ImportError:
        _HAS_FAST_HASHES = False

try:
    import bcrypt
except ImportError:
    _pip_install("bcrypt")
    try:
        import bcrypt
    except ImportError:
        bcrypt = None

try:
    import psutil
except ImportError:
    _pip_install("psutil")
    try:
        import psutil
    except ImportError:
        psutil = None

try:
    import chardet
except ImportError:
    _pip_install("chardet")
    try:
        import chardet
    except ImportError:
        chardet = None

CPU_USAGE_THRESHOLD = 99.5
_CPU_CHECK_INTERVAL = 0.2
_SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
LOG_FILE = os.path.join(_SCRIPT_DIR, "Hash_Cracking_Results_ClatsCracker.txt")
ALIAS_MAP = {'shakeke128': 'shake128', 'sha1v2': 'sha1_v2', 'ntplm': 'ntlm', 'md5-sha1': 'md5_sha1'}
_DEFAULT_THREADS = max(1, (os.cpu_count() or 1))
_ENC_CACHE: Dict[str, str] = {}
SCRIPT_NAME = os.path.basename(sys.argv[0] if sys.argv else '')
logger = logging.getLogger("clatscracker")
logger.setLevel(logging.INFO)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(filename)s — %(message)s"))
logger.addHandler(_fh)
write_log = logger.info

hash_lengths = {'crc32': 8,'adler32': 8,'md4': 32,'md5': 32,'ripemd160': 40,'sha1': 40,'sha1_v2': 40,'sha224': 56,'sha256': 64,'sha3_224': 56,'sha3_256': 64,'sha3_384': 96,'sha3_512': 128,'sha512': 128,'sha512_224': 56,'sha512_256': 64,'blake2_224': 56,'blake2b': 128,'blake2s': 64,'sha384': 96,'shake128': 64,'shake256': 128,'shakeke128': 64,'sm3': 64,'md5_sha1': 72,'mdc2': 32,'whirlpool': 128,'scrypt': 128}
_HASH_FUNCS = {
    'crc32': lambda b: format(zlib.crc32(b) & 0xffffffff, '08x'),
    'adler32': lambda b: format(zlib.adler32(b) & 0xffffffff, '08x'),
    'md4': (lambda b: _MD4.new(data=b).hexdigest()) if _HAS_FAST_HASHES else (lambda b: hashlib.new('md4', b).hexdigest()),
    'md5': lambda b: hashlib.md5(b).hexdigest(),
    'ripemd160': (lambda b: _RIPEMD160.new(data=b).hexdigest()) if _HAS_FAST_HASHES else (lambda b: hashlib.new('ripemd160', b).hexdigest()),
    'blake2_224': lambda b: hashlib.blake2b(b, digest_size=28).hexdigest(),
    'sha224': lambda b: hashlib.sha224(b).hexdigest(),'sha256': lambda b: hashlib.sha256(b).hexdigest(),'sha512': lambda b: hashlib.sha512(b).hexdigest(),
    'sha3_224': lambda b: hashlib.sha3_224(b).hexdigest(),'sha3_256': lambda b: hashlib.sha3_256(b).hexdigest(),'sha3_384': lambda b: hashlib.sha3_384(b).hexdigest(),'sha3_512': lambda b: hashlib.sha3_512(b).hexdigest(),
    'sha1': lambda b: hashlib.sha1(b).hexdigest(),'sha512_224': lambda b: hashlib.new('sha512_224', b).hexdigest(),'sha512_256': lambda b: hashlib.new('sha512_256', b).hexdigest(),
    'blake2b': lambda b: hashlib.blake2b(b).hexdigest(),'blake2s': lambda b: hashlib.blake2s(b).hexdigest(),'sha384': lambda b: hashlib.sha384(b).hexdigest(),
    'shake128': lambda b: hashlib.shake_128(b).hexdigest(32),'shake256': lambda b: hashlib.shake_256(b).hexdigest(64),'shakeke128': lambda b: hashlib.shake_128(b).hexdigest(32),
    'sm3': lambda b: hashlib.new('sm3', b).hexdigest(),
    'md5_sha1': lambda b: hashlib.md5(b).hexdigest() + hashlib.sha1(b).hexdigest(),
    'mdc2': lambda b: hashlib.new('mdc2', b).hexdigest(),'whirlpool': lambda b: hashlib.new('whirlpool', b).hexdigest(),
    'scrypt': lambda b: hashlib.scrypt(b, salt=b'', n=16384, r=8, p=1, dklen=64).hex(),
}
_ARGON2_PH = PasswordHasher(type=Type.ID)

def canonical_algo(name: str) -> str:
    return ALIAS_MAP.get(name.lower(), name.lower())

class CrackerState:
    def __init__(self):
        self.passwords_tried = 0
        self.total_passwords = 0
        self.found_password: Optional[str] = None
        self.threads_count = _DEFAULT_THREADS
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
    if h.startswith('$2'):
        return ['bcrypt']
    if h.startswith('$argon2id$'):
        return ['argon2id']
    if (h.startswith('$P$') or h.startswith('$H$')) and len(h) == 34:
        return ['phpass_md5']
    hl, l = h.lower(), len(h)
    if l == 32 and all(c in '0123456789abcdef' for c in hl):
        return ['md5', 'ntlm']
    cand = [k for k, v in hash_lengths.items() if l == v]
    if l == 128 and all(c in '0123456789abcdef' for c in hl):
        cand.append('scrypt')
    return list(dict.fromkeys(cand)) or None

def validate_hash_length(a: str, h: str) -> bool:
    if a in {'bcrypt', 'argon2id', 'scrypt', 'phpass_md5', 'ntlm'}:
        return True
    exp = hash_lengths.get(a)
    return False if exp and len(h) != exp else True

_cpu_last = 0.0
_next_cpu_check = 0.0
def throttle_cpu():
    global _cpu_last, _next_cpu_check
    if psutil:
        now = time.time()
        if now >= _next_cpu_check:
            _cpu_last = psutil.cpu_percent(0.05)
            _next_cpu_check = now + _CPU_CHECK_INTERVAL
    if _cpu_last > CPU_USAGE_THRESHOLD:
        time.sleep(0.2)

def compile_checker(d: str, a: str):
    if a == 'bcrypt':
        ref = d.encode()
        return (lambda p: bcrypt and bcrypt.checkpw(p.encode(), ref))
    if a == 'argon2id':
        def _chk(p: str):
            try:
                _ARGON2_PH.verify(d, p)
                return True
            except Exception:
                return False
        return _chk
    if a == 'phpass_md5':
        return lambda p: phpass_verify(p, d)
    if a == 'ntlm':
        return lambda p: nthash.verify(p, d)
    if a == 'sha1_v2':
        return lambda p: hmac.compare_digest(hashlib.sha1(hashlib.sha1(p.encode()).digest()).hexdigest(), d)
    if a == 'scrypt':
        return lambda p: hmac.compare_digest(hashlib.scrypt(p.encode(), salt=b'', n=16384, r=8, p=1, dklen=64).hex(), d)
    if a in ('shake128', 'shakeke128'):
        return lambda p: hmac.compare_digest(hashlib.shake_128(p.encode()).hexdigest(32), d)
    if a == 'shake256':
        return lambda p: hmac.compare_digest(hashlib.shake_256(p.encode()).hexdigest(64), d)
    fn = _HASH_FUNCS.get(a)
    return (lambda p: fn(p.encode()) == d) if fn else (lambda _: False)

def _process_chunk(chunk: List[str], d: str, a: str, step: int) -> Tuple[int, Optional[str]]:
    checker = compile_checker(d, a)
    processed = 0
    for pwd in chunk:
        processed += 1
        if checker(pwd):
            return processed, pwd
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
        with open(path, 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            lines = []
            for line in iter(mm.readline, b''):
                lines.append(line.rstrip(b'\n').decode(enc, errors='replace'))
                if len(lines) >= chunk:
                    yield lines
                    lines = []
            if lines:
                yield lines
    except Exception:
        return

def _generate_passwords(chars: str, length: int, chunk: int = 100000):
    prod = itertools.product(chars, repeat=length)
    while True:
        slice_ = list(itertools.islice(prod, chunk))
        if not slice_:
            break
        yield [''.join(t) for t in slice_]

def dictionary_crack_worker(path: str, d: str, checker, state: CrackerState, step: int, cb):
    if not os.path.exists(path):
        write_log(f"Dictionary {path} not found")
        return
    for chunk in lines_in_chunks(path):
        if state.abort_requested or state.found_password:
            break
        processed_chunk = 0
        for pwd in chunk:
            if state.abort_requested or state.found_password:
                break
            processed_chunk += 1
            if checker(pwd):
                with state.found_lock:
                    state.found_password = pwd
                    state.abort_requested = True
                    break
        with state.progress_lock:
            state.passwords_tried += processed_chunk
            pct = (state.passwords_tried / state.total_passwords * 100) if state.total_passwords else 0
        cb(pct, state)
        if state.abort_requested or state.found_password:
            break

def concurrent_hash_cracker(dicts: List[str], d: str, a: str, state: CrackerState, cb, done):
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
    checker = compile_checker(d, a)
    max_workers = min(state.threads_count, len(dicts))
    with ThreadPoolExecutor(max_workers=max_workers) as tpe:
        futs = [tpe.submit(dictionary_crack_worker, p, d, checker, state, 5_000_000, cb) for p in dicts if os.path.exists(p)]
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

def brute_force_crack(d: str, a: str, chars: str, length: int, state: CrackerState, cb, done):
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    state.cracking_complete = False
    state.start_time = time.time()
    state.total_passwords = len(chars) ** length
    write_log("Bruteforce started")
    step = max(1, 5_000_000 // state.threads_count)
    for batch in _generate_passwords(chars, length, step):
        if state.abort_requested or state.found_password:
            break
        futs = [_POOL.submit(_process_chunk, batch[i:i + step], d, a, step) for i in range(0, len(batch), step)]
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
        master.title("ClatsCracker Hash Cracking Tool GUI v1.06.9")
        master.geometry("850x820")
        master.resizable(False, False)
        self.state = CrackerState()
        self.current_hash = ""
        self.current_algo = ""
        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        for i in range(5):
            self.main_frame.columnconfigure(i, weight=1)
        branding_text = r"""
 ██████╗██╗      █████╗ ████████╗███████╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║     ██║     ███████║   ██║   ███████╗██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║     ██║     ██╔══██║   ██║   ╚════██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
      C L A T S C R A C K E R      H A S H   C R A C K I N G    T O O L    (Version 1.06.9)
"""
        self.branding_label = ttk.Label(self.main_frame, text=branding_text, font=("Courier", 10, "bold"), justify="center", foreground="blue", background="white", anchor="center")
        self.branding_label.grid(row=0, column=0, columnspan=5, pady=(0, 10), sticky="ew")
        ttk.Label(self.main_frame, text="Hash Value:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.hash_entry = ttk.Entry(self.main_frame, width=60)
        self.hash_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Button(self.main_frame, text="Paste", command=self._paste).grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        ttk.Label(self.main_frame, text="Algorithm:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.algo_var = tk.StringVar()
        self.algo_box = ttk.Combobox(self.main_frame, textvariable=self.algo_var, state="readonly", values=['auto', *sorted(hash_lengths), 'bcrypt', 'scrypt', 'argon2id', 'phpass_md5', 'ntlm', 'ntplm', 'shake128', 'shake256', 'shakeke128'])
        self.algo_box.current(0)
        self.algo_box.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Label(self.main_frame, text="Method:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.method_var = tk.StringVar(value='dictionary')
        ttk.Radiobutton(self.main_frame, text="Dictionary", variable=self.method_var, value='dictionary', command=self._toggle).grid(row=3, column=1, sticky=tk.W)
        ttk.Radiobutton(self.main_frame, text="Bruteforce", variable=self.method_var, value='brute', command=self._toggle).grid(row=3, column=2, sticky=tk.W)
        ttk.Label(self.main_frame, text="Dictionaries:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.dict_list = tk.Listbox(self.main_frame, width=60, height=4, selectmode=tk.MULTIPLE)
        self.dict_list.grid(row=4, column=1, sticky=tk.W)
        ttk.Button(self.main_frame, text="Add", command=self._add_dict).grid(row=4, column=2, sticky=tk.W, padx=5)
        ttk.Button(self.main_frame, text="Remove", command=self._rem_dict).grid(row=4, column=3, sticky=tk.W, padx=5)
        ttk.Label(self.main_frame, text="Charset:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.charset_var = tk.StringVar()
        self.charset_box = ttk.Combobox(self.main_frame, textvariable=self.charset_var, state="readonly", values=['Alphanumeric', 'Hex', 'ASCII', 'Custom'])
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
        self.thr_var = tk.StringVar()
        self.thr_box = ttk.Combobox(self.main_frame, textvariable=self.thr_var, state="readonly", values=['1 (Low)', '8 (Medium)', '12 (High)', 'Custom'])
        self.thr_box.current(1)
        self.thr_box.grid(row=7, column=1, sticky=tk.W)
        self.thr_box.bind("<<ComboboxSelected>>", self._thr_toggle)
        self.thr_custom = ttk.Entry(self.main_frame, width=10, state='disabled')
        self.thr_custom.grid(row=7, column=2, sticky=tk.W)
        ttk.Button(self.main_frame, text="Start", command=self._start).grid(row=8, column=1, sticky=tk.W, pady=15)
        self.abort_btn = ttk.Button(self.main_frame, text="Abort", command=self._abort, state='disabled')
        self.abort_btn.grid(row=8, column=2, sticky=tk.W, pady=15)
        self.progress = ttk.Progressbar(self.main_frame, orient='horizontal', length=600, mode='determinate')
        self.progress.grid(row=9, column=0, columnspan=4, pady=10)
        self.tried_var = tk.StringVar(value="Tried:0")
        self.pct_var = tk.StringVar(value="0%")
        self.eta_var = tk.StringVar(value="ETA:N/A")
        self.aps_var = tk.StringVar(value="APS:0")
        m = ttk.Frame(self.main_frame)
        m.grid(row=10, column=0, columnspan=4, sticky='w')
        ttk.Label(m, textvariable=self.tried_var).grid(row=0, column=0, padx=5)
        ttk.Label(m, textvariable=self.pct_var).grid(row=0, column=1, padx=5)
        ttk.Label(m, textvariable=self.eta_var).grid(row=0, column=2, padx=5)
        ttk.Label(m, textvariable=self.aps_var).grid(row=0, column=3, padx=5)
        self.log = scrolledtext.ScrolledText(self.main_frame, width=90, height=10, state='disabled')
        self.log.grid(row=11, column=0, columnspan=4, pady=10)
        self._toggle()
        self._metrics()

    def _gui(self, fn, *a, **k):
        self.master.after(0, fn, *a, **k)
    def _add_dict(self):
        files = filedialog.askopenfilenames(title="Select Dictionaries", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        for f in files:
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
        st = 'normal' if dic else 'disabled'
        self.dict_list.config(state=st)
        for w in (self.charset_box, self.charset_custom, self.len_entry):
            w.config(state='disabled' if dic else 'normal')
    def _paste(self):
        try:
            self.hash_entry.delete(0, tk.END)
            self.hash_entry.insert(0, self.master.clipboard_get())
        except tk.TclError:
            messagebox.showerror("Clipboard", "Clipboard is empty")
    def _charset(self) -> str:
        c = self.charset_box.get()
        if c == 'Alphanumeric':
            return string.ascii_letters + string.digits
        if c == 'Hex':
            return '0123456789abcdef'
        if c == 'ASCII':
            return ''.join(chr(i) for i in range(33, 127))
        if c == 'Custom':
            return self.charset_custom.get()
        return string.ascii_letters + string.digits
    def _threads(self) -> int:
        t = self.thr_box.get()
        if t.startswith('Custom') and self.thr_custom.get().isdigit():
            return int(self.thr_custom.get())
        first = t.split()[0]
        if first.isdigit():
            return int(first)
        return os.cpu_count() or 1
    def _metrics(self):
        if self.state.start_time:
            elapsed = max(1e-3, time.time() - self.state.start_time)
            aps = self.state.passwords_tried / elapsed
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
            aps = state.passwords_tried / elapsed
            remaining = max(0, state.total_passwords - state.passwords_tried)
            eta = remaining / aps if aps else float('inf')
            self.eta_var.set(f"ETA:{eta:.1f}s")
        else:
            self.eta_var.set("ETA:N/A")
    def _done(self, pwd: Optional[str]):
        self._gui(self._done_ui, pwd)
    def _done_ui(self, pwd: Optional[str]):
        self.state.cracking_complete = True
        self.abort_btn.config(state='disabled')
        try:
            logger.handlers[0].flush()
        except Exception:
            pass
        elapsed = time.time() - self.state.start_time if self.state.start_time else 0
        if pwd:
            write_log(f"SessionEnd | Script:{SCRIPT_NAME} | Hash:{self.current_hash} | Algorithm:{self.current_algo} | Cracked:Yes | Password:{pwd} | Duration:{elapsed:.2f}s")
            self._log("Found: " + pwd)
            messagebox.showinfo("Cracked", pwd)
        else:
            if self.state.abort_requested:
                write_log(f"SessionEnd | Script:{SCRIPT_NAME} | Hash:{self.current_hash} | Algorithm:{self.current_algo} | Cracked:Aborted | Duration:{elapsed:.2f}s")
                self._log("Aborted")
                messagebox.showwarning("Aborted", "Process aborted")
            else:
                write_log(f"SessionEnd | Script:{SCRIPT_NAME} | Hash:{self.current_hash} | Algorithm:{self.current_algo} | Cracked:No | Duration:{elapsed:.2f}s")
                self._log("Not found")
                messagebox.showinfo("Done", "Password not found")
        self.progress['value'] = 0
    def _abort(self):
        if messagebox.askyesno("Abort", "Abort the cracking process?"):
            self.state.abort_requested = True
            self.abort_btn.config(state='disabled')
            try:
                _POOL.shutdown(cancel_futures=True, wait=False)
            except Exception:
                pass
    def _start(self):
        d = self.hash_entry.get().strip()
        a_raw = self.algo_box.get()
        if not d:
            messagebox.showerror("Input", "Enter a hash value")
            return
        a = canonical_algo(a_raw)
        if a == 'auto':
            cand = guess_hash_algorithm(d)
            if not cand:
                messagebox.showerror("Algorithm", "Unable to guess algorithm")
                return
            a = cand[0] if len(cand) == 1 else (self._choose(cand) or '')
            if not a:
                return
            self._log("Detected: " + a)
        if not validate_hash_length(a, d):
            messagebox.showerror("Length", "Hash length does not match algorithm")
            return
        self.state.threads_count = self._threads()
        self.state.cracking_complete = False
        self.progress['value'] = 0
        self.abort_btn.config(state='normal')
        self._log("Starting …")
        self.current_hash = d
        self.current_algo = a
        write_log(f"SessionStart | Script:{SCRIPT_NAME} | Hash:{d} | Algorithm:{a} | StartTime:{time.strftime('%Y-%m-%d %H:%M:%S')}")
        global _POOL
        try:
            _POOL.shutdown(cancel_futures=True, wait=False)
        except Exception:
            pass
        _POOL = ProcessPoolExecutor(max_workers=self.state.threads_count, initializer=_worker_init, initargs=(0,))
        if self.method_var.get() == 'dictionary':
            dicts = list(self.dict_list.get(0, tk.END))
            if not dicts:
                messagebox.showerror("Dictionary", "Add at least one dictionary file")
                return
            threading.Thread(target=concurrent_hash_cracker, args=(dicts, d, a, self.state, self._progress, self._done), daemon=True).start()
        else:
            if a not in _HASH_FUNCS and a not in {'sha1_v2', 'scrypt', 'ntlm', 'ntplm', 'sha512_224', 'sha512_256', 'shake128', 'shake256', 'shakeke128'}:
                messagebox.showerror("Unsupported", "Bruteforce not supported for this algorithm")
                return
            cs = self._charset()
            l_str = self.len_entry.get().strip()
            if not cs:
                messagebox.showerror("Charset", "Character set is empty")
                return
            if not (l_str.isdigit() and int(l_str) > 0):
                messagebox.showerror("Length", "Invalid length")
                return
            threading.Thread(target=brute_force_crack, args=(d, a, cs, int(l_str), self.state, self._progress, self._done), daemon=True).start()
    def _choose(self, cands: List[str]) -> Optional[str]:
        w = tk.Toplevel(self.master)
        w.title("Select algorithm")
        w.geometry("200x200")
        w.grab_set()
        lb = tk.Listbox(w)
        for c in cands:
            lb.insert(tk.END, c)
        lb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        sel = []
        def ok():
            sel.append(lb.get(lb.curselection()[0]) if lb.curselection() else '')
            if sel[0]:
                w.destroy()
            else:
                messagebox.showerror("Select", "Choose an algorithm")
        ttk.Button(w, text="Select", command=ok).pack(pady=5)
        self.master.wait_window(w)
        return sel[0] if sel else None

def _worker_init(nice_val: int):
    try:
        os.nice(nice_val)
    except AttributeError:
        pass

def main():
    mp.freeze_support()
    try:
        mp.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    global _POOL
    _POOL = ProcessPoolExecutor(max_workers=os.cpu_count() or 1, initializer=_worker_init, initargs=(0,))
    root = tk.Tk()
    HashCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()