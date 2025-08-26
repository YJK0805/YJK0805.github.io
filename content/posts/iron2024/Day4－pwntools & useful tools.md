---
title: "Day4－pwntools & useful tools"
date: 2024-09-18
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

這篇文章整理了筆者在練習 CTF 題目時常用的工具，有些工具在後續也會頻繁使用。另外，如果你有興趣一起跟著文章進行練習，可以使用文中提供的 Docker 環境，裡面已經包含了後續教學中會使用到的工具，此 [repo](https://github.com/YJK0805/PWN-CTF-note) 包含後面的題目及環境

## 環境

Dockerfile

```
FROM ubuntu:22.04
MAINTAINER YJK

RUN apt-get update
RUN yes | unminimize
RUN apt-get install -y tini iproute2 iputils-ping net-tools netcat
RUN apt-get install -y openssh-server sudo vim grep gawk rsync tmux diffutils file
RUN apt-get install -y gcc gdb make yasm nasm tcpdump python3 python3-pip python3-virtualenv
RUN apt-get install -y gcc-multilib g++-multilib
RUN apt-get install -y libc6-dbg dpkg-dev
RUN apt-get install -y curl git zsh
RUN apt-get install -y ruby-dev wget
RUN pip3 install pwntools capstone filebytes keystone-engine ropper
RUN gem install seccomp-tools
RUN gem install one_gadget
RUN mkdir /var/run/sshd

RUN echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config
RUN sed -i 's/nullok_secure/nullok/' /etc/pam.d/common-auth

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER root
RUN git clone https://github.com/pwndbg/pwndbg ~/pwndbg
RUN cd ~/pwndbg && ./setup.sh
RUN git clone https://github.com/scwuaptx/Pwngdb.git ~/Pwngdb
RUN cp ~/Pwngdb/.gdbinit ~/
RUN rm -rf ~/.gdbinit
RUN echo "source ~/pwndbg/gdbinit.py" >> ~/.gdbinit
RUN echo "source ~/Pwngdb/pwngdb.py" >> ~/.gdbinit
RUN echo "source ~/Pwngdb/angelheap/gdbinit.py" >> ~/.gdbinit
RUN echo "define hook-run" >> ~/.gdbinit
RUN echo "python" >> ~/.gdbinit
RUN echo "import angelheap" >> ~/.gdbinit
RUN echo "angelheap.init_angelheap()" >> ~/.gdbinit
RUN echo "end" >> ~/.gdbinit
RUN echo "end" >> ~/.gdbinit

USER root
# run the service
EXPOSE 22
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/sbin/sshd", "-D"]
```

docker-compose.yml

```yml=
version: '2'

services:
  main:
    build: .
    restart: unless-stopped
    privileged: true
    ports:
      - "22224:22"
    environment:
      - EDITOR=vim
    volumes:
      - ./share:/home
    networks:
        default:

networks:
    default:
```

## Useful Tools

### objdump

- 用於查看檔案的各種資訊
- 常用功能是反組譯程式
    - 使用 `objdump -M intel -d chal`，`-M intel` 指定架構為 Intel，`-d chal` 指定要反組譯的檔案為 `chal`

![objdump](/images/iron2024/day4_image1.png)

### checksec

- 查看檔案開啟了哪些保護機制
- Pwntools 內建此功能，也可以手動安裝 `checksec.sh`

![checksec](/images/iron2024/day4_image2.png)

### one_gadget

- 如果能控制好 `rbp` 和 return address，就有機會使用 one_gadget 取得 shell
- 用於 libc 的利用
- 後續內容會進一步介紹

![one_gadget](/images/iron2024/day4_image3.png)

### nc

- 遠端連線工具
- 題目幾乎都是使用 `nc` 進行連線

### seccomp-tools

- 用來檢查程式的 seccomp 規則
- 可以幫助了解應該撰寫什麼樣的 shellcode，或避免使用哪些函數

![seccomp-tools](/images/iron2024/day4_image4.png)

### ROPgadget、ropper

- 這兩個工具用來列出 binary 中可以使用的 ROP gadgets
- 也能幫助快速產出 ROP chain

![ROPgadget](/images/iron2024/day4_image5.png)

![ropper](/images/iron2024/day4_image6.png)

### gdb

- Command line 形式的除錯工具
- 有多種插件可以讓 gdb 更加好用

#### gdb Plugins

- [peda](https://github.com/longld/peda)
- [pwndbg](https://github.com/pwndbg/pwndbg)
    - 專為 pwn 開發的插件
    - 提供許多方便打 pwn 時使用的指令
- [gef](https://github.com/hugsy/gef)
- [pwngdb](https://github.com/scwuaptx/Pwngdb)
    - 由大神 angelboy 撰寫
    - 提供多種方便 pwn 利用的指令

筆者提供的 Docker 環境即包含 pwndbg 和 pwngdb。

## Pwntools

- 匯入套件
    - `from pwn import *`
- 連線到遠端
    - `remote('IP address', port)`
- 執行本地端程式
    - `process('./chal')`
- 傳送資料
    - `r.send(payload)`：傳送 payload
    - `r.sendline(payload)`：傳送 payload 並換行
    - `r.sendafter(string, payload)`：在收到指定 string 後傳送 payload
    - `r.sendlineafter(string, payload)`：在收到指定 string 後傳送 payload 並換行
- 接收資料
    - `r.recv(n)`：接收 n 個字元
    - `r.recvline()`：接收一行資料
    - `r.recvlines(n)`：接收 n 行資料
    - `r.recvuntil(string)`：接收到指定的 string 為止
- 取得互動控制
    - `r.interactive()`
- 將數字轉為特定架構格式
    - `p32(0xdeadbeef)`
    - `p64(0xdeadbeef)`
- 將資料轉回數字
    - `hex(u32(b'\xef\xbe\xad\xde'))`
    - `hex(u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00'))`
- 從 local 端程式進行 debug
    - `gdb.attach(r)`
    - 可以指定視窗分割模式
        - `context.terminal = ["tmux", "splitw", "-h"]`
