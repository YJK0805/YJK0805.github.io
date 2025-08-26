---
title: "Day26－Heap overflow"
date: 2024-10-10
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

前兩天介紹了 Use After Free 的概念和利用方式，今天要介紹另一種 Overflow，稱為 Heap Overflow。

## Heap overflow

Heap Overflow 簡單來說就是發生在 heap 段的 buffer overflow。與 Stack Overflow 不同，它通常無法直接控制程式的執行流程。取而代之的是，攻擊者可以間接透過覆蓋下一個 chunk 的 header，利用 malloc 或 free 的行為，達成任意位置寫入，進而間接控制執行流程。

## 如何攻擊

攻擊的方式是透過 Overflow 覆蓋已經 free 掉的 chunk 中的 fd 和 bk，然後利用前面提到的 unlink 機制（即 `fd->bk = BK` 和 `BK->fd = FD`）來更改記憶體位置。具體來說，unlink 的程式碼如下：

```c
unlink(P,BK,FD){
    FD = P->fd;
    BK = P->bk;
    FD->bk = BK;
    BK->fd = FD;
}
```

在較舊的 libc 版本中，由於檢查機制較少，可以透過一些步驟構造出成功開啟 shell 的 chain，步驟如下：

- 將要 free 掉的 chunk(P) 的 fd 改為 GOT entry - 24，bk 改為 shellcode 的地址。
- free 掉 chunk P。
- `FD->bk = BK`，因此 `GOT entry - 24 + 24 = shellcode address`，達成 GOT Hijacking。
- `BK->fd = FD`，因此 `shellcode address + 16 = GOT entry - 24`。
- 需要注意，shellcode 的第 16 至 24 byte 會因為這個操作而被破壞。
- 攻擊者需要修改 shellcode，讓它透過 jmp 的方式跳到後續地址執行。
- 下一次呼叫到 GOT entry 時，就會跳轉到 shellcode，成功開啟 shell。

## 保護機制

現在已經有多種針對 chunk 的檢查和保護機制，導致上述的攻擊方式難以實現。例如：

- Double free 檢測
- next size 檢查
- double linked list 檢測
- size 與 prev_size 檢查

由於 double linked list 和 size vs. prev_size 的檢查，使得這種攻擊變得更難實施。因此，攻擊者需要使用一些方法來繞過這些檢查。關於如何繞過這些保護，我們將在明天的內容中詳細介紹，因為這會相對複雜和困難。