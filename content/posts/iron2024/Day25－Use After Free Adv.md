---
title: "Day25－Use After Free Adv"
date: 2024-10-09
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

昨天的題目是透過直接將執行流程改為我們事先設計好的後門。但如果我們沒有設置後門，其實在早期版本的 libc 中，仍然可以使用其他方式 leak 出 libc，並進一步將執行流程轉向 one_gadget 或是直接使用 system 開啟 shell。

## 利用方式

在 libc 2.23 版本中，我們可以透過一些技巧來 leak 出 libc base，甚至進而控制執行流程。過程簡單來說就是：

1. 先 `malloc` 一塊 unsorted bin 大小的記憶體空間。
2. 再申請一塊較小的空間，以防止後續 `free` 掉 unsorted bin 大小的空間時，該 chunk 與 top chunk 合併。
3. 接著使用 Use After Free 技巧，先 `free` 掉 unsorted bin 大小的空間，再輸出該空間的內容，如此就能 leak 出 libc 的地址。
4. 之後我們可以減去 offset，拿到 libc base 地址。
5. 接著 `malloc` 一塊 fastbin 大小的 chunk，並修改它的 `fd`，將滿足條件的地址放進 fastbin。
6. 最後，`malloc` 一塊相同大小的 chunk 並使用它。如果將它修改為 one_gadget，即可輕鬆拿到 shell。

之所以會使用到 `__malloc_hook`，是因為它與這個過程的密切關聯。

## __malloc_hook

`__libc_malloc` 在執行 `malloc` 時，會先檢查 `__malloc_hook` 是否為空。如果 `__malloc_hook` 不為空，則會在執行 `malloc` 前先調用它，初始化過程完成後，`__malloc_hook` 的值會變成 0。

因為在 fastbin 中分配 chunk 的過程中會檢查 size 是否允許，所以我們需要在 `__malloc_hook` 周圍找到一個允許的地址，並利用這個地址來偽造 chunk。

## 問題

有時候，one_gadget 的條件可能無法滿足，導致無法成功開啟 shell。這時可以利用 `malloc_hook` 與 `realloc_hook` 相鄰的特性，將 `malloc_hook` 改為 `_libc_realloc + 0x14`，並將 `realloc_hook` 改為 one_gadget。這樣可以控制 `malloc_hook` 指向的位置，並避開 `_libc_realloc` 的部分指令，從而調整 one_gadget 所需的條件，最終成功開啟 shell。

## 總結

今天介紹了在 libc 2.23 版本中利用 Use After Free 技巧來 leak 出 libc 地址，進而控制執行流程。透過操控 `__malloc_hook` 和 `realloc_hook`，我們可以在特定情況下達成開啟 shell 的目的，即便 one_gadget 的條件不完全滿足。這是一種常見的漏洞利用方式，能夠有效地繞過機制並取得程式控制權。