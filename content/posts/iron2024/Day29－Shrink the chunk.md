---
title: "Day29－Shrink the chunk"
date: 2024-10-13
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

昨天介紹了 Fastbin Corruption，今天我們將介紹這次鐵人賽的最後一個漏洞：Shrink the chunk。

## Shrink the chunk

Shrink the chunk 這個漏洞的前提是存在一個 off-by-one 的 null byte 漏洞。這類漏洞其實並不少見，因為如果使用像 `strcpy` 或 `strcat` 這類在結尾會補 0 的函數，就有可能導致此類漏洞。這個漏洞主要目的是創造出 overlap chunk，從而修改 chunk 的內容，並利用 unsorted bin 和 smallbin 的 unlink 行為來達成目的。

## 利用方式

假設 fastbin 是空的，並且通過 `malloc` 分配三個 chunk 到 heap 中，分別為 A、B、C，大小分別是 0x40、0x170 和 0x100。在 B 的資料的 offset 位置 0xf0 填入 0x100，目的是為了通過 `prev_size == size` 的檢查。接著我們釋放 B，然後釋放 A，這裡是為了觸發 A 的 off-by-one 漏洞。

接著，我們再分配回 A（需要注意 malloc 的大小），此時就可以觸發 off-by-one 漏洞，並將原本 B 的 0x171 改寫成 0x100。這樣，這一塊會被認為是 0x100 大小。當我們再次 `malloc` 時，會發現因為這塊記憶體需要從 unsorted bin 中取出，因此會進行 unlink 操作，並檢查 `prev_size` 和 `size`。這就是為什麼我們一開始在 B 中放入 0x100 的原因。

接著，我們再將剩餘的區塊 `malloc` 出來，會發現只剩下 0x71 的區塊。此時，繼續 `malloc` 一塊大小為 0x30 的區塊。假設這塊區域內有一個 function pointer，當我們再次釋放切下的第二塊 B，並釋放最底下的 C 時，C 會根據 `prev_size` 檢查上一塊是否已被釋放，若前一塊已被釋放，則會進行 merge 操作。此時，unsorted bin 會存入這一塊合併後的超大 chunk，因為整塊都被合併了。當我們下次執行 `malloc` 時，這塊大 chunk 會分配給 user。

同時，這也產生了 overlap chunk，因為在之前分配 0x30 時，這一操作已經切到了同一塊記憶體。接著，如果我們再次拿取底下這整塊大的 chunk，就可以任意修改這塊記憶體。若這塊區塊中包含有 function pointer，那麼我們就有機會控制程式的執行流程。

## overlap chunk

其實前面的描述中提到了 overlap chunk。那這是因為它是一個非常強大且重要的情況，因為如果 overlap 的區塊中包含有 function pointer 或是可以控制程式流程的 struct，我們就有機會控制程式的執行流程。同時，配合 fastbin 中已釋放的 chunk，我們也可以通過修改 fd 來達到進一步的利用效果。

## 總結

今天的內容主要介紹了 Shrink the chunk 漏洞的原理和利用方式。這個漏洞通常發生在 off-by-one 的 null byte 漏洞下，常見於 `strcpy` 或 `strcat` 等函數的使用。透過精心的 `malloc` 和 `free` 操作，攻擊者可以在 heap 中製造 overlap chunk，從而修改記憶體中的內容。若這些 overlap chunk 包含可控的 function pointer，則有可能進一步控制程式的執行流程。這種利用方式結合了 unsorted bin 和 smallbin 的特性，達到最終的漏洞利用目標。