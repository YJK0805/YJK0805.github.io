---
title: "Day23－malloc & free"
date: 2024-10-07
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

昨天介紹了一些基本的名詞，今天我們來簡單說明 `malloc` 和 `free` 的運作流程。

## malloc

前面提到，`malloc` 可以更有效率地分配記憶體空間，按需分配以減少浪費。事實上，`malloc` 的分配邏輯相當複雜，但我們可以簡化來理解其基本運作。

當 `malloc` 請求一段記憶體空間時，會依據請求的大小，依次查找 `fast bin`、`small bin` 和 `large bin`，以檢查是否有合適大小的 chunk（記憶體區塊）。如果找到合適的 chunk，就會直接返回該區塊，否則會檢查 `unsorted bin` 中是否有合適的 chunk。

如果符合以下條件之一：

- chunk 位於 small bin 中
- 有剩餘區塊（remainder）
- size 大於等於 `nb`
- 獨立的 chunk（lone chunk）

那麼系統會將剩餘的 chunk 放回 `unsorted bin`。如果不符合條件，則會從 `unsorted bin` 中切割合適的 chunk，並繼續尋找符合大小的 chunk。如果找到合適大小的 chunk 就返回它；否則會將這些 chunk 按大小存放到對應的 `small bin` 或 `large bin`，直到 `unsorted bin` 被清空。

接著，對於 small bin size 的 chunk，會找到稍大於請求的 chunk 並將其切割，剩餘部分則放入 `unsorted bin`。對於 large bin size 的 chunk，流程大致相同。如果所有 bin 都無法滿足請求，則會向 `top chunk` 要求更多空間。如果 `top chunk` 也沒有足夠空間，系統會透過 `brk` 或 `mmap` 向 kernel 請求額外記憶體。

以下為簡化的流程圖：

![malloc](/images/iron2024/day23_image1.png)

不過這其實是較早期的 malloc 流程，隨著 glibc 的更新，現在的流程有所不同，因為加入了一些 struct 與一些機制。

## free

`free` 的功能是釋放之前透過動態配置記憶體的函數所分配的記憶體空間。在進行 `free` 操作之前，系統會檢查指標位址、對齊（alignment）、標誌（flag）等，以確認這塊記憶體是否可被釋放。如果符合條件才會釋放。

除了釋放記憶體，`free` 還會檢查周圍的 chunk 是否為 free 狀態，以進行合併操作，避免 heap 中出現過多破碎的 chunk。這個過程稱為 `merge freed chunk`。

### merge freed chunk

為了避免 heap segment 中出現過多的破碎 chunk，在 `free` 釋放記憶體時，會檢查周圍的 chunk 是否為 free 並進行合併。合併後，還會進行 `unlink` 以移除重複的 chunk。不過，只有那些不是通過 `mmap` 分配的 chunk 才會進行 `unlink`。

合併與 `unlink` 的兩種情況：

- 連續記憶體的下一塊是 top chunk，上一塊是 free chunk，最後會合併到 top chunk。
- 連續記憶體的下一塊不是 top chunk，但上下兩塊皆為 free chunk。

簡單的合併流程如下：

- 如果上一塊是 free chunk，則合併上一塊 chunk 並對其進行 `unlink`。
- 如果下一塊是 top chunk，則合併到 top chunk。
- 如果下一塊是一般 chunk：
    - 如果是 free 狀態，則合併並對下一塊進行 `unlink`，最後將其加入 `unsorted bin`。
    - 如果未使用，則直接加入 `unsorted bin`。

## 總結

以上即為簡化的 `malloc` 與 `free` 流程說明。不過這是針對較舊版本的 libc，隨著新版 libc 增加了許多結構體與檢查機制，許多攻擊方法已經與過去有所不同。不過在後續內容中，我們依然會針對一些過去的漏洞與攻擊手法進行介紹。