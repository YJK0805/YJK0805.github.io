---
title: "Day28－Fastbin corruption"
date: 2024-09-28
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

在完成了兩天的 Heap Overflow 介紹後，我們將進一步探討另一個常見的漏洞：Fastbin Corruption。

## Fastbin Corruption

Fastbin Corruption 顧名思義，與 fastbin 密切相關。這類漏洞的前提通常是存在 double free 的情況。其基本利用方式是通過修改已經 free 的 fastbin chunk 的 `fd` 指標，讓下一次 `malloc` 分配時獲取到惡意控制的位置。不過，為了成功利用 double free 漏洞來修改 free 後的 chunk，我們需要了解 fastbin 的特性並滿足相關的檢查條件。

## fastbin 的檢查

### free 操作中的檢查

在 `free` 操作中，系統會進行以下檢查：
1. chunk 的地址必須小於 `-size`。
2. 地址需要對齊，並且 chunk 的大小至少要滿足最小要求（如 0x20），且需是 0x10 的倍數。
3. 下一個 chunk 的大小應該大於最小值且小於 `system_memory` 的大小。
4. 最重要的一點是，系統會檢查要 `free` 的 chunk 是否與當前 fastbin 中對應大小的第一個 chunk 相同，若相同則無法 free。

### malloc 操作中的檢查

在 `malloc` 操作中，系統會根據所需的 `byte` 數量來獲取對應的 fastbin index，並查找適合的 chunk。系統檢查該 fastbin 中的第一個 chunk 是否符合大小要求。特別的是，實際比對時會使用 fastbin 第一個 chunk 的大小來取得 index 並進行驗證。

## 如何利用 Fastbin Corruption

利用 fastbin corruption 的核心在於 `free` 時只會檢查 fastbin 中第一個 chunk 和當前要 free 的 chunk 是否不同。透過這個特性，我們可以構造出重疊的 chunks，從而達成類似 Use After Free 的效果。由於只需滿足 fastbin 的大小檢查，我們可以通過操控 chunk 的 `fd` 來讓系統分配到我們控制的地址。

另外，系統使用 `unsigned int`（4 byte）來計算 index，因此偽造的地址並不需要滿足 8 byte 對齊的要求，這進一步簡化了利用過程。

## 利用流程簡述

1. 先 `malloc` 三塊相同大小的 fastbin chunk，然後 `free` 第一塊和第二塊，這樣它們會連在一起。
2. 再次 `free` 第一塊，這樣 fastbin 中的第一塊和第三塊會指向同一個區域。
3. 此時，通過觸發 `malloc`，我們就能控制這塊 chunk，並可以查找 GOT 表中適合修改的地方。
4. GOT 表應該以 4 byte 為單位進行尋找，並且不需要要求對齊。找到合適的地方後，我們可以利用 `malloc` 分配該區域，然後直接修改 GOT 表。
5. 最後，我們可以使用先前分配的 chunk 寫入 `/bin/sh`，並在 free 這塊 chunk 時取得我們需要的參數。

需要注意的是，前後幾次 `malloc` 的大小必須符合特定條件，否則會影響漏洞利用的效果。


## 總結

總結來說 fastbin corruption 是一種基於 fastbin 分配機制的漏洞，通常利用 double free 來修改 free 後的 chunk 指標 (`fd`)。攻擊者可以通過操控 `malloc` 和 `free` 操作，實現記憶體重疊，並控制記憶體分配，最終達成修改 GOT 表等惡意行為。其核心利用方式是利用 fastbin 特性和檢查中的漏洞，讓系統分配到攻擊者指定的位置。這類漏洞對於利用特定的記憶體結構具有很高的靈活性。