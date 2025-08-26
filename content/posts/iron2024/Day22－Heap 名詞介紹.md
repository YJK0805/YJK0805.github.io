---
title: "Day22－Heap 名詞介紹"
date: 2024-09-22
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

在昨天的文章中，我們提到 Heap 涉及到許多關鍵名詞與概念，如 chunk 和 bin。由於這些名詞在後續討論 malloc 流程時會高度關聯，因此今天我們先對這些重要名詞做一些簡單介紹，為後續的學習打好基礎。

## chunk

chunk 是 glibc 在進行記憶體管理時使用的資料結構。例如，當你呼叫 malloc 分配記憶體時，實際上得到的是一塊 chunk。chunk 的最小大小是 SIZE_T (unsigned long int，8 byte) 的四倍。chunk 包含兩部分：**chunk header**（由 prev_size 和 size 組成）以及 **user data**，malloc 返回的指標實際上是指向 user data 的位址。

當一塊 chunk 被 free 掉後，它會被加入一個名為 bin 的 linked list 中。根據大小，chunk 可以分為三類：allocated chunk、free chunk 和 top chunk。

### allocated chunk

allocated chunk 的特殊之處在於當前一塊 chunk 是 free 狀態時，allocated chunk 的 prev_size 欄位會存儲上一塊 chunk（包含 header）的大小。此外，allocated chunk 的 size 欄位還包含了三個 flag：

- **P：PREV_INUSE (bit 0)**：上一塊 chunk 是否正在使用中
- **M：IS_MMAPPED (bit 1)**：該 chunk 是否由 mmap 分配
- **N：NON_MAIN_ARENA (bit 2)**：是否屬於 main arena 之外的其他記憶體區域

allocated chunk 的結構如下圖所示：

![image](/images/iron2024/day22_image1.png)

### freed chunk

當一個 chunk 被 free 後，其結構會包含 prev_size、size、fd 和 bk。如果該 chunk 的大小超過 0x400，則還會包含 fd_nextsize 和 bk_nextsize 欄位。

- **fd** 指向 linked list 中下一個 chunk 的位址，並非記憶體中的下一塊連續 chunk。
- **bk** 指向 linked list 中前一個 chunk 的位址，並非記憶體中的上一塊連續 chunk。
- **fd_nextsize** 指向下一個 large chunk。
- **bk_nextsize** 指向前一個 large chunk。

freed chunk 的結構如下圖所示：

![image](/images/iron2024/day22_image2.png)

### top chunk

程式首次執行 malloc 時，heap 會被切分成兩部分：分配出去的 chunk 和剩餘的 top chunk。如果之後需要更多記憶體，會從 top chunk 中切出額外的空間來使用。top chunk 也包含 prev_size 和 size 欄位，size 代表 top chunk 還剩下多少空間可供分配。

## bin

bin 是一個 linked list 結構，存在的目的是為了加速 malloc 查找適合大小的 chunk。每當一塊 chunk 被 free 後，會根據其大小被加入對應的 bin。bin 根據 chunk 的大小，分為以下幾類：fast bin、small bin、large bin 和 unsorted bin。

### fast bin

fast bin 使用單向鏈結（singly linked list），適用於 chunk size 小於 144 byte 的情況。fast bin 不包含 bk 欄位，且在 free 後不會將下一塊 chunk 的 inuse flag 設為 0。fast bin 進一步細分為 10 個不同大小的 bin（例如 0x20、0x30 等）。這些 bin 使用 LIFO（Last In First Out）原則，當 malloc 需要相同大小的空間時，會從對應的 fast bin 中取出最近釋放的 chunk。

### unsorted bin

unsorted bin 使用環狀雙向鏈結（circular double linked list）。當一個 chunk 大小大於等於 144 byte 時，glibc 不會立刻將該 chunk 加入到對應大小的 bin，而是先放入 unsorted bin。當下一次 malloc 被呼叫時，glibc 會先從 unsorted bin 中尋找合適的 chunk，若找不到，才會將 unsorted bin 中的 chunk 移動到對應的 bin。

### small bin

small bin 也使用環狀雙向鏈結，適用於 chunk size 小於 1024 byte 的情況。small bin 使用 FIFO（First In First Out）原則，並進一步細分為 62 個不同大小的 bin（例如 0x20、0x30 等）。特殊情況下，0x20~0x70 大小的 chunk 可能被分到 fast bin，而不是 small bin。

### Large bin

large bin 也使用環狀雙向鏈結，但與其他 bin 不同的是，large bin 是一個已排序的鏈結。適用於 chunk size 大於等於 1024 byte 的情況。由於 large chunk 的大小不固定，因此 large bin 中的 chunk 會依大小排序，大的放前面，小的放後面，這樣可以加速搜尋。large bin 的機制依然是 FIFO。

## 總結

以上是一些常見 Heap 名詞的介紹，這些概念會與後續的主題息息相關。理解這些名詞有助於深入掌握 malloc 的運作原理。如果有任何錯誤或需要補充的部分，歡迎大家指正，讓我們一起學習、進步！