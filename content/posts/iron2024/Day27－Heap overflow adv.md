---
title: "Day27－Heap overflow adv"
date: 2024-09-27
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

昨天我們提到了較新版本的 libc 針對 `unlink` 所引入的一些機制，今天就進一步介紹這些機制的細節。

## Corrupted double linked list

`Corrupted double linked list` 機制會檢查雙向鏈表（double linked list）是否被破壞，具體來說是檢查循環雙向鏈表（circular doubly linked list）的完整性。原則上，一個節點的前向指針與後向指針應該形成一個封閉的循環，如果鏈表被破壞，程式就會顯示 `Corrupted double linked list`，並且中斷運行。具體條件如下：

- `P->bk->fd == P`
- `P->fd->bk == P`

## Corrupted size vs. prev_size

`Corrupted size vs. prev_size` 機制主要是用來防止 `size` 或 `prev_size` 被篡改。這個檢查的邏輯可以表示為：

- `chunksize(P) == next_chunk(P)->prev_size`

此機制是從 `glibc 2.26` 版本開始新增的。

## How to bypass

儘管這些機制增加了攻擊的難度，但仍有可能進行攻擊，只是過程會更複雜。攻擊的核心思路是構造出符合檢查條件的假 `chunk`，整體流程大致如下：

1. 偽造 `chunk` 結構。
2. 需要知道指向該 `chunk` 的 pointer 及該指針的 address。
    - 由於能修改的區域有限，可能需要間接進行讀取或寫入操作。
3. 構造 `chunk size` 與 `next_chunk->prev_size` 一起偽造。
4. 假設 `r` 是第二塊 `chunk`，且存在溢出問題，`q` 是第三塊：
    - 先偽造 `chunk`，注意偽造 `r` 的 `size` 時需要扣掉 header 的大小。接著填入 `fd` 和 `bk`，並繼續溢出到 `q` 的 `prev_size` 和 `size`。當這些 `chunk` 被巧妙地佈置好後，`r` 會指向我們偽造的 `chunk`。
    - 接著 `free(q)`。
    - 此時檢查 `q` 和 `r` 是否已被 free（可觀察相關的 flag）。
    - 在接下來的操作中，會利用 `q` 的 `prev_size` 計算出正確位置，發現 `r` 被視為一個 `chunk`，因此進行 `unlink` 操作。
    - 按照設計進行 `unlink(r, FD, BK)`，具體過程為：
        - `FD = r->fd = &r - 0x18`
        - `BK = r->bk = &r - 0x10`
    - 進行檢查：
        - `prev_size2 == fake_size == 0x80`
        - `r->fd->bk == r = *(&r - 0x18 + 0x18) = r`
        - `r->bk->fd == r = *(&r - 0x10 + 0x10) = r`
    - 然後更新 pointer：
        - `FD->bk = BK`：
            - `*(&r - 0x18 + 0x18) == &r - 0x10`
        - `BK->fd = FD`：
            - `*(&r - 0x10 + 0x10) == &r - 0x18`
    - 最後結束操作：
        - `r` 通常會成為一個指向 data 的 pointer，因此可以利用 `r` 修改附近的 pointer，進而造成任意位置讀寫。如果指針附近有 `function pointer`，甚至可以直接控制執行流程。

現今較新的 `libc` 版本引入了更多的檢查機制，因此攻擊 `glibc` 變得更加困難，甚至在某些情況下已經無法達成。

## 總結

隨著 `glibc` 版本的更新，越來越多的檢查機制被引入來防止 `heap overflow` 攻擊，例如 `Corrupted double linked list` 和 `Corrupted size vs. prev_size` 機制。這些檢查增加了攻擊的難度，但透過偽造符合檢查條件的 `chunk`，仍然有可能進行利用。不過，在最新的 `libc` 版本中，這類攻擊變得更加困難甚至不可行，這也反映了現代系統在安全性上的逐步加強。