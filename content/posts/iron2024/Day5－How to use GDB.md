---
title: "Day5－How to use GDB"
date: 2024-09-05
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 簡介

GDB 是 GNU Debugger 的縮寫，它是一個功能強大的 command line debug 工具，支援多種程式語言如 C、C++、Fortran 等等。當我們在進行開發時，如果程式在執行過程中發生 segmentation fault 或其他錯誤，GDB 可以幫助我們追蹤程式 crash 的原因。我們可以透過設置中斷點、檢查變數內容等，來針對特定問題進行 debug

## 改造？

原生的 GDB 有時候可能顯得過於簡單，缺少一些便利的視覺化工具或記憶體分析功能。因此，許多使用者會安裝外掛來補強 GDB 的功能，像是 `pwndbg` 或 `peda` 等外掛，可以讓我們更容易地看到 stack、register 等資訊，從而提高 debug 效率

## 使用

- **執行程式並設定中斷點**:
    - 在 GDB 中，我們可以使用 `run` 或 `r` 來執行程式，通常會先設定中斷點（`break`）在程式的某一個位置，例如 `main` 函式，這樣程式會在到達該點時停止執行，方便我們進行檢查。
    - ex: `b main` 在 `main` 函式處設置中斷點。

- **踩到中斷點後要繼續執行程式**:
    - 當程式停止於中斷點時，使用 `continue` 或 `c` 來繼續執行程式。

- **觀察 register**:
    - 當程式在中斷點停止後，我們可以使用 `info` 指令查看目前的 register 狀態、函式列表等資訊。例如，使用 `info registers` 來查看目前的 register 內容。
    - 使用 `x` 指令可以檢查具體的記憶體位址，通過格式化選項來調整輸出，例如 `x/2gx $rax` 顯示從寄存器 `rax` 開始的兩個 giant word。

- **反組譯執行的程式**:
    - 使用 `disassemble` 指令可以查看程式的反組譯結果，幫助分析程式的指令。

- **下一步指令**:
    - `ni` 直接執行到下一行指令（不進入函式）。
    - `si` 如果遇到函式，則會進入函式內部。

- **結束函式**:
    - `finish` 讓程式執行到目前函式的結束，並返回呼叫者。

- **顯示暫存器、函式、中斷點資訊**:
    - 使用 `info` 來顯示各種資訊，如 `info functions` 列出所有函式，`info breakpoints` 顯示目前的中斷點。

- **列出記憶體資訊**:
    - `x $[register]` 或 `x [address]` 可以查看指定位址的記憶體內容。
    - 可以使用不同格式顯示記憶體，格式為 `x/<fmt> <address>`，其中:
        - `fmt = count + size + format`
        - 例如: `x/2gx $rax`
        - size: b (byte)、h (halfword)、w (word)、g (giant, 8 bytes)
        - format: x (hex)、d (decimal)、c (char)、s (string)…

- **刪除中斷點**:
    - 使用 `delete`、`del` 或 `d` 可以刪除中斷點。若要刪除特定中斷點，使用 `delete [breakpoint id]`。

- **直接讓指令跳轉到指定位址**:
    - 使用 `jump location` 讓程式執行跳轉到指定位址。

- **查看指令**:
    - 使用 `help` 可以查看 GDB 的指令說明。

## PWN 常用

在 PWN 競賽中，我們經常會使用一些增強 GDB 的外掛來幫助我們快速分析程式的記憶體佈局和進行漏洞利用。以下是幾個常見的外掛指令：

- **查看 libc base**:
    - 使用 `libc` 指令來查看 `libc` 的 base address，這在某些攻擊技巧中非常重要，因為我們需要精確定位 `libc` 函式的位址。

- **查看 PIE base**:
    - 使用 `pie` 指令來顯示程式的 PIE (Position Independent Executable) base address。

- **查看 heap base**:
    - 使用 `heap` 指令來顯示 heap 的 base address

- **查看 GOT 表**:
    - 使用 `got` 指令來查看 GOT 表，便於我們瞭解動態函式載入時的位址。

- **查看 PLT 表**:
    - 使用 `plt` 指令來查看 PLT 表，分析函式載入過程。

- **查看 heap 資訊**:
    - 使用 `heapinfo` 來查看 heap 的詳細資訊

- **查看偏移量**:
    - 使用 `off [libc function]` 指令來查看 `libc` 函式的偏移量，便於計算攻擊所需的位址偏移
