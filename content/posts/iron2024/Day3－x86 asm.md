---
title: "Day3－x86 asm"
date: 2024-09-03
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## Introduction

ASM 是 Assembly（組合語言）的縮寫。組合語言屬於低階語言，通常專為特定架構設計。相對於低階語言，高階語言更易於理解和使用。以下是兩者的比較：

| 層級     | 優點                   | 缺點                   | 範例            |
| -------- | ---------------------- | ---------------------- | --------------- |
| 高階語言 | 易學易懂、除錯容易     | 執行效率較低、佔用記憶體較多 | C、C++、Python  |
| 低階語言 | 執行效率高、速度快     | 相容性差、不易維護     | 組合語言、機器語言 |

學習組合語言的原因之一是許多程式語言在執行前會先編譯成機器語言。儘管近年來的 PWN 題目通常會提供程式碼，但如果要挖掘漏洞或檢測產品韌體，仍需要進行程式碼的逆向分析。因此，我們會將編譯好的程式反組譯成組合語言，以便閱讀和理解。以下是一個 C 程式編譯過程的流程圖：

![圖片1](/images/iron2024/day3_image1.png)

## 你需要知道的 ASM

- Registers
- Flags
- Sections
- Instructions
- Stack frame
- Calling Convention

## Registers（暫存器）

暫存器是處理運算時暫存數值的地方，具有讀寫速度快的特性。根據資料型態大小，暫存器可以分為以下四種：

- QWORD: 64 bits, Quad Word
- DWORD: 32 bits, Double Word
- WORD: 16 bits
- BYTE: 8 bits

根據功能，暫存器又可以分為以下四種：

| 名稱            | 功用           |
| --------------- | -------------- |
| 通用暫存器       | 運算、計數     |
| 區段暫存器       | 指向記憶體區段 |
| 指標暫存器       | 指向堆疊或陣列 |
| 旗標暫存器       | 紀錄狀態（進位、溢位等） |

### 通用暫存器

| Register                     | AX、BX、CX、DX、DI、SI、BP、SP | R8 ~ R15 |
| ---------------------------- | ------------------------------ | -------- |
| **64 bit**                   | 前綴加 R，例如：RAX、RDI        | 前綴加 R，例如：R8、R9 |
| **32 bit**                   | 前綴加 E，例如：EAX、EDI；後綴加 D，例如：R8D、R9D | 前綴加 E，例如：EAX、EDI；後綴加 D，例如：R8D、R9D |
| **16 bit**                   | 無變化，例如：AX、DI；後綴加 W，例如：R8W、R9W | 無變化，例如：AX、DI；後綴加 W，例如：R8W、R9W |
| **8 bit**                    | 後綴加 X（X 可替換為 H/L），例如：AH、BL、DIL、BPL；後綴加 B，例如：R8B、R9B | 後綴加 X（X 可替換為 H/L），例如：AH、BL、DIL、BPL；後綴加 B，例如：R8B、R9B |

### 區段暫存器

| 名稱  | 作用                        |
| ----- | --------------------------- |
| CS    | 指向 Code Segment           |
| DS    | 指向 Data Segment           |
| SS    | 指向 Stack Segment          |
| ES、FS、GS | 指向 Data Segment（選擇性使用） |

### 指標暫存器

| 名稱  | 作用                                    |
| ----- | --------------------------------------- |
| SP    | Stack Pointer，指向 stack 頂端          |
| BP    | Base Pointer，指向 stack 的任何位置     |
| IP    | 指向目前執行指令的地址                  |
| SI    | Source Index，指向資料來源              |
| DI    | Destination Index，指向資料目的地       |

### 旗標暫存器

| 名稱  | 作用                                                     |
| ----- | -------------------------------------------------------- |
| CF    | Carry Flag：最高位元有進位或借位，CF = 1；否則為 0       |
| PF    | Parity Flag：判斷運算後最低 8 位元的 1 的數量，奇數個 PF = 1；否則為 0 |
| AF    | Auxiliary Flag：運算後第 3 位元產生進位或借位，AF = 1；否則為 0 |
| ZF    | Zero Flag：運算後結果為 0，則 ZF = 1；否則為 0             |
| SF    | Sign Flag：運算後，SF=1 表示負數；否則為 0              |
| OF    | Overflow Flag：運算後結果溢位，OF=1；否則為 0           |
| TF    | Trap Flag：用於 Debug，TF=1 時，每次執行一個指令        |
| DF    | Direction Flag：字串運算，DF=0 從低位到高位；DF=1 反之  |
| IF    | Interrupt Flag：IF=1 時，接受外部中斷；IF=0 則無法       |

## 語法格式

常見的格式有兩種：Intel 和 AT&T。如果有興趣，也可以使用 [Compiler Explorer](https://godbolt.org/) 將程式轉為 ASM 進行觀察。原則上，大家比較偏向使用 Intel 格式，因為它的語法接近正常的程式語言，且更易於閱讀。以下是兩種語法格式的比較：

**Intel**

```asm
push rbp
mov rbp, rsp
pop rbp
```
AT&T
```asm=
push %rbp
mov %rsp,%rbp
pop %rbp
```

## 組成

| 名稱      | 功用                                |
|-----------|-------------------------------------|
| Label     | 標記，供指令進行跳轉                 |
| Section   | 隔開常數變數、可變變數、程式碼區段   |
| Instruction| 指令或偽指令                        |
| Operand   | 運算子                              |

## 常見指令

| 指令 | 作用                          | 範例語法              |
|------|-------------------------------|-----------------------|
| push | 將資料放進 stack              | `push rbp`            |
| pop  | 將資料從 stack 拿出           | `pop rbp`             |
| mov  | 將資料從 A 放入 B             | `mov B, A`            |
| ret  | 回傳                          | `ret`                 |
| lea  | 將變數位址複製給暫存器         | `lea rax, [rbp-0xc]`  |
| nop  | 無任何操作                     | `nop`                 |

## 基本運算

| 指令 | 作用                          | 範例語法        |
|------|-------------------------------|-----------------|
| inc  | 將變數加1                     | `inc rax`       |
| dec  | 將變數減1                     | `dec rax`       |
| add  | 將變數加指定數目              | `add rax, 0x1`  |
| sub  | 將變數減指定數目              | `sub rax, 0x1`  |
| mul  | 將變數相乘                    | `mul cx`        |
| div  | 將變數相除                    | `div cx`        |

## 位元運算

| 指令 | 作用                          | 範例語法           |
|------|-------------------------------|--------------------|
| and  | 做 & 運算                     | `and al, 0x05`     |
| or   | 做 \| 運算                     | `or al, 0x05`      |
| xor  | 做 ^ 運算                     | `xor al, 0x05`     |
| not  | 做 ! 運算                     | `not al`           |
| neg  | 計算二進位補數                 | `neg al`           |
| shl  | 左移指定位數                  | `shl rax, 2`       |
| shr  | 右移指定位數                  | `shr rax, 2`       |
| rol  | 左循環位移指定位數            | `rol rax, 2`       |
| ror  | 右循環位移指定位數            | `ror rax, 2`       |

## 其他比較

| 指令 | 作用                                | 範例語法          |
|------|-------------------------------------|-------------------|
| cmp  | 由相減比較兩數，設定 ZF、CF         | `cmp rax, rbx`    |
| test | 由 & 比較兩數，設定 SF、ZF、PF      | `test rax, rax`   |
| jmp  | 跳轉到指定地址                      | `jmp 0x00001140`  |

## 跳轉指令

組合語言有許多跳轉指令，統稱為 Jcc，Jump condition code，通常會搭配比較指令使用，不過因為指令有很多，所以就不一一列出介紹了，大家可以遇到的時候再上網查找

## Stack Frame

簡單來說，如果一個程式會呼叫其他的函式，這些函式的資料會依次壓入堆疊，就像堆疊盤子一樣。當主函式 (`main`) 呼叫 `func1`，`func1` 呼叫 `func2`，而 `func2` 再呼叫 `func3`，此時的堆疊會從上往下排列為：`func3 -> func2 -> func1 -> main`。每當一個函式結束時，控制權會根據堆疊中的返回地址依次傳回到前一個函式，直到返回主函式。

## Calling Convention

函式呼叫不僅僅是跳轉到函式地址執行程式碼再跳回來，它還涉及參數的傳遞。不同的 Calling Convention 會規定參數如何傳遞給函式，例如，某些參數會透過暫存器傳遞，而其他參數則可能會依序壓入堆疊。這在控制執行流程時特別重要，因為了解每個暫存器存放的值以及如何操作 stack 是實現目標的關鍵。不同的指令集和編譯器可能會使用不同的 Calling Convention，因此熟悉這些規則在漏洞攻擊和逆向工程中是必須的，不過在此就不再多做說明不然讀者對於內容會相對抽象，之後講到其他章節會再說明。
