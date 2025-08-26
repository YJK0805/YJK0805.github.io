---
title: "Day2－ELF format & protection"
date: 2024-09-16
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## ELF format

ELF 是 Executable and Linkable Format 的縮寫，可以簡單稱為可執行檔。不同平台有不同的可執行檔格式，如 Windows 的 exe 和 Linux 的 ELF。而 ELF 檔又包含各種區段 (Section)，這些區段在執行時會映射 (mapping) 到記憶體中。常見的區段包括：.text、.bss、.data、.rodata、.got、.plt 等。以下是對這些區段的介紹：

- .text
    - 存放編譯後的程式碼
- .bss
    - 存放未初始化的全域變數
- .data
    - 存放初始化的全域變數
- .rodata
    - 存放可讀不可寫的資料
    - ex: 輸出文字
- .got (Global Offset Table)
    - 用於儲存動態鏈接 (dynamic linking) 時需要的外部函數的地址，並幫助程式在執行期間通過這些地址來訪問函數或變數。
- .plt
    - 用於動態呼叫外部函數
    - 呼叫一個外部函數時，程式會先跳到 .plt，然後再由 .plt 透過 .got 找到實際的函數地址

以下是一段程式碼中各段落存在的區段

```c
#include <stdio.h>
int a; // .bss
int b = 100; // .data
// .text start
int main(){
    puts("Hello World!"); // .rodata
    return 0;
}
// .text end
```

各區段皆可能成為後續內容可以利用的部分，不過目前可以先看過即可，後續講述到攻擊手法時會再進一步介紹

## Protection

一個 ELF 檔會有許多保護機制，並且可以在編譯時加入參數決定是否要開啟，而開啟的多寡就可能同時決定這個 ELF 檔會有什麼樣的攻擊手法可以利用。以下是常見的保護機制：

- PIE (Position-Independent Executable)
    - 可執行檔的程式碼和資料段在映射到記憶體時會隨機化
    - 開啟時，每次執行位置都不同，反之則固定某個值
    - 關閉方式：
        - ```bash
          gcc main.c -no-pie
          ```
    - ASLR (Address Space Layout Randomization)
        - 針對 Process 的防護機制，對整個進程的地址空間（如動態載入 library、stack、heap 等）進行隨機化
        - 如果開啟 PIE，則需要搭配開啟 ASLR 才會有效果
        - 關閉方式
            - ```bash
              echo 0 > /proc/sys/kernel/randomize_va_space // 關閉
              echo 1 > /proc/sys/kernel/randomize_va_space // 半隨機
              echo 2 > /proc/sys/kernel/randomize_va_space // 全隨機
              ```
- NX (No-Execute/ Data Execution Prevention)
    - 可寫的不可執行、可執行的不可寫
    - 防範 Shell Code 類型的攻擊
    - 關閉方式：
        - ```bash
          gcc main.c -zexecstack
          ```
- Canary (Stack Canary/ Stack Protector)
    - 在返回地址前插入一個 8 byte 的隨機值（即 Canary 值），在函數返回時驗證該值是否未被修改，從而防止 buffer overflow 攻擊
    - Canary 值的第一個 byte 是 null byte（如果適當利用，可能有機會提取到資訊）
    - 每次執行程式時，Canary 值都是隨機的
    - 關閉方式
        - `gcc main.c -fno-stack-protector`
    - 有多種開啟參數
        - ```bash
          gcc main.c –fstack-protector // 動態配置記憶體或 buffer > 8bytes 的函數加入
          gcc main.c –fstack-protector-all // 所有 function 都加入
          gcc main.c –fstack-protector-strong // -fstack-protector 的條件及程式內有 local 變數為陣列類型或變數位址用來賦值或當作函式參數或以 register 類型宣告的 local 變數
          gcc main.c –fstack-protector-explicit // 只對以 __attribute__((stack_protect)) 宣告的 function 加入
          ```
    - 分辨有無開啟
        - 後面會講到如何 disassemble 程式，如果 disassemble 有 call 到以下 plt 表就代表該 function 有 canary
        - ![image](/images/iron2024/day2_image1.png)
- RELRO (Relocation Read-Only)
    - 為了防範 Lazy Binding 問題
    - 分為 No / Partial / Full 三種模式
        - No RELRO 模式完全不保護 .got 表，攻擊者可以輕易修改其中的函數地址
        - Partial RELRO 會將 .got 鎖定為只讀，但延遲綁定仍然存在潛在風險
        - Full RELRO 則完全保護 .got 表及相關的鏈接資訊，防止所有類型的修改和利用
    - 三種模式的編譯參數
        - ```
          gcc -z norelro main.c // No RELRO
          gcc -z lazy main.c // Partial RELRO
          gcc -z now main.c     // Full RELRO
          ```
    - 三種模式比對 (O：可寫、X：不可寫)
        |  | Link Map | GOT |
        | -------- | -------- | -------- |
        | No | O | O |
        | Partial | X | O |
        | Full | X | X |

## 確認檔案開啟的保護機制

- checksec

![image](/images/iron2024/day2_image2.png)