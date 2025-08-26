---
title: "Day8－format string bug"
date: 2024-09-08
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## What is a Format String?

在 C 語言中，`printf` 和 `scanf` 是兩個常用的函式，它們透過格式化字串來處理參數。例如：

- `scanf("%s", s);`
- `printf("Hello, %s\n", s);`

這兩個例子會讀取格式化字串，並將 `%s` 解析後替換為傳入的參數。

## Format String Vulnerability

如果在撰寫程式時未遵循安全方式，例如使用 `printf(buf)` 直接傳入變數而非格式化字串，這樣的漏洞可能會導致我們可以洩漏變數或 stack 的殘值。因此，有機會取得如 PIE base、libc base 和 canary 的值，甚至可能修改任意變數或記憶體中的值。如果能成功修改記憶體的值，便能改變程式的執行流程，例如往後會提到的 GOT Hijacking 攻擊。

## Format String 格式

- 格式
    - `%[parameter][flags][field width][.precision][length]type`
- Parameter
    - 可忽略
    - `n$` 表示顯示第 n 個參數
    - `printf("%3$d %2$d %1$d\n", 1, 2, 3);`
    - 輸出結果為 `3 2 1`
- Type
    - `d/i`、`u`：整數
    - `x/X`：十六進位
    - `o`：八進位
    - `c`、`s`：字元、字串
    - `p`：指標
    - `n`：可寫入變數
- 寫入資料
    - `printf("Hello%n\n", &a);`
    - 此時 `a=5`，因為 `Hello` 字串佔了 5 個字元

## Lab

本章節沒有提供 Lab，但接下來的內容會將此主題應用於實際的 Lab 中，例如 leak 可以繞過各種保護機制的資訊或更改任意記憶體的值。大家可以期待之後的實作內容。

## 總結

這一章節僅作為格式化字串漏洞的介紹。如果想進一步實作，筆者在社團社課中提供了兩個 [Lab](https://github.com/YJK0805/HackerSir_PWN_Class/tree/master/Class2) 題目（`format_string1` 和 `format_string2`）。另外，2024 年的 [picoCTF](https://play.picoctf.org/practice?category=6&originalEvent=73&page=1) 也有一系列格式化字串的練習題。如果覺得內容過於入門，還可以參考這篇 [blog](https://r888800009.github.io/software/security/binary/format-string-attack/)，深入了解進階利用方法及內容。
