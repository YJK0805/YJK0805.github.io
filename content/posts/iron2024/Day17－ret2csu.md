---
title: "Day17－ret2csu"
date: 2024-09-17
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


# 前言

經過了這麼多天的 Lab，今天的內容就輕鬆一下，只講原理，不提供練習 Lab 囉！

如果大家有注意看前兩天的程式碼，應該會發現我都寫了一個 `pop rdi` 指令進去。這是因為現在較新的編譯器版本不再包含 `__libc_csu_init`，因此傳遞參數變得相對困難。不過，在有這個函式的情況下，會有更多傳遞參數的 gadgets 可以使用，甚至可以直接用一大段 `__libc_csu_init` 來設定參數並取得 shell。這種技巧被稱為 ret2csu。

## __libc_csu_init

`__libc_csu_init` 是編譯器在編譯時會自動加入的函式，用來初始化 libc 函式庫。由於大部分程式都會使用 libc 函式，這個函式原則上一定會存在（不過現今新版編譯器已不再編入這個函式）。

這是 `__libc_csu_init` 的部分內容：

![image](/images/iron2024/day17_image1.png)

仔細觀察可以發現，最底下的這段程式碼非常適合用來放參數以及控制流程。

## 使用方式

我們可以控制 `rbp`、`rbx`、`r12`、`r13`、`r14`、`r15`，並跳至 gadgets 開頭。對應一下就會發現，`r13` 和 `r14` 可以用來控制 `rsi`、`rdx` 等暫存器。這樣就能解決很多程式中找不到相關 gadgets 來控制參數的問題。

此外，我們還可以透過 `r15` 和 `rbx` 指定任意記憶體位置。接著將 rbx 和 rbp 分別指定為 0 和 1，在呼叫完後確保 `rbx == rbp == 1`，此時 `jne` 不會生效，我們就可以繼續使用後面的一連串 pop 指令，最終達成任意 ROP 攻擊。