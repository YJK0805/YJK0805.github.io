---
title: "Day1－Introduction to PWN & How to PWN"
date: 2024-09-01
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## What is PWN？

PWN 也稱為 Binary Exploitation，簡單來說，就是透過找尋程式中的漏洞，並利用這些漏洞來取得伺服器權限，或是直接使用 shell 獲取檔案，或者進行各種不同的利用。至於 PWN 的念法，有很多有趣的說法。由於 PWN 源自於 "own" 這個詞，因此有人讀作 "碰"，但也有不少人讀作 "胖"。

## How to PWN？

從上面的簡單介紹可以看出，PWN 主要是透過發現程式中的漏洞，並利用這些漏洞達成我們想要的目標。那麼，應該如何找到漏洞呢？在這個過程中，我們可能會使用以下方法：

1. 模糊測試 (Fuzzing)
2. 分析原始碼
3. 反組譯至組合語言
4. 反編譯到原始碼
5. ...

找到漏洞後，如何利用這些漏洞？常見的方法包括：

1. 控制程式的執行流程
2. 覆蓋返回位址 (Return Address)
3. 修改變數值

至於我們的目標，通常包括以下幾點：

1. 提取檔案
2. 讀寫檔案
3. 獲取 Shell

## 接下來的內容

上述所有內容將在後續的文章中一一為大家詳細介紹，並提供豐富的練習範例和實戰題目來進行漏洞利用。如果有想要學習的特定內容，也歡迎大家在下方留言區許願。