---
title: "Day9－Lazy binding & GOT"
date: 2024-09-09
draft: false
tags: ["iron-man-2024", "pwn", "binary-exploitation"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 簡介

如果大家經常使用 `file` 指令來查看檔案資訊，應該會經常看到像下面這樣的一大串訊息：

![image](/images/iron2024/day9_image1.png)

你會注意到其中有一個資訊是 `dynamically linked`，這表示這是一個動態鏈結的程式。動態鏈結意味著程式在執行時，會從外部函式庫載入一些函式，例如常見的 `printf`、`scanf` 等。

## Lazy Binding

Lazy binding 是動態鏈結程式的一種機制。當程式包含一個或多個函式庫時，不一定會使用到所有的函式。換句話說，有些函式庫中的函式可能永遠不會被執行。

Lazy binding 的機制是在程式首次呼叫某個函式時，系統才會查找該函式的位置，並將其填入 GOT 表（Global Offset Table）。後續的呼叫則會直接從 GOT 表中取得函式的位址。那什麼是 GOT 表呢？

## GOT

前面提到，函式庫中的函式位址是在載入時才決定的，因此在編譯階段無法得知這些函式的具體位址。GOT 表儲存了這些函式的指標，而程式在一開始執行時，並不會直接存取 GOT 表，而是先透過 PLT 表（Procedure Linkage Table）中的 offset。

例如，在下方的反編譯程式碼中，我們看到在 `main` 函式中呼叫了 `printf@plt`，而 `printf@plt` 最終會跳轉到 `printf@GLIBC_2.2.5`，也就是實際在 libc 中的 `printf` 函式。

![image](/images/iron2024/day9_image2.png)

![image](/images/iron2024/day9_image3.png)

## 攻擊？

大家可能會認為，這樣通過外部函式呼叫應該不會有什麼問題。但仔細想一想，事情或許並非如此。如果 PLT 表或 GOT 表可以被修改或重寫，那這樣的機制就不再安全了。

例如，將 `printf` 函式的指標改寫成 `system` 或者後門函式，甚至控制傳入的參數，這樣的情境可能會導致嚴重的安全漏洞。而這部分的內容將會在明天探討，也就是 GOT Hijacking 的攻擊技術。
