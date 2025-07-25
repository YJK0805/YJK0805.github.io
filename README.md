# YJK 的資安研究筆記

這是使用 Hugo 和 PaperMod 主題建立的個人技術部落格，專注於資安研究、CVE 分析和 CTF writeups。

## 功能特色

- ✨ **現代化設計**：使用 PaperMod 主題，支援響應式設計
- 🌙 **主題切換**：支援 Dark/Light 模式自動切換
- 🔍 **全文搜尋**：內建文章搜尋功能
- 📱 **行動裝置友善**：完美支援各種螢幕尺寸
- 🚀 **自動部署**：使用 GitHub Actions 自動部署到 GitHub Pages

## 開始使用

### 1. 安裝 Hugo Extended

```bash
# Windows (使用 winget)
winget install Hugo.Hugo.Extended

# macOS (使用 Homebrew)
brew install hugo

# Linux (使用 snap)
snap install hugo --channel=extended
```

### 2. 克隆專案

```bash
git clone --recursive https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 3. 本地開發

```bash
# 啟動開發伺服器
hugo server --buildDrafts

# 瀏覽器開啟 http://localhost:1313
```

### 4. 建置網站

```bash
hugo --gc --minify
```

## 配置說明

### 基本設定

編輯 `hugo.toml` 檔案：

```toml
baseURL = 'https://your-username.github.io/'  # 替換成你的 GitHub Pages URL
title = 'YJK 的資安研究筆記'
theme = 'PaperMod'
```

### 個人資訊設定

```toml
[params.profileMode]
enabled = true
title = "YJK"
subtitle = "資安研究員 / CTF 玩家"

[[params.socialIcons]]
name = "github"
url = "https://github.com/your-username"  # 替換成你的 GitHub
```

## 內容管理

### 目錄結構

```
content/
├── posts/          # 所有文章
├── cve/           # CVE 分析報告
├── ctf/           # CTF writeups
└── about/         # 關於頁面
```

### 建立新文章

```bash
# 建立 CVE 分析文章
hugo new cve/cve-2024-xxxx.md

# 建立 CTF writeup
hugo new ctf/competition-name-2024.md

# 建立一般文章
hugo new posts/article-title.md
```

### 文章 Front Matter 範例

```yaml
---
title: "文章標題"
date: 2025-07-25
draft: false
tags: ["CVE", "security", "analysis"]
categories: ["CVE Analysis"]
author: "YJK"
showToc: true
TocOpen: true
---
```

## 部署到 GitHub Pages

### 1. 建立 GitHub Repository

建立一個名為 `your-username.github.io` 的公開 repository。

### 2. 啟用 GitHub Pages

1. 前往 repository 的 Settings
2. 在 Pages 部分選擇 "GitHub Actions" 作為 Source
3. 推送程式碼後會自動觸發部署

### 3. 推送程式碼

```bash
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/your-username/your-username.github.io.git
git push -u origin main
```

## 主題特色

### Dark/Light 模式切換

PaperMod 主題內建支援：
- 自動模式：跟隨系統設定
- 手動切換：點擊右上角的主題切換按鈕
- 記憶使用者偏好：使用 localStorage 儲存

### 搜尋功能

支援全文搜尋：
- 按 `/` 快速開啟搜尋
- 支援中英文搜尋
- 即時搜尋結果

### 程式碼高亮

支援多種程式語言語法高亮：
- Python
- C/C++
- JavaScript
- Bash
- 等等...

## 自訂樣式

如需自訂樣式，可以在 `assets/css/extended/` 目錄下建立 CSS 檔案。

## 常見問題

### Q: 如何更新主題？

```bash
git submodule update --remote themes/PaperMod
```

### Q: 如何新增社交連結？

在 `hugo.toml` 中新增：

```toml
[[params.socialIcons]]
name = "twitter"
url = "https://twitter.com/your-username"
```

### Q: 如何啟用留言功能？

可以整合 Disqus 或 utterances，詳見 PaperMod 文件。

## 授權

本專案使用 MIT 授權條款。

## 聯絡方式

- GitHub: [your-username](https://github.com/your-username)
- Email: your-email@example.com

---

**快速開始指令摘要：**

```bash
# 1. 克隆並初始化
git clone --recursive https://github.com/your-username/your-repo.git
cd your-repo

# 2. 啟動開發伺服器
hugo server --buildDrafts

# 3. 建置網站
hugo --gc --minify
```