// 程式碼區塊增強功能
document.addEventListener('DOMContentLoaded', function() {
    enhanceCodeBlocks();
});

function enhanceCodeBlocks() {
    // 等待一點時間確保 DOM 完全載入
    setTimeout(() => {
        // 更全面的選擇器
        const selectors = [
            '.post-content .highlight', 
            '.post-content pre', 
            '.highlight',
            'pre code',
            'pre',
            '.post-content div[class*="highlight"]'
        ];
        
        let allCodeBlocks = new Set(); // 使用 Set 避免重複
        
        selectors.forEach(selector => {
            const blocks = document.querySelectorAll(selector);
            blocks.forEach(block => allCodeBlocks.add(block));
        });
        
        const codeBlocks = Array.from(allCodeBlocks);
        console.log('Found code blocks:', codeBlocks.length);
        console.log('Code blocks:', codeBlocks);
        
        codeBlocks.forEach((block, index) => {
            // 跳過已經處理過的區塊
            if (block.classList.contains('enhanced')) return;
            block.classList.add('enhanced');
            
            // 找到實際的程式碼內容
            let actualCodeElement = block;
            let pre = null;
            let code = null;
            
            if (block.tagName === 'PRE') {
                pre = block;
                code = block.querySelector('code');
            } else if (block.tagName === 'CODE') {
                code = block;
                pre = block.parentElement.tagName === 'PRE' ? block.parentElement : null;
                actualCodeElement = pre || block;
            } else {
                pre = block.querySelector('pre');
                code = block.querySelector('code');
            }
            
            // 獲取程式碼文本
            let codeText = '';
            if (code) {
                codeText = code.textContent || code.innerText;
            } else if (pre) {
                codeText = pre.textContent || pre.innerText;
            } else {
                codeText = block.textContent || block.innerText;
            }
            
            if (!codeText.trim()) {
                console.log(`Skipping empty code block ${index}`);
                return;
            }
            
            // 計算行數
            const lines = codeText.split('\n');
            const nonEmptyLines = lines.filter(line => line.trim().length > 0);
            const lineCount = Math.max(lines.length, nonEmptyLines.length);
            const isLong = lineCount > 8; // 降低到8行就摺疊
            
            console.log(`Code block ${index}: lines=${lineCount}, isLong=${isLong}`);
            console.log('First few lines:', lines.slice(0, 3));
            
            // 獲取語言
            const language = getLanguageFromBlock(actualCodeElement) || getLanguageFromContent(codeText);
            
            // 確保有合適的容器
            let container = actualCodeElement;
            if (!container.classList.contains('highlight')) {
                if (container.parentElement && container.parentElement.classList.contains('highlight')) {
                    container = container.parentElement;
                } else {
                    // 創建新容器
                    const wrapper = document.createElement('div');
                    wrapper.className = 'highlight';
                    container.parentNode.insertBefore(wrapper, container);
                    wrapper.appendChild(container);
                    container = wrapper;
                }
            }
            
            // 確保有 pre 元素
            if (!pre) {
                if (container.querySelector('pre')) {
                    pre = container.querySelector('pre');
                } else {
                    console.log(`No pre element found for code block ${index}`);
                    return;
                }
            }
            
            // 檢查是否已經有 header
            if (container.querySelector('.code-header')) {
                return;
            }
            
            // 創建標題欄
            const header = createCodeHeader(language, isLong);
            
            // 包裝程式碼內容
            const contentWrapper = document.createElement('div');
            contentWrapper.className = 'code-content';
            if (isLong) {
                contentWrapper.classList.add('collapsed');
            }
            
            // 重新組織結構
            container.insertBefore(header, pre);
            container.insertBefore(contentWrapper, pre);
            contentWrapper.appendChild(pre);
            
            // 設置摺疊功能
            if (isLong) {
                setupCollapseFeature(container, contentWrapper);
            }
            
            console.log(`Enhanced code block ${index} (${language}, ${lineCount} lines)`);
        });
    }, 100);
}

function getLanguageFromBlock(block) {
    // 嘗試從類名獲取語言
    const classList = Array.from(block.classList);
    
    // 查找 language-xxx 或 highlight-xxx 格式
    for (const className of classList) {
        if (className.startsWith('language-')) {
            return className.replace('language-', '');
        }
        if (className.startsWith('highlight-')) {
            return className.replace('highlight-', '');
        }
    }
    
    // 檢查內部元素
    const code = block.querySelector('code');
    if (code) {
        const codeClasses = Array.from(code.classList);
        for (const className of codeClasses) {
            if (className.startsWith('language-')) {
                return className.replace('language-', '');
            }
        }
    }
    
    // 常見語言檢測
    const content = block.textContent;
    if (content.includes('#!/bin/bash') || content.includes('#!/bin/sh')) return 'bash';
    if (content.includes('def ') && content.includes('import ')) return 'python';
    if (content.includes('function') && content.includes('console.log')) return 'javascript';
    if (content.includes('#include') && content.includes('int main')) return 'c';
    if (content.includes('class ') && content.includes('public ')) return 'java';
    if (content.includes('SELECT') && content.includes('FROM')) return 'sql';
    if (content.includes('<?php')) return 'php';
    if (content.includes('<!DOCTYPE') || content.includes('<html')) return 'html';
    if (content.includes('{') && content.includes('margin:')) return 'css';
    
    return 'code';
}

function getLanguageFromContent(content) {
    const trimmed = content.trim();
    
    // C/C++ 檢測
    if (trimmed.includes('#include <') && (trimmed.includes('int main') || trimmed.includes('void '))) {
        return 'c';
    }
    
    // Python 檢測
    if (trimmed.includes('def ') || trimmed.includes('import ') || trimmed.includes('from ')) {
        return 'python';
    }
    
    // JavaScript 檢測
    if (trimmed.includes('function ') || trimmed.includes('console.log') || trimmed.includes('const ') || trimmed.includes('let ')) {
        return 'javascript';
    }
    
    // Bash/Shell 檢測
    if (trimmed.startsWith('#!/bin/bash') || trimmed.startsWith('#!/bin/sh') || trimmed.includes('echo ')) {
        return 'bash';
    }
    
    // PHP 檢測
    if (trimmed.includes('<?php') || trimmed.includes('$_')) {
        return 'php';
    }
    
    // SQL 檢測
    if ((/SELECT|INSERT|UPDATE|DELETE|CREATE|DROP/i).test(trimmed)) {
        return 'sql';
    }
    
    return 'code';
}

function createCodeHeader(language, isLong) {
    const header = document.createElement('div');
    header.className = 'code-header';
    
    const languageSpan = document.createElement('span');
    languageSpan.className = 'code-language';
    languageSpan.textContent = getLanguageDisplayName(language);
    
    const actions = document.createElement('div');
    actions.className = 'code-actions';
    
    if (isLong) {
        const collapseBtn = document.createElement('button');
        collapseBtn.className = 'code-collapse-btn';
        collapseBtn.textContent = '展開';
        collapseBtn.setAttribute('data-collapsed', 'true');
        actions.appendChild(collapseBtn);
    }
    
    header.appendChild(languageSpan);
    header.appendChild(actions);
    
    return header;
}

function getLanguageDisplayName(lang) {
    const languageMap = {
        'js': 'JavaScript',
        'javascript': 'JavaScript',
        'ts': 'TypeScript',
        'typescript': 'TypeScript',
        'py': 'Python',
        'python': 'Python',
        'c': 'C',
        'cpp': 'C++',
        'cxx': 'C++',
        'java': 'Java',
        'php': 'PHP',
        'html': 'HTML',
        'css': 'CSS',
        'scss': 'SCSS',
        'sass': 'Sass',
        'bash': 'Bash',
        'sh': 'Shell',
        'shell': 'Shell',
        'sql': 'SQL',
        'json': 'JSON',
        'xml': 'XML',
        'yaml': 'YAML',
        'yml': 'YAML',
        'go': 'Go',
        'rust': 'Rust',
        'dockerfile': 'Dockerfile',
        'makefile': 'Makefile',
        'diff': 'Diff',
        'text': 'Text',
        'code': 'Code'
    };
    
    return languageMap[lang.toLowerCase()] || lang.toUpperCase();
}

function setupCollapseFeature(block, contentWrapper) {
    const collapseBtn = block.querySelector('.code-collapse-btn');
    if (!collapseBtn) {
        console.log('No collapse button found in:', block);
        return;
    }
    
    console.log('Setting up collapse feature for:', block);
    
    collapseBtn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        
        const isCollapsed = collapseBtn.getAttribute('data-collapsed') === 'true';
        
        console.log('Collapse button clicked, isCollapsed:', isCollapsed);
        
        if (isCollapsed) {
            // 展開
            contentWrapper.classList.remove('collapsed');
            contentWrapper.style.maxHeight = 'none';
            collapseBtn.textContent = '收起';
            collapseBtn.setAttribute('data-collapsed', 'false');
        } else {
            // 收起
            contentWrapper.classList.add('collapsed');
            contentWrapper.style.maxHeight = '300px';
            collapseBtn.textContent = '展開';
            collapseBtn.setAttribute('data-collapsed', 'true');
            
            // 滾動到程式碼區塊頂部
            block.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
}