// 閱讀進度條與浮動目錄功能
document.addEventListener('DOMContentLoaded', function() {
    // 只在文章頁面顯示進度條和浮動目錄
    if (!document.querySelector('.post-content')) return;
    
    // 建立進度條元素
    const progressBar = document.createElement('div');
    progressBar.className = 'reading-progress';
    document.body.appendChild(progressBar);
    
    // 建立浮動目錄按鈕
    const floatingTocBtn = document.createElement('div');
    floatingTocBtn.className = 'floating-toc';
    floatingTocBtn.title = '目錄';
    floatingTocBtn.innerHTML = `
        <svg viewBox="0 0 24 24">
            <path d="M3,9H17V7H3V9M3,13H17V11H3V13M3,17H17V15H3V17M19,17H21V15H19V17M19,7V9H21V7H19M19,13H21V11H19V13Z" />
        </svg>
    `;
    document.body.appendChild(floatingTocBtn);
    
    // 建立回到頂部按鈕
    const scrollToTopBtn = document.createElement('div');
    scrollToTopBtn.className = 'scroll-to-top-btn';
    scrollToTopBtn.title = '回到頂部';
    scrollToTopBtn.innerHTML = `
        <svg viewBox="0 0 24 24">
            <path d="M7,14L12,9L17,14H7Z" />
        </svg>
    `;
    document.body.appendChild(scrollToTopBtn);
    
    // 建立浮動目錄面板
    const floatingTocPanel = document.createElement('div');
    floatingTocPanel.className = 'floating-toc-panel';
    document.body.appendChild(floatingTocPanel);
    
    // 生成浮動目錄內容
    function generateFloatingToc() {
        const headings = document.querySelectorAll('.post-content h1, .post-content h2, .post-content h3, .post-content h4, .post-content h5, .post-content h6');
        if (headings.length === 0) {
            floatingTocBtn.style.display = 'none';
            return;
        }
        
        let tocHTML = '<h4>目錄</h4><ul>';
        
        headings.forEach((heading, index) => {
            const level = heading.tagName.toLowerCase().substring(1);
            const id = heading.id || `heading-${index}`;
            const text = heading.textContent.trim();
            
            // 如果標題沒有 id，添加一個
            if (!heading.id) {
                heading.id = id;
            }
            
            tocHTML += `<li data-level="${level}"><a href="#${id}">${text}</a></li>`;
        });
        
        tocHTML += '</ul>';
        floatingTocPanel.innerHTML = tocHTML;
        
        // 為目錄連結添加點擊事件
        floatingTocPanel.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({ behavior: 'smooth' });
                    floatingTocPanel.classList.remove('show');
                }
            });
        });
    }
    
    // 更新當前閱讀位置高亮
    function updateActiveHeading() {
        const headings = document.querySelectorAll('.post-content h1, .post-content h2, .post-content h3, .post-content h4, .post-content h5, .post-content h6');
        const tocLinks = floatingTocPanel.querySelectorAll('a');
        
        let activeHeading = null;
        
        headings.forEach(heading => {
            const rect = heading.getBoundingClientRect();
            if (rect.top <= 100) {
                activeHeading = heading;
            }
        });
        
        // 移除所有 active 類別
        tocLinks.forEach(link => link.classList.remove('active'));
        
        // 添加 active 類別到當前標題
        if (activeHeading) {
            const activeLink = floatingTocPanel.querySelector(`a[href="#${activeHeading.id}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
            }
        }
    }
    
    // 計算閱讀進度
    function updateReadingProgress() {
        const article = document.querySelector('.post-content');
        if (!article) return;
        
        const articleRect = article.getBoundingClientRect();
        const articleHeight = article.offsetHeight;
        const windowHeight = window.innerHeight;
        
        // 計算已閱讀的百分比
        const scrolled = Math.max(0, -articleRect.top);
        const progress = Math.min(100, (scrolled / (articleHeight - windowHeight + 200)) * 100);
        
        // 更新進度條寬度
        progressBar.style.width = progress + '%';
        
        // 更新當前閱讀位置
        updateActiveHeading();
    }
    
    // 檢查是否顯示回到頂部按鈕
    function updateScrollToTopState() {
        const scrolled = window.pageYOffset || document.documentElement.scrollTop;
        if (scrolled > 300) {
            scrollToTopBtn.classList.add('show');
        } else {
            scrollToTopBtn.classList.remove('show');
        }
    }
    
    // 目錄按鈕點擊事件
    let tocVisible = false;
    floatingTocBtn.addEventListener('click', function(e) {
        e.preventDefault();
        tocVisible = !tocVisible;
        floatingTocPanel.classList.toggle('show', tocVisible);
    });
    
    // 回到頂部按鈕點擊事件
    scrollToTopBtn.addEventListener('click', function(e) {
        e.preventDefault();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    
    // 點擊其他地方關閉目錄
    document.addEventListener('click', function(e) {
        if (!floatingTocBtn.contains(e.target) && !floatingTocPanel.contains(e.target)) {
            tocVisible = false;
            floatingTocPanel.classList.remove('show');
        }
    });
    
    // 監聽滾動事件
    window.addEventListener('scroll', function() {
        updateReadingProgress();
        updateScrollToTopState();
    });
    window.addEventListener('resize', updateReadingProgress);
    
    // 初始化
    generateFloatingToc();
    updateReadingProgress();
    updateScrollToTopState();
});