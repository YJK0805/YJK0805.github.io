// 圖片處理增強功能
document.addEventListener('DOMContentLoaded', function() {
    setupLazyLoading();
    setupImageModal();
});

// 圖片 Lazy Loading
function setupLazyLoading() {
    const images = document.querySelectorAll('.post-content img');
    
    // 創建 Intersection Observer
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                loadImage(img);
                observer.unobserve(img);
            }
        });
    }, {
        rootMargin: '50px 0px',
        threshold: 0.01
    });
    
    images.forEach(img => {
        // 設置 lazy loading
        if (img.src) {
            img.dataset.src = img.src;
            img.src = '';
            img.classList.add('img-lazy');
            
            // 創建佔位符
            const placeholder = createPlaceholder();
            img.parentNode.insertBefore(placeholder, img);
            img.style.display = 'none';
            
            imageObserver.observe(img);
        }
    });
}

function createPlaceholder() {
    const placeholder = document.createElement('div');
    placeholder.className = 'img-placeholder';
    placeholder.textContent = '圖片載入中...';
    return placeholder;
}

function loadImage(img) {
    const placeholder = img.previousElementSibling;
    
    img.onload = function() {
        img.classList.add('loaded');
        img.style.display = 'block';
        if (placeholder && placeholder.classList.contains('img-placeholder')) {
            placeholder.remove();
        }
    };
    
    img.onerror = function() {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'img-error';
        img.parentNode.replaceChild(errorDiv, img);
        if (placeholder && placeholder.classList.contains('img-placeholder')) {
            placeholder.remove();
        }
    };
    
    img.src = img.dataset.src;
}

// 圖片點擊放大功能
function setupImageModal() {
    const images = document.querySelectorAll('.post-content img');
    let currentImageIndex = 0;
    let imageList = [];
    
    // 創建模態框
    const modal = createImageModal();
    document.body.appendChild(modal);
    
    // 為每張圖片添加點擊事件
    images.forEach((img, index) => {
        img.addEventListener('click', function() {
            imageList = Array.from(images);
            currentImageIndex = index;
            showImageModal(this, modal);
        });
    });
    
    // 鍵盤事件
    document.addEventListener('keydown', function(e) {
        if (modal.classList.contains('show')) {
            switch(e.key) {
                case 'Escape':
                    hideImageModal(modal);
                    break;
                case 'ArrowLeft':
                    navigateImage(-1, modal);
                    break;
                case 'ArrowRight':
                    navigateImage(1, modal);
                    break;
            }
        }
    });
}

function createImageModal() {
    const modal = document.createElement('div');
    modal.className = 'image-modal';
    
    const img = document.createElement('img');
    img.alt = 'Enlarged image';
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'image-modal-close';
    closeBtn.innerHTML = '×';
    closeBtn.onclick = () => hideImageModal(modal);
    
    const info = document.createElement('div');
    info.className = 'image-modal-info';
    
    const prevBtn = document.createElement('button');
    prevBtn.className = 'image-modal-nav prev';
    prevBtn.innerHTML = '‹';
    prevBtn.onclick = () => navigateImage(-1, modal);
    
    const nextBtn = document.createElement('button');
    nextBtn.className = 'image-modal-nav next';
    nextBtn.innerHTML = '›';
    nextBtn.onclick = () => navigateImage(1, modal);
    
    modal.appendChild(img);
    modal.appendChild(closeBtn);
    modal.appendChild(info);
    modal.appendChild(prevBtn);
    modal.appendChild(nextBtn);
    
    // 點擊背景關閉
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            hideImageModal(modal);
        }
    });
    
    return modal;
}

function showImageModal(clickedImg, modal) {
    const modalImg = modal.querySelector('img');
    const modalInfo = modal.querySelector('.image-modal-info');
    const prevBtn = modal.querySelector('.prev');
    const nextBtn = modal.querySelector('.next');
    
    modalImg.src = clickedImg.src || clickedImg.dataset.src;
    modalImg.alt = clickedImg.alt || '圖片';
    
    // 設置圖片信息
    const imgInfo = getImageInfo(clickedImg);
    modalInfo.textContent = imgInfo;
    
    // 顯示/隱藏導航按鈕
    const imageList = document.querySelectorAll('.post-content img');
    if (imageList.length > 1) {
        prevBtn.style.display = 'flex';
        nextBtn.style.display = 'flex';
    } else {
        prevBtn.style.display = 'none';
        nextBtn.style.display = 'none';
    }
    
    modal.classList.add('show');
    document.body.style.overflow = 'hidden';
}

function hideImageModal(modal) {
    modal.classList.remove('show');
    document.body.style.overflow = '';
}

function navigateImage(direction, modal) {
    const images = document.querySelectorAll('.post-content img');
    currentImageIndex += direction;
    
    if (currentImageIndex < 0) {
        currentImageIndex = images.length - 1;
    } else if (currentImageIndex >= images.length) {
        currentImageIndex = 0;
    }
    
    const targetImg = images[currentImageIndex];
    showImageModal(targetImg, modal);
}

function getImageInfo(img) {
    let info = '';
    
    if (img.alt) {
        info = img.alt;
    } else if (img.title) {
        info = img.title;
    } else {
        // 嘗試從檔案名獲取信息
        const src = img.src || img.dataset.src;
        if (src) {
            const filename = src.split('/').pop().split('?')[0];
            info = filename;
        }
    }
    
    return info || '圖片';
}

// 支援觸控手勢（移動設備）
function setupTouchGestures(modal) {
    let startX = 0;
    let startY = 0;
    
    modal.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
    });
    
    modal.addEventListener('touchend', function(e) {
        if (!startX || !startY) return;
        
        const endX = e.changedTouches[0].clientX;
        const endY = e.changedTouches[0].clientY;
        
        const diffX = startX - endX;
        const diffY = startY - endY;
        
        // 水平滑動距離大於垂直滑動距離
        if (Math.abs(diffX) > Math.abs(diffY)) {
            if (Math.abs(diffX) > 50) { // 最小滑動距離
                if (diffX > 0) {
                    // 向左滑動，顯示下一張
                    navigateImage(1, modal);
                } else {
                    // 向右滑動，顯示上一張
                    navigateImage(-1, modal);
                }
            }
        } else {
            // 垂直滑動，如果向下滑動距離夠大則關閉
            if (diffY < -100) {
                hideImageModal(modal);
            }
        }
        
        startX = 0;
        startY = 0;
    });
}