// ===== EzVeriPhish Main JS =====

// Loading state on form submit
const form = document.getElementById('analyzeForm');
if (form) {
    form.addEventListener('submit', function () {
        const btn = document.getElementById('analyzeBtn');
        if (!btn) return;
        const emailContent = document.getElementById('emailContent');
        if (!emailContent || !emailContent.value.trim()) return;
        btn.disabled = true;
        const text   = btn.querySelector('.btn-text');
        const loader = btn.querySelector('.btn-loader');
        if (text)   text.style.display   = 'none';
        if (loader) loader.style.display = 'flex';
    });
}

// Animate stat numbers on history page
function animateNumber(el) {
    const target = parseInt(el.textContent, 10);
    if (isNaN(target) || target === 0) return;
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 30));
    const interval = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current;
        if (current >= target) clearInterval(interval);
    }, 30);
}

document.querySelectorAll('.stat-number').forEach(animateNumber);

// Animate result page entrance
const resultPage = document.querySelector('.result-page');
if (resultPage) {
    resultPage.style.opacity = '0';
    resultPage.style.transform = 'translateY(20px)';
    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            resultPage.style.transition = 'opacity 0.45s ease, transform 0.45s ease';
            resultPage.style.opacity = '1';
            resultPage.style.transform = 'translateY(0)';
        });
    });
}

// Feature card stagger animation on index
document.querySelectorAll('.feature-card').forEach((card, i) => {
    card.style.animationDelay = `${i * 0.1}s`;
});

// Highlight blacklisted URL rows
document.querySelectorAll('.url-item-danger').forEach(el => {
    el.style.animationName = 'flashDanger';
    el.style.animationDuration = '0.6s';
    el.style.animationTimingFunction = 'ease';
});

// Inject flash animation
const style = document.createElement('style');
style.textContent = `
@keyframes flashDanger {
    0%   { background: #ffe4e4; }
    50%  { background: #fff0f0; }
    100% { background: #fff5f5; }
}`;
document.head.appendChild(style);
