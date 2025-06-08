// Common UI Animations and Behaviors
document.addEventListener('DOMContentLoaded', function() {
    // Header fade-in animation
    const header = document.querySelector('.refined-header');
    if (header) {
        requestAnimationFrame(() => {
            header.classList.add('visible');
        });
    }

    // Section divider animations
    const dividers = document.querySelectorAll('.section-divider');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });
    
    dividers.forEach(divider => observer.observe(divider));
}); 