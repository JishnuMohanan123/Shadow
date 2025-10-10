/**
 * Shadow 1834 - Base JavaScript
 * Common functionality and cyber-themed notifications
 */

// Cyber notification system with enhanced animations
function showCyberNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.cyber-notification');
    existingNotifications.forEach(notification => {
        notification.style.animation = 'slide-out-right 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    });

    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'cyber-notification';
    notification.setAttribute('role', 'alert');
    notification.setAttribute('aria-live', 'assertive');

    // Set notification style based on type
    let bgColor, borderColor, icon, soundEffect;
    switch(type) {
        case 'success':
            bgColor = 'rgba(0, 255, 136, 0.2)';
            borderColor = '#00ff88';
            icon = '✅';
            soundEffect = 'success';
            break;
        case 'error':
            bgColor = 'rgba(255, 68, 68, 0.2)';
            borderColor = '#ff4444';
            icon = '❌';
            soundEffect = 'error';
            break;
        case 'warning':
            bgColor = 'rgba(255, 170, 0, 0.2)';
            borderColor = '#ffaa00';
            icon = '⚠️';
            soundEffect = 'warning';
            break;
        default:
            bgColor = 'rgba(0, 255, 255, 0.2)';
            borderColor = '#00ffff';
            icon = 'ℹ️';
            soundEffect = 'info';
    }

    notification.style.background = bgColor;
    notification.style.border = `2px solid ${borderColor}`;
    notification.style.color = '#ffffff';
    notification.style.fontFamily = "'Orbitron', monospace";

    notification.innerHTML = `
        <span style="font-size: 1.2rem; margin-right: 0.5rem; animation: bounce-in 0.5s ease-out;">${icon}</span>
        <span style="flex: 1; font-weight: 600;">${message}</span>
        <button class="notification-close" style="background: none; border: none; color: inherit; font-size: 1.2rem; cursor: pointer; padding: 0 0.5rem; transition: all 0.2s;">&times;</button>
    `;

    document.body.appendChild(notification);

    // Add close button functionality
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        notification.style.animation = 'slide-out-right 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    });

    closeBtn.addEventListener('mouseenter', () => {
        closeBtn.style.transform = 'scale(1.2) rotate(90deg)';
    });

    closeBtn.addEventListener('mouseleave', () => {
        closeBtn.style.transform = 'scale(1) rotate(0deg)';
    });

    // Show notification with slide-in animation
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);

    // Simulate sound effect with visual feedback
    simulateSoundEffect(soundEffect);

    // Auto-hide after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slide-out-right 0.5s ease-out';
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 5000);
}

// Simulate sound effects with visual feedback
function simulateSoundEffect(type) {
    const body = document.body;

    switch(type) {
        case 'success':
            body.style.animation = 'none';
            setTimeout(() => {
                body.style.animation = 'success-flash 0.3s ease-out';
            }, 10);
            break;
        case 'error':
            // Error shake animation removed
            break;
        case 'warning':
            body.style.animation = 'none';
            setTimeout(() => {
                body.style.animation = 'warning-pulse 0.5s ease-out';
            }, 10);
            break;
    }

    setTimeout(() => {
        body.style.animation = '';
    }, 600);
}

// Add ripple effect to buttons and cards
function createRipple(event) {
    const element = event.currentTarget;
    const ripple = document.createElement('span');
    const rect = element.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = event.clientX - rect.left - size / 2;
    const y = event.clientY - rect.top - size / 2;

    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = x + 'px';
    ripple.style.top = y + 'px';
    ripple.className = 'ripple-effect';

    // Remove existing ripples
    const existingRipples = element.querySelectorAll('.ripple-effect');
    existingRipples.forEach(r => r.remove());

    element.appendChild(ripple);

    setTimeout(() => ripple.remove(), 600);
}

// Enhanced hover effects for cards
function enhanceCardAnimations() {
    const cards = document.querySelectorAll('.card, .module-card, .stat-card');

    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
            this.style.transform = 'translateY(-5px) scale(1.02)';
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });

        // Add tilt effect on mouse move
        card.addEventListener('mousemove', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            const rotateX = (y - centerY) / 20;
            const rotateY = (centerX - x) / 20;

            this.style.transform = `
                perspective(1000px)
                rotateX(${rotateX}deg)
                rotateY(${rotateY}deg)
                translateY(-5px)
                scale(1.02)
            `;
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    });
}

// Particle effect system
function createParticles(x, y, color = '#00ffff', count = 10) {
    for (let i = 0; i < count; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.cssText = `
            position: fixed;
            width: 4px;
            height: 4px;
            background: ${color};
            border-radius: 50%;
            pointer-events: none;
            z-index: 9999;
            box-shadow: 0 0 10px ${color};
        `;

        const angle = (Math.PI * 2 * i) / count;
        const velocity = 2 + Math.random() * 3;
        const tx = Math.cos(angle) * velocity * 30;
        const ty = Math.sin(angle) * velocity * 30;

        particle.style.left = x + 'px';
        particle.style.top = y + 'px';

        document.body.appendChild(particle);

        particle.animate([
            {
                transform: 'translate(0, 0) scale(1)',
                opacity: 1
            },
            {
                transform: `translate(${tx}px, ${ty}px) scale(0)`,
                opacity: 0
            }
        ], {
            duration: 600 + Math.random() * 400,
            easing: 'cubic-bezier(0, .9, .57, 1)'
        }).onfinish = () => particle.remove();
    }
}

// Typewriter effect for text
function typewriterEffect(element, text, speed = 50) {
    let i = 0;
    element.textContent = '';

    function type() {
        if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }

    type();
}

// Glitch effect for text
function glitchText(element, duration = 300) {
    const originalText = element.textContent;
    const glitchChars = '!<>-_\\/[]{}—=+*^?#________';
    let iterations = 0;
    const maxIterations = duration / 30;

    const interval = setInterval(() => {
        element.textContent = originalText
            .split('')
            .map((char, index) => {
                if (index < iterations) {
                    return originalText[index];
                }
                return glitchChars[Math.floor(Math.random() * glitchChars.length)];
            })
            .join('');

        iterations += 1/3;

        if (iterations >= originalText.length) {
            clearInterval(interval);
            element.textContent = originalText;
        }
    }, 30);
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the home/login page
    const isHomePage = document.querySelector('.login-page') !== null;

    // Add additional animation keyframes
    if (!document.querySelector('#cyber-animations')) {
        const style = document.createElement('style');
        style.id = 'cyber-animations';
        style.textContent = `
            @keyframes slide-out-right {
                0% { transform: translateX(0); opacity: 1; }
                100% { transform: translateX(120%); opacity: 0; }
            }

            @keyframes success-flash {
                0%, 100% { background-color: transparent; }
                50% { background-color: rgba(0, 255, 136, 0.05); }
            }

            @keyframes warning-pulse {
                0%, 100% { box-shadow: none; }
                50% { box-shadow: inset 0 0 50px rgba(255, 170, 0, 0.1); }
            }

            .ripple-effect {
                position: absolute;
                border-radius: 50%;
                background: rgba(0, 255, 255, 0.5);
                pointer-events: none;
                animation: ripple-animation 0.6s ease-out;
            }

            @keyframes ripple-animation {
                0% {
                    transform: scale(0);
                    opacity: 1;
                }
                100% {
                    transform: scale(2);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // Only apply these animations on the home page
    if (isHomePage) {
        // Initialize card animations
        enhanceCardAnimations();

        // Add glitch effect to titles on hover
        const titles = document.querySelectorAll('h1, h2, h3');
        titles.forEach(title => {
            let glitchTimeout;
            title.addEventListener('mouseenter', function() {
                glitchTimeout = setTimeout(() => {
                    glitchText(this, 400);
                }, 200);
            });

            title.addEventListener('mouseleave', function() {
                clearTimeout(glitchTimeout);
            });
        });

        // Add entrance animations to elements
        const animatedElements = document.querySelectorAll('.card, .stat-card, .module-card');
        animatedElements.forEach((element, index) => {
            element.style.opacity = '0';
            element.style.transform = 'translateY(30px)';
            setTimeout(() => {
                element.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }, index * 100);
        });

        // Parallax effect for background
        let ticking = false;
        document.addEventListener('mousemove', function(e) {
            if (!ticking) {
                window.requestAnimationFrame(() => {
                    const x = e.clientX / window.innerWidth;
                    const y = e.clientY / window.innerHeight;

                    const cards = document.querySelectorAll('.card, .module-card');
                    cards.forEach(card => {
                        const speed = card.dataset.speed || 5;
                        const moveX = (x - 0.5) * speed;
                        const moveY = (y - 0.5) * speed;

                        if (!card.matches(':hover')) {
                            card.style.transform = `translate(${moveX}px, ${moveY}px)`;
                        }
                    });

                    ticking = false;
                });

                ticking = true;
            }
        });
    }

    // Add ripple effect to all buttons (keeping this on all pages)
    const buttons = document.querySelectorAll('.btn, button, .btn-primary, .btn-secondary, .btn-success');
    buttons.forEach(button => {
        button.style.position = 'relative';
        button.style.overflow = 'hidden';
        button.addEventListener('click', createRipple);

        // Add particle effect on button click
        button.addEventListener('click', function(e) {
            if (!this.disabled) {
                createParticles(e.clientX, e.clientY, '#00ffff', 8);
            }
        });
    });

    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Esc key to close notifications
        if (e.key === 'Escape') {
            const notifications = document.querySelectorAll('.cyber-notification');
            notifications.forEach(n => {
                n.style.animation = 'slide-out-right 0.3s ease-out';
                setTimeout(() => n.remove(), 300);
            });
        }
    });

    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add hover effect to links
    const links = document.querySelectorAll('a:not(.btn)');
    links.forEach(link => {
        link.addEventListener('mouseenter', function() {
            this.style.transition = 'all 0.2s ease';
            this.style.textShadow = '0 0 10px currentColor';
        });

        link.addEventListener('mouseleave', function() {
            this.style.textShadow = '';
        });
    });

    // Add loading indicator for forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = this.querySelector('[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                const originalText = submitBtn.textContent;
                submitBtn.style.position = 'relative';
                submitBtn.style.pointerEvents = 'none';

                // Add loading animation
                const loader = document.createElement('span');
                loader.style.cssText = `
                    display: inline-block;
                    width: 14px;
                    height: 14px;
                    border: 2px solid rgba(255, 255, 255, 0.3);
                    border-top-color: #fff;
                    border-radius: 50%;
                    animation: spin 0.6s linear infinite;
                    margin-left: 8px;
                `;

                const spinKeyframes = `
                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }
                `;

                if (!document.querySelector('#spin-animation')) {
                    const spinStyle = document.createElement('style');
                    spinStyle.id = 'spin-animation';
                    spinStyle.textContent = spinKeyframes;
                    document.head.appendChild(spinStyle);
                }

                submitBtn.appendChild(loader);
            }
        });
    });

    console.log('%c⚡ SHADOW 1834 SYSTEMS ONLINE ⚡', 'color: #00ffff; font-size: 20px; font-weight: bold; text-shadow: 0 0 10px #00ffff;');
    console.log('%cCyber Warfare Training Platform Initialized', 'color: #00ff88; font-size: 14px;');
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        showCyberNotification,
        createRipple,
        createParticles,
        typewriterEffect,
        glitchText,
        enhanceCardAnimations
    };
}
