/**
 * Shadow 1834 - Advanced Interactive Animations
 * Enhanced user interaction effects
 */

// ============================================
// 1. CUSTOM CURSOR TRAIL - DISABLED
// ============================================
// Cursor trail effects have been disabled

// ============================================
// 2. FLOATING CYBER PARTICLES BACKGROUND
// ============================================
class CyberParticles {
    constructor() {
        this.particles = [];
        this.particleCount = 30;
        this.init();
    }

    init() {
        const container = document.createElement('div');
        container.id = 'cyber-particles-container';
        container.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
            overflow: hidden;
        `;
        document.body.insertBefore(container, document.body.firstChild);

        for (let i = 0; i < this.particleCount; i++) {
            this.createParticle(container);
        }
    }

    createParticle(container) {
        const particle = document.createElement('div');
        const size = Math.random() * 4 + 2;
        const startX = Math.random() * window.innerWidth;
        const startY = Math.random() * window.innerHeight;
        const duration = Math.random() * 20 + 15;
        const delay = Math.random() * 5;

        const symbols = ['0', '1', '⚡', '◆', '●', '■', '▲'];
        const symbol = symbols[Math.floor(Math.random() * symbols.length)];

        particle.textContent = Math.random() > 0.7 ? symbol : '';
        particle.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            background: ${Math.random() > 0.5 ? '#00ffff' : '#00ff88'};
            border-radius: 50%;
            left: ${startX}px;
            top: ${startY}px;
            opacity: ${Math.random() * 0.3 + 0.1};
            box-shadow: 0 0 ${size * 2}px currentColor;
            font-size: ${size * 2}px;
            color: #00ffff;
            font-family: 'Orbitron', monospace;
            animation: float-particle ${duration}s linear ${delay}s infinite;
        `;

        container.appendChild(particle);
    }
}

// ============================================
// 3. CONFETTI EXPLOSION
// ============================================
function createConfetti(x, y) {
    const colors = ['#00ffff', '#00ff88', '#0088ff', '#ffaa00', '#ff4444'];
    const particleCount = 50;

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        const color = colors[Math.floor(Math.random() * colors.length)];
        const size = Math.random() * 8 + 4;

        particle.style.cssText = `
            position: fixed;
            width: ${size}px;
            height: ${size}px;
            background: ${color};
            left: ${x}px;
            top: ${y}px;
            border-radius: ${Math.random() > 0.5 ? '50%' : '0'};
            pointer-events: none;
            z-index: 10000;
            box-shadow: 0 0 10px ${color};
        `;

        document.body.appendChild(particle);

        const angle = (Math.PI * 2 * i) / particleCount;
        const velocity = Math.random() * 300 + 200;
        const tx = Math.cos(angle) * velocity;
        const ty = Math.sin(angle) * velocity;
        const rotation = Math.random() * 720 - 360;

        particle.animate([
            {
                transform: `translate(-50%, -50%) rotate(0deg)`,
                opacity: 1
            },
            {
                transform: `translate(${tx}px, ${ty + 200}px) rotate(${rotation}deg)`,
                opacity: 0
            }
        ], {
            duration: 2000 + Math.random() * 1000,
            easing: 'cubic-bezier(0, .9, .57, 1)'
        }).onfinish = () => particle.remove();
    }
}

// ============================================
// 4. SCORE COUNTER ANIMATION
// ============================================
function animateScoreCounter(element, start, end, duration = 2000) {
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function for smooth animation
        const easeOutExpo = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);

        const current = Math.floor(start + (end - start) * easeOutExpo);
        element.textContent = current;

        // Add visual effects during counting
        if (progress < 1) {
            element.style.transform = `scale(${1 + Math.sin(progress * Math.PI) * 0.1})`;
            element.style.textShadow = `0 0 ${20 + Math.sin(progress * Math.PI * 4) * 10}px #00ffff`;
            requestAnimationFrame(update);
        } else {
            element.textContent = end;
            element.style.transform = 'scale(1)';
            element.style.textShadow = '0 0 10px #00ffff';
        }
    }

    requestAnimationFrame(update);
}

// ============================================
// 5. CARD FLIP ANIMATION
// ============================================
function createFlipCard(card) {
    card.style.transformStyle = 'preserve-3d';
    card.style.transition = 'transform 0.6s cubic-bezier(0.4, 0.0, 0.2, 1)';

    let isFlipped = false;

    card.addEventListener('click', function(e) {
        if (!e.target.closest('a, button')) {
            isFlipped = !isFlipped;
            this.style.transform = isFlipped ? 'rotateY(180deg)' : 'rotateY(0deg)';
        }
    });
}

// ============================================
// 6. INTERACTIVE PROGRESS BARS
// ============================================
function enhanceProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');

    progressBars.forEach(bar => {
        const fill = bar.querySelector('.progress-fill');
        if (!fill) return;

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const width = fill.style.width || '0%';
                    fill.style.width = '0%';

                    setTimeout(() => {
                        fill.style.transition = 'width 1.5s cubic-bezier(0.4, 0.0, 0.2, 1)';
                        fill.style.width = width;

                        // Add sparkle effect
                        createSparkle(bar);
                    }, 100);

                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });

        observer.observe(bar);
    });
}

function createSparkle(element) {
    const sparkle = document.createElement('div');
    sparkle.style.cssText = `
        position: absolute;
        top: -2px;
        right: 0;
        width: 4px;
        height: calc(100% + 4px);
        background: linear-gradient(90deg, transparent, #ffffff, transparent);
        animation: sparkle-slide 2s ease-in-out;
        pointer-events: none;
    `;

    element.style.position = 'relative';
    element.appendChild(sparkle);

    setTimeout(() => sparkle.remove(), 2000);
}

// ============================================
// 7. TYPING SOUND EFFECT SIMULATION
// ============================================
class TypingSoundSimulator {
    constructor() {
        this.isTyping = false;
        this.init();
    }

    init() {
        const inputs = document.querySelectorAll('input[type="text"], input[type="password"], textarea');

        inputs.forEach(input => {
            input.addEventListener('keydown', (e) => {
                this.simulateKeyPress(e);
            });
        });
    }

    simulateKeyPress(event) {
        // Visual feedback
        const flash = document.createElement('div');
        flash.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at ${event.clientX}px ${event.clientY}px,
                rgba(0, 255, 255, 0.1), transparent 300px);
            pointer-events: none;
            z-index: 9999;
            animation: key-flash 0.15s ease-out;
        `;

        document.body.appendChild(flash);
        setTimeout(() => flash.remove(), 150);

        // Ripple effect from key position
        createParticles(event.clientX, event.clientY, '#00ffff', 3);
    }
}

// ============================================
// 8. INTERACTIVE HOVER ZONE - DISABLED
// ============================================
// Mouse glow effect has been removed

// ============================================
// 9. BADGE UNLOCK ANIMATION
// ============================================
function animateBadgeUnlock(badgeElement) {
    // Create overlay
    const overlay = document.createElement('div');
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        z-index: 10000;
        display: flex;
        align-items: center;
        justify-content: center;
        animation: fadeIn 0.3s ease-out;
    `;

    // Create badge showcase
    const showcase = document.createElement('div');
    showcase.style.cssText = `
        background: linear-gradient(135deg, rgba(0, 255, 255, 0.1), rgba(0, 136, 255, 0.1));
        border: 3px solid #00ffff;
        border-radius: 20px;
        padding: 3rem;
        text-align: center;
        animation: zoomIn 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
        box-shadow: 0 0 50px rgba(0, 255, 255, 0.5);
    `;

    showcase.innerHTML = `
        <div style="font-size: 6rem; margin-bottom: 1rem; animation: rotate-glow 2s linear infinite;">
            ${badgeElement.textContent || '🏆'}
        </div>
        <h2 style="color: #00ffff; font-family: 'Orbitron', monospace; font-size: 2rem; margin-bottom: 1rem; animation: text-flicker 0.5s ease-out;">
            ACHIEVEMENT UNLOCKED!
        </h2>
        <p style="color: #00ff88; font-family: 'Rajdhani', monospace; font-size: 1.2rem;">
            New badge earned!
        </p>
        <button onclick="this.closest('[style*=fixed]').remove()"
                style="margin-top: 2rem; padding: 1rem 2rem; background: rgba(0, 255, 255, 0.2);
                       border: 2px solid #00ffff; border-radius: 8px; color: #00ffff;
                       font-family: 'Orbitron', monospace; cursor: pointer; font-size: 1rem;
                       transition: all 0.3s ease;">
            CONTINUE
        </button>
    `;

    overlay.appendChild(showcase);
    document.body.appendChild(overlay);

    // Create confetti
    setTimeout(() => {
        createConfetti(window.innerWidth / 2, window.innerHeight / 2);
    }, 300);

    // Auto close after 5 seconds
    setTimeout(() => {
        overlay.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => overlay.remove(), 300);
    }, 5000);
}

// ============================================
// 10. SHAKE ELEMENT ON ERROR - DISABLED
// ============================================
// Shake animations have been removed
function shakeElement(element, intensity = 'medium') {
    // Shake animation disabled - function kept for compatibility
    return;
}

// ============================================
// INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    // Add required CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes fadeOut {
            from { opacity: 1; }
            to { opacity: 0; }
        }

        @keyframes zoomIn {
            from { transform: scale(0) rotate(-180deg); opacity: 0; }
            to { transform: scale(1) rotate(0deg); opacity: 1; }
        }

        @keyframes float-particle {
            0% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(-20px) rotate(180deg); }
            100% { transform: translateY(0) rotate(360deg); }
        }

        @keyframes sparkle-slide {
            0% { left: 0; opacity: 0; }
            50% { opacity: 1; }
            100% { left: 100%; opacity: 0; }
        }

        @keyframes key-flash {
            0% { opacity: 1; }
            100% { opacity: 0; }
        }
    `;
    document.head.appendChild(style);

    // Cursor trail disabled

    // Initialize floating particles
    new CyberParticles();

    // Initialize typing simulator
    new TypingSoundSimulator();

    // Enhance progress bars
    enhanceProgressBars();

    // Hover zones disabled - mouse glow effect removed

    // Animate score counters
    document.querySelectorAll('.stat-number').forEach(counter => {
        const target = parseInt(counter.textContent);
        if (!isNaN(target)) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        animateScoreCounter(counter, 0, target, 2000);
                        observer.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.5 });

            observer.observe(counter);
        }
    });

    // Click celebration disabled

    console.log('%c🚀 ADVANCED ANIMATIONS LOADED 🚀', 'color: #00ff88; font-size: 16px; font-weight: bold;');
});

// Export functions
if (typeof window !== 'undefined') {
    window.InteractiveAnimations = {
        createConfetti,
        animateScoreCounter,
        createFlipCard,
        animateBadgeUnlock,
        shakeElement,
        CursorTrail,
        CyberParticles
    };
}
