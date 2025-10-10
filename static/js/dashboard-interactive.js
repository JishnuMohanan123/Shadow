/**
 * Shadow 1834 - Dashboard Interactive Enhancements
 * Advanced interactivity for mission selection and dashboard
 */

// ============================================
// 1. MISSION CARD INTERACTIVITY
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    initializeMissionCards();
    initializeFiltering();
    initializeStatsAnimations();
    initializeTooltips();
});

function initializeMissionCards() {
    const missionCards = document.querySelectorAll('.module-card');

    missionCards.forEach(card => {
        // Add 3D tilt effect on hover
        card.addEventListener('mousemove', function(e) {
            if (this.classList.contains('locked')) return;

            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const centerX = rect.width / 2;
            const centerY = rect.height / 2;

            const rotateX = (y - centerY) / 20;
            const rotateY = (centerX - x) / 20;

            this.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale(1.02)`;
            this.style.transition = 'transform 0.1s ease';
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) scale(1)';
            this.style.transition = 'transform 0.3s ease';
        });

        // Add click ripple effect
        card.addEventListener('click', function(e) {
            if (this.classList.contains('locked')) {
                // Locked card - no shake animation
                showCyberNotification('🔒 Security Clearance Required! Complete previous missions to unlock.', 'warning');
                return;
            }

            createRippleEffect(e, this);
        });

        // Add glow effect for available missions
        if (!card.classList.contains('locked') && !card.classList.contains('completed')) {
            addPulsingGlow(card);
        }

        // Add completion celebration for completed cards
        if (card.classList.contains('completed')) {
            addCompletionEffects(card);
        }
    });
}

function createRippleEffect(event, element) {
    const ripple = document.createElement('div');
    const rect = element.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = event.clientX - rect.left - size / 2;
    const y = event.clientY - rect.top - size / 2;

    ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(0, 255, 255, 0.6), transparent);
        left: ${x}px;
        top: ${y}px;
        pointer-events: none;
        z-index: 10;
    `;

    element.style.position = 'relative';
    element.style.overflow = 'hidden';
    element.appendChild(ripple);

    ripple.animate([
        { transform: 'scale(0)', opacity: 1 },
        { transform: 'scale(2)', opacity: 0 }
    ], {
        duration: 600,
        easing: 'ease-out'
    }).onfinish = () => ripple.remove();
}

function addPulsingGlow(card) {
    // Add subtle pulsing border glow for available missions
    const glowInterval = setInterval(() => {
        if (card.classList.contains('locked') || card.classList.contains('completed')) {
            clearInterval(glowInterval);
            return;
        }

        card.style.boxShadow = '0 0 30px rgba(0, 255, 255, 0.5), 0 0 60px rgba(0, 255, 255, 0.3)';
        setTimeout(() => {
            card.style.boxShadow = '';
        }, 1000);
    }, 3000);
}

function addCompletionEffects(card) {
    // Add checkmark animation overlay
    const checkmark = document.createElement('div');
    checkmark.style.cssText = `
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 80px;
        opacity: 0;
        pointer-events: none;
        z-index: 5;
    `;
    checkmark.textContent = '✓';

    card.style.position = 'relative';
    card.appendChild(checkmark);

    // Add green tint overlay
    card.style.background = 'linear-gradient(135deg, rgba(0, 255, 136, 0.1), rgba(0, 136, 255, 0.05))';
}

// ============================================
// 2. FILTERING SYSTEM
// ============================================

function initializeFiltering() {
    // Create filter controls
    const missionsSection = document.querySelector('.missions-section');
    if (!missionsSection) return;

    const filterHTML = `
        <div class="mission-filters" style="margin: 1.5rem 0; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;">
            <div style="color: #00ffff; font-family: 'Orbitron', monospace; font-size: 0.9rem; font-weight: 600;">
                FILTER:
            </div>
            <button class="filter-btn active" data-filter="all" style="padding: 0.5rem 1rem; background: rgba(0, 255, 255, 0.2); border: 2px solid #00ffff; border-radius: 6px; color: #00ffff; font-family: 'Orbitron', monospace; cursor: pointer; transition: all 0.3s;">
                ALL MISSIONS
            </button>
            <button class="filter-btn" data-filter="available" style="padding: 0.5rem 1rem; background: rgba(0, 255, 255, 0.05); border: 2px solid rgba(0, 255, 255, 0.3); border-radius: 6px; color: #00ffff; font-family: 'Orbitron', monospace; cursor: pointer; transition: all 0.3s;">
                AVAILABLE
            </button>
            <button class="filter-btn" data-filter="completed" style="padding: 0.5rem 1rem; background: rgba(0, 255, 136, 0.05); border: 2px solid rgba(0, 255, 136, 0.3); border-radius: 6px; color: #00ff88; font-family: 'Orbitron', monospace; cursor: pointer; transition: all 0.3s;">
                COMPLETED
            </button>
            <button class="filter-btn" data-filter="locked" style="padding: 0.5rem 1rem; background: rgba(255, 68, 68, 0.05); border: 2px solid rgba(255, 68, 68, 0.3); border-radius: 6px; color: #ff4444; font-family: 'Orbitron', monospace; cursor: pointer; transition: all 0.3s;">
                LOCKED
            </button>
            <div style="flex: 1;"></div>
            <select id="difficultyFilter" style="padding: 0.5rem 1rem; background: rgba(0, 136, 255, 0.1); border: 2px solid rgba(0, 136, 255, 0.3); border-radius: 6px; color: #00ffff; font-family: 'Orbitron', monospace; cursor: pointer;">
                <option value="all">ALL DIFFICULTIES</option>
                <option value="low">LOW THREAT</option>
                <option value="medium">MEDIUM THREAT</option>
                <option value="high">HIGH THREAT</option>
                <option value="critical">CRITICAL THREAT</option>
            </select>
        </div>
    `;

    missionsSection.querySelector('.section-header').insertAdjacentHTML('afterend', filterHTML);

    // Add filter button event listeners
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons
            filterButtons.forEach(b => {
                b.classList.remove('active');
                b.style.background = 'rgba(0, 255, 255, 0.05)';
                b.style.borderColor = 'rgba(0, 255, 255, 0.3)';
            });

            // Add active class to clicked button
            this.classList.add('active');
            this.style.background = 'rgba(0, 255, 255, 0.2)';
            this.style.borderColor = '#00ffff';

            filterMissions(this.dataset.filter);
        });

        // Hover effects
        btn.addEventListener('mouseenter', function() {
            if (!this.classList.contains('active')) {
                this.style.background = 'rgba(0, 255, 255, 0.15)';
                this.style.transform = 'translateY(-2px)';
            }
        });

        btn.addEventListener('mouseleave', function() {
            if (!this.classList.contains('active')) {
                this.style.background = 'rgba(0, 255, 255, 0.05)';
                this.style.transform = 'translateY(0)';
            }
        });
    });

    // Difficulty filter
    document.getElementById('difficultyFilter').addEventListener('change', function() {
        filterByDifficulty(this.value);
    });
}

function filterMissions(filter) {
    const cards = document.querySelectorAll('.module-card');
    let visibleCount = 0;

    cards.forEach((card, index) => {
        let shouldShow = false;

        switch(filter) {
            case 'all':
                shouldShow = true;
                break;
            case 'available':
                shouldShow = !card.classList.contains('locked') && !card.classList.contains('completed');
                break;
            case 'completed':
                shouldShow = card.classList.contains('completed');
                break;
            case 'locked':
                shouldShow = card.classList.contains('locked');
                break;
        }

        if (shouldShow) {
            card.style.display = 'block';
            card.style.animation = `fadeInScale 0.5s ease-out ${index * 0.1}s both`;
            visibleCount++;
        } else {
            card.style.animation = 'fadeOut 0.3s ease-out';
            setTimeout(() => {
                card.style.display = 'none';
            }, 300);
        }
    });

    // Show count notification
    showCyberNotification(`📊 Showing ${visibleCount} mission(s)`, 'info');
}

function filterByDifficulty(difficulty) {
    const cards = document.querySelectorAll('.module-card');
    let visibleCount = 0;

    cards.forEach((card, index) => {
        const difficultyBadge = card.querySelector('.difficulty-badge');
        if (!difficultyBadge) return;

        const cardDifficulty = difficultyBadge.textContent.trim().toLowerCase();
        const shouldShow = difficulty === 'all' || cardDifficulty === difficulty;

        if (shouldShow) {
            card.style.display = 'block';
            card.style.animation = `fadeInScale 0.5s ease-out ${index * 0.1}s both`;
            visibleCount++;
        } else {
            card.style.animation = 'fadeOut 0.3s ease-out';
            setTimeout(() => {
                card.style.display = 'none';
            }, 300);
        }
    });

    showCyberNotification(`🎯 Filtered by ${difficulty.toUpperCase()} difficulty - ${visibleCount} mission(s)`, 'info');
}

// ============================================
// 3. ANIMATED STATISTICS
// ============================================

function initializeStatsAnimations() {
    const statNumbers = document.querySelectorAll('.stat-number');

    // Intersection Observer for scroll animations
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateStatNumber(entry.target);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    statNumbers.forEach(stat => observer.observe(stat));

    // Add hover effects to stat cards
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-10px) scale(1.03)';
            this.style.boxShadow = '0 10px 40px rgba(0, 255, 255, 0.3)';

            // Pulse the stat number
            const number = this.querySelector('.stat-number');
            if (number) {
                number.style.animation = 'pulse 0.6s ease-in-out';
            }
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';

            const number = this.querySelector('.stat-number');
            if (number) {
                number.style.animation = '';
            }
        });
    });
}

function animateStatNumber(element) {
    const targetValue = parseInt(element.textContent);
    if (isNaN(targetValue)) return;

    const duration = 2000;
    const startTime = performance.now();

    function updateNumber(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function
        const easeOutQuart = 1 - Math.pow(1 - progress, 4);
        const currentValue = Math.floor(targetValue * easeOutQuart);

        element.textContent = currentValue;

        // Add visual effects during counting
        element.style.transform = `scale(${1 + Math.sin(progress * Math.PI) * 0.1})`;
        element.style.textShadow = `0 0 ${20 + Math.sin(progress * Math.PI * 4) * 10}px #00ffff`;

        if (progress < 1) {
            requestAnimationFrame(updateNumber);
        } else {
            element.textContent = targetValue;
            element.style.transform = 'scale(1)';
            element.style.textShadow = '0 0 10px #00ffff';
        }
    }

    requestAnimationFrame(updateNumber);
}

// ============================================
// 4. INTERACTIVE TOOLTIPS
// ============================================

function initializeTooltips() {
    // Add tooltips to mission cards
    const missionCards = document.querySelectorAll('.module-card');

    missionCards.forEach(card => {
        const tooltip = document.createElement('div');
        tooltip.className = 'mission-tooltip';
        tooltip.style.cssText = `
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%) translateY(-10px);
            background: rgba(0, 0, 0, 0.95);
            border: 2px solid #00ffff;
            border-radius: 8px;
            padding: 1rem;
            min-width: 250px;
            opacity: 0;
            pointer-events: none;
            transition: all 0.3s ease;
            z-index: 1000;
            box-shadow: 0 10px 30px rgba(0, 255, 255, 0.3);
        `;

        // Get mission details
        const title = card.querySelector('h3')?.textContent || 'Mission';
        const description = card.querySelector('p')?.textContent || '';
        const difficulty = card.querySelector('.difficulty-badge')?.textContent || 'Unknown';
        const reward = card.querySelector('[style*="REWARD"]')?.textContent || '';

        tooltip.innerHTML = `
            <div style="color: #00ffff; font-family: 'Orbitron', monospace; font-weight: 700; margin-bottom: 0.5rem; font-size: 0.9rem;">
                ${title}
            </div>
            <div style="color: #a0c4ff; font-size: 0.8rem; margin-bottom: 0.5rem; line-height: 1.4;">
                ${description.substring(0, 100)}${description.length > 100 ? '...' : ''}
            </div>
            <div style="display: flex; gap: 0.5rem; font-size: 0.75rem;">
                <span style="background: rgba(255, 170, 0, 0.2); color: #ffaa00; padding: 0.25rem 0.5rem; border-radius: 4px;">
                    ${difficulty}
                </span>
                <span style="background: rgba(0, 255, 136, 0.2); color: #00ff88; padding: 0.25rem 0.5rem; border-radius: 4px;">
                    ${reward}
                </span>
            </div>
        `;

        card.style.position = 'relative';
        card.appendChild(tooltip);

        card.addEventListener('mouseenter', function() {
            tooltip.style.opacity = '1';
            tooltip.style.transform = 'translateX(-50%) translateY(0)';
        });

        card.addEventListener('mouseleave', function() {
            tooltip.style.opacity = '0';
            tooltip.style.transform = 'translateX(-50%) translateY(-10px)';
        });
    });
}

// ============================================
// 5. ADD NECESSARY ANIMATIONS TO STYLESHEET
// ============================================

const style = document.createElement('style');
style.textContent = `
    @keyframes fadeInScale {
        from {
            opacity: 0;
            transform: scale(0.9) translateY(20px);
        }
        to {
            opacity: 1;
            transform: scale(1) translateY(0);
        }
    }

    @keyframes fadeOut {
        from {
            opacity: 1;
            transform: scale(1);
        }
        to {
            opacity: 0;
            transform: scale(0.9);
        }
    }

    @keyframes pulse {
        0%, 100% {
            transform: scale(1);
        }
        50% {
            transform: scale(1.1);
        }
    }

    .module-card {
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .module-card:hover {
        cursor: pointer;
    }

    .module-card.locked:hover {
        cursor: not-allowed;
    }
`;
document.head.appendChild(style);

console.log('%c🚀 Dashboard Interactive Enhancements Loaded', 'color: #00ff88; font-size: 14px; font-weight: bold;');
