/**
 * Shadow 1834 - Achievement & Reward System
 * Real-time achievement unlocks, badge notifications, and reward animations
 */

// ============================================
// ACHIEVEMENT SYSTEM
// ============================================

class AchievementSystem {
    constructor() {
        this.achievements = [];
        this.unlockedAchievements = this.loadUnlockedAchievements();
        this.initializeAchievements();
    }

    initializeAchievements() {
        // Define all possible achievements
        this.achievements = [
            {
                id: 'first_mission',
                name: 'First Steps',
                description: 'Complete your first mission',
                icon: '⭐',
                points: 25,
                trigger: (stats) => stats.completedMissions >= 1
            },
            {
                id: 'perfect_score',
                name: 'Flawless Victory',
                description: 'Score 100% on any mission',
                icon: '🏆',
                points: 50,
                trigger: (stats) => stats.perfectScores >= 1
            },
            {
                id: 'streak_master',
                name: 'Streak Master',
                description: 'Answer 5 questions correctly in a row',
                icon: '🔥',
                points: 30,
                trigger: (stats) => stats.maxStreak >= 5
            },
            {
                id: 'all_missions',
                name: 'Mission Complete',
                description: 'Complete all available missions',
                icon: '👑',
                points: 100,
                trigger: (stats) => stats.completedMissions >= 5
            },
            {
                id: 'point_collector',
                name: 'Point Collector',
                description: 'Earn 1000 cyber points',
                icon: '💎',
                points: 40,
                trigger: (stats) => stats.totalPoints >= 1000
            },
            {
                id: 'speed_runner',
                name: 'Speed Runner',
                description: 'Complete a mission in under 3 minutes',
                icon: '⚡',
                points: 35,
                trigger: (stats) => stats.fastestCompletion <= 180
            }
        ];
    }

    checkAchievements(userStats) {
        const newlyUnlocked = [];

        this.achievements.forEach(achievement => {
            if (!this.unlockedAchievements.includes(achievement.id)) {
                if (achievement.trigger(userStats)) {
                    this.unlockAchievement(achievement);
                    newlyUnlocked.push(achievement);
                }
            }
        });

        return newlyUnlocked;
    }

    unlockAchievement(achievement) {
        this.unlockedAchievements.push(achievement.id);
        this.saveUnlockedAchievements();
        this.showAchievementUnlock(achievement);
    }

    showAchievementUnlock(achievement) {
        // Create achievement unlock overlay
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

        const achievementCard = document.createElement('div');
        achievementCard.style.cssText = `
            background: linear-gradient(135deg, rgba(0, 255, 255, 0.1), rgba(0, 136, 255, 0.1));
            border: 3px solid #00ffff;
            border-radius: 20px;
            padding: 3rem;
            text-align: center;
            animation: zoomInBounce 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            box-shadow: 0 0 60px rgba(0, 255, 255, 0.6);
            max-width: 500px;
        `;

        achievementCard.innerHTML = `
            <div style="font-size: 6rem; margin-bottom: 1rem; animation: rotatePulse 2s ease-in-out infinite;">
                ${achievement.icon}
            </div>
            <h2 style="color: #00ffff; font-family: 'Orbitron', monospace; font-size: 2rem; margin-bottom: 1rem; animation: textGlow 1s ease-in-out infinite alternate; text-transform: uppercase; letter-spacing: 2px;">
                ACHIEVEMENT UNLOCKED!
            </h2>
            <h3 style="color: #00ff88; font-family: 'Orbitron', monospace; font-size: 1.5rem; margin-bottom: 0.5rem;">
                ${achievement.name}
            </h3>
            <p style="color: #a0c4ff; font-family: 'Rajdhani', monospace; font-size: 1.1rem; margin-bottom: 2rem;">
                ${achievement.description}
            </p>
            <div style="background: rgba(0, 255, 136, 0.2); border: 2px solid #00ff88; border-radius: 10px; padding: 1rem; margin-bottom: 2rem;">
                <div style="color: #00ff88; font-size: 2rem; font-weight: 700; font-family: 'Orbitron', monospace;">
                    +${achievement.points} POINTS
                </div>
            </div>
            <button onclick="this.closest('[style*=fixed]').remove()"
                    style="padding: 1rem 2rem; background: rgba(0, 255, 255, 0.2); border: 2px solid #00ffff; border-radius: 8px; color: #00ffff; font-family: 'Orbitron', monospace; cursor: pointer; font-size: 1rem; transition: all 0.3s; text-transform: uppercase; letter-spacing: 1px;">
                CONTINUE
            </button>
        `;

        overlay.appendChild(achievementCard);
        document.body.appendChild(overlay);

        // Add confetti explosion
        setTimeout(() => {
            this.createAchievementConfetti();
        }, 300);

        // Play achievement sound
        this.playAchievementSound();

        // Auto close after 8 seconds
        setTimeout(() => {
            overlay.style.animation = 'fadeOut 0.5s ease-out';
            setTimeout(() => overlay.remove(), 500);
        }, 8000);
    }

    createAchievementConfetti() {
        const colors = ['#00ffff', '#00ff88', '#0088ff', '#ffaa00', '#ffd700'];
        const confettiCount = 100;

        for (let i = 0; i < confettiCount; i++) {
            const confetti = document.createElement('div');
            confetti.style.cssText = `
                position: fixed;
                width: ${Math.random() * 10 + 5}px;
                height: ${Math.random() * 10 + 5}px;
                background: ${colors[Math.floor(Math.random() * colors.length)]};
                left: ${Math.random() * 100}%;
                top: -20px;
                z-index: 10001;
                border-radius: ${Math.random() > 0.5 ? '50%' : '0'};
                pointer-events: none;
                box-shadow: 0 0 10px currentColor;
            `;

            document.body.appendChild(confetti);

            const duration = 2000 + Math.random() * 2000;
            const rotation = Math.random() * 720 - 360;

            confetti.animate([
                { transform: 'translateY(0) rotate(0deg)', opacity: 1 },
                { transform: `translateY(${window.innerHeight + 100}px) rotate(${rotation}deg)`, opacity: 0 }
            ], {
                duration: duration,
                easing: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)'
            }).onfinish = () => confetti.remove();
        }
    }

    playAchievementSound() {
        // Create audio context for achievement sound
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();

            // Play a series of ascending notes
            const notes = [523.25, 659.25, 783.99, 1046.50]; // C, E, G, C
            notes.forEach((freq, index) => {
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();

                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);

                oscillator.frequency.value = freq;
                oscillator.type = 'sine';

                const startTime = audioContext.currentTime + (index * 0.15);
                gainNode.gain.setValueAtTime(0.3, startTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, startTime + 0.5);

                oscillator.start(startTime);
                oscillator.stop(startTime + 0.5);
            });
        } catch (e) {
            console.log('Audio not supported');
        }
    }

    loadUnlockedAchievements() {
        const saved = localStorage.getItem('shadow1834_achievements');
        return saved ? JSON.parse(saved) : [];
    }

    saveUnlockedAchievements() {
        localStorage.setItem('shadow1834_achievements', JSON.stringify(this.unlockedAchievements));
    }
}

// ============================================
// MINI NOTIFICATION SYSTEM
// ============================================

class NotificationManager {
    constructor() {
        this.queue = [];
        this.isShowing = false;
    }

    showMiniNotification(message, icon = '✨', color = '#00ffff') {
        this.queue.push({ message, icon, color });
        if (!this.isShowing) {
            this.processQueue();
        }
    }

    processQueue() {
        if (this.queue.length === 0) {
            this.isShowing = false;
            return;
        }

        this.isShowing = true;
        const { message, icon, color } = this.queue.shift();

        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            background: rgba(0, 0, 0, 0.95);
            border: 2px solid ${color};
            border-radius: 10px;
            padding: 1rem 1.5rem;
            color: ${color};
            font-family: 'Orbitron', monospace;
            font-size: 0.9rem;
            z-index: 9999;
            box-shadow: 0 0 30px ${color}50;
            animation: slideInRight 0.4s ease-out;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        `;

        notification.innerHTML = `
            <span style="font-size: 1.5rem;">${icon}</span>
            <span>${message}</span>
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.4s ease-out';
            setTimeout(() => {
                notification.remove();
                this.processQueue();
            }, 400);
        }, 2500);
    }
}

// ============================================
// SCORE ANIMATION SYSTEM
// ============================================

function animateScoreIncrease(element, startValue, endValue, duration = 1500) {
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function
        const easeOutExpo = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
        const currentValue = Math.floor(startValue + (endValue - startValue) * easeOutExpo);

        element.textContent = currentValue;

        // Visual effects
        element.style.transform = `scale(${1 + Math.sin(progress * Math.PI) * 0.15})`;
        element.style.textShadow = `0 0 ${30 + Math.sin(progress * Math.PI * 4) * 15}px #00ffff`;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = endValue;
            element.style.transform = 'scale(1)';
            element.style.textShadow = '0 0 15px #00ffff';
        }
    }

    requestAnimationFrame(update);
}

// ============================================
// ADD ANIMATION STYLES
// ============================================

const achievementStyles = document.createElement('style');
achievementStyles.textContent = `
    @keyframes zoomInBounce {
        0% {
            transform: scale(0) rotate(-180deg);
            opacity: 0;
        }
        50% {
            transform: scale(1.1) rotate(10deg);
        }
        100% {
            transform: scale(1) rotate(0deg);
            opacity: 1;
        }
    }

    @keyframes rotatePulse {
        0%, 100% {
            transform: rotate(0deg) scale(1);
        }
        25% {
            transform: rotate(-10deg) scale(1.1);
        }
        75% {
            transform: rotate(10deg) scale(1.1);
        }
    }

    @keyframes textGlow {
        0% {
            text-shadow: 0 0 10px #00ffff, 0 0 20px #00ffff;
        }
        100% {
            text-shadow: 0 0 20px #00ffff, 0 0 40px #00ffff, 0 0 60px #00ffff;
        }
    }

    @keyframes slideInRight {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(achievementStyles);

// Initialize global instances
window.achievementSystem = new AchievementSystem();
window.notificationManager = new NotificationManager();

console.log('%c✨ Achievement System Loaded', 'color: #ffd700; font-size: 14px; font-weight: bold;');
