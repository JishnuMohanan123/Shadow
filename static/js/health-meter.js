/**
 * Shadow 1834 - Cyber Health Meter & Progress Storage
 * Dynamic health/security meter and local storage management
 */

// ============================================
// CYBER HEALTH METER
// ============================================

class CyberHealthMeter {
    constructor(containerElement) {
        this.container = containerElement;
        this.currentHealth = 100;
        this.maxHealth = 100;
        this.init();
    }

    init() {
        if (!this.container) return;

        const meterHTML = `
            <div class="cyber-health-meter" style="background: rgba(0, 0, 0, 0.5); border: 2px solid #00ffff; border-radius: 10px; padding: 1rem; margin-bottom: 1.5rem;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span id="healthIcon" style="font-size: 1.5rem;">🛡️</span>
                        <span style="color: #00ffff; font-family: 'Orbitron', monospace; font-weight: 700; font-size: 0.9rem;">
                            CYBER SECURITY STATUS
                        </span>
                    </div>
                    <span id="healthPercent" style="color: #00ff88; font-family: 'Orbitron', monospace; font-size: 1.2rem; font-weight: 700;">
                        100%
                    </span>
                </div>

                <div class="health-bar-container" style="background: rgba(0, 0, 0, 0.5); border: 2px solid #333; border-radius: 8px; height: 30px; position: relative; overflow: hidden;">
                    <div id="healthBar" class="health-bar-fill" style="height: 100%; width: 100%; background: linear-gradient(90deg, #00ff88, #00ffff); transition: all 0.8s cubic-bezier(0.4, 0, 0.2, 1); position: relative; box-shadow: 0 0 20px rgba(0, 255, 136, 0.5);">
                        <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); animation: shimmer 2s infinite;"></div>
                    </div>
                </div>

                <div id="healthStatus" style="text-align: center; margin-top: 0.5rem; color: #00ff88; font-family: 'Rajdhani', monospace; font-size: 0.85rem; font-weight: 600;">
                    OPTIMAL SECURITY
                </div>
            </div>
        `;

        this.container.innerHTML = meterHTML;
    }

    updateHealth(amount, reason = '') {
        const previousHealth = this.currentHealth;
        this.currentHealth = Math.max(0, Math.min(this.maxHealth, this.currentHealth + amount));

        const percentage = (this.currentHealth / this.maxHealth) * 100;
        const healthBar = document.getElementById('healthBar');
        const healthPercent = document.getElementById('healthPercent');
        const healthStatus = document.getElementById('healthStatus');
        const healthIcon = document.getElementById('healthIcon');

        // Animate health bar
        if (healthBar) {
            healthBar.style.width = `${percentage}%`;

            // Update color based on health level
            if (percentage > 70) {
                healthBar.style.background = 'linear-gradient(90deg, #00ff88, #00ffff)';
                healthBar.style.boxShadow = '0 0 20px rgba(0, 255, 136, 0.5)';
            } else if (percentage > 40) {
                healthBar.style.background = 'linear-gradient(90deg, #ffaa00, #ff8800)';
                healthBar.style.boxShadow = '0 0 20px rgba(255, 170, 0, 0.5)';
            } else {
                healthBar.style.background = 'linear-gradient(90deg, #ff4444, #ff0000)';
                healthBar.style.boxShadow = '0 0 20px rgba(255, 68, 68, 0.5)';
            }
        }

        // Update percentage text
        if (healthPercent) {
            healthPercent.textContent = `${Math.round(percentage)}%`;
            healthPercent.style.color = percentage > 70 ? '#00ff88' : percentage > 40 ? '#ffaa00' : '#ff4444';
        }

        // Update status message
        if (healthStatus) {
            let statusText, statusColor;
            if (percentage > 70) {
                statusText = 'OPTIMAL SECURITY';
                statusColor = '#00ff88';
            } else if (percentage > 40) {
                statusText = 'SECURITY COMPROMISED';
                statusColor = '#ffaa00';
            } else {
                statusText = 'CRITICAL THREAT LEVEL';
                statusColor = '#ff4444';
            }
            healthStatus.textContent = statusText;
            healthStatus.style.color = statusColor;
        }

        // Update icon
        if (healthIcon) {
            if (percentage > 70) healthIcon.textContent = '🛡️';
            else if (percentage > 40) healthIcon.textContent = '⚠️';
            else healthIcon.textContent = '🚨';
        }

        // Show damage/heal effect
        if (amount < 0) {
            this.showDamageEffect(-amount, reason);
        } else if (amount > 0) {
            this.showHealEffect(amount, reason);
        }

        // Check for critical state
        if (percentage <= 20 && previousHealth > 20) {
            this.showCriticalAlert();
        }
    }

    showDamageEffect(damage, reason) {
        // Flash red
        const flash = document.createElement('div');
        flash.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 68, 68, 0.3);
            z-index: 9999;
            pointer-events: none;
            animation: damageFlash 0.5s ease-out;
        `;
        document.body.appendChild(flash);
        setTimeout(() => flash.remove(), 500);

        // Show damage notification
        if (window.notificationManager && reason) {
            window.notificationManager.showMiniNotification(`-${damage}% Security: ${reason}`, '⚠️', '#ff4444');
        }
    }

    showHealEffect(heal, reason) {
        // Flash green
        const flash = document.createElement('div');
        flash.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 255, 136, 0.2);
            z-index: 9999;
            pointer-events: none;
            animation: healFlash 0.5s ease-out;
        `;
        document.body.appendChild(flash);
        setTimeout(() => flash.remove(), 500);

        // Show heal notification
        if (window.notificationManager && reason) {
            window.notificationManager.showMiniNotification(`+${heal}% Security: ${reason}`, '✅', '#00ff88');
        }
    }

    showCriticalAlert() {
        const alert = document.createElement('div');
        alert.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(0, 0, 0, 0.95);
            border: 3px solid #ff4444;
            border-radius: 12px;
            padding: 2rem;
            z-index: 10000;
            text-align: center;
            animation: criticalPulse 0.5s ease-in-out infinite;
            box-shadow: 0 0 60px rgba(255, 68, 68, 0.6);
        `;

        alert.innerHTML = `
            <div style="font-size: 4rem; margin-bottom: 1rem;">🚨</div>
            <h2 style="color: #ff4444; font-family: 'Orbitron', monospace; margin-bottom: 1rem; text-transform: uppercase;">
                CRITICAL SECURITY BREACH
            </h2>
            <p style="color: #ffffff; font-family: 'Rajdhani', monospace; margin-bottom: 1.5rem;">
                Your cyber security is critically compromised!
            </p>
            <button onclick="this.closest('[style*=fixed]').remove()"
                    style="padding: 0.75rem 1.5rem; background: rgba(255, 68, 68, 0.2); border: 2px solid #ff4444; border-radius: 6px; color: #ff4444; font-family: 'Orbitron', monospace; cursor: pointer;">
                ACKNOWLEDGED
            </button>
        `;

        document.body.appendChild(alert);

        setTimeout(() => {
            alert.style.animation = 'fadeOut 0.5s ease-out';
            setTimeout(() => alert.remove(), 500);
        }, 5000);
    }

    reset() {
        this.updateHealth(this.maxHealth - this.currentHealth, 'System Reset');
    }
}

// ============================================
// PROGRESS STORAGE SYSTEM
// ============================================

class ProgressStorage {
    constructor() {
        this.storageKey = 'shadow1834_progress';
    }

    saveProgress(data) {
        try {
            const currentProgress = this.loadProgress();
            const updatedProgress = { ...currentProgress, ...data, lastUpdated: new Date().toISOString() };
            localStorage.setItem(this.storageKey, JSON.stringify(updatedProgress));
            return true;
        } catch (e) {
            console.error('Failed to save progress:', e);
            return false;
        }
    }

    loadProgress() {
        try {
            const saved = localStorage.getItem(this.storageKey);
            return saved ? JSON.parse(saved) : this.getDefaultProgress();
        } catch (e) {
            console.error('Failed to load progress:', e);
            return this.getDefaultProgress();
        }
    }

    getDefaultProgress() {
        return {
            totalScore: 0,
            completedMissions: [],
            achievements: [],
            stats: {
                questionsAnswered: 0,
                correctAnswers: 0,
                perfectScores: 0,
                maxStreak: 0,
                totalPlayTime: 0
            },
            lastUpdated: new Date().toISOString()
        };
    }

    updateStat(statName, value) {
        const progress = this.loadProgress();
        if (!progress.stats) progress.stats = {};
        progress.stats[statName] = value;
        this.saveProgress(progress);
    }

    incrementStat(statName, amount = 1) {
        const progress = this.loadProgress();
        if (!progress.stats) progress.stats = {};
        progress.stats[statName] = (progress.stats[statName] || 0) + amount;
        this.saveProgress(progress);
    }

    clearProgress() {
        if (confirm('Are you sure you want to reset all progress? This cannot be undone.')) {
            localStorage.removeItem(this.storageKey);
            localStorage.removeItem('shadow1834_achievements');
            showCyberNotification('All progress has been reset', 'warning');
            setTimeout(() => location.reload(), 1500);
        }
    }

    exportProgress() {
        const progress = this.loadProgress();
        const dataStr = JSON.stringify(progress, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `shadow1834_backup_${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        URL.revokeObjectURL(url);
        showCyberNotification('Progress exported successfully', 'success');
    }
}

// ============================================
// SESSION TIMER
// ============================================

class SessionTimer {
    constructor() {
        this.startTime = Date.now();
        this.elapsed = 0;
        this.interval = null;
    }

    start() {
        this.startTime = Date.now();
        this.interval = setInterval(() => {
            this.elapsed = Math.floor((Date.now() - this.startTime) / 1000);
        }, 1000);
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
        }
        return this.elapsed;
    }

    getFormattedTime() {
        const minutes = Math.floor(this.elapsed / 60);
        const seconds = this.elapsed % 60;
        return `${minutes}:${seconds.toString().padStart(2, '0')}`;
    }
}

// ============================================
// ADD STYLES
// ============================================

const healthStyles = document.createElement('style');
healthStyles.textContent = `
    @keyframes shimmer {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(100%); }
    }

    @keyframes damageFlash {
        0%, 100% { opacity: 0; }
        50% { opacity: 1; }
    }

    @keyframes healFlash {
        0%, 100% { opacity: 0; }
        50% { opacity: 1; }
    }

    @keyframes criticalPulse {
        0%, 100% {
            transform: translate(-50%, -50%) scale(1);
            box-shadow: 0 0 60px rgba(255, 68, 68, 0.6);
        }
        50% {
            transform: translate(-50%, -50%) scale(1.05);
            box-shadow: 0 0 80px rgba(255, 68, 68, 0.8);
        }
    }

    .health-bar-fill {
        position: relative;
        overflow: hidden;
    }
`;
document.head.appendChild(healthStyles);

// Initialize global instances
window.progressStorage = new ProgressStorage();
window.sessionTimer = new SessionTimer();

console.log('%c🛡️ Health Meter & Progress Storage Loaded', 'color: #00ff88; font-size: 14px; font-weight: bold;');
