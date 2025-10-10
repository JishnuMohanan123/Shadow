/**
 * Shadow 1834 - Sound Effects System
 * Real-time audio feedback for user interactions
 */

class SoundEffects {
    constructor() {
        this.enabled = localStorage.getItem('soundEnabled') !== 'false';
        this.volume = parseFloat(localStorage.getItem('soundVolume') || '0.3');
        this.sounds = {};
        this.initSounds();
    }

    initSounds() {
        // Define sound frequencies and patterns for different events
        this.soundPatterns = {
            success: { freq: [523.25, 659.25, 783.99], duration: 150 },
            error: { freq: [392, 349.23, 293.66], duration: 200 },
            warning: { freq: [440, 440], duration: 100 },
            click: { freq: [800], duration: 50 },
            hover: { freq: [600], duration: 30 },
            unlock: { freq: [523.25, 659.25, 783.99, 1046.50], duration: 120 },
            achievement: { freq: [659.25, 783.99, 987.77, 1174.66], duration: 200 },
            levelUp: { freq: [523.25, 587.33, 659.25, 783.99, 880, 1046.50], duration: 150 },
            notification: { freq: [1046.50, 1174.66], duration: 100 },
            message: { freq: [783.99, 880], duration: 80 }
        };
    }

    playSound(type) {
        if (!this.enabled) return;

        const pattern = this.soundPatterns[type];
        if (!pattern) return;

        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const masterGain = audioContext.createGain();
        masterGain.connect(audioContext.destination);
        masterGain.gain.value = this.volume;

        pattern.freq.forEach((frequency, index) => {
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(masterGain);

            oscillator.frequency.value = frequency;
            oscillator.type = 'sine';

            const startTime = audioContext.currentTime + (index * pattern.duration / 1000);
            const endTime = startTime + (pattern.duration / 1000);

            gainNode.gain.setValueAtTime(0, startTime);
            gainNode.gain.linearRampToValueAtTime(this.volume, startTime + 0.01);
            gainNode.gain.linearRampToValueAtTime(0, endTime);

            oscillator.start(startTime);
            oscillator.stop(endTime);
        });

        // Close audio context after sound finishes
        setTimeout(() => {
            audioContext.close();
        }, pattern.freq.length * pattern.duration + 100);
    }

    toggle() {
        this.enabled = !this.enabled;
        localStorage.setItem('soundEnabled', this.enabled);
        return this.enabled;
    }

    setVolume(volume) {
        this.volume = Math.max(0, Math.min(1, volume));
        localStorage.setItem('soundVolume', this.volume);
    }
}

// Initialize global sound system
window.soundEffects = new SoundEffects();

// Enhanced notification system with sound
function showEnhancedNotification(message, type = 'info', options = {}) {
    const {
        duration = 5000,
        action = null,
        actionText = 'Action',
        sound = true,
        icon = null
    } = options;

    // Play sound effect
    if (sound) {
        window.soundEffects.playSound(type);
    }

    // Remove existing notifications if needed
    if (!options.stack) {
        const existing = document.querySelectorAll('.enhanced-notification');
        existing.forEach(n => {
            n.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => n.remove(), 300);
        });
    }

    const notification = document.createElement('div');
    notification.className = `enhanced-notification notification-${type}`;

    const icons = {
        success: icon || '✅',
        error: icon || '❌',
        warning: icon || '⚠️',
        info: icon || 'ℹ️',
        achievement: icon || '🏆',
        levelup: icon || '⬆️',
        message: icon || '💬'
    };

    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-icon">${icons[type] || icons.info}</span>
            <span class="notification-message">${message}</span>
            ${action ? `<button class="notification-action">${actionText}</button>` : ''}
            <button class="notification-close">&times;</button>
        </div>
        <div class="notification-progress"></div>
    `;

    document.body.appendChild(notification);

    // Add click handlers
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    });

    if (action) {
        const actionBtn = notification.querySelector('.notification-action');
        actionBtn.addEventListener('click', () => {
            action();
            notification.remove();
        });
    }

    // Show notification
    setTimeout(() => notification.classList.add('show'), 10);

    // Auto-hide with progress bar
    const progress = notification.querySelector('.notification-progress');
    progress.style.transition = `width ${duration}ms linear`;
    setTimeout(() => progress.style.width = '0%', 50);

    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.5s ease-out';
        setTimeout(() => notification.remove(), 500);
    }, duration);

    return notification;
}

// Popup modal system
function showPopup(title, content, options = {}) {
    const {
        type = 'info',
        buttons = [{ text: 'OK', action: null, primary: true }],
        closable = true,
        sound = true
    } = options;

    if (sound) {
        window.soundEffects.playSound(type);
    }

    const overlay = document.createElement('div');
    overlay.className = 'popup-overlay';

    const popup = document.createElement('div');
    popup.className = `popup popup-${type}`;

    const buttonHTML = buttons.map(btn =>
        `<button class="popup-btn ${btn.primary ? 'btn-primary' : 'btn-secondary'}" data-action="${btn.text}">${btn.text}</button>`
    ).join('');

    popup.innerHTML = `
        ${closable ? '<button class="popup-close">&times;</button>' : ''}
        <div class="popup-header">
            <h3>${title}</h3>
        </div>
        <div class="popup-body">
            ${content}
        </div>
        <div class="popup-footer">
            ${buttonHTML}
        </div>
    `;

    overlay.appendChild(popup);
    document.body.appendChild(overlay);

    // Animation
    setTimeout(() => {
        overlay.classList.add('show');
        popup.classList.add('show');
    }, 10);

    // Close handler
    const closePopup = () => {
        overlay.classList.remove('show');
        popup.classList.remove('show');
        setTimeout(() => overlay.remove(), 300);
    };

    if (closable) {
        const closeBtn = popup.querySelector('.popup-close');
        closeBtn.addEventListener('click', closePopup);
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closePopup();
        });
    }

    // Button handlers
    buttons.forEach((btn, index) => {
        const btnElement = popup.querySelectorAll('.popup-btn')[index];
        btnElement.addEventListener('click', () => {
            if (btn.action) btn.action();
            closePopup();
        });
    });

    return overlay;
}

// Add styles for notifications and popups
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
    .enhanced-notification {
        position: fixed;
        top: 20px;
        right: -400px;
        z-index: 10000;
        min-width: 300px;
        max-width: 400px;
        background: rgba(10, 14, 26, 0.95);
        border: 2px solid;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
        transition: right 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        backdrop-filter: blur(10px);
    }

    .enhanced-notification.show {
        right: 20px;
    }

    .notification-success { border-color: #00ff88; }
    .notification-error { border-color: #ff4444; }
    .notification-warning { border-color: #ffaa00; }
    .notification-info { border-color: #00ffff; }
    .notification-achievement { border-color: #ffd700; }
    .notification-levelup { border-color: #00ff88; }
    .notification-message { border-color: #0088ff; }

    .notification-content {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 16px;
        position: relative;
    }

    .notification-icon {
        font-size: 24px;
        animation: bounceIn 0.5s ease-out;
    }

    .notification-message {
        flex: 1;
        color: #fff;
        font-family: 'Rajdhani', sans-serif;
        font-size: 15px;
        line-height: 1.4;
    }

    .notification-action {
        background: rgba(0, 255, 255, 0.2);
        border: 1px solid #00ffff;
        color: #00ffff;
        padding: 6px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-family: 'Rajdhani', sans-serif;
        font-weight: 600;
        transition: all 0.2s;
    }

    .notification-action:hover {
        background: rgba(0, 255, 255, 0.3);
        transform: translateY(-2px);
    }

    .notification-close {
        background: none;
        border: none;
        color: rgba(255, 255, 255, 0.6);
        font-size: 24px;
        cursor: pointer;
        padding: 0;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
    }

    .notification-close:hover {
        color: #fff;
        transform: rotate(90deg);
    }

    .notification-progress {
        position: absolute;
        bottom: 0;
        left: 0;
        height: 3px;
        width: 100%;
        background: currentColor;
        opacity: 0.6;
    }

    @keyframes slideOutRight {
        to { transform: translateX(120%); opacity: 0; }
    }

    @keyframes bounceIn {
        0% { transform: scale(0); }
        50% { transform: scale(1.2); }
        100% { transform: scale(1); }
    }

    /* Popup Styles */
    .popup-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        backdrop-filter: blur(5px);
        z-index: 10001;
        display: flex;
        align-items: center;
        justify-content: center;
        opacity: 0;
        transition: opacity 0.3s ease;
    }

    .popup-overlay.show {
        opacity: 1;
    }

    .popup {
        background: linear-gradient(135deg, rgba(20, 40, 80, 0.95), rgba(10, 14, 26, 0.95));
        border: 2px solid #00ffff;
        border-radius: 12px;
        min-width: 400px;
        max-width: 600px;
        max-height: 80vh;
        overflow: auto;
        position: relative;
        transform: scale(0.7) translateY(-50px);
        opacity: 0;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 20px 60px rgba(0, 255, 255, 0.3);
    }

    .popup.show {
        transform: scale(1) translateY(0);
        opacity: 1;
    }

    .popup-close {
        position: absolute;
        top: 16px;
        right: 16px;
        background: none;
        border: none;
        color: rgba(255, 255, 255, 0.6);
        font-size: 28px;
        cursor: pointer;
        width: 32px;
        height: 32px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
        z-index: 1;
    }

    .popup-close:hover {
        color: #fff;
        transform: rotate(90deg);
    }

    .popup-header {
        padding: 24px;
        border-bottom: 1px solid rgba(0, 255, 255, 0.3);
    }

    .popup-header h3 {
        margin: 0;
        color: #00ffff;
        font-family: 'Orbitron', monospace;
        font-size: 24px;
        text-transform: uppercase;
    }

    .popup-body {
        padding: 24px;
        color: #fff;
        font-family: 'Rajdhani', sans-serif;
        font-size: 16px;
        line-height: 1.6;
    }

    .popup-footer {
        padding: 16px 24px;
        border-top: 1px solid rgba(0, 255, 255, 0.3);
        display: flex;
        gap: 12px;
        justify-content: flex-end;
    }

    .popup-btn {
        padding: 10px 24px;
        border-radius: 6px;
        font-family: 'Rajdhani', sans-serif;
        font-weight: 600;
        font-size: 16px;
        cursor: pointer;
        transition: all 0.2s;
        text-transform: uppercase;
    }

    .popup-success { border-color: #00ff88; }
    .popup-error { border-color: #ff4444; }
    .popup-warning { border-color: #ffaa00; }
    .popup-achievement { border-color: #ffd700; }

    @media (max-width: 640px) {
        .enhanced-notification {
            right: -100%;
            left: 10px;
            min-width: auto;
            max-width: calc(100% - 20px);
        }

        .enhanced-notification.show {
            right: auto;
        }

        .popup {
            min-width: 90%;
            margin: 20px;
        }
    }
`;
document.head.appendChild(notificationStyles);

// Export functions
if (typeof window !== 'undefined') {
    window.SoundEffects = SoundEffects;
    window.showEnhancedNotification = showEnhancedNotification;
    window.showPopup = showPopup;
}
