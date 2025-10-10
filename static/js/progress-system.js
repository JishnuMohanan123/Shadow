/**
 * Shadow 1834 - Enhanced Progress System
 * Animated progress bars, skill tracking, and visual feedback
 */

class ProgressTracker {
    constructor() {
        this.init();
    }

    init() {
        this.initProgressBars();
        this.initSkillRadar();
        this.initLevelProgress();
    }

    // Animated circular progress
    createCircularProgress(container, value, maxValue, options = {}) {
        const {
            size = 120,
            strokeWidth = 8,
            color = '#00ffff',
            backgroundColor = 'rgba(0, 255, 255, 0.2)',
            label = '',
            animated = true
        } = options;

        const percentage = (value / maxValue) * 100;
        const radius = (size - strokeWidth) / 2;
        const circumference = radius * 2 * Math.PI;
        const offset = circumference - (percentage / 100) * circumference;

        const svg = `
            <svg class="circular-progress" width="${size}" height="${size}">
                <circle
                    class="progress-bg"
                    cx="${size / 2}"
                    cy="${size / 2}"
                    r="${radius}"
                    stroke="${backgroundColor}"
                    stroke-width="${strokeWidth}"
                    fill="none"
                />
                <circle
                    class="progress-bar"
                    cx="${size / 2}"
                    cy="${size / 2}"
                    r="${radius}"
                    stroke="${color}"
                    stroke-width="${strokeWidth}"
                    fill="none"
                    stroke-dasharray="${circumference}"
                    stroke-dashoffset="${animated ? circumference : offset}"
                    stroke-linecap="round"
                    transform="rotate(-90 ${size / 2} ${size / 2})"
                    style="transition: stroke-dashoffset 1s ease-in-out;"
                />
                <text
                    x="50%"
                    y="50%"
                    text-anchor="middle"
                    dominant-baseline="middle"
                    class="progress-text"
                    style="fill: ${color}; font-family: 'Orbitron', monospace; font-size: ${size / 5}px; font-weight: bold;">
                    ${Math.round(percentage)}%
                </text>
                ${label ? `<text
                    x="50%"
                    y="70%"
                    text-anchor="middle"
                    dominant-baseline="middle"
                    style="fill: rgba(255, 255, 255, 0.7); font-family: 'Rajdhani', sans-serif; font-size: ${size / 8}px;">
                    ${label}
                </text>` : ''}
            </svg>
        `;

        container.innerHTML = svg;

        if (animated) {
            setTimeout(() => {
                const progressBar = container.querySelector('.progress-bar');
                progressBar.style.strokeDashoffset = offset;
            }, 100);
        }

        return container;
    }

    // Linear progress bar with animation
    createLinearProgress(container, value, maxValue, options = {}) {
        const {
            height = 24,
            color = '#00ffff',
            backgroundColor = 'rgba(0, 255, 255, 0.1)',
            showLabel = true,
            showPercentage = true,
            animated = true,
            glow = true
        } = options;

        const percentage = Math.min(100, (value / maxValue) * 100);

        container.innerHTML = `
            <div class="linear-progress-container" style="width: 100%; height: ${height}px; background: ${backgroundColor}; border-radius: ${height / 2}px; position: relative; overflow: hidden; border: 1px solid rgba(0, 255, 255, 0.3);">
                <div class="linear-progress-bar" style="
                    height: 100%;
                    width: ${animated ? '0%' : percentage + '%'};
                    background: linear-gradient(90deg, ${color}, ${this.lightenColor(color, 20)});
                    border-radius: ${height / 2}px;
                    transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
                    position: relative;
                    ${glow ? `box-shadow: 0 0 20px ${color}, inset 0 0 20px rgba(255, 255, 255, 0.2);` : ''}
                ">
                    <div class="progress-shimmer" style="
                        position: absolute;
                        top: 0;
                        left: -100%;
                        width: 100%;
                        height: 100%;
                        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
                        animation: shimmer 2s infinite;
                    "></div>
                </div>
                ${showPercentage ? `
                    <div class="progress-percentage" style="
                        position: absolute;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        color: #fff;
                        font-family: 'Orbitron', monospace;
                        font-size: ${height * 0.6}px;
                        font-weight: bold;
                        text-shadow: 0 0 10px rgba(0, 0, 0, 0.8);
                        z-index: 1;
                    ">${Math.round(percentage)}%</div>
                ` : ''}
                ${showLabel ? `
                    <div class="progress-label" style="
                        position: absolute;
                        top: 50%;
                        left: 12px;
                        transform: translateY(-50%);
                        color: #fff;
                        font-family: 'Rajdhani', sans-serif;
                        font-size: ${height * 0.5}px;
                        font-weight: 600;
                        z-index: 1;
                    ">${value} / ${maxValue}</div>
                ` : ''}
            </div>
        `;

        if (animated) {
            setTimeout(() => {
                const bar = container.querySelector('.linear-progress-bar');
                bar.style.width = percentage + '%';
            }, 100);
        }

        return container;
    }

    // Skill radar chart
    initSkillRadar() {
        const radarContainers = document.querySelectorAll('[data-skill-radar]');
        radarContainers.forEach(container => {
            const skills = JSON.parse(container.dataset.skillRadar);
            this.createSkillRadar(container, skills);
        });
    }

    createSkillRadar(container, skills) {
        const size = 300;
        const center = size / 2;
        const maxRadius = size / 2 - 40;
        const numSkills = skills.length;

        let points = [];
        skills.forEach((skill, index) => {
            const angle = (Math.PI * 2 * index) / numSkills - Math.PI / 2;
            const radius = (skill.value / 100) * maxRadius;
            const x = center + radius * Math.cos(angle);
            const y = center + radius * Math.sin(angle);
            points.push(`${x},${y}`);
        });

        const labels = skills.map((skill, index) => {
            const angle = (Math.PI * 2 * index) / numSkills - Math.PI / 2;
            const labelRadius = maxRadius + 30;
            const x = center + labelRadius * Math.cos(angle);
            const y = center + labelRadius * Math.sin(angle);
            return `
                <text x="${x}" y="${y}" text-anchor="middle" dominant-baseline="middle"
                      style="fill: #00ffff; font-family: 'Rajdhani', sans-serif; font-size: 14px; font-weight: 600;">
                    ${skill.name}
                </text>
            `;
        }).join('');

        // Create background grid
        let gridCircles = '';
        for (let i = 1; i <= 5; i++) {
            const r = (maxRadius / 5) * i;
            gridCircles += `<circle cx="${center}" cy="${center}" r="${r}" fill="none" stroke="rgba(0, 255, 255, 0.1)" stroke-width="1"/>`;
        }

        container.innerHTML = `
            <svg width="${size}" height="${size}" class="skill-radar">
                ${gridCircles}
                <polygon points="${points.join(' ')}"
                         fill="rgba(0, 255, 255, 0.2)"
                         stroke="#00ffff"
                         stroke-width="2"
                         class="radar-polygon"
                         style="opacity: 0; transition: opacity 0.5s ease;">
                </polygon>
                ${labels}
            </svg>
        `;

        setTimeout(() => {
            container.querySelector('.radar-polygon').style.opacity = '1';
        }, 100);
    }

    // Progress bars initialization
    initProgressBars() {
        // Linear progress bars
        document.querySelectorAll('[data-progress]').forEach(element => {
            const value = parseInt(element.dataset.progress);
            const maxValue = parseInt(element.dataset.progressMax || 100);
            const options = {
                color: element.dataset.progressColor || '#00ffff',
                height: parseInt(element.dataset.progressHeight || 24),
                showLabel: element.dataset.progressLabel !== 'false',
                showPercentage: element.dataset.progressPercentage !== 'false'
            };
            this.createLinearProgress(element, value, maxValue, options);
        });

        // Circular progress bars
        document.querySelectorAll('[data-circular-progress]').forEach(element => {
            const value = parseInt(element.dataset.circularProgress);
            const maxValue = parseInt(element.dataset.circularMax || 100);
            const options = {
                size: parseInt(element.dataset.circularSize || 120),
                color: element.dataset.circularColor || '#00ffff',
                label: element.dataset.circularLabel || ''
            };
            this.createCircularProgress(element, value, maxValue, options);
        });
    }

    // Level progress with XP tracking
    initLevelProgress() {
        const levelContainers = document.querySelectorAll('[data-level-progress]');
        levelContainers.forEach(container => {
            const currentXP = parseInt(container.dataset.currentXp || 0);
            const requiredXP = parseInt(container.dataset.requiredXp || 100);
            const level = parseInt(container.dataset.level || 1);

            this.createLevelProgress(container, level, currentXP, requiredXP);
        });
    }

    createLevelProgress(container, level, currentXP, requiredXP) {
        const percentage = (currentXP / requiredXP) * 100;

        container.innerHTML = `
            <div class="level-progress-container">
                <div class="level-badge">
                    <div class="level-number">${level}</div>
                    <div class="level-label">LEVEL</div>
                </div>
                <div class="level-bar-container">
                    <div class="level-bar" style="width: 0%; transition: width 1.5s cubic-bezier(0.4, 0, 0.2, 1);">
                        <div class="level-bar-glow"></div>
                    </div>
                    <div class="level-info">
                        <span>${currentXP} / ${requiredXP} XP</span>
                        <span>${Math.round(percentage)}%</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            container.querySelector('.level-bar').style.width = percentage + '%';
        }, 100);
    }

    // Helper function to lighten colors
    lightenColor(color, percent) {
        const num = parseInt(color.replace("#", ""), 16);
        const amt = Math.round(2.55 * percent);
        const R = (num >> 16) + amt;
        const G = (num >> 8 & 0x00FF) + amt;
        const B = (num & 0x0000FF) + amt;
        return "#" + (0x1000000 + (R < 255 ? R < 1 ? 0 : R : 255) * 0x10000 +
            (G < 255 ? G < 1 ? 0 : G : 255) * 0x100 +
            (B < 255 ? B < 1 ? 0 : B : 255))
            .toString(16).slice(1);
    }
}

// Add styles
const progressStyles = document.createElement('style');
progressStyles.textContent = `
    @keyframes shimmer {
        0% { left: -100%; }
        100% { left: 100%; }
    }

    .level-progress-container {
        display: flex;
        align-items: center;
        gap: 20px;
        padding: 20px;
        background: rgba(0, 255, 255, 0.05);
        border: 1px solid rgba(0, 255, 255, 0.2);
        border-radius: 12px;
    }

    .level-badge {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        width: 80px;
        height: 80px;
        background: linear-gradient(135deg, #00ffff, #00ff88);
        border-radius: 50%;
        box-shadow: 0 0 30px rgba(0, 255, 255, 0.5);
        position: relative;
    }

    .level-badge::before {
        content: '';
        position: absolute;
        inset: 3px;
        background: #0a0e1a;
        border-radius: 50%;
    }

    .level-number {
        font-family: 'Orbitron', monospace;
        font-size: 32px;
        font-weight: bold;
        color: #00ffff;
        z-index: 1;
    }

    .level-label {
        font-family: 'Rajdhani', sans-serif;
        font-size: 12px;
        color: #00ff88;
        z-index: 1;
        margin-top: -5px;
    }

    .level-bar-container {
        flex: 1;
        position: relative;
    }

    .level-bar {
        height: 30px;
        background: linear-gradient(90deg, #00ffff, #00ff88);
        border-radius: 15px;
        position: relative;
        overflow: hidden;
        box-shadow: 0 0 20px rgba(0, 255, 255, 0.5);
    }

    .level-bar-glow {
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.4), transparent);
        animation: shimmer 2s infinite;
    }

    .level-info {
        display: flex;
        justify-content: space-between;
        margin-top: 8px;
        font-family: 'Rajdhani', sans-serif;
        font-size: 14px;
        color: rgba(255, 255, 255, 0.8);
    }

    .skill-radar {
        filter: drop-shadow(0 0 10px rgba(0, 255, 255, 0.3));
    }

    .circular-progress {
        filter: drop-shadow(0 0 10px rgba(0, 255, 255, 0.3));
    }
`;
document.head.appendChild(progressStyles);

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    window.progressTracker = new ProgressTracker();
});

// Export
if (typeof window !== 'undefined') {
    window.ProgressTracker = ProgressTracker;
}
