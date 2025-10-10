/**
 * Shadow 1834 - Enhanced Achievement & Badge System
 * Comprehensive achievement tracking with tiers, badges, and rewards
 */

class EnhancedAchievementSystem {
    constructor() {
        this.achievements = [];
        this.badges = [];
        this.unlockedAchievements = this.loadProgress('achievements') || [];
        this.unlockedBadges = this.loadProgress('badges') || [];
        this.achievementProgress = this.loadProgress('achievementProgress') || {};
        this.initializeAchievements();
        this.initializeBadges();
    }

    initializeAchievements() {
        this.achievements = [
            // Beginner Achievements
            {
                id: 'first_login',
                name: 'Welcome Agent',
                description: 'Log in for the first time',
                icon: '👋',
                tier: 'bronze',
                points: 10,
                category: 'starter',
                trigger: (stats) => true
            },
            {
                id: 'first_mission',
                name: 'First Steps',
                description: 'Complete your first mission',
                icon: '⭐',
                tier: 'bronze',
                points: 25,
                category: 'missions',
                trigger: (stats) => stats.completedMissions >= 1
            },
            {
                id: 'five_missions',
                name: 'Getting Started',
                description: 'Complete 5 missions',
                icon: '🚀',
                tier: 'silver',
                points: 50,
                category: 'missions',
                trigger: (stats) => stats.completedMissions >= 5
            },
            {
                id: 'ten_missions',
                name: 'Mission Expert',
                description: 'Complete 10 missions',
                icon: '🎯',
                tier: 'gold',
                points: 100,
                category: 'missions',
                trigger: (stats) => stats.completedMissions >= 10
            },

            // Accuracy Achievements
            {
                id: 'perfect_score',
                name: 'Flawless Victory',
                description: 'Score 100% on any mission',
                icon: '💯',
                tier: 'silver',
                points: 50,
                category: 'accuracy',
                trigger: (stats) => stats.perfectScores >= 1
            },
            {
                id: 'five_perfect',
                name: 'Perfectionist',
                description: 'Score 100% on 5 missions',
                icon: '🏆',
                tier: 'gold',
                points: 150,
                category: 'accuracy',
                trigger: (stats) => stats.perfectScores >= 5
            },
            {
                id: 'no_mistakes',
                name: 'Untouchable',
                description: 'Complete 3 missions without a single mistake',
                icon: '🛡️',
                tier: 'platinum',
                points: 200,
                category: 'accuracy',
                trigger: (stats) => stats.flawlessStreak >= 3
            },

            // Streak Achievements
            {
                id: 'streak_5',
                name: 'Hot Streak',
                description: 'Answer 5 questions correctly in a row',
                icon: '🔥',
                tier: 'bronze',
                points: 30,
                category: 'streak',
                trigger: (stats) => stats.maxStreak >= 5
            },
            {
                id: 'streak_10',
                name: 'On Fire',
                description: 'Answer 10 questions correctly in a row',
                icon: '🔥',
                tier: 'silver',
                points: 60,
                category: 'streak',
                trigger: (stats) => stats.maxStreak >= 10
            },
            {
                id: 'streak_20',
                name: 'Unstoppable',
                description: 'Answer 20 questions correctly in a row',
                icon: '💥',
                tier: 'gold',
                points: 120,
                category: 'streak',
                trigger: (stats) => stats.maxStreak >= 20
            },

            // Speed Achievements
            {
                id: 'speed_runner',
                name: 'Speed Demon',
                description: 'Complete a mission in under 3 minutes',
                icon: '⚡',
                tier: 'silver',
                points: 40,
                category: 'speed',
                trigger: (stats) => stats.fastestCompletion <= 180
            },
            {
                id: 'lightning_fast',
                name: 'Lightning Fast',
                description: 'Complete a mission in under 2 minutes',
                icon: '⚡',
                tier: 'gold',
                points: 80,
                category: 'speed',
                trigger: (stats) => stats.fastestCompletion <= 120
            },

            // Points Achievements
            {
                id: 'points_500',
                name: 'Point Collector',
                description: 'Earn 500 cyber points',
                icon: '💎',
                tier: 'bronze',
                points: 25,
                category: 'points',
                trigger: (stats) => stats.totalPoints >= 500
            },
            {
                id: 'points_1000',
                name: 'Wealth Accumulator',
                description: 'Earn 1000 cyber points',
                icon: '💎',
                tier: 'silver',
                points: 50,
                category: 'points',
                trigger: (stats) => stats.totalPoints >= 1000
            },
            {
                id: 'points_5000',
                name: 'Cyber Millionaire',
                description: 'Earn 5000 cyber points',
                icon: '💰',
                tier: 'gold',
                points: 100,
                category: 'points',
                trigger: (stats) => stats.totalPoints >= 5000
            },

            // Social Achievements
            {
                id: 'leaderboard_top10',
                name: 'Rising Star',
                description: 'Reach top 10 on the leaderboard',
                icon: '⭐',
                tier: 'silver',
                points: 60,
                category: 'social',
                trigger: (stats) => stats.leaderboardRank <= 10 && stats.leaderboardRank > 0
            },
            {
                id: 'leaderboard_top3',
                name: 'Elite Agent',
                description: 'Reach top 3 on the leaderboard',
                icon: '🥉',
                tier: 'gold',
                points: 150,
                category: 'social',
                trigger: (stats) => stats.leaderboardRank <= 3 && stats.leaderboardRank > 0
            },
            {
                id: 'leaderboard_first',
                name: 'Champion',
                description: 'Reach #1 on the leaderboard',
                icon: '👑',
                tier: 'platinum',
                points: 300,
                category: 'social',
                trigger: (stats) => stats.leaderboardRank === 1
            },

            // Special Achievements
            {
                id: 'night_owl',
                name: 'Night Owl',
                description: 'Complete a mission between midnight and 5 AM',
                icon: '🦉',
                tier: 'silver',
                points: 35,
                category: 'special',
                trigger: (stats) => stats.nightOwlMissions >= 1
            },
            {
                id: 'early_bird',
                name: 'Early Bird',
                description: 'Complete a mission between 5 AM and 8 AM',
                icon: '🐦',
                tier: 'silver',
                points: 35,
                category: 'special',
                trigger: (stats) => stats.earlyBirdMissions >= 1
            },
            {
                id: 'weekend_warrior',
                name: 'Weekend Warrior',
                description: 'Complete 5 missions on weekends',
                icon: '🎖️',
                tier: 'gold',
                points: 75,
                category: 'special',
                trigger: (stats) => stats.weekendMissions >= 5
            }
        ];
    }

    initializeBadges() {
        this.badges = [
            {
                id: 'phishing_expert',
                name: 'Phishing Expert',
                description: 'Master all phishing detection missions',
                icon: '🎣',
                color: '#ff6b6b',
                requirement: { category: 'phishing', missions: 5 }
            },
            {
                id: 'malware_hunter',
                name: 'Malware Hunter',
                description: 'Complete all malware analysis missions',
                icon: '🦠',
                color: '#4ecdc4',
                requirement: { category: 'malware', missions: 5 }
            },
            {
                id: 'password_guardian',
                name: 'Password Guardian',
                description: 'Master password security missions',
                icon: '🔐',
                color: '#45b7d1',
                requirement: { category: 'passwords', missions: 5 }
            },
            {
                id: 'network_defender',
                name: 'Network Defender',
                description: 'Complete all network security missions',
                icon: '🛡️',
                color: '#f9ca24',
                requirement: { category: 'network', missions: 5 }
            },
            {
                id: 'social_engineer_detector',
                name: 'Social Engineering Detector',
                description: 'Master social engineering awareness',
                icon: '🎭',
                color: '#a29bfe',
                requirement: { category: 'social', missions: 5 }
            },
            {
                id: 'cyber_sage',
                name: 'Cyber Sage',
                description: 'Achieve 100% completion on all missions',
                icon: '🧙',
                color: '#ffd700',
                requirement: { allMissions: true, perfectScores: true }
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

    checkBadges(userStats) {
        const newlyUnlocked = [];

        this.badges.forEach(badge => {
            if (!this.unlockedBadges.includes(badge.id)) {
                if (this.checkBadgeRequirement(badge, userStats)) {
                    this.unlockBadge(badge);
                    newlyUnlocked.push(badge);
                }
            }
        });

        return newlyUnlocked;
    }

    checkBadgeRequirement(badge, stats) {
        const req = badge.requirement;

        if (req.category && req.missions) {
            return (stats.categoryMissions && stats.categoryMissions[req.category] >= req.missions);
        }

        if (req.allMissions && req.perfectScores) {
            return stats.allMissionsComplete && stats.allPerfectScores;
        }

        return false;
    }

    unlockAchievement(achievement) {
        this.unlockedAchievements.push(achievement.id);
        this.saveProgress('achievements', this.unlockedAchievements);
        this.showAchievementUnlock(achievement);

        // Play sound and show notification
        if (window.soundEffects) {
            window.soundEffects.playSound('achievement');
        }
    }

    unlockBadge(badge) {
        this.unlockedBadges.push(badge.id);
        this.saveProgress('badges', this.unlockedBadges);
        this.showBadgeUnlock(badge);

        if (window.soundEffects) {
            window.soundEffects.playSound('unlock');
        }
    }

    showAchievementUnlock(achievement) {
        const tierColors = {
            bronze: '#cd7f32',
            silver: '#c0c0c0',
            gold: '#ffd700',
            platinum: '#e5e4e2'
        };

        const popup = showPopup(
            `Achievement Unlocked!`,
            `
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 80px; margin-bottom: 16px; animation: bounceIn 0.6s ease-out;">${achievement.icon}</div>
                <h2 style="color: ${tierColors[achievement.tier]}; font-family: 'Orbitron', monospace; margin-bottom: 8px; text-transform: uppercase;">
                    ${achievement.name}
                </h2>
                <p style="color: rgba(255, 255, 255, 0.8); font-size: 18px; margin-bottom: 16px;">
                    ${achievement.description}
                </p>
                <div style="display: inline-block; background: rgba(0, 255, 255, 0.2); border: 1px solid #00ffff; border-radius: 20px; padding: 8px 20px;">
                    <span style="color: #00ffff; font-weight: bold;">+${achievement.points} Points</span>
                </div>
                <div style="margin-top: 16px; text-transform: uppercase; font-size: 14px; color: ${tierColors[achievement.tier]};">
                    ${achievement.tier} Tier
                </div>
            </div>
            `,
            {
                type: 'achievement',
                buttons: [{ text: 'Awesome!', primary: true }],
                sound: false
            }
        );

        // Add confetti effect
        this.createAchievementConfetti();
    }

    showBadgeUnlock(badge) {
        const popup = showPopup(
            `Badge Earned!`,
            `
            <div style="text-align: center; padding: 20px;">
                <div style="
                    width: 120px;
                    height: 120px;
                    margin: 0 auto 20px;
                    background: ${badge.color};
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 60px;
                    box-shadow: 0 0 40px ${badge.color};
                    animation: badgePulse 1s ease-out;
                ">${badge.icon}</div>
                <h2 style="color: ${badge.color}; font-family: 'Orbitron', monospace; margin-bottom: 8px;">
                    ${badge.name}
                </h2>
                <p style="color: rgba(255, 255, 255, 0.8); font-size: 16px;">
                    ${badge.description}
                </p>
            </div>
            `,
            {
                type: 'achievement',
                buttons: [{ text: 'Collect', primary: true }],
                sound: false
            }
        );
    }

    createAchievementConfetti() {
        const colors = ['#ffd700', '#00ffff', '#00ff88', '#ff6b6b', '#a29bfe'];
        for (let i = 0; i < 50; i++) {
            const confetti = document.createElement('div');
            const color = colors[Math.floor(Math.random() * colors.length)];
            const left = Math.random() * 100;
            const animationDuration = 2 + Math.random() * 2;
            const size = 8 + Math.random() * 8;

            confetti.style.cssText = `
                position: fixed;
                left: ${left}%;
                top: -20px;
                width: ${size}px;
                height: ${size}px;
                background: ${color};
                border-radius: ${Math.random() > 0.5 ? '50%' : '0'};
                opacity: 0.8;
                pointer-events: none;
                z-index: 10002;
                animation: confettiFall ${animationDuration}s linear;
            `;

            document.body.appendChild(confetti);

            setTimeout(() => confetti.remove(), animationDuration * 1000);
        }
    }

    getAchievementsByCategory(category) {
        return this.achievements.filter(a => a.category === category);
    }

    getUnlockedAchievements() {
        return this.achievements.filter(a => this.unlockedAchievements.includes(a.id));
    }

    getProgress() {
        return {
            totalAchievements: this.achievements.length,
            unlockedAchievements: this.unlockedAchievements.length,
            totalBadges: this.badges.length,
            unlockedBadges: this.unlockedBadges.length,
            totalPoints: this.getUnlockedAchievements().reduce((sum, a) => sum + a.points, 0)
        };
    }

    saveProgress(key, data) {
        localStorage.setItem(`shadow_${key}`, JSON.stringify(data));
    }

    loadProgress(key) {
        const data = localStorage.getItem(`shadow_${key}`);
        return data ? JSON.parse(data) : null;
    }
}

// Add animation styles
const achievementStyles = document.createElement('style');
achievementStyles.textContent = `
    @keyframes confettiFall {
        to {
            top: 100%;
            transform: translateY(0) rotate(360deg);
        }
    }

    @keyframes badgePulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
    }
`;
document.head.appendChild(achievementStyles);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.enhancedAchievements = new EnhancedAchievementSystem();
});

// Export
if (typeof window !== 'undefined') {
    window.EnhancedAchievementSystem = EnhancedAchievementSystem;
}
