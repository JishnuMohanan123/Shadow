/**
 * SHADOW - Terminal Effects
 * Typing animations and sound effects
 */

(function() {
    'use strict';

    // Typing effect for elements with .typing-text class
    function typeWriter(element, text, speed = 50) {
        let i = 0;
        element.textContent = '';
        element.style.opacity = '1';

        function type() {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;

                // Play keyboard sound (if available)
                playKeySound();

                // Variable speed for realistic typing
                const randomSpeed = speed + Math.random() * 30;
                setTimeout(type, randomSpeed);
            }
        }

        type();
    }

    // Initialize typing effects
    window.addEventListener('load', function() {
        const typingElements = document.querySelectorAll('.typing-text');

        typingElements.forEach((element, index) => {
            const text = element.textContent;
            const delay = index * 500; // Stagger the typing animations

            setTimeout(() => {
                typeWriter(element, text, 40);
            }, delay);
        });

        // Slower typing for subtitles
        const slowElements = document.querySelectorAll('.typing-text-slow');
        slowElements.forEach((element, index) => {
            const text = element.textContent;
            const delay = 1000 + (index * 1000);

            setTimeout(() => {
                typeWriter(element, text, 70);
            }, delay);
        });
    });

    // Sound effects
    function playKeySound() {
        const keySound = document.getElementById('keySound');
        if (keySound && Math.random() > 0.7) { // Play randomly for variety
            keySound.currentTime = 0;
            keySound.volume = 0.1;
            keySound.play().catch(e => {}); // Ignore if autoplay blocked
        }
    }

    function playGlitchSound() {
        const glitchSound = document.getElementById('glitchSound');
        if (glitchSound) {
            glitchSound.currentTime = 0;
            glitchSound.volume = 0.15;
            glitchSound.play().catch(e => {});
        }
    }

    // Expose functions globally
    window.playGlitchSound = playGlitchSound;
    window.typeWriter = typeWriter;

    // Glitch effect on title
    const glitchElements = document.querySelectorAll('.glitch');
    glitchElements.forEach(element => {
        setInterval(() => {
            if (Math.random() > 0.95) {
                element.style.textShadow = '2px 2px #FF0000, -2px -2px #00FFFF';
                setTimeout(() => {
                    element.style.textShadow = '0 0 20px #39FF14';
                }, 50);
            }
        }, 100);
    });

    // Add scan line effect
    function createScanLine() {
        const scanLine = document.createElement('div');
        scanLine.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, #00FF00, transparent);
            opacity: 0.3;
            pointer-events: none;
            z-index: 9999;
            animation: scan 3s linear infinite;
        `;
        document.body.appendChild(scanLine);
    }

    createScanLine();

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Escape key to go back
        if (e.key === 'Escape') {
            const backButton = document.querySelector('a[href="/"]');
            if (backButton) {
                playGlitchSound();
                window.location.href = '/';
            }
        }
    });

    // Add glitch effect to buttons on hover
    const buttons = document.querySelectorAll('.matrix-button');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            if (Math.random() > 0.7) {
                playGlitchSound();
            }
        });
    });

    console.log('%c[SYSTEM] Terminal effects loaded', 'color: #00FF00; font-family: monospace;');

})();
