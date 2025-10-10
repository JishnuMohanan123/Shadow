/**
 * SHADOW - Matrix Rain Animation
 * Creates falling code effect using HTML Canvas
 */

(function() {
    'use strict';

    // Get canvas element
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    // Set canvas to full screen
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Matrix characters - mix of letters, numbers, and symbols
    const matrixChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?/~';
    const chars = matrixChars.split('');

    // Font size and columns
    const fontSize = 14;
    const columns = canvas.width / fontSize;

    // Array to store y-position of each drop
    const drops = [];

    // Initialize drops
    for (let i = 0; i < columns; i++) {
        drops[i] = Math.random() * -100; // Start above screen with random offset
    }

    // Drawing function
    function draw() {
        // Semi-transparent black to create trail effect
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Set text properties
        ctx.font = fontSize + 'px monospace';

        // Draw characters
        for (let i = 0; i < drops.length; i++) {
            // Random character
            const char = chars[Math.floor(Math.random() * chars.length)];

            // Different shades of green for depth
            const brightness = Math.random();
            if (brightness > 0.95) {
                // Bright white for leading character
                ctx.fillStyle = '#FFFFFF';
            } else if (brightness > 0.8) {
                // Bright green
                ctx.fillStyle = '#00FF00';
            } else if (brightness > 0.5) {
                // Medium green
                ctx.fillStyle = '#00AA00';
            } else {
                // Dark green
                ctx.fillStyle = '#003300';
            }

            // Draw the character
            const x = i * fontSize;
            const y = drops[i] * fontSize;
            ctx.fillText(char, x, y);

            // Reset drop to top when it reaches bottom
            if (y > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }

            // Move drop down
            drops[i]++;
        }
    }

    // Animation loop
    setInterval(draw, 33); // ~30fps for smooth animation

})();
