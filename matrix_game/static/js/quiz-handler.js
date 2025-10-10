/**
 * SHADOW - Quiz Handler
 * Manages quiz interactions, API calls, and UI updates
 */

(function() {
    'use strict';

    let currentQuestion = null;
    let selectedAnswer = null;
    let questionData = null;

    // Elements
    const questionContainer = document.getElementById('questionContainer');
    const questionText = document.getElementById('questionText');
    const optionsContainer = document.getElementById('optionsContainer');
    const progressText = document.getElementById('progressText');
    const progressBar = document.getElementById('progressBar');
    const scoreValue = document.getElementById('scoreValue');
    const categoryBadge = document.getElementById('categoryText');
    const terminalLog = document.getElementById('terminalLog');
    const feedbackOverlay = document.getElementById('feedbackOverlay');
    const loadingScreen = document.getElementById('loadingScreen');
    const actionButtons = document.getElementById('actionButtons');

    // Initialize quiz
    function init() {
        console.log('[SYSTEM] Initializing quiz interface...');
        addTerminalLog('> INITIALIZING QUIZ MODULE...');
        addTerminalLog('> CONNECTING TO DATABASE...');

        setTimeout(() => {
            addTerminalLog('> CONNECTION ESTABLISHED', 'success');
            loadQuestion();
        }, 1500);
    }

    // Add log to terminal
    function addTerminalLog(message, type = '') {
        const logLine = document.createElement('p');
        logLine.className = 'log-line ' + type;
        logLine.textContent = message;
        terminalLog.appendChild(logLine);
        terminalLog.scrollTop = terminalLog.scrollHeight;
    }

    // Load question from API
    function loadQuestion() {
        showLoading();

        fetch('/api/question')
            .then(response => response.json())
            .then(data => {
                if (data.complete) {
                    // Quiz is complete
                    window.location.href = '/result';
                } else if (data.error) {
                    addTerminalLog('> ERROR: ' + data.error, 'error');
                    setTimeout(() => window.location.href = '/', 2000);
                } else {
                    questionData = data;
                    displayQuestion(data);
                }
            })
            .catch(error => {
                console.error('Error loading question:', error);
                addTerminalLog('> CRITICAL ERROR: Failed to load mission data', 'error');
            });
    }

    // Display question on screen
    function displayQuestion(data) {
        hideLoading();

        // Update progress
        const progress = (data.current / data.total) * 100;
        progressBar.style.width = progress + '%';
        progressText.textContent = `QUESTION ${data.current} / ${data.total}`;

        // Update category badge
        const categoryName = data.category.replace('_', ' ').toUpperCase();
        categoryBadge.textContent = categoryName;

        // Clear previous options
        optionsContainer.innerHTML = '';
        selectedAnswer = null;
        actionButtons.style.display = 'none';

        // Display question with typing effect
        questionContainer.style.display = 'block';
        typeText(questionText, data.question);

        // Add log
        addTerminalLog(`> LOADING QUESTION ${data.current}...`);
        addTerminalLog(`> CATEGORY: ${categoryName}`, 'success');

        // Create option buttons with delay
        setTimeout(() => {
            const options = ['A', 'B', 'C', 'D'];
            options.forEach((letter, index) => {
                setTimeout(() => {
                    createOptionButton(letter, data.options[letter]);
                }, index * 150);
            });
        }, 1000);
    }

    // Create option button
    function createOptionButton(letter, text) {
        const button = document.createElement('button');
        button.className = 'option-button';
        button.innerHTML = `
            <span class="option-label">${letter}</span>
            <span class="option-text">${text}</span>
        `;

        button.addEventListener('click', () => selectOption(button, letter));
        optionsContainer.appendChild(button);

        // Slide in animation
        setTimeout(() => {
            button.style.opacity = '0';
            button.style.transform = 'translateX(-30px)';
            button.style.transition = 'all 0.3s ease';

            setTimeout(() => {
                button.style.opacity = '1';
                button.style.transform = 'translateX(0)';
            }, 10);
        }, 0);
    }

    // Select an option
    function selectOption(button, letter) {
        // Remove previous selection
        const allButtons = optionsContainer.querySelectorAll('.option-button');
        allButtons.forEach(btn => btn.classList.remove('selected'));

        // Select current
        button.classList.add('selected');
        selectedAnswer = letter;

        // Log selection
        addTerminalLog(`> OPTION ${letter} SELECTED`);

        // Submit answer immediately
        setTimeout(() => {
            submitAnswer();
        }, 500);
    }

    // Submit answer to server
    function submitAnswer() {
        if (!selectedAnswer) {
            addTerminalLog('> ERROR: No option selected', 'error');
            return;
        }

        // Disable all buttons
        const allButtons = optionsContainer.querySelectorAll('.option-button');
        allButtons.forEach(btn => btn.disabled = true);

        addTerminalLog('> SUBMITTING ANSWER...');
        addTerminalLog('> ANALYZING RESPONSE...');

        fetch('/api/answer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ answer: selectedAnswer })
        })
            .then(response => response.json())
            .then(data => {
                handleAnswerResult(data);
            })
            .catch(error => {
                console.error('Error submitting answer:', error);
                addTerminalLog('> ERROR: Failed to submit answer', 'error');
            });
    }

    // Handle answer result
    function handleAnswerResult(data) {
        const isCorrect = data.correct;
        const correctOption = data.correct_option;

        // Update score
        scoreValue.textContent = data.score;

        // Highlight correct/incorrect
        const allButtons = optionsContainer.querySelectorAll('.option-button');
        allButtons.forEach(button => {
            const letter = button.querySelector('.option-label').textContent;

            if (letter === correctOption) {
                button.classList.add('correct');
            } else if (letter === selectedAnswer && !isCorrect) {
                button.classList.add('incorrect');
            }
        });

        // Show feedback
        setTimeout(() => {
            showFeedback(isCorrect);

            // Add log
            if (isCorrect) {
                addTerminalLog('> ACCESS GRANTED ✅', 'success');
                playCorrectSound();
            } else {
                addTerminalLog('> ACCESS DENIED ❌', 'error');
                addTerminalLog(`> CORRECT ANSWER: ${correctOption}`, 'warning');
                playWrongSound();
            }

            // Show next button after feedback
            setTimeout(() => {
                hideFeedback();
                actionButtons.style.display = 'block';
            }, 2000);

        }, 1000);
    }

    // Show feedback overlay
    function showFeedback(isCorrect) {
        const feedbackIcon = document.getElementById('feedbackIcon');
        const feedbackText = document.getElementById('feedbackText');
        const feedbackMessage = document.getElementById('feedbackMessage');

        if (isCorrect) {
            feedbackIcon.textContent = '✅';
            feedbackIcon.style.color = '#00FF00';
            feedbackText.textContent = 'ACCESS GRANTED';
            feedbackText.style.color = '#00FF00';
            feedbackMessage.textContent = 'Correct! Security protocol validated.';
        } else {
            feedbackIcon.textContent = '❌';
            feedbackIcon.style.color = '#FF0000';
            feedbackText.textContent = 'ACCESS DENIED';
            feedbackText.style.color = '#FF0000';
            feedbackMessage.textContent = 'Incorrect. Security breach detected.';
        }

        feedbackOverlay.style.display = 'flex';
    }

    // Hide feedback overlay
    function hideFeedback() {
        feedbackOverlay.style.display = 'none';
    }

    // Load next question
    window.loadNextQuestion = function() {
        addTerminalLog('> LOADING NEXT MISSION...');
        loadQuestion();
    };

    // Show/hide loading
    function showLoading() {
        loadingScreen.style.display = 'block';
        questionContainer.style.display = 'none';
    }

    function hideLoading() {
        loadingScreen.style.display = 'none';
    }

    // Typing effect
    function typeText(element, text) {
        let i = 0;
        element.textContent = '';

        function type() {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
                setTimeout(type, 30);
            }
        }

        type();
    }

    // Sound effects
    function playCorrectSound() {
        const sound = document.getElementById('correctSound');
        if (sound) {
            sound.currentTime = 0;
            sound.volume = 0.3;
            sound.play().catch(e => {});
        }
    }

    function playWrongSound() {
        const sound = document.getElementById('wrongSound');
        if (sound) {
            sound.currentTime = 0;
            sound.volume = 0.3;
            sound.play().catch(e => {});
        }
    }

    // Start quiz when page loads
    window.addEventListener('load', init);

    console.log('%c[SYSTEM] Quiz handler loaded', 'color: #00FF00; font-family: monospace;');

})();
