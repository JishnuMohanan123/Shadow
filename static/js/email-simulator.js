/**
 * Shadow 1834 - Interactive Email Client Simulator
 * Realistic email interface for phishing training scenarios
 */

class EmailSimulator {
    constructor(containerElement) {
        this.container = containerElement;
        this.currentEmail = null;
        this.onDecisionCallback = null;
    }

    createEmailClient(emailData, onDecision) {
        this.currentEmail = emailData;
        this.onDecisionCallback = onDecision;

        const clientHTML = `
            <div class="email-client" style="background: #1a1a1a; border: 2px solid #333; border-radius: 10px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.5);">
                <!-- Email Toolbar -->
                <div class="email-toolbar" style="background: #2a2a2a; padding: 0.75rem 1.5rem; border-bottom: 1px solid #333; display: flex; align-items: center; gap: 1rem;">
                    <div style="color: #00ffff; font-family: 'Orbitron', monospace; font-weight: 700; font-size: 1.1rem;">
                        📧 SECURE MAIL
                    </div>
                    <div style="flex: 1;"></div>
                    <button class="email-action-btn" style="padding: 0.4rem 0.8rem; background: rgba(0, 136, 255, 0.2); border: 1px solid #0088ff; border-radius: 5px; color: #0088ff; font-size: 0.8rem; cursor: pointer; font-family: 'Orbitron', monospace;">
                        📥 INBOX
                    </button>
                    <button class="email-action-btn" style="padding: 0.4rem 0.8rem; background: rgba(255, 170, 0, 0.2); border: 1px solid #ffaa00; border-radius: 5px; color: #ffaa00; font-size: 0.8rem; cursor: pointer; font-family: 'Orbitron', monospace;">
                        🗑️ TRASH
                    </button>
                </div>

                <!-- Email Header -->
                <div class="email-header" style="background: #222; padding: 1.5rem; border-bottom: 1px solid #333;">
                    <div style="margin-bottom: 1rem;">
                        <div style="color: #00ffff; font-family: 'Orbitron', monospace; font-size: 0.8rem; margin-bottom: 0.5rem; opacity: 0.7;">
                            FROM:
                        </div>
                        <div class="email-from" style="display: flex; align-items: center; gap: 1rem; background: rgba(0, 136, 255, 0.1); padding: 0.75rem; border-radius: 6px; border-left: 3px solid #0088ff; cursor: pointer; transition: all 0.3s;"
                             onmouseover="this.style.background='rgba(0, 136, 255, 0.2)'; showTooltip(this, 'Click to inspect sender details')"
                             onmouseout="this.style.background='rgba(0, 136, 255, 0.1)'; hideTooltip()"
                             onclick="inspectEmailAddress('${emailData.from.email}', '${emailData.from.name}')">
                            <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #0088ff, #00ffff); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;">
                                ${emailData.from.name.charAt(0)}
                            </div>
                            <div style="flex: 1;">
                                <div style="color: #ffffff; font-weight: 600; font-size: 1rem; font-family: 'Rajdhani', monospace;">
                                    ${emailData.from.name}
                                </div>
                                <div class="email-address" style="color: #00ff88; font-size: 0.85rem; font-family: 'Courier New', monospace;">
                                    &lt;${emailData.from.email}&gt;
                                </div>
                            </div>
                            <div class="inspect-icon" style="color: #0088ff; font-size: 1.2rem;">
                                🔍
                            </div>
                        </div>
                    </div>

                    <div style="margin-bottom: 1rem;">
                        <div style="color: #00ffff; font-family: 'Orbitron', monospace; font-size: 0.8rem; margin-bottom: 0.5rem; opacity: 0.7;">
                            TO:
                        </div>
                        <div style="color: #a0c4ff; font-size: 0.9rem; font-family: 'Courier New', monospace;">
                            ${emailData.to}
                        </div>
                    </div>

                    <div style="margin-bottom: 1rem;">
                        <div style="color: #00ffff; font-family: 'Orbitron', monospace; font-size: 0.8rem; margin-bottom: 0.5rem; opacity: 0.7;">
                            SUBJECT:
                        </div>
                        <div style="color: #ffffff; font-size: 1.1rem; font-weight: 600; font-family: 'Rajdhani', monospace;">
                            ${emailData.subject}
                        </div>
                    </div>

                    <div style="color: #888; font-size: 0.85rem; font-family: 'Rajdhani', monospace;">
                        ${emailData.date}
                    </div>
                </div>

                <!-- Email Body -->
                <div class="email-body" style="padding: 2rem; background: #1a1a1a; min-height: 300px; color: #ffffff; font-family: 'Rajdhani', monospace; line-height: 1.8; font-size: 1.05rem;">
                    ${this.processEmailBody(emailData.body)}
                </div>

                <!-- Email Actions -->
                <div class="email-actions" style="background: #222; padding: 1.5rem; border-top: 1px solid #333; display: flex; gap: 1rem; justify-content: center;">
                    <button class="decision-btn trust-btn" onclick="emailSimulator.makeDecision('trust')"
                            style="padding: 1rem 2rem; background: linear-gradient(135deg, rgba(0, 255, 136, 0.2), rgba(0, 255, 136, 0.1)); border: 2px solid #00ff88; border-radius: 8px; color: #00ff88; font-family: 'Orbitron', monospace; font-size: 1rem; cursor: pointer; transition: all 0.3s; font-weight: 600; text-transform: uppercase;">
                        ✅ TRUST & PROCEED
                    </button>
                    <button class="decision-btn report-btn" onclick="emailSimulator.makeDecision('report')"
                            style="padding: 1rem 2rem; background: linear-gradient(135deg, rgba(255, 170, 0, 0.2), rgba(255, 170, 0, 0.1)); border: 2px solid #ffaa00; border-radius: 8px; color: #ffaa00; font-family: 'Orbitron', monospace; font-size: 1rem; cursor: pointer; transition: all 0.3s; font-weight: 600; text-transform: uppercase;">
                        ⚠️ MARK AS SUSPICIOUS
                    </button>
                    <button class="decision-btn delete-btn" onclick="emailSimulator.makeDecision('delete')"
                            style="padding: 1rem 2rem; background: linear-gradient(135deg, rgba(255, 68, 68, 0.2), rgba(255, 68, 68, 0.1)); border: 2px solid #ff4444; border-radius: 8px; color: #ff4444; font-family: 'Orbitron', monospace; font-size: 1rem; cursor: pointer; transition: all 0.3s; font-weight: 600; text-transform: uppercase;">
                        🗑️ DELETE & BLOCK
                    </button>
                </div>
            </div>
        `;

        this.container.innerHTML = clientHTML;
        this.addEmailInteractivity();
    }

    processEmailBody(body) {
        // Process links with hover inspection
        return body.replace(
            /<a href="([^"]+)">([^<]+)<\/a>/g,
            (match, url, text) => {
                return `<a href="#" class="email-link"
                          data-url="${url}"
                          onclick="inspectLink('${url}', '${text}'); return false;"
                          onmouseover="showLinkPreview(this, '${url}')"
                          onmouseout="hideLinkPreview()"
                          style="color: #0088ff; text-decoration: underline; cursor: pointer; position: relative; transition: all 0.2s;">
                          ${text}
                        </a>`;
            }
        );
    }

    addEmailInteractivity() {
        // Add hover effects to buttons
        const buttons = this.container.querySelectorAll('.decision-btn');
        buttons.forEach(btn => {
            btn.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-3px) scale(1.05)';
                this.style.boxShadow = `0 10px 30px ${this.style.borderColor}50`;
            });

            btn.addEventListener('mouseleave', function() {
                this.style.transform = '';
                this.style.boxShadow = '';
            });
        });
    }

    makeDecision(decision) {
        // Disable all buttons
        const buttons = this.container.querySelectorAll('.decision-btn');
        buttons.forEach(btn => {
            btn.disabled = true;
            btn.style.opacity = '0.5';
            btn.style.cursor = 'not-allowed';
        });

        // Show visual feedback
        this.showDecisionFeedback(decision);

        // Call callback after animation
        setTimeout(() => {
            if (this.onDecisionCallback) {
                this.onDecisionCallback(decision, this.currentEmail);
            }
        }, 1500);
    }

    showDecisionFeedback(decision) {
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: ${decision === 'trust' ? 'rgba(0, 255, 136, 0.2)' :
                         decision === 'report' ? 'rgba(255, 170, 0, 0.2)' :
                         'rgba(255, 68, 68, 0.2)'};
            z-index: 9998;
            pointer-events: none;
            animation: flashDecision 0.5s ease-in-out;
        `;
        document.body.appendChild(overlay);
        setTimeout(() => overlay.remove(), 500);
    }
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function inspectEmailAddress(email, name) {
    const parts = email.split('@');
    const domain = parts[1] || '';

    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: rgba(0, 0, 0, 0.95);
        border: 2px solid #00ffff;
        border-radius: 12px;
        padding: 2rem;
        z-index: 10000;
        min-width: 400px;
        box-shadow: 0 20px 60px rgba(0, 255, 255, 0.3);
        animation: zoomIn 0.3s ease-out;
    `;

    modal.innerHTML = `
        <h3 style="color: #00ffff; font-family: 'Orbitron', monospace; margin-bottom: 1.5rem; text-align: center;">
            🔍 EMAIL ANALYSIS
        </h3>
        <div style="background: rgba(0, 136, 255, 0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
            <div style="color: #00ff88; font-size: 0.8rem; margin-bottom: 0.5rem;">SENDER NAME:</div>
            <div style="color: #ffffff; font-size: 1rem; font-family: 'Courier New', monospace;">${name}</div>
        </div>
        <div style="background: rgba(0, 136, 255, 0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
            <div style="color: #00ff88; font-size: 0.8rem; margin-bottom: 0.5rem;">EMAIL ADDRESS:</div>
            <div style="color: #ffffff; font-size: 1rem; font-family: 'Courier New', monospace;">${email}</div>
        </div>
        <div style="background: rgba(255, 170, 0, 0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem;">
            <div style="color: #ffaa00; font-size: 0.8rem; margin-bottom: 0.5rem;">DOMAIN:</div>
            <div style="color: #ffffff; font-size: 1rem; font-family: 'Courier New', monospace;">${domain}</div>
        </div>
        <div style="text-align: center;">
            <button onclick="this.closest('[style*=fixed]').remove()"
                    style="padding: 0.75rem 1.5rem; background: rgba(0, 255, 255, 0.2); border: 2px solid #00ffff; border-radius: 6px; color: #00ffff; font-family: 'Orbitron', monospace; cursor: pointer;">
                CLOSE
            </button>
        </div>
    `;

    document.body.appendChild(modal);

    // Remove on background click
    modal.addEventListener('click', function(e) {
        if (e.target === this) {
            this.remove();
        }
    });
}

function inspectLink(url, text) {
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: rgba(0, 0, 0, 0.95);
        border: 2px solid #ff4444;
        border-radius: 12px;
        padding: 2rem;
        z-index: 10000;
        min-width: 500px;
        box-shadow: 0 20px 60px rgba(255, 68, 68, 0.3);
        animation: zoomIn 0.3s ease-out;
    `;

    const isPhishing = url.includes('suspicious') || url.includes('fake') || url.includes('malicious');

    modal.innerHTML = `
        <h3 style="color: #ff4444; font-family: 'Orbitron', monospace; margin-bottom: 1.5rem; text-align: center;">
            🔗 LINK ANALYSIS
        </h3>
        <div style="background: rgba(255, 68, 68, 0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
            <div style="color: #ff4444; font-size: 0.8rem; margin-bottom: 0.5rem;">LINK TEXT:</div>
            <div style="color: #ffffff; font-size: 1rem; font-family: 'Courier New', monospace;">${text}</div>
        </div>
        <div style="background: rgba(255, 68, 68, 0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
            <div style="color: #ff4444; font-size: 0.8rem; margin-bottom: 0.5rem;">ACTUAL URL:</div>
            <div style="color: #ffaa00; font-size: 0.9rem; font-family: 'Courier New', monospace; word-break: break-all;">${url}</div>
        </div>
        <div style="background: ${isPhishing ? 'rgba(255, 68, 68, 0.2)' : 'rgba(0, 255, 136, 0.2)'}; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; border: 2px solid ${isPhishing ? '#ff4444' : '#00ff88'};">
            <div style="color: ${isPhishing ? '#ff4444' : '#00ff88'}; font-weight: 700; font-family: 'Orbitron', monospace; text-align: center; font-size: 1.1rem;">
                ${isPhishing ? '⚠️ SUSPICIOUS LINK DETECTED' : '✓ LINK APPEARS SAFE'}
            </div>
        </div>
        <div style="text-align: center;">
            <button onclick="this.closest('[style*=fixed]').remove()"
                    style="padding: 0.75rem 1.5rem; background: rgba(255, 68, 68, 0.2); border: 2px solid #ff4444; border-radius: 6px; color: #ff4444; font-family: 'Orbitron', monospace; cursor: pointer;">
                CLOSE
            </button>
        </div>
    `;

    document.body.appendChild(modal);
}

function showLinkPreview(element, url) {
    const preview = document.createElement('div');
    preview.className = 'link-preview';
    preview.style.cssText = `
        position: absolute;
        bottom: 100%;
        left: 0;
        background: rgba(0, 0, 0, 0.95);
        border: 1px solid #0088ff;
        border-radius: 6px;
        padding: 0.5rem 0.75rem;
        font-size: 0.8rem;
        color: #0088ff;
        font-family: 'Courier New', monospace;
        white-space: nowrap;
        z-index: 1000;
        pointer-events: none;
        margin-bottom: 0.5rem;
    `;
    preview.textContent = url;
    element.appendChild(preview);
}

function hideLinkPreview() {
    const previews = document.querySelectorAll('.link-preview');
    previews.forEach(p => p.remove());
}

function showTooltip(element, text) {
    // Tooltip functionality can be added here
}

function hideTooltip() {
    // Tooltip cleanup
}

// ============================================
// ADD STYLES
// ============================================

const emailStyles = document.createElement('style');
emailStyles.textContent = `
    @keyframes flashDecision {
        0%, 100% { opacity: 0; }
        50% { opacity: 1; }
    }

    @keyframes zoomIn {
        from {
            transform: translate(-50%, -50%) scale(0);
            opacity: 0;
        }
        to {
            transform: translate(-50%, -50%) scale(1);
            opacity: 1;
        }
    }

    .email-link:hover {
        color: #00ffff !important;
        text-shadow: 0 0 10px #00ffff;
    }

    .decision-btn:active {
        transform: scale(0.95) !important;
    }
`;
document.head.appendChild(emailStyles);

// Initialize global email simulator
window.emailSimulator = new EmailSimulator(document.createElement('div'));

console.log('%c📧 Email Simulator Loaded', 'color: #0088ff; font-size: 14px; font-weight: bold;');
