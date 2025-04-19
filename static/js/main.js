/**
 * Inbox Exodus - Main JavaScript
 * Client-side functionality for the web application
 */

function toggleMode(isLegalMode) {
    fetch('/api/set-mode', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            legal_mode: isLegalMode
        })
    });

    // Update UI elements
    document.querySelectorAll('.litigation-feature').forEach(el => {
        el.style.display = isLegalMode ? 'block' : 'none';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    // Initialize API status indicators
    updateApiStatus();

    // Initialize any tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize any popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Form validation
    var forms = document.querySelectorAll('.needs-validation');
    Array.prototype.slice.call(forms).forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
});

/**
 * Update API status indicators
 */
function updateApiStatus() {
    fetch('/status')
        .then(response => response.json())
        .then(data => {
            // Update system status
            const systemStatus = document.getElementById('system-status');
            if (systemStatus) {
                systemStatus.textContent = data.status;
                systemStatus.className = 'badge bg-success';
            }

            // Update Microsoft API status
            const msStatus = document.getElementById('ms-api-status');
            if (msStatus) {
                if (data.api_integration.microsoft) {
                    msStatus.textContent = 'Connected';
                    msStatus.className = 'badge bg-success';
                } else {
                    msStatus.textContent = 'Ready to Connect';
                    msStatus.className = 'badge bg-info';
                }
            }

            // Update Google API status
            const googleStatus = document.getElementById('google-api-status');
            if (googleStatus) {
                if (data.api_integration.google) {
                    googleStatus.textContent = 'Connected';
                    googleStatus.className = 'badge bg-success';
                } else {
                    googleStatus.textContent = 'Ready to Connect';
                    googleStatus.className = 'badge bg-info';
                }
            }

            // Update OpenAI status
            const openaiStatus = document.getElementById('openai-status');
            if (openaiStatus) {
                if (data.api_integration.openai) {
                    openaiStatus.textContent = 'Ready';
                    openaiStatus.className = 'badge bg-success';
                } else {
                    openaiStatus.textContent = 'Not Configured';
                    openaiStatus.className = 'badge bg-warning';
                }
            }
        })
        .catch(error => {
            console.error('Error fetching API status:', error);
        });
}

/**
 * Connect to Microsoft 365
 */
function connectMicrosoft() {
    // Redirect to Microsoft OAuth flow
    window.location.href = '/connect/microsoft';
}

/**
 * Connect to Google Workspace
 */
function connectGoogle() {
    // Redirect to Google OAuth flow
    window.location.href = '/connect/google';
}

/**
 * Start a new migration job
 */
function startMigration() {
    const form = document.getElementById('migration-form');
    if (form) {
        if (form.checkValidity()) {
            // Show loading spinner
            const submitBtn = document.getElementById('start-migration-btn');
            if (submitBtn) {
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting...';
                submitBtn.disabled = true;
            }

            // Submit the form
            form.submit();
        } else {
            form.classList.add('was-validated');
        }
    }
}

/**
 * Update migration job progress
 */
function updateJobProgress(jobId) {
    fetch(`/migrations/${jobId}/status`)
        .then(response => response.json())
        .then(data => {
            const progressBar = document.getElementById(`progress-${jobId}`);
            if (progressBar) {
                const percentage = Math.round((data.processed_files / data.total_files) * 100);
                progressBar.style.width = `${percentage}%`;
                progressBar.setAttribute('aria-valuenow', percentage);

                const progressText = document.getElementById(`progress-text-${jobId}`);
                if (progressText) {
                    progressText.textContent = `${data.processed_files} / ${data.total_files} (${percentage}%)`;
                }

                // Update status badge
                const statusBadge = document.getElementById(`status-${jobId}`);
                if (statusBadge) {
                    statusBadge.textContent = data.status;

                    // Update badge color based on status
                    statusBadge.className = 'badge ';
                    switch (data.status) {
                        case 'pending':
                            statusBadge.className += 'bg-warning';
                            break;
                        case 'in_progress':
                            statusBadge.className += 'bg-info';
                            break;
                        case 'completed':
                            statusBadge.className += 'bg-success';
                            break;
                        case 'failed':
                            statusBadge.className += 'bg-danger';
                            break;
                        default:
                            statusBadge.className += 'bg-secondary';
                    }
                }

                // Continue polling if job is in progress
                if (data.status === 'in_progress') {
                    setTimeout(() => updateJobProgress(jobId), 5000);
                }
            }
        })
        .catch(error => {
            console.error(`Error updating job ${jobId} progress:`, error);
        });
}
// Migration Flow Animation
function createMigrationFlow() {
    const container = document.getElementById('migrationFlow');
    if (!container) return;

    function createParticle() {
        const particle = document.createElement('div');
        particle.className = 'file-particle';
        particle.style.left = '5%';
        particle.style.top = Math.random() * 180 + 'px';
        container.appendChild(particle);

        // Trigger animation
        setTimeout(() => {
            particle.classList.add('organized');
        }, 100);

        // Remove particle after animation
        setTimeout(() => {
            container.removeChild(particle);
        }, 2500);
    }

    // Create particles periodically
    setInterval(createParticle, 300);
}

// Initialize animations when document loads
document.addEventListener('DOMContentLoaded', () => {
    createMigrationFlow();
});
