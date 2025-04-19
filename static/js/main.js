/**
 * Inbox Exodus Main JavaScript
 * Contains general application functionality
 */

// Enable Bootstrap tooltips and popovers
document.addEventListener('DOMContentLoaded', function () {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Legal Mode Toggle
    const modeToggle = document.getElementById('modeToggle');
    if (modeToggle) {
        modeToggle.addEventListener('change', function() {
            toggleMode(this.checked);
        });
    }
});

/**
 * Toggle between normal and legal mode
 * 
 * @param {boolean} isLegalMode - Whether legal mode is enabled
 */
function toggleMode(isLegalMode) {
    // Add your logic here to handle the mode toggle.
    // This would likely involve updating the backend configuration
    // or applying different CSS classes.
    console.log("Legal mode is:", isLegalMode);
    
    // Example implementation (to be customized):
    if (isLegalMode) {
        // Apply legal mode styling or functionality
        document.body.classList.add('legal-mode');
        // Could make API call to update user preference
    } else {
        // Remove legal mode styling or functionality
        document.body.classList.remove('legal-mode');
        // Could make API call to update user preference
    }
}

/**
 * Format file size in bytes to human readable format
 * 
 * @param {number} bytes - Size in bytes
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted file size
 */
function formatFileSize(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Format date to a human-readable string
 * 
 * @param {Date|string} date - Date object or date string
 * @returns {string} Formatted date string
 */
function formatDate(date) {
    if (!date) return 'N/A';
    
    const d = new Date(date);
    if (isNaN(d.getTime())) return 'Invalid date';
    
    return d.toLocaleString();
}

/**
 * Show alert message
 * 
 * @param {string} message - The message to display
 * @param {string} type - The type of alert (success, danger, warning, info)
 * @param {string} containerId - The ID of the container to add the alert to
 */
function showAlert(message, type = 'info', containerId = 'alertContainer') {
    const container = document.getElementById(containerId);
    
    if (!container) {
        console.error(`Alert container with ID "${containerId}" not found`);
        return;
    }
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    container.appendChild(alertDiv);
    
    // Auto-close after 5 seconds
    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alertDiv);
        bsAlert.close();
    }, 5000);
}