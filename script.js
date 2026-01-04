/**
 * WebShield Frontend - Main JavaScript
 * Handles scan requests, UI updates, and results display
 */

// Configuration
const CONFIG = {
    API_ENDPOINT: 'https://your-cloud-run-service-url.run.app/scan',
    USE_MOCK_DATA: true  // Change this to true
};

// DOM Elements
const elements = {
    scanForm: document.getElementById('scanForm'),
    urlInput: document.getElementById('urlInput'),
    scanButton: document.getElementById('scanButton'),
    loadingState: document.getElementById('loadingState'),
    resultsSection: document.getElementById('resultsSection'),
    newScanButton: document.getElementById('newScanButton'),
    
    // Result elements
    riskLevel: document.getElementById('riskLevel'),
    scannedUrl: document.getElementById('scannedUrl'),
    highCount: document.getElementById('highCount'),
    mediumCount: document.getElementById('mediumCount'),
    lowCount: document.getElementById('lowCount'),
    totalCount: document.getElementById('totalCount')
};

/**
 * Initialize event listeners
 */
function init() {
    elements.scanForm.addEventListener('submit', handleScanSubmit);
    elements.newScanButton.addEventListener('click', resetScan);
    
    // Add input validation styling
    elements.urlInput.addEventListener('input', validateUrl);
}

/**
 * Validate URL input
 */
function validateUrl() {
    const url = elements.urlInput.value;
    const urlPattern = /^https?:\/\/.+/i;
    
    if (url && !urlPattern.test(url)) {
        elements.urlInput.style.borderColor = 'var(--severity-high)';
    } else {
        elements.urlInput.style.borderColor = 'var(--border-color)';
    }
}

/**
 * Handle scan form submission
 */
async function handleScanSubmit(e) {
    e.preventDefault();
    
    const url = elements.urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a valid URL');
        return;
    }
    
    // Start scanning
    showLoading();
    
    try {
        const results = await performScan(url);
        displayResults(results, url);
    } catch (error) {
        showError(error.message || 'Scan failed. Please try again.');
        hideLoading();
    }
}

/**
 * Perform vulnerability scan
 */
async function performScan(url) {
    // Use mock data for testing if configured
    if (CONFIG.USE_MOCK_DATA) {
        return await getMockData();
    }
    
    try {
        const response = await fetch(CONFIG.API_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        return data;
        
    } catch (error) {
        console.error('Scan error:', error);
        throw new Error('Unable to connect to scanning service. Please check your API endpoint.');
    }
}

/**
 * Mock data for testing (simulates API response)
 */
function getMockData() {
    return new Promise((resolve) => {
        setTimeout(() => {
            // Generate random vulnerability data
            const high = Math.floor(Math.random() * 5);
            const medium = Math.floor(Math.random() * 8);
            const low = Math.floor(Math.random() * 10);
            const total = high + medium + low;
            
            let summary;
            if (high >= 3) {
                summary = 'High Risk Website';
            } else if (high >= 1 || medium >= 5) {
                summary = 'Medium Risk Website';
            } else {
                summary = 'Low Risk Website';
            }
            
            resolve({
                summary,
                high,
                medium,
                low,
                total
            });
        }, 3000); // Simulate 3-second scan time
    });
}

/**
 * Display scan results
 */
function displayResults(data, url) {
    // Hide loading, show results
    hideLoading();
    elements.resultsSection.classList.remove('hidden');
    
    // Scroll to results
    elements.resultsSection.scrollIntoView({ behavior: 'smooth' });
    
    // Display scanned URL
    elements.scannedUrl.textContent = url;
    
    // Display counts with animation
    animateCount(elements.highCount, data.high);
    animateCount(elements.mediumCount, data.medium);
    animateCount(elements.lowCount, data.low);
    animateCount(elements.totalCount, data.total);
    
    // Display risk level
    displayRiskLevel(data.summary);
}

/**
 * Display risk level badge
 */
function displayRiskLevel(summary) {
    const riskBadge = document.createElement('span');
    riskBadge.className = 'risk-badge';
    riskBadge.textContent = summary;
    
    // Determine risk class based on summary
    if (summary.toLowerCase().includes('high')) {
        riskBadge.classList.add('high');
    } else if (summary.toLowerCase().includes('medium')) {
        riskBadge.classList.add('medium');
    } else {
        riskBadge.classList.add('low');
    }
    
    // Replace existing content
    elements.riskLevel.innerHTML = '';
    elements.riskLevel.appendChild(riskBadge);
}

/**
 * Animate number counting
 */
function animateCount(element, targetValue) {
    const duration = 1000; // 1 second
    const steps = 30;
    const stepValue = targetValue / steps;
    const stepDuration = duration / steps;
    
    let currentValue = 0;
    const interval = setInterval(() => {
        currentValue += stepValue;
        
        if (currentValue >= targetValue) {
            element.textContent = targetValue;
            clearInterval(interval);
        } else {
            element.textContent = Math.floor(currentValue);
        }
    }, stepDuration);
}

/**
 * Show loading state
 */
function showLoading() {
    elements.scanButton.disabled = true;
    elements.loadingState.classList.remove('hidden');
    elements.resultsSection.classList.add('hidden');
}

/**
 * Hide loading state
 */
function hideLoading() {
    elements.scanButton.disabled = false;
    elements.loadingState.classList.add('hidden');
}

/**
 * Reset scan (start new scan)
 */
function resetScan() {
    // Hide results
    elements.resultsSection.classList.add('hidden');
    
    // Clear form
    elements.urlInput.value = '';
    elements.urlInput.style.borderColor = 'var(--border-color)';
    
    // Scroll to scan section
    elements.scanForm.scrollIntoView({ behavior: 'smooth' });
    
    // Focus input
    elements.urlInput.focus();
}

/**
 * Show error message
 */
function showError(message) {
    let errorElement = document.querySelector('.error-message');

    if (!errorElement) {
        errorElement = document.createElement('div');
        errorElement.className = 'error-message';
        const scanCard = document.querySelector('.scan-card');
        scanCard.appendChild(errorElement);
    }

    errorElement.textContent = message;
    errorElement.style.display = 'block';

    setTimeout(() => { errorElement.style.display = 'none'; }, 5000);
}

// function showError(message) {
//     // Create error element if it doesn't exist
//     let errorElement = document.querySelector('.error-message');
    
//     if (!errorElement) {
//         errorElement = document.createElement('div');
//         errorElement.className = 'error-message';
//         errorElement.style.cssText = `
//             background: rgba(239, 68, 68, 0.2);
//             border: 1px solid var(--severity-high);
//             color: var(--severity-high);
//             padding: 15px 20px;
//             border-radius: 10px;
//             margin-top: 20px;
//             text-align: center;
//             animation: slideDown 0.3s ease;
//         `;
//         elements.scanCard.appendChild(errorElement);
//     }
    
//     errorElement.textContent = message;
//     errorElement.style.display = 'block';
    
//     // Hide after 5 seconds
//     setTimeout(() => {
//         errorElement.style.display = 'none';
//     }, 5000);
// }

/**
 * Add slide down animation
 */
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

/**
 * CONFIGURATION INSTRUCTIONS FOR DEPLOYMENT
 * ==========================================
 * 
 * Before deploying to Firebase Hosting:
 * 
 * 1. Update the API_ENDPOINT in CONFIG object above with your Cloud Run URL:
 *    API_ENDPOINT: 'https://your-actual-service-url.run.app/scan'
 * 
 * 2. Set USE_MOCK_DATA to false for production
 * 
 * 3. For local testing, you can set USE_MOCK_DATA to true
 * 
 * 4. Make sure your Cloud Run service has CORS enabled to accept requests
 *    from your Firebase Hosting domain
 * 
 * Expected API Response Format:
 * {
 *   "summary": "High Risk Website",
 *   "high": 3,
 *   "medium": 5,
 *   "low": 2,
 *   "total": 10
 * }
 */