/**
 * WebShield Backend Server
 * Node.js + Express + Google Web Security Scanner Integration
 */

const express = require('express');
const cors = require('cors');
const { WebSecurityScannerClient } = require('@google-cloud/web-security-scanner');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Google Scanner Client
const scannerClient = new WebSecurityScannerClient();

// Your GCP Project ID
const PROJECT_ID = process.env.GCP_PROJECT_ID || 'your-gcp-project-id';

// Scan Config name (will be created dynamically)
const SCAN_DISPLAY_NAME = 'CyberStack Scan';

/**
 * Health check endpoint
 */
app.get('/', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'WebShield Vulnerability Scanner (Google API)',
        version: '1.0.0'
    });
});

/**
 * Main scan endpoint
 * POST /scan
 * Body: { url: "https://your-app.appspot.com" }
 */
app.post('/scan', async (req, res) => {
    if (!req.body || !req.body.url) {
        return res.status(400).json({ error: 'Bad format: url is missing' });
    }

    const targetUrl = req.body.url;

    // Validate URL format
    if (!isValidUrl(targetUrl)) {
        return res.status(400).json({ error: 'Invalid URL' });
    }

    try {
        console.log(`\n========================================`);
        console.log(`Starting Google Web Security Scan for: ${targetUrl}`);
        console.log(`========================================\n`);

        // Step 1: Create Scan Config
        const [scanConfig] = await scannerClient.createScanConfig({
            parent: `projects/${PROJECT_ID}`,
            scanConfig: {
                displayName: SCAN_DISPLAY_NAME,
                startingUrls: [targetUrl],
                maxQps: 15,
                userAgent: 'CHROME_LINUX',
                schedule: { intervalDurationDays: 1 }
            }
        });

        console.log(`Scan Config Created: ${scanConfig.name}`);

        // Step 2: Start Scan Run
        const [scanRun] = await scannerClient.startScanRun({
            name: scanConfig.name
        });

        console.log(`Scan Run Started: ${scanRun.name}`);
        console.log('⚠ Waiting for scan to complete (this may take several minutes)...');

        // Step 3: Poll scan run status until DONE
        const finalScanRun = await waitForScanCompletion(scanRun.name);

        console.log('Scan completed! Fetching findings...');

        // Step 4: List Findings
        const [findings] = await scannerClient.listFindings({
            parent: scanConfig.name
        });

        // Step 5: Process findings
        const processedResults = processFindings(findings);

        console.log(`Scan results processed: High=${processedResults.high}, Medium=${processedResults.medium}, Low=${processedResults.low}`);

        // Return results
        res.json(processedResults);

    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({
            error: 'Scan failed',
            message: error.message
        });
    }
});

/**
 * Poll scan run status until completion
 */
async function waitForScanCompletion(scanRunName, maxWaitMs = 300000) {
    const startTime = Date.now();
    const pollInterval = 5000; // 5 sec

    while (Date.now() - startTime < maxWaitMs) {
        const [scanRun] = await scannerClient.getScanRun({ name: scanRunName });
        const status = scanRun?.executionState;

        console.log(`Scan progress: ${scanRun?.progress || 0}% | Status: ${status}`);

        if (status === 'FINISHED') return scanRun;

        await sleep(pollInterval);
    }

    throw new Error('Scan timeout reached');
}

/**
 * Process findings from Google Scanner
 */
function processFindings(findings) {
    const severityCounts = { high: 0, medium: 0, low: 0 };

    findings.forEach(f => {
        const severity = f.severity?.toLowerCase();
        if (severity === 'high') severityCounts.high++;
        else if (severity === 'medium') severityCounts.medium++;
        else severityCounts.low++;
    });

    let summary;
    if (severityCounts.high > 3) summary = 'High Risk Website';
    else if (severityCounts.high >= 1 || severityCounts.medium >= 5) summary = 'Medium Risk Website';
    else summary = 'Low Risk Website';

    return {
        summary,
        ...severityCounts,
        total: severityCounts.high + severityCounts.medium + severityCounts.low
    };
}

/**
 * Validate URL format
 */
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

/**
 * Sleep utility
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Start server
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`WebShield Backend (Google Scanner)`);
    console.log(`========================================`);
    console.log(`Server running on port: ${PORT}`);
    console.log(`========================================\n`);
});

module.exports = app;
