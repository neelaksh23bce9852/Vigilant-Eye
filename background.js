// Vigilant Eye - Central Intelligence (Background)

// Storage Keys
const HISTORY_KEY = 'threatHistory';
const REPORTS_KEY = 'incidentReports';

// 1. Event Listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    // A. Live Updates
    if (request.action === "updateStatus") {
        const tabId = sender.tab.id;
        const { threats, score, details } = request.data;

        // Update Badge
        updateBadge(tabId, threats, score);

        // AUTO-REPORTING LOGIC (The "Specialist" Feature)
        if (score < 45) { // Critical Threshold
            processAutoReport(request.data, sender.tab);
        }
    }

    // B. Data Requests
    if (request.action === "getHistory") {
        // Return simple state for popup
        // Implementation omitted for brevity as popup uses direct messaging usually
    }

    if (request.action === "getDetailedReports") {
        chrome.storage.local.get([REPORTS_KEY], (res) => {
            sendResponse(res[REPORTS_KEY] || []);
        });
        return true; // Async
    }
});

// 2. Auto-Reporting Engine
function processAutoReport(scanData, tab) {
    const url = new URL(tab.url);

    // Check if recently reported to avoid spamming the "database"
    chrome.storage.local.get([REPORTS_KEY], (result) => {
        let reports = result[REPORTS_KEY] || [];

        // Simple duplicate check (same domain within 1 hour)
        const existing = reports.find(r =>
            r.domain === url.hostname &&
            (Date.now() - r.timestamp) < 3600000
        );

        if (!existing) {
            // Generate New Forensic Report
            const incidentId = "INC-" + Math.floor(Math.random() * 1000000);

            const newReport = {
                id: incidentId,
                timestamp: Date.now(),
                severity: "CRITICAL",
                domain: url.hostname,
                fullUrl: tab.url,
                score: scanData.score,
                evidence: {
                    triggers: scanData.details.phishingKeywords,
                    badLinks: scanData.details.suspiciousLinks.length,
                    forms: scanData.details.sensitiveForms
                },
                status: "REPORTED_TO_AUTHORITIES" // Simulated
            };

            reports.unshift(newReport);
            // Cap storage
            if (reports.length > 50) reports.pop();

            chrome.storage.local.set({ [REPORTS_KEY]: reports }, () => {
                console.log(`[VIGILANT] Auto-Report Generated: ${incidentId}`);

                // Notify User
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icons/icon128.png',
                    title: '⚠️ Automatic Incident Report Filed',
                    message: `High threat detected at ${url.hostname}. Incident #${incidentId} has been logged with CyberWatch.`,
                    priority: 2
                });

                // Tell Content Script to Update UI
                chrome.tabs.sendMessage(tab.id, {
                    action: "reportConfirmed",
                    reportId: incidentId
                });
            });
        }
    });
}

// 3. UI Helpers
function updateBadge(tabId, count, score) {
    if (score < 100) {
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
    } else {
        chrome.action.setBadgeText({ text: "", tabId });
    }
}
