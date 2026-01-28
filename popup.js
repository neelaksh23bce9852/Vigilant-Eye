document.addEventListener('DOMContentLoaded', () => {
    // 1. Tab Navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

            e.target.classList.add('active');
            const viewId = 'view-' + e.target.id.split('-')[1];
            document.getElementById(viewId).classList.add('active');
        });
    });

    // 2. Scan Button
    document.getElementById('scan-btn').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0].id) {
                chrome.scripting.executeScript({
                    target: { tabId: tabs[0].id },
                    function: () => window.location.reload()
                });
                window.close();
            }
        });
    });

    // 3. Open HQ Button
    document.getElementById('btn-open-hq').addEventListener('click', () => {
        chrome.tabs.create({ url: 'forensics.html' });
    });

    // 4. Load Data
    loadData();
});

function loadData() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const activeTab = tabs[0];

        if (!activeTab || !activeTab.url) {
            renderError("No active tab.");
            return;
        }

        try {
            const urlObj = new URL(activeTab.url);
            document.getElementById('meta-domain').innerText = urlObj.hostname || "Local File";
            document.getElementById('meta-proto').innerText = urlObj.protocol.replace(':', '').toUpperCase();
            if (urlObj.protocol === 'http:') {
                document.getElementById('meta-proto').style.color = 'red';
            }
        } catch (e) {
            document.getElementById('meta-domain').innerText = "Unknown";
        }

        // Try content script first
        chrome.tabs.sendMessage(activeTab.id, { action: "getDetailedStatus" }, (response) => {
            if (chrome.runtime.lastError || !response) {
                // Fallback to background cache
                chrome.runtime.sendMessage({ action: "getHistory", tabId: activeTab.id }, (bgResponse) => {
                    if (bgResponse && bgResponse.data) {
                        renderOverview(bgResponse.data);
                        renderDetails(bgResponse.data);
                    } else {
                        diagnoseError(activeTab.url);
                    }
                });
                return;
            }
            renderOverview(response);
            renderDetails(response);
        });
    });
}

function diagnoseError(url) {
    if (url.startsWith("file://")) {
        renderError("For local files, check 'Allow access to file URLs' in settings.", true);
    } else if (url.startsWith("chrome://") || url.startsWith("edge://")) {
        renderError("Restricted System Page.");
    } else {
        renderError("Connection Failed. Refresh page.");
    }
}

function renderOverview(data) {
    if (!data) return;
    const circle = document.querySelector('.circle');
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (data.score / 100) * circumference;

    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    circle.style.strokeDashoffset = offset;

    let color = '#22c55e'; // Green
    if (data.score < 80) color = '#f59e0b'; // Orange
    if (data.score < 50) color = '#ef4444'; // Red
    circle.style.stroke = color;

    document.getElementById('score-text').innerText = data.score;
    document.getElementById('threat-summary').innerText =
        data.score === 100 ? "System Safe" :
            data.score > 50 ? "Caution Advised" : "CRITICAL THREAT";
    document.getElementById('threat-summary').style.color = color;

    document.getElementById('cnt-phishing').innerText = data.details.phishingKeywords.length;
    document.getElementById('cnt-links').innerText = data.details.suspiciousLinks.length;
    document.getElementById('cnt-hidden').innerText = data.details.hiddenElements.length;
}

function renderDetails(data) {
    const list = document.getElementById('details-list');
    list.innerHTML = '';
    if (!data) return;

    if (data.score === 100) {
        list.innerHTML = '<div class="console-line">> No threats detected. Safe to browse.</div>';
        return;
    }

    // Arrays might be null in some cached states, add safety check
    const safelyLoop = (arr, prefix, cls) => {
        if (arr && arr.length) {
            arr.forEach(item => {
                const div = document.createElement('div');
                div.className = `console-line ${cls}`;
                div.innerText = `> [${prefix}] ${typeof item === 'string' ? item : (item.reason || 'Detected')}`;
                list.appendChild(div);
            });
        }
    };

    safelyLoop(data.details.phishingKeywords, 'KEYWORD', 'warn');
    safelyLoop(data.details.suspiciousLinks, 'LINK', 'danger');
    safelyLoop(data.details.sensitiveForms, 'FORM', 'danger');
    safelyLoop(data.details.hiddenElements, 'HIDDEN', 'warn');
}

function renderError(msg, isActionable = false) {
    document.getElementById('status-text').innerText = "Inactive";
    document.getElementById('score-text').innerText = "--";
    let html = `<div class="console-line danger">> ${msg}</div>`;
    if (isActionable) {
        html += `<div class="console-line text-muted">> Go to Extensions > Vigilant Eye > Details > Allow File URLs</div>`;
    }
    document.getElementById('details-list').innerHTML = html;
}
