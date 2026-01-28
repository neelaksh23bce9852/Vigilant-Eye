// Vigilant Eye - Real-time Forensics Dashboard
// Key Features: Storage Listener, Tab Navigation, Log Clearing

const REPORTS_KEY = 'incidentReports';

document.addEventListener('DOMContentLoaded', () => {

    // A. Navigation Logic
    const menuItems = document.querySelectorAll('.menu-item');
    const views = document.querySelectorAll('.view-section');

    menuItems.forEach(item => {
        item.addEventListener('click', () => {
            // 1. Remove active state from all
            menuItems.forEach(i => i.classList.remove('active'));
            views.forEach(v => v.classList.remove('active'));

            // 2. Add active to clicked
            item.classList.add('active');
            const targetId = item.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // B. Initial Load & Listeners
    loadReports();

    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === 'local' && changes[REPORTS_KEY]) {
            renderTable(changes[REPORTS_KEY].newValue);
        }
    });

    // C. Settings Logic (Visual Only for Toggle)
    document.querySelectorAll('.toggle-switch').forEach(toggle => {
        toggle.addEventListener('click', () => {
            toggle.classList.toggle('on');
        });
    });

    // D. Clear Logs
    document.getElementById('btn-clear-logs').addEventListener('click', () => {
        if (confirm("Are you sure you want to purge all forensic data?")) {
            chrome.storage.local.set({ [REPORTS_KEY]: [] });
        }
    });
});

function loadReports() {
    chrome.storage.local.get([REPORTS_KEY], (result) => {
        renderTable(result[REPORTS_KEY] || []);
    });
}

function renderTable(reports) {
    const tbody = document.getElementById('report-table');
    const kpiTotal = document.getElementById('total-reports');
    const kpiCritical = document.getElementById('critical-score');

    if (!reports || reports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#64748b; padding:20px;">No incidents recorded in database.</td></tr>';
        kpiTotal.innerText = "0";
        kpiCritical.innerText = "0";
        return;
    }

    // Sort by newest first
    reports.sort((a, b) => b.timestamp - a.timestamp);

    kpiTotal.innerText = reports.length;
    kpiCritical.innerText = reports.filter(r => r.score < 50).length;

    let html = '';
    reports.forEach(r => {
        const date = new Date(r.timestamp);
        const timeStr = date.toLocaleTimeString();
        const dateStr = date.toLocaleDateString();

        let badgeClass = 'critical';
        if (r.score > 40) badgeClass = 'warn';

        html += `
        <tr class="new-row">
            <td style="font-family:monospace; color:#3b82f6;">${r.id}</td>
            <td>${dateStr} <span style="color:#64748b">${timeStr}</span></td>
            <td><span class="badge ${badgeClass}">${r.severity}</span></td>
            <td><div style="font-weight:bold;">${r.domain}</div></td>
            <td style="color:#22c55e; font-size:12px;">✔ ${r.status}</td>
        </tr>
        `;
    });
    tbody.innerHTML = html;
}
