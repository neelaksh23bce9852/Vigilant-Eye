// Vigilant Eye - Specialist Edition Content Script

let rules = null;
let sidebarUI = null;
let isScanPending = false;
let scanTimer = null;
let currentReportId = null;

// State
let threatState = {
  keywords: [],
  links: [],
  forms: [],
  hidden: [],
  score: 100
};

// 1. Initialization
(async () => {
  try {
    const response = await fetch(chrome.runtime.getURL('rules/scamRules.json'));
    rules = await response.json();

    createSidebar();
    requestAnimationFrame(() => performScan());

    const observer = new MutationObserver((mutations) => {
      if (!isScanPending) {
        isScanPending = true;
        clearTimeout(scanTimer);
        scanTimer = setTimeout(() => {
          performScan();
          isScanPending = false;
        }, 750);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: false, characterData: true });

    // Listen for Report Confirmation
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.action === "reportConfirmed") {
        currentReportId = msg.reportId;
        updateSidebar(); // Re-render to show report ID
      }
    });

  } catch (e) {
    console.error("Vigilant Init Error:", e);
  }
})();

// 2. High-Performance Scan Logic
function performScan() {
  if (!rules) return;

  // Reset State
  const newState = { keywords: [], links: [], forms: [], hidden: [], score: 100, details: { phishingKeywords: [], suspiciousLinks: [], sensitiveForms: [], hiddenElements: [] } };

  // -- A. Fast Text Scan --
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => {
      if (node.parentElement.closest('#vigilant-sidebar-root')) return NodeFilter.FILTER_REJECT;
      const tag = node.parentElement.tagName;
      if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEXTAREA') return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    }
  });

  let textNode;
  while ((textNode = walker.nextNode())) {
    const text = textNode.nodeValue;
    if (text.length < 3) continue;

    for (const keyword of rules.keywords) {
      if (text.toLowerCase().includes(keyword.toLowerCase())) {
        const regex = new RegExp(`\\b${escapeRegExp(keyword)}\\b`, 'i');
        if (regex.test(text)) {
          if (!textNode.parentElement.classList.contains('vigilant-highlight-text')) {
            highlightNode(textNode, keyword);
          }
          newState.keywords.push(keyword);
          newState.details.phishingKeywords.push(keyword);
          break;
        }
      }
    }
  }

  // -- B. Link Analysis --
  const links = document.querySelectorAll('a[href]');
  let suspiciousLinks = 0;
  links.forEach(link => {
    if (link.dataset.vigilantChecked) return;
    link.dataset.vigilantChecked = "true";

    const href = link.href;
    const text = link.innerText;

    let mismatch = false;
    try {
      if (text.includes('.') && text.length < 40) {
        const textUrl = new URL(text.startsWith('http') ? text : 'http://' + text);
        const hrefUrl = new URL(href);
        if (textUrl.hostname.replace('www.', '') !== hrefUrl.hostname.replace('www.', '')) {
          mismatch = true;
        }
      }
    } catch (e) { }

    if (mismatch) {
      link.style.borderBottom = "2px dashed red";
      newState.links.push({ type: "Mismatch", url: href });
      newState.details.suspiciousLinks.push({ reason: "Mismatch", url: href });
      suspiciousLinks++;
    }

    if (rules.suspiciousTLDs.some(tld => href.includes(tld))) {
      link.style.color = "red";
      link.style.fontWeight = "bold";
      newState.links.push({ type: "Bad TLD", url: href });
      newState.details.suspiciousLinks.push({ reason: "Bad TLD", url: href });
      suspiciousLinks++;
    }
  });

  // -- C. Form Analysis --
  document.querySelectorAll('input').forEach(input => {
    const name = (input.name || '').toLowerCase();
    if (input.type === 'password' || rules.sensitiveData.some(d => name.includes(d))) {
      if (window.location.protocol === 'http:') {
        input.style.border = "2px solid red";
        newState.forms.push("Insecure Form (HTTP)");
        newState.details.sensitiveForms.push("Insecure (HTTP)");
      }
      if (rules.sensitiveData.some(d => name.includes(d))) {
        newState.forms.push("Sensitive Request: " + name);
        newState.details.sensitiveForms.push("Sensitive: " + name);
      }
    }
  });

  // Score Calc
  let detectedCount = newState.keywords.length + newState.links.length + newState.forms.length;
  newState.score = Math.max(0, 100 - (detectedCount * 10));

  // Update UI
  threatState = newState;
  updateSidebar();

  // Notify Background for Auto-Report
  chrome.runtime.sendMessage({
    action: "updateStatus",
    data: {
      threats: detectedCount,
      score: newState.score,
      details: newState.details
    }
  });
}

// 3. Sidebar UI
function createSidebar() {
  if (document.getElementById('vigilant-sidebar-root')) return;

  const root = document.createElement('div');
  root.id = 'vigilant-sidebar-root';
  root.innerHTML = `
        <div id="vigilant-sidebar-toggle">
            <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z"/></svg>
        </div>
        <div class="v-sidebar-header">
            <div class="v-sidebar-title">
                 🛡️ VIGILANT <span style="color:#3b82f6">OPS</span>
            </div>
            <div class="v-scan-status">
                <div class="v-status-dot" id="v-status-dot"></div>
                <span id="v-status-text">Active Monitoring</span>
            </div>
        </div>
        <div class="v-sidebar-content" id="v-sidebar-list">
        </div>
        
        <!-- AUTOMATED REPORT SECTION -->
        <div id="v-report-status" style="display:none; background:rgba(239, 68, 68, 0.1); border-top:1px solid #ef4444; padding:15px;">
            <div style="font-size:10px; color:#ef4444; font-weight:bold; letter-spacing:1px; margin-bottom:5px;">AUTOMATED ACTION</div>
            <div style="font-size:12px; color:#fff;">Report <span id="v-report-id"></span> Filed.</div>
            <div style="font-size:10px; color:#94a3b8;">Sent to CyberWatch Fraud DB</div>
        </div>

        <div class="v-sidebar-footer">
            <div class="v-score-label">THREAT SCORE</div>
            <div class="v-score-val" id="v-score-display">100</div>
        </div>
    `;

  document.body.appendChild(root);

  const toggle = root.querySelector('#vigilant-sidebar-toggle');
  toggle.addEventListener('click', () => root.classList.toggle('visible'));

  sidebarUI = {
    root,
    list: root.querySelector('#v-sidebar-list'),
    score: root.querySelector('#v-score-display'),
    toggle,
    reportPanel: root.querySelector('#v-report-status'),
    reportId: root.querySelector('#v-report-id')
  };
}

function updateSidebar() {
  if (!sidebarUI) return;

  sidebarUI.score.innerText = threatState.score;
  sidebarUI.score.className = 'v-score-val ' + (threatState.score < 50 ? 'danger' : threatState.score < 80 ? 'warn' : '');

  const list = sidebarUI.list;
  list.innerHTML = '';

  if (threatState.score === 100) {
    list.innerHTML = `<div style="text-align:center; padding:20px; color:#64748b;">No active threats.</div>`;
    sidebarUI.toggle.classList.remove('danger-state');
  } else {
    sidebarUI.toggle.classList.add('danger-state');
    // Render Threats
    [...new Set(threatState.keywords)].forEach(k => {
      list.innerHTML += `<div class="v-threat-card high">⚠️ Keyword: <strong>"${k}"</strong></div>`;
    });
    threatState.links.forEach(l => {
      list.innerHTML += `<div class="v-threat-card medium">🔗 ${l.type}</div>`;
    });
    threatState.forms.forEach(f => {
      list.innerHTML += `<div class="v-threat-card high">🔒 ${f}</div>`;
    });
  }

  // SHOW REPORT STATUS
  if (currentReportId) {
    sidebarUI.reportPanel.style.display = 'block';
    sidebarUI.reportId.innerText = currentReportId;
  } else {
    sidebarUI.reportPanel.style.display = 'none';
  }
}

function highlightNode(node, term) {
  if (node.parentElement.classList.contains('vigilant-highlight-text')) return;
  const span = document.createElement('span');
  span.className = 'vigilant-highlight-wrapper';
  span.innerHTML = node.nodeValue.replace(new RegExp(`(${escapeRegExp(term)})`, 'gi'), '<span class="vigilant-highlight-text">$1</span>');
  node.parentElement.replaceChild(span, node);
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
