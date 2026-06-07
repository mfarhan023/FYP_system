document.addEventListener('DOMContentLoaded', () => {
  // --- UI Elements ---
  const statusSection = document.getElementById('statusSection');
  const statusText = document.getElementById('statusText');
  
  const resultCard = document.getElementById('resultCard');
  const scanSource = document.getElementById('scanSource');
  const riskBadge = document.getElementById('riskBadge');

  const urlCount = document.getElementById('urlCount');
  const urlList = document.getElementById('urlList');
  const featureCount = document.getElementById('featureCount');
  const featureList = document.getElementById('featureList');
  
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsPanel = document.getElementById('settingsPanel');
  const apiUrlInput = document.getElementById('apiUrlInput');
  const saveSettingsBtn = document.getElementById('saveSettingsBtn');
  
  const rescanBtn = document.getElementById('rescanBtn');
  
  const errorCard = document.getElementById('errorCard');
  const errorText = document.getElementById('errorText');
  const retryBtn = document.getElementById('retryBtn');

  let activeTextContent = "";
  let activeTextSource = "";

  // --- Initialize Settings ---
  const DEFAULT_API_URL = 'http://localhost:5000';
  let apiUrl = localStorage.getItem('ezveri_api_url') || DEFAULT_API_URL;
  apiUrlInput.value = apiUrl;

  // --- Accordion Toggles ---
  document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
      const item = header.parentElement;
      item.classList.toggle('active');
    });
  });

  // --- Settings Panel Toggle ---
  settingsBtn.addEventListener('click', () => {
    settingsPanel.classList.toggle('hidden');
  });

  saveSettingsBtn.addEventListener('click', () => {
    let url = apiUrlInput.value.trim();
    if (url.endsWith('/')) {
      url = url.slice(0, -1);
    }
    if (!url) {
      url = DEFAULT_API_URL;
    }
    localStorage.setItem('ezveri_api_url', url);
    apiUrl = url;
    settingsPanel.classList.add('hidden');
    
    // Re-scan
    startAutomaticScan();
  });

  // --- Rescan & Retry ---
  rescanBtn.addEventListener('click', startAutomaticScan);
  retryBtn.addEventListener('click', startAutomaticScan);

  // --- Automatic Scan Entry Point ---
  startAutomaticScan();

  function startAutomaticScan() {
    showLoading("Scanning active tab...");
    
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (!tabs || tabs.length === 0) {
        showError("No active tab found.");
        return;
      }
      
      const tab = tabs[0];
      
      // Inject script into active tab to read its content
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: extractEmailOrPageText
      }, (results) => {
        if (chrome.runtime.lastError) {
          // scripting not allowed on pages like chrome:// or settings
          console.warn("Scripting failed: ", chrome.runtime.lastError.message);
          showError("Cannot access this page (restricted tab).");
          return;
        }

        if (results && results[0] && results[0].result) {
          const data = results[0].result;
          if (data.text && data.text.trim().length >= 5) {
            activeTextContent = data.text;
            activeTextSource = data.source;
            analyzeContent(data.text, data.source);
          } else {
            showError("No email content or readable page text detected.");
          }
        } else {
          showError("Failed to extract page text.");
        }
      });
    });
  }

  // --- Content Extraction Script (Runs inside the webpage) ---
  function extractEmailOrPageText() {
    // 1. Check for active selection first
    const selection = window.getSelection().toString().trim();
    if (selection) {
      return { text: selection, source: "Selected Text" };
    }

    const host = window.location.hostname.toLowerCase();
    let textContent = "";
    let sourceName = "Webpage Content";

    // 2. Gmail specific extraction
    if (host.includes('mail.google.com')) {
      const gmailBodies = Array.from(document.querySelectorAll('.a3s'));
      if (gmailBodies && gmailBodies.length > 0) {
        // Filter to only visible and non-empty email containers
        const activeContainers = gmailBodies.filter(el => el.offsetHeight > 0 && el.innerText.trim().length > 0);
        if (activeContainers.length > 0) {
          textContent = activeContainers.map(el => el.innerText).join('\n\n');
          sourceName = "Gmail Active Email";
        }
      }
    }

    // 3. Outlook specific extraction
    if (!textContent && (host.includes('outlook') || host.includes('office') || host.includes('live.com'))) {
      const outlookBody = document.querySelector('.ReadingPaneContainer') || 
                          document.querySelector('[role="main"]') || 
                          document.querySelector('.allowTextSelection');
      if (outlookBody) {
        textContent = outlookBody.innerText;
        sourceName = "Outlook Email Body";
      }
    }

    // 4. Fallback: general body text (limit to first 12,000 characters to prevent payload blowup)
    if (!textContent) {
      if (document.body) {
        textContent = document.body.innerText.slice(0, 12000);
      }
      sourceName = "Webpage Content";
    }

    return { text: textContent, source: sourceName };
  }


  // --- Core API Calling Logic ---
  function analyzeContent(text, source) {
    showLoading(`Analyzing ${source}...`);
    
    fetch(`${apiUrl}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email_content: text })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`Server returned code ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      if (data.status === 'success' && data.result) {
        renderResults(data.result, source);
      } else {
        throw new Error(data.message || 'Unknown backend error.');
      }
    })
    .catch(err => {
      console.error(err);
      showError(`API Error: ${err.message}. Make sure Flask is running at ${apiUrl}`);
    });
  }

  // --- UI Presentation ---
  function renderResults(res, source) {
    statusSection.classList.add('hidden');
    errorCard.classList.add('hidden');
    resultCard.classList.remove('hidden');

    scanSource.textContent = source;
    riskBadge.textContent = res.label;
    
    // Clear previous dynamic lists
    urlList.innerHTML = '';
    featureList.innerHTML = '';

    // 1. Label and Badge Style
    riskBadge.className = 'risk-badge'; // reset
    if (res.label === 'Confirmed Phishing') {
      riskBadge.classList.add('risk-phishing');
    } else if (res.label === 'Suspicious') {
      riskBadge.classList.add('risk-suspicious');
    } else {
      riskBadge.classList.add('risk-safe');
    }

    // 3. URLs Populating
    const evidence = res.url_evidence || [];
    urlCount.textContent = evidence.length;
    
    const urlsAccordion = document.getElementById('urlsAccordion');
    if (evidence.length === 0) {
      urlList.innerHTML = '<li style="color: var(--text-secondary); font-style: italic;">No URLs detected.</li>';
      urlsAccordion.classList.remove('active');
    } else {
      evidence.forEach(urlObj => {
        const li = document.createElement('li');
        li.className = 'url-item';
        
        let textLabel = 'Low Risk';
        let badgeClass = 'badge-safe';
        
        if (urlObj.blacklisted) {
          textLabel = 'Phishing';
          badgeClass = 'badge-phish';
        } else {
          const urlLower = urlObj.url.toLowerCase();
          
          let domain = "";
          try {
            const parsed = new URL(urlLower);
            domain = parsed.hostname;
          } catch (e) {
            const match = urlLower.match(/^(?:https?:\/\/)?(?:www\.)?([^\/\?#]+)/);
            domain = match ? match[1] : "";
          }
          
          const SUSPICIOUS_TLDS = [
            '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
            '.ru', '.cn', '.pw', '.top', '.club', '.info',
            '.biz', '.link', '.click', '.download', '.zip',
            '.id'
          ];
          
          const URL_SHORTENERS = [
            'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co',
            'buff.ly', 'is.gd', 'rb.gy', 'cutt.ly', 'tiny.cc',
            'shorturl.at', 'clck.ru', 'su.pr', 'adf.ly'
          ];
          
          const isInsecure = urlLower.startsWith('http://');
          const hasIp = /^(?:https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlLower);
          const isShortened = URL_SHORTENERS.some(s => urlLower.includes(s));
          const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld) || urlLower.includes(tld + '/'));
          const hyphenCount = (domain.split('/')[0] || '').split('-').length - 1;
          const hasHyphens = hyphenCount >= 2;
          const isTooLong = urlObj.url.length > 75;
          
          if (isInsecure || hasIp || isShortened || hasSuspiciousTld || hasHyphens || isTooLong) {
            textLabel = 'Suspicious';
            badgeClass = 'badge-suspicious';
          }
        }
        
        li.innerHTML = `
          <span style="font-weight: 500; word-break: break-all;">${urlObj.url}</span>
          <div class="url-meta" style="margin-top: 4px; display: flex; justify-content: flex-end;">
            <span class="badge ${badgeClass}">${textLabel}</span>
          </div>
        `;
        urlList.appendChild(li);
      });
      urlsAccordion.classList.add('active'); // auto open if URLs exist
    }

    // 4. Heuristics Populating
    const features = res.triggered_features || [];
    featureCount.textContent = features.length;
    
    const heuristicsAccordion = document.getElementById('heuristicsAccordion');
    if (features.length === 0) {
      featureList.innerHTML = '<li style="color: var(--text-secondary); font-style: italic;">No suspicious text features triggered.</li>';
      heuristicsAccordion.classList.remove('active');
    } else {
      features.forEach(feat => {
        const li = document.createElement('li');
        li.style.display = 'flex';
        li.style.alignItems = 'flex-start';
        li.style.gap = '6px';
        li.style.width = '100%';
        li.style.padding = '6px 0';
        li.style.borderBottom = '1px solid var(--border-color)';
        
        let headerText = "";
        
        if (typeof feat === 'object' && feat !== null) {
          let evidenceText = "";
          if (feat.evidence && Array.isArray(feat.evidence) && feat.evidence.length > 0) {
            evidenceText = ` <span style="font-weight: normal; color: var(--text-secondary); font-style: italic;">(${feat.evidence.map(item => `"${item}"`).join(', ')})</span>`;
          }
          headerText = `${feat.feature_name}${evidenceText}`;
        } else {
          headerText = feat;
        }
        
        li.innerHTML = `
          <span style="color: var(--color-suspicious); font-weight: bold; font-size: 14px; line-height: 1.2;">•</span>
          <span style="font-weight: 500; color: var(--text-primary); line-height: 1.4; word-break: break-word;">${headerText}</span>
        `;
        featureList.appendChild(li);
      });
      heuristicsAccordion.classList.add('active'); // auto open if features exist
    }
  }

  function showLoading(msg) {
    statusSection.classList.remove('hidden');
    resultCard.classList.add('hidden');
    errorCard.classList.add('hidden');
    statusText.textContent = msg;
  }

  function showError(msg) {
    statusSection.classList.add('hidden');
    resultCard.classList.add('hidden');
    errorCard.classList.remove('hidden');
    errorText.textContent = msg;
  }
});
