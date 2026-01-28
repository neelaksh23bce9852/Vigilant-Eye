# Vigilant Eye Extension

A real-time cybersecurity browser extension detecting scams, phishing attempts, and sensitive data requests.

## Installation

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer Mode** in the top right corner.
3. Click **Load unpacked**.
4. Select this `vigilant-eye-extension` directory.
5. The extension is now active.

## Testing

1. Open the file `demo-test-page.html` in Chrome.
2. Observe the following:
   - **Highlights**: Scam keywords like "urgent", "verify account" are highlighted in yellow.
   - **Tooltips**: Hover over highlights to see warnings.
   - **Form Warnings**: Input fields asking for "Password" or "SSN" have red borders.
   - **Banner**: An alert banner appears at the top of the page.
3. Click the extension icon in the toolbar to see the **Safety Dashboard**.

## Files to Note

- `rules/scamRules.json`: Configure the keywords and patterns here.
- `content/content.js`: Main logic for scanning the page.
- `popup/`: Code for the extension popup UI.

## Note on Icons

If you see missing icon errors, please place a PNG file named `icon128.png`, `icon48.png`, and `icon16.png` in the `icons/` folder.
