SafeNest balancing patch

Replace these files in your project:
- backend-api/app.py
- content.js
- background.js

What changed:
- Better @ handling: only serious when @ appears in URL authority/userinfo area.
- Better iframe handling: iframe count alone is weak; hidden/cross-origin iframes matter more.
- Trusted-domain balancing: trusted domains reduce weak penalties but do not bypass strong red flags.
- Cleaner explanation generation: strong red flags and weak signals separated internally.
- Risk labels remain: Safe < 30, Suspicious 30-59, High Risk >= 60.
- Cache key upgraded from scan:v3 to scan:v4 to avoid old cached results.

After replacing:
1. Reload the extension.
2. Redeploy Render for backend-api/app.py.
3. Clear extension cache once:
   chrome.storage.local.clear(() => console.log('SafeNest cache cleared'));
