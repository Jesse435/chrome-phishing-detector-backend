SafeNest scoring patch

Replace backend-api/app.py with this patched file.

What changed:
- Added small trusted-root domain handling to reduce false positives on major legitimate sites.
- Trusted domains are NOT blindly marked safe. They are still analyzed.
- Weak signals like long URLs, account/payment keywords, login forms, iframes, and external links are weighted lower on trusted domains.
- Strong red flags still count: IP address URLs, missing HTTPS, @ symbol, brand impersonation.
- Added brand impersonation detection for domains like amaz0n-login.com or amazon-secure.xyz.
- Added final false-positive cap for verified trusted roots when no strong red flags exist.

After replacing:
1. Commit and push.
2. Redeploy Render.
3. Clear extension cache once with chrome.storage.local.clear().
