LEDGERGUARD MANAGER LOGIN FIX — FRONTEND ONLY

Files to replace:
- templates/index.html
- static/script.js
- static/style.css

What this fixes:
- Shows the manager sign-in modal every time the dashboard is opened/refreshed.
- Clears any stale Flask session cookie by POSTing to /api/manager-logout at startup.
- The top-right Manager sign-in button opens the modal when logged out.
- Every Approve/Reject action opens manager authentication again, even if already signed in.
- After successful re-authentication, the originally selected approval/rejection continues.
- Failed login keeps the modal open and displays the server error.
- Adds a cache-busting version string to the CSS/JS URLs.

Backend compatibility:
Uses your existing endpoints: /api/manager-logout, /api/manager-login,
/api/session-status, /api/approve/<request_id>, and the dashboard APIs.
Does not change app.py, .env, ledgerguard.db, or the encryption key.

Install:
1. Back up your current templates/index.html and static folder.
2. Copy these three files into the matching locations in your LedgerGuard project.
3. Keep app.py, .env, and ledgerguard.db unchanged.
4. Restart Flask with: python app.py
5. Open http://127.0.0.1:5000 and press Ctrl+Shift+R.

Expected:
- Sign-in modal appears at startup.
- After sign-in, clicking Approve or Reject asks for manager credentials again.
- After successful authentication, that request is processed.
