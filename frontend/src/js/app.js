// Get base path from current location (handles API Gateway stage prefix)
function getBasePath() {
    const path = window.location.pathname;
    // Match /prod or /prod/ and ensure trailing slash
    const match = path.match(/^\/[^\/]+/);
    return match ? match[0] + '/' : '/';
}

async function fetchUserInfo() {
    try {
        const basePath = getBasePath();
        const response = await fetch(`${basePath}api/auth/user`, { credentials: 'include' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        // Build with textContent rather than innerHTML: these values come from
        // the user's Cognito profile, and an address containing markup would
        // otherwise be parsed as HTML.
        const welcome = document.createElement('p');
        const strong = document.createElement('strong');
        strong.textContent = `Welcome, ${data.email}`;
        welcome.appendChild(strong);

        const userId = document.createElement('p');
        userId.textContent = `User ID: ${data.userId}`;

        const userInfo = document.getElementById('user-info');
        userInfo.replaceChildren(welcome, userId);

        document.getElementById('response-data').textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

function showError(message) {
    const paragraph = document.createElement('p');
    paragraph.className = 'error';
    paragraph.textContent = message;
    document.getElementById('user-info').replaceChildren(paragraph);
    document.getElementById('response-data').textContent = message;
}

async function logout() {
    try {
        const basePath = getBasePath();
        const logoutBtn = document.getElementById('logout-btn');

        // Disable button and show loading state
        logoutBtn.disabled = true;
        logoutBtn.textContent = 'Logging out...';

        const response = await fetch(`${basePath}api/auth/logout`, {
            method: 'POST',
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`Logout failed: HTTP ${response.status}`);
        }

        // Redirect to home page (will trigger re-authentication)
        window.location.href = basePath;
    } catch (error) {
        console.error('Logout error:', error);
        alert(`Logout failed: ${error.message}`);

        // Re-enable button on error
        const logoutBtn = document.getElementById('logout-btn');
        logoutBtn.disabled = false;
        logoutBtn.textContent = 'Logout';
    }
}

// Wired here rather than with an inline onclick attribute, which the page's
// Content-Security-Policy blocks.
document.getElementById('logout-btn').addEventListener('click', logout);

fetchUserInfo();
