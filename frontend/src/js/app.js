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
        document.getElementById('user-info').innerHTML = `
            <p><strong>Welcome, ${data.email}</strong></p>
            <p>User ID: ${data.userId}</p>
        `;
        document.getElementById('response-data').textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        document.getElementById('user-info').innerHTML = `<p style="color: #c0392b;">Error: ${error.message}</p>`;
        document.getElementById('response-data').textContent = `Error: ${error.message}`;
    }
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

fetchUserInfo();
