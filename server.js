const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

// Configuration
const CONFIG = {
    sessionExpiry: 24 * 60 * 60 * 1000, // 24 hours
    maxLoginAttempts: 10,
    loginAttemptWindow: 2 * 60 * 1000, // 5 minutes
    cleanupInterval: 60 * 60 * 1000, // 1 hour
    passwordVersion: 1, // INCREMENT THIS to invalidate all sessions on next restart
    maxSessions: 10,
    sessionWarningThreshold: 15, // Show warning when sessions >= this number
    enableIPBinding: false, // Set to true for production security
    production: process.env.NODE_ENV === 'production' // Auto-detect production
};

// User storage
// Default user - configure via environment variables
const DEFAULT_USER = process.env.DEFAULT_USER || 'lyco';
const DEFAULT_PASS = process.env.DEFAULT_PASS || 'lyco123';

// Default admin - change password for security
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

const users = new Map([
    [DEFAULT_USER, { password: DEFAULT_PASS, name: '', role: 'user' }],
    [ADMIN_USER, { password: ADMIN_PASS, name: 'Administrator', role: 'admin' }],
]);

// Session storage
const sessions = new Map();
const loginAttempts = new Map();

// Generate secure session token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Get all active sessions count
function getActiveSessionsCount() {
    return sessions.size;
}

// Log session status (silent for production)
function logSessionStatus(action, sessionInfo = '') {
    const count = getActiveSessionsCount();
    // Session logging disabled for production deployment
}

// Clean old sessions periodically
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [token, session] of sessions) {
        if (now - session.createdAt > CONFIG.sessionExpiry) {
            sessions.delete(token);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        logSessionStatus('EXPIRED', `cleaned: ${cleaned}`);
    }
}, CONFIG.cleanupInterval);

// Normalize IP address (handle IPv6 localhost ::1 vs IPv4 127.0.0.1)
function normalizeIP(ip) {
    if (!ip) return 'unknown';
    // ::1 is IPv6 localhost, treat as same as 127.0.0.1
    if (ip === '::1' || ip === '127.0.0.1' || ip === '::ffff:127.0.0.1') {
        return '127.0.0.1';
    }
    return ip;
}

// Get session from cookie header with IP and User-Agent validation
function getSession(cookieHeader, clientIP, userAgent) {
    if (!cookieHeader) return null;

    const cookies = Object.fromEntries(
        cookieHeader.split(';').map(c => {
            const [k, v] = c.trim().split('=');
            return [k, v];
        })
    );

    const sessionToken = cookies['session'];
    if (!sessionToken) return null;

    const session = sessions.get(sessionToken);
    if (!session) return null;

    // Check password version - invalidate if password changed
    if (session.passwordVersion !== CONFIG.passwordVersion) {
        sessions.delete(sessionToken);
        return null;
    }

    // Check if session expired
    if (Date.now() - session.createdAt > CONFIG.sessionExpiry) {
        sessions.delete(sessionToken);
        return null;
    }

    // IP binding - only check if enabled in config
    if (CONFIG.enableIPBinding && normalizeIP(session.ip) !== normalizeIP(clientIP)) {
        sessions.delete(sessionToken);
        return null;
    }

    // User-Agent binding - invalidate if user agent changed significantly
    if (session.userAgent && userAgent && !session.userAgent.includes(userAgent.substring(0, 50))) {
        sessions.delete(sessionToken);
        return null;
    }

    return session;
}

// Set cookie header
function setSessionCookie(res, token) {
    const cookieOptions = [
        `Path=/`,
        `HttpOnly`,
        `Max-Age=${CONFIG.sessionExpiry / 1000}`
    ];

    if (CONFIG.production) {
        cookieOptions.push('SameSite=None', 'Secure');
    } else {
        cookieOptions.push('SameSite=Lax');
    }

    res.setHeader('Set-Cookie', [`session=${token}; ${cookieOptions.join('; ')}`]);
}

// Clear session cookie
function clearSessionCookie(res) {
    const cookieOptions = [
        'Path=/',
        'HttpOnly',
        'Max-Age=0'
    ];

    if (CONFIG.production) {
        cookieOptions.push('SameSite=None', 'Secure');
    } else {
        cookieOptions.push('SameSite=Lax');
    }

    res.setHeader('Set-Cookie', [`session=; ${cookieOptions.join('; ')}`]);
}

// API proxy handler
function makeApiRequest(service, cookieId) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify({ cookieId, service });

        const options = {
            hostname: 'acct-gen.vercel.app',
            port: 443,
            path: '/api/nftoken',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': '*/*',
                'Origin': 'https://acct-gen.vercel.app',
                'Referer': 'https://acct-gen.vercel.app/dashboard/user/generate',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        };

        options.headers['content-length'] = Buffer.byteLength(payload);

        const req = https.request(options, (res) => {
            const zlib = require('zlib');
            const encoding = res.headers['content-encoding'];
            let data = res;

            if (encoding === 'gzip') {
                data = res.pipe(zlib.createGunzip());
            } else if (encoding === 'deflate') {
                data = res.pipe(zlib.createInflate());
            } else if (encoding === 'br') {
                data = res.pipe(zlib.createBrotliDecompress());
            }

            let responseData = '';
            data.on('data', (chunk) => { responseData += chunk; });
            data.on('end', () => {
                try {
                    resolve(JSON.parse(responseData));
                } catch (e) {
                    resolve({ raw: responseData });
                }
            });
        });

        req.on('error', reject);
        req.setTimeout(15000, () => { req.destroy(); reject(new Error('Timeout')); });
        req.write(payload);
        req.end();
    });
}

// Create server
const server = http.createServer(async (req, res) => {
    // CORS headers
    // CORS - allow the origin that made the request
    const origin = req.headers.origin || '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const url = req.url.split('?')[0];

    // Get real client IP (handle proxies)
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.socket?.remoteAddress
        || 'unknown';

    // Serve static files
    if (url === '/' || url === '/index.html' || url === '/browser.html') {
        const filePath = path.join(__dirname, 'browser.html');
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end('Error loading file');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(data);
        });
        return;
    }

    // Serve admin.html
    if (url === '/admin.html' || url === '/admin') {
        const filePath = path.join(__dirname, 'admin.html');
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end('Error loading file');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(data);
        });
        return;
    }

    // API Routes
    const apiRoutes = {
        '/api/login': { method: 'POST', auth: false },
        '/api/logout': { method: 'POST', auth: true },
        '/api/auth': { method: 'GET', auth: false },
        '/api/admin-auth': { method: 'GET', auth: false },
        '/api/proxy': { method: 'POST', auth: true },
        '/api/sessions': { method: 'GET', auth: true, adminOnly: true },
        '/api/sessions/kill': { method: 'POST', auth: true, adminOnly: true },
        '/api/users': { method: 'GET', auth: true, adminOnly: true },
        '/api/users/create': { method: 'POST', auth: true, adminOnly: true },
        '/api/users/delete': { method: 'POST', auth: true, adminOnly: true },
        '/api/users/username/role': { method: 'PUT', auth: true, adminOnly: true },
        '/api/users/username/password': { method: 'PUT', auth: true, adminOnly: true },
        '/api/users/username/username': { method: 'PUT', auth: true, adminOnly: true }
    };

    // Handle dynamic routes
    let route = apiRoutes[url];

    if (!route) {
        if (url.match(/^\/api\/users\/[^/]+\/role$/)) {
            route = apiRoutes['/api/users/username/role'];
        } else if (url.match(/^\/api\/users\/[^/]+\/password$/)) {
            route = apiRoutes['/api/users/username/password'];
        } else if (url.match(/^\/api\/users\/[^/]+\/username$/)) {
            route = apiRoutes['/api/users/username/username'];
        } else if (url.match(/^\/api\/users\/delete$/)) {
            route = apiRoutes['/api/users/delete'];
        } else if (url.match(/^\/api\/users\/create$/)) {
            route = apiRoutes['/api/users/create'];
        }
    }

    // 404 for unknown routes
    if (!route) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
        return;
    }

    // Method check
    if (req.method !== route.method) {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Method not allowed' }));
        return;
    }

    // Auth check for protected routes
    const session = getSession(req.headers.cookie, clientIP, req.headers['user-agent']);

    if (route.auth && !session) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized', code: 'NO_SESSION' }));
        return;
    }

    // Admin-only check
    if (route.adminOnly && session && session.role !== 'admin') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Admin access required', code: 'ADMIN_ONLY' }));
        return;
    }

    // Get request body
    const getBody = () => {
        return new Promise((resolve, reject) => {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => resolve(body));
            req.on('error', reject);
        });
    };

    // Handle routes
    try {
        switch (url) {
            case '/api/login': {
                const body = await getBody();
                const { username, password, name } = JSON.parse(body);

                // Validate input
                if (!username || !password) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Username and password required' }));
                    return;
                }

                // Rate limiting check
                const attempts = loginAttempts.get(username) || { count: 0, firstAttempt: Date.now() };
                if (attempts.count >= CONFIG.maxLoginAttempts) {
                    if (Date.now() - attempts.firstAttempt < CONFIG.loginAttemptWindow) {
                        res.writeHead(429, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'Too many login attempts. Try again later.' }));
                        return;
                    }
                    // Reset attempts after window
                    attempts.count = 0;
                    attempts.firstAttempt = Date.now();
                }

                // Check credentials
                const user = users.get(username);
                if (!user || user.password !== password) {
                    // Increment failed attempts
                    attempts.count++;
                    loginAttempts.set(username, attempts);

                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Invalid credentials' }));
                    return;
                }

                // Clear failed attempts on success
                loginAttempts.delete(username);

                // 🚨 SESSION LIMIT CHECK - REJECT if full (check FIRST, before needing name)
                const currentSessions = getActiveSessionsCount();
                if (currentSessions >= CONFIG.maxSessions) {
                    logSessionStatus('REJECTED', `${username} - limit: ${CONFIG.maxSessions}`);
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Server at maximum capacity. Please try again later.' }));
                    return;
                }

                // If no name provided, require user to enter name first (no session created)
                if (!name) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, needsName: true, name: username, role: user.role }));
                    return;
                }

                // Create session with password version and security bindings
                const sessionToken = generateToken();
                const displayName = name;

                sessions.set(sessionToken, {
                    username: username,
                    name: displayName,
                    role: user.role,
                    createdAt: Date.now(),
                    ip: normalizeIP(clientIP),
                    userAgent: req.headers['user-agent'],
                    passwordVersion: CONFIG.passwordVersion
                });

                // Log login
                logSessionStatus('LOGIN', username);

                setSessionCookie(res, sessionToken);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    name: displayName,
                    role: user.role,
                    token: sessionToken  // Return token in response for API authorization
                }));
                break;
            }

            case '/api/logout': {
                const cookie = req.headers.cookie;
                if (cookie) {
                    const cookies = Object.fromEntries(
                        cookie.split(';').map(c => {
                            const [k, v] = c.trim().split('=');
                            return [k, v];
                        })
                    );
                    if (cookies['session']) {
                        const session = sessions.get(cookies['session']);
                        sessions.delete(cookies['session']);
                        logSessionStatus('LOGOUT', session?.username || 'unknown');
                    }
                }

                clearSessionCookie(res);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
                break;
            }

            case '/api/auth': {
                if (session) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        authenticated: true,
                        name: session.name,
                        role: session.role
                    }));
                } else {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ authenticated: false }));
                }
                break;
            }

            case '/api/proxy': {
                const body = await getBody();
                const { service, cookieId } = JSON.parse(body);

                if (!service) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Service required' }));
                    return;
                }

                const result = await makeApiRequest(service, cookieId || 'random');
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
                break;
            }

            // ADMIN: Get all sessions
            case '/api/sessions': {
                const allSessions = [];
                for (const [token, s] of sessions) {
                    allSessions.push({
                        token: token,
                        username: s.username,
                        name: s.name,
                        role: s.role,
                        ip: s.ip,
                        createdAt: s.createdAt
                    });
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    sessions: allSessions,
                    passwordVersion: CONFIG.passwordVersion
                }));
                break;
            }

            // ADMIN: Kill a session
            case '/api/sessions/kill': {
                const body = await getBody();
                const { token } = JSON.parse(body);

                if (!token) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Token required' }));
                    return;
                }

                if (sessions.has(token)) {
                    const s = sessions.get(token);
                    const targetUsername = s.username;

                    // Kill only this specific session (by token)
                    sessions.delete(token);

                    logSessionStatus('KILLED', `by admin: ${session.username}, target: ${targetUsername}`);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Session not found' }));
                }
                break;
            }

            // ADMIN: Get all users
            case '/api/users': {
                const allUsers = [];
                for (const [username, u] of users) {
                    allUsers.push({
                        username: username,
                        name: u.name,
                        role: u.role
                    });
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ users: allUsers }));
                break;
            }

            // ADMIN: Create new user
            case '/api/users/create': {
                const body = await getBody();
                const { username, password, role, name } = JSON.parse(body);

                if (!username || !password) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Username and password required' }));
                    return;
                }

                if (users.has(username)) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Username already exists' }));
                    return;
                }

                users.set(username, {
                    password: password,
                    name: name || '',
                    role: role || 'user'
                });

                logSessionStatus('USER CREATED', `by admin: ${username}`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, username, role: role || 'user' }));
                break;
            }

            // ADMIN: Delete user
            case '/api/users/delete': {
                const body = await getBody();
                const { username } = JSON.parse(body);

                if (!username) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Username required' }));
                    return;
                }

                if (!users.has(username)) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'User not found' }));
                    return;
                }

                // Prevent admin from deleting themselves
                if (username === session.username) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Cannot delete your own account' }));
                    return;
                }

                users.delete(username);

                // Also kill all sessions for this user
                for (const [token, s] of sessions) {
                    if (s.username === username) {
                        sessions.delete(token);
                    }
                }

                logSessionStatus('USER DELETED', `by admin: ${username}`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, username }));
                break;
            }

            // ADMIN: Change user role (URL: /api/users/username/role)
            case '/api/users/username/role': {
                // Parse username from URL: /api/users/lyco/role -> lyco
                const match = url.match(/^\/api\/users\/([^/]+)\/role$/);
                if (!match) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Invalid URL format' }));
                    return;
                }
                const targetUsername = match[1];

                const body = await getBody();
                const { role } = JSON.parse(body);

                if (!role || !['admin', 'user'].includes(role)) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Role must be admin or user' }));
                    return;
                }

                if (!users.has(targetUsername)) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'User not found' }));
                    return;
                }

                const userData = users.get(targetUsername);
                userData.role = role;
                users.set(targetUsername, userData);

                logSessionStatus('ROLE CHANGE', `by admin: ${targetUsername} -> ${role}`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, username: targetUsername, role: role }));
                break;
            }

            // ADMIN: Change user password
            case '/api/users/username/password': {
                const match = url.match(/^\/api\/users\/([^/]+)\/password$/);
                if (!match) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Invalid URL format' }));
                    return;
                }
                const targetUsername = match[1];

                const body = await getBody();
                const { password } = JSON.parse(body);

                if (!password || password.length < 3) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Password must be at least 3 characters' }));
                    return;
                }

                if (!users.has(targetUsername)) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'User not found' }));
                    return;
                }

                const userData = users.get(targetUsername);
                const oldPass = userData.password;
                userData.password = password;
                users.set(targetUsername, userData);

                // Increment password version to invalidate all sessions
                CONFIG.passwordVersion++;

                logSessionStatus('PASSWORD CHANGE', `by admin: ${targetUsername}`);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, username: targetUsername, newVersion: CONFIG.passwordVersion }));
                break;
            }

            // ADMIN: Change username
            case '/api/users/username/username': {
                const match = url.match(/^\/api\/users\/([^/]+)\/username$/);
                if (!match) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Invalid URL format' }));
                    return;
                }
                const oldUsername = match[1];

                const body = await getBody();
                const { username } = JSON.parse(body);

                if (!username || username.length < 2) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Username must be at least 2 characters' }));
                    return;
                }

                if (users.has(username)) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Username already exists' }));
                    return;
                }

                if (!users.has(oldUsername)) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'User not found' }));
                    return;
                }

                const userData = users.get(oldUsername);
                users.delete(oldUsername);
                users.set(username, userData);

                logSessionStatus('USERNAME CHANGE', `by admin: ${oldUsername} -> ${username}`);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, oldUsername: oldUsername, newUsername: username }));
                break;
            }
        }
    } catch (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
    }
});

server.listen(PORT, () => {
    // Server started silently
    logSessionStatus('STARTUP', 'server started');
});
