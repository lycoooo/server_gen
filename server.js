const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;

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
                'authority': 'acct-gen.vercel.app',
                'method': 'POST',
                'path': '/api/nftoken',
                'scheme': 'https',
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br, zstd',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/json',
                'cookie': 'sb-lcokreopfsbobvxqfteb-auth-token=base64-eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1Wa05HUTNNVEkyTFRKbVpHTXROR1UzTnkwNE9UZzRMVGt5WVdRNVpqQTBOVGs1WXlJc0luUjVjQ0k2SWtwWFZDSjkuZXlKcGMzTWlPaUpvZEhSd2N6b3ZMMnhqYjJ0eVpXOXdabk5pYjJKMmVIRm1kR1ZpTG5OMWNHRmlZWE5sTG1OdkwyRjFkR2d2ZGpFaUxDSnpkV0lpT2lJeE0yVmpZV1JqWXkxaU4yRmtMVFJtTnpRdE9EQmxZUzFsWXpGaFpXTmlZVFpsTURRaUxDSmhkV1FpT2lKaGRYUm9aVzUwYVdOaGRHVmtJaXdpWlhod0lqb3hOemd5TkRrd016STRMQ0pwWVhRaU9qRTNPREkwT0RZM01qZ3NJbVZ0WVdsc0lqb2ljR2hBWm5KbFpTNWpiMjBpTENKd2FHOXVaU0k2SWlJc0ltRndjRjl0WlhSaFpHRjBZU0k2ZXlKd2NtOTJhV1JsY2lJNkltVnRZV2xzSWl3aWNISnZkbWxrWlhKeklqcGJJbVZ0WVdsc0lsMTlMQ0oxYzJWeVgyMWxkR0ZrWVhSaElqcDdJbVZ0WVdsc1gzWmxjbWxtYVdWa0lqcDBjblZsTENKeWIyeGxJam9pZFhObGNpSjlMQ0p5YjJ4bElqb2lZWFYwYUdWdWRHbGpZWFJsWkNJc0ltRmhiQ0k2SW1GaGJERWlMQ0poYlhJaU9sdDdJbTFsZEdodlpDSTZJbkJoYzNOM2IzSmtJaXdpZEdsdFpYTjBZVzF3SWpveE56Z3lORGd6TWpFMmZWMHNJbk5sYzNOcGIyNWZhV1FpT2lKaU0yWTVNR0psWmkxaE1UZzJMVFEyTXpjdFlqVTFNaTFpTlRrMU1XUXpNek13TXpFaUxDSnBjMTloYm05dWVXMXZkWE1pT21aaGJITmxmUS51cEdlXzlGMFhoQmNxdVFTV2tBektJRU9iaUdDZFdyMzNPMDlOVHg3TllXRmdhX0FFMW0zNUM5OEFJb1F3RHBidl9RUWZLVHV0QXpxUHpPQTE5WFdNUSIsInRva2VuX3R5cGUiOiJiZWFyZXIiLCJleHBpcmVzX2luIjozNjAwLCJleHBpcmVzX2F0IjoxNzgyNDkwMzI4LCJyZWZyZXNoX3Rva2VuIjoiNXBidndxdnA0aWdkIiwidXNlciI6eyJpZCI6IjEzZWNhZGNjLWI3YWQtNGY3NC04MGVhLWVjMWFlY2JhNmUwNCIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImVtYWlsIjoicGhAZnJlZS5jb20iLCJlbWFpbF9jb25maXJtZWRfYXQiOiIyMDI2LTA2LTI0VDE0OjQ3OjExLjM0MDAxNFoiLCJwaG9uZSI6IiIsImNvbmZpcm1lZF9hdCI6IjIwMjYtMDYtMjRUMTQ6NDc6MTEuMzQwMDE0WiIsImxhc3Rfc2lnbl9pbl9hdCI6IjIwMjYtMDYtMjZUMTU6MTA6MDAuNDU2MjIxWiIsImFwcF9tZXRhZGF0YSI6eyJwcm92aWRlciI6ImVtYWlsIiwicHJvdmlkZXJzIjpbImVtYWlsIl19LCJ1c2VyX21ldGFkYXRhIjp7ImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJyb2xlIjoidXNlciJ9LCJpZGVudGl0aWVzIjpbeyJpZGVudGl0eV9pZCI6ImI5ZmE1NDRjLTNlMjEtNGZkNS1iMjhlLTk5NTBlNTBkM2RjOCIsImlkIjoiMTNlY2FkY2MtYjdhZC00Zjc0LTgwZWEtZWMxYWVjYmE2ZTA0IiwidXNlcl9pZCI6IjEzZWNhZGNjLWI3YWQtNGY3NC04MGVhLWVjMWFlY2JhNmUwNCIsImlkZW50aXR5X2RhdGEiOnsiZW1haWwiOiJwaEBmcmUuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInN1YiI6IjEzZWNhZGNjLWI3YWQtNGY3NC04MGVhLWVjMWFlY2JhNmUwNCJ9LCJwcm92aWRlciI6ImVtYWlsIiwibGFzdF9zaWduX2luX2F0IjoiMjAyNi0wNi0yNFQxNDo0NzoxMS4zMzYxMzRaIiwiY3JlYXRlZF9hdCI6IjIwMjYtMDYtMjRUMTQ6NDc6MTEuMzM2MTk3WiIsInVwZGF0ZWRfYXQiOiIyMDI2LTA2LTI0VDE0OjQ3OjExLjMzNjE5N1oiLCJlbWFpbCI6InBoQGZyZWUuY29tIn1dLCJjcmVhdGVkX2F0IjoiMjAyNi0wNi0yNFQxNDo0NzoxMS4zMjgyNzdaIiwidXBkYXRlZF9hdCI6IjIwMjYtMDYtMjZUMTU6MTA6MDEuMDEzODA2WiIsImlzX2Fub255bW91cyI6ZmFsc2V9fQ',
                'origin': 'https://acct-gen.vercel.app',
                'priority': 'u=1, i',
                'referer': 'https://acct-gen.vercel.app/dashboard/user/generate',
                'sec-ch-ua': '"Microsoft Edge";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
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
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Serve browser.html
    if (req.url === '/' || req.url === '/index.html' || req.url === '/browser.html') {
        const filePath = path.join(__dirname, 'browser.html');
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end('Error loading browser.html');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
        return;
    }

    // API proxy endpoint
    if (req.url === '/api/proxy' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { service, cookieId } = JSON.parse(body);
                const result = await makeApiRequest(service, cookieId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
        return;
    }

    res.writeHead(404);
    res.end('Not Found');
});

server.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log('  🎉 Server running!');
    console.log('='.repeat(50));
    console.log('  Open your browser and go to:');
    console.log('  ➤ http://localhost:' + PORT);
    console.log('='.repeat(50));
    console.log('');
    console.log('  Press Ctrl+C to stop the server');
    console.log('');
});