#!/usr/bin/env node
// server.js - Lightweight test server for callbacks, webhooks, and forward auth
//
// Endpoints:
//   GET  /health              - Health check (200)
//   GET  /requests            - List recorded requests (JSON array)
//   DELETE /requests          - Clear recorded requests
//   GET  /requests/count      - Count of recorded requests
//   GET  /requests/last       - Last recorded request
//
//   POST /callback            - Record callback, return 200
//   POST /callback/*          - Record callback with path, return 200
//   PUT  /callback/*          - Record callback, return 200
//
//   GET  /auth/forward        - Forward auth endpoint
//                               Returns 200 if X-Auth-Token == "valid-token"
//                               Returns 401 otherwise
//                               Sets X-User-ID and X-User-Role on success
//
//   GET  /echo                - Echo request details as JSON
//   POST /echo                - Echo request details as JSON
//   *    /echo                - Echo request details as JSON
//
//   GET  /status/:code        - Return specified HTTP status code
//   GET  /delay/:ms           - Delay response by N milliseconds
//   POST /json                - Parse and re-emit JSON body
//   GET  /html                - Return sample HTML page
//   GET  /markdown            - Return sample Markdown
//   *    /slow-backend        - Simulates slow backend (3s delay, for fallback tests)
//   *    /fail                - Always returns 502 (for fallback tests)
//
// Usage:
//   node server.js [port]     - Default port: 18888
//
// Environment:
//   TEST_SERVER_PORT=18888

const http = require('http');
const url = require('url');

const PORT = parseInt(process.env.TEST_SERVER_PORT || process.argv[2] || '18888', 10);

// In-memory request log
let recordedRequests = [];
const MAX_RECORDED = 1000;

function recordRequest(req, body) {
    const entry = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        path: url.parse(req.url).pathname,
        headers: { ...req.headers },
        body: body || '',
        remoteAddress: req.socket.remoteAddress,
    };
    recordedRequests.push(entry);
    if (recordedRequests.length > MAX_RECORDED) {
        recordedRequests = recordedRequests.slice(-MAX_RECORDED);
    }
    return entry;
}

function readBody(req) {
    return new Promise((resolve) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    });
}

function sendJSON(res, statusCode, data) {
    const body = JSON.stringify(data, null, 2);
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
    });
    res.end(body);
}

const SAMPLE_HTML = `<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <!-- This is a comment that should be stripped -->
    <style>body { margin: 0; }</style>
</head>
<body>
    <h1>Hello World</h1>
    <p>This is a <strong>test</strong> page with <a href="https://example.com">a link</a>.</p>
    <script>console.log("test");</script>
</body>
</html>`;

const SAMPLE_MARKDOWN = `# Test Document

This is a **bold** and *italic* test.

## Section 2

- Item one
- Item two
- Item three

[Link text](https://example.com)

\`\`\`javascript
console.log("hello");
\`\`\`
`;

async function handleRequest(req, res) {
    const parsed = url.parse(req.url, true);
    const path = parsed.pathname;
    const method = req.method;
    const body = await readBody(req);

    // --- Health check ---
    if (path === '/health') {
        return sendJSON(res, 200, { status: 'ok' });
    }

    // --- Recorded requests management ---
    if (path === '/requests' && method === 'GET') {
        return sendJSON(res, 200, recordedRequests);
    }
    if (path === '/requests' && method === 'DELETE') {
        const count = recordedRequests.length;
        recordedRequests = [];
        return sendJSON(res, 200, { cleared: count });
    }
    if (path === '/requests/count' && method === 'GET') {
        return sendJSON(res, 200, { count: recordedRequests.length });
    }
    if (path === '/requests/last' && method === 'GET') {
        const last = recordedRequests[recordedRequests.length - 1] || null;
        return sendJSON(res, 200, last);
    }

    // --- Callback recording ---
    if (path.startsWith('/callback')) {
        const entry = recordRequest(req, body);
        return sendJSON(res, 200, { recorded: true, id: recordedRequests.length, entry });
    }

    // --- Forward auth ---
    if (path === '/auth/forward') {
        const token = req.headers['x-auth-token'] || '';
        if (token === 'valid-token') {
            res.writeHead(200, {
                'Content-Type': 'text/plain',
                'X-User-ID': 'user-42',
                'X-User-Role': 'admin',
            });
            return res.end('OK');
        }
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        return res.end('Unauthorized');
    }

    // --- Echo ---
    if (path.startsWith('/echo')) {
        const echoData = {
            method,
            path,
            query: parsed.query,
            headers: { ...req.headers },
            body,
            url: req.url,
        };
        return sendJSON(res, 200, echoData);
    }

    // --- Status code ---
    const statusMatch = path.match(/^\/status\/(\d+)$/);
    if (statusMatch) {
        const code = parseInt(statusMatch[1], 10);
        return sendJSON(res, code, { status: code, message: http.STATUS_CODES[code] || 'Unknown' });
    }

    // --- Delay ---
    const delayMatch = path.match(/^\/delay\/(\d+)$/);
    if (delayMatch) {
        const ms = parseInt(delayMatch[1], 10);
        await new Promise((resolve) => setTimeout(resolve, ms));
        return sendJSON(res, 200, { delayed: ms });
    }

    // --- JSON echo ---
    if (path === '/json' && method === 'POST') {
        try {
            const parsed = JSON.parse(body);
            return sendJSON(res, 200, { received: parsed });
        } catch {
            return sendJSON(res, 400, { error: 'Invalid JSON', body });
        }
    }

    // --- HTML sample ---
    if (path === '/html') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(SAMPLE_HTML);
    }

    // --- Markdown sample ---
    if (path === '/markdown') {
        res.writeHead(200, { 'Content-Type': 'text/markdown' });
        return res.end(SAMPLE_MARKDOWN);
    }

    // --- Slow backend (for fallback/timeout tests) ---
    if (path === '/slow-backend') {
        await new Promise((resolve) => setTimeout(resolve, 3000));
        return sendJSON(res, 200, { delayed: 3000 });
    }

    // --- Always fail (for fallback tests) ---
    if (path === '/fail') {
        return sendJSON(res, 502, { error: 'Simulated backend failure' });
    }

    // --- Default: serve echo for any unmatched path ---
    const defaultData = {
        method, path, query: parsed.query,
        headers: { ...req.headers }, body, url: req.url,
    };
    sendJSON(res, 200, defaultData);
}

const server = http.createServer(handleRequest);

server.listen(PORT, '127.0.0.1', () => {
    console.log(`Test server listening on http://127.0.0.1:${PORT}`);
    console.log('Endpoints: /health /echo /callback /auth/forward /requests /status/:code /delay/:ms /html /markdown');
});

// Graceful shutdown
process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT', () => { server.close(); process.exit(0); });
