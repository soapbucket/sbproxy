#!/usr/bin/env node
// mock-ai.js - Mock OpenAI-compatible API server for AI gateway testing
//
// Endpoints:
//   POST /v1/chat/completions   - Chat completions (streaming + non-streaming)
//   GET  /v1/models             - List available models
//   POST /v1/embeddings         - Text embeddings (mock)
//
// Special behaviors:
//   - model "error-model"       -> returns 500
//   - model "timeout-model"     -> delays 10s then responds
//   - model "rate-limited"      -> returns 429
//   - message containing "SSN 123-45-6789" -> PII test content
//   - message containing "JAILBREAK" -> jailbreak test content
//   - Header X-Fail: true       -> returns 502 (for failover tests)
//   - Header X-Delay-Ms: N      -> delays N ms
//
// Usage:
//   node mock-ai.js [port]      - Default port: 18889
//
// The server ID is returned in responses so you can verify which
// mock server handled the request (for multi-provider routing tests).

const http = require('http');
const url = require('url');

const PORT = parseInt(process.env.MOCK_AI_PORT || process.argv[2] || '18889', 10);
const SERVER_ID = process.env.MOCK_AI_ID || `mock-ai-${PORT}`;

const MODELS = [
    { id: 'gpt-4o-mini', owned_by: 'openai' },
    { id: 'gpt-4o', owned_by: 'openai' },
    { id: 'gpt-4', owned_by: 'openai' },
    { id: 'gpt-3.5-turbo', owned_by: 'openai' },
    { id: 'claude-3-sonnet', owned_by: 'anthropic' },
    { id: 'error-model', owned_by: 'test' },
    { id: 'timeout-model', owned_by: 'test' },
    { id: 'rate-limited', owned_by: 'test' },
];

let requestCount = 0;

function readBody(req) {
    return new Promise((resolve) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    });
}

function sendJSON(res, statusCode, data) {
    const body = JSON.stringify(data);
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'X-Mock-Server': SERVER_ID,
        'X-Request-Count': String(++requestCount),
    });
    res.end(body);
}

function sendSSE(res, chunks) {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Mock-Server': SERVER_ID,
    });

    let i = 0;
    const interval = setInterval(() => {
        if (i < chunks.length) {
            res.write(`data: ${JSON.stringify(chunks[i])}\n\n`);
            i++;
        } else {
            res.write('data: [DONE]\n\n');
            clearInterval(interval);
            res.end();
        }
    }, 10);
}

function makeCompletion(model, content, promptTokens) {
    const completionTokens = Math.ceil(content.length / 4);
    return {
        id: `chatcmpl-mock-${Date.now()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: model,
        choices: [{
            index: 0,
            message: { role: 'assistant', content },
            finish_reason: 'stop',
        }],
        usage: {
            prompt_tokens: promptTokens || 10,
            completion_tokens: completionTokens,
            total_tokens: (promptTokens || 10) + completionTokens,
        },
        system_fingerprint: 'mock-fp',
    };
}

function makeStreamChunks(model, content) {
    const id = `chatcmpl-mock-${Date.now()}`;
    const words = content.split(' ');
    const chunks = [];

    // First chunk: role
    chunks.push({
        id, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000),
        model, choices: [{ index: 0, delta: { role: 'assistant' }, finish_reason: null }],
    });

    // Content chunks
    for (const word of words) {
        chunks.push({
            id, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000),
            model, choices: [{ index: 0, delta: { content: word + ' ' }, finish_reason: null }],
        });
    }

    // Final chunk
    chunks.push({
        id, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000),
        model, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
        usage: { prompt_tokens: 10, completion_tokens: words.length, total_tokens: 10 + words.length },
    });

    return chunks;
}

async function handleRequest(req, res) {
    const parsed = url.parse(req.url, true);
    const path = parsed.pathname;
    const method = req.method;

    // Health check
    if (path === '/health') {
        return sendJSON(res, 200, { status: 'ok', server: SERVER_ID });
    }

    // Simulate failure via header
    if (req.headers['x-fail'] === 'true') {
        return sendJSON(res, 502, { error: { message: 'Simulated failure', type: 'server_error' } });
    }

    // Simulate delay via header
    const delayMs = parseInt(req.headers['x-delay-ms'] || '0', 10);
    if (delayMs > 0) {
        await new Promise((r) => setTimeout(r, delayMs));
    }

    // --- /v1/models ---
    if (path === '/v1/models' && method === 'GET') {
        return sendJSON(res, 200, {
            object: 'list',
            data: MODELS.map((m) => ({
                id: m.id, object: 'model', created: 1700000000, owned_by: m.owned_by,
            })),
        });
    }

    // --- /v1/chat/completions ---
    if (path === '/v1/chat/completions' && method === 'POST') {
        const body = await readBody(req);
        let reqBody;
        try {
            reqBody = JSON.parse(body);
        } catch {
            return sendJSON(res, 400, { error: { message: 'Invalid JSON', type: 'invalid_request_error' } });
        }

        const model = reqBody.model || 'gpt-4o-mini';
        const messages = reqBody.messages || [];
        const stream = reqBody.stream === true;
        const lastMessage = messages[messages.length - 1]?.content || '';

        // Special models for error testing
        if (model === 'error-model') {
            return sendJSON(res, 500, { error: { message: 'Internal server error', type: 'server_error' } });
        }
        if (model === 'timeout-model') {
            await new Promise((r) => setTimeout(r, 10000));
            return sendJSON(res, 200, makeCompletion(model, 'Delayed response'));
        }
        if (model === 'rate-limited') {
            res.writeHead(429, {
                'Content-Type': 'application/json',
                'Retry-After': '5',
                'X-RateLimit-Remaining': '0',
            });
            return res.end(JSON.stringify({ error: { message: 'Rate limit exceeded', type: 'rate_limit_error' } }));
        }

        // Echo the last user message back as the assistant response
        const responseContent = `Mock response to: ${lastMessage}`;

        // Estimate prompt tokens from messages
        const promptTokens = messages.reduce((sum, m) => sum + Math.ceil((m.content || '').length / 4), 0);

        if (stream) {
            return sendSSE(res, makeStreamChunks(model, responseContent));
        }

        return sendJSON(res, 200, makeCompletion(model, responseContent, promptTokens));
    }

    // --- /v1/embeddings ---
    if (path === '/v1/embeddings' && method === 'POST') {
        const body = await readBody(req);
        let reqBody;
        try {
            reqBody = JSON.parse(body);
        } catch {
            return sendJSON(res, 400, { error: { message: 'Invalid JSON', type: 'invalid_request_error' } });
        }

        const input = Array.isArray(reqBody.input) ? reqBody.input : [reqBody.input || ''];
        const data = input.map((text, i) => ({
            object: 'embedding',
            index: i,
            embedding: Array(1536).fill(0).map(() => Math.random() * 2 - 1),
        }));

        return sendJSON(res, 200, {
            object: 'list',
            data,
            model: reqBody.model || 'text-embedding-ada-002',
            usage: { prompt_tokens: input.join(' ').length / 4, total_tokens: input.join(' ').length / 4 },
        });
    }

    // --- Echo endpoint (for general testing) ---
    if (path.startsWith('/echo')) {
        const body = await readBody(req);
        return sendJSON(res, 200, {
            method, path, query: parsed.query,
            headers: { ...req.headers }, body,
        });
    }

    // 404 for unknown paths
    sendJSON(res, 404, { error: { message: `Unknown endpoint: ${path}`, type: 'not_found' } });
}

const server = http.createServer(handleRequest);

server.listen(PORT, '127.0.0.1', () => {
    console.log(`Mock AI server (${SERVER_ID}) listening on http://127.0.0.1:${PORT}`);
    console.log('Endpoints: /v1/chat/completions, /v1/models, /v1/embeddings, /echo, /health');
});

process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT', () => { server.close(); process.exit(0); });
