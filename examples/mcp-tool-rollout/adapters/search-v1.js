// v1 <-> v2 adapter for `search`, used once the legacy upstream is
// retired and 1.x calls are served off the new server. Referenced
// from sb.yml as `js:adapters/search-v1.js`; paths resolve relative
// to the proxy's working directory.

// v1 callers send {q}; v2 expects {query, limit}.
function request(args) {
    return {
        query: args.q,
        limit: args.limit === undefined ? 10 : args.limit,
    };
}

// v2 returns {results: [...]}; v1 callers expect {hits: [...]}.
function response(result) {
    if (result && result.results !== undefined) {
        result.hits = result.results;
        delete result.results;
    }
    return result;
}
