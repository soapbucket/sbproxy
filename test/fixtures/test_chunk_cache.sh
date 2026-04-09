#!/bin/bash

# Chunk Cache Testing Script
# Tests all HackerNews chunk cache configurations

set -e

BASE_URL="https://localhost:8443"
DEBUG_FLAG="-H X-Sb-Flags: debug"
CURL_OPTS="-ksv"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          Chunk Cache Testing Suite                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function test_config() {
    local hostname=$1
    local description=$2
    local test_name=$3
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing: ${hostname}${NC}"
    echo -e "${YELLOW}${description}${NC}"
    echo ""
    
    case $test_name in
        "signature")
            test_signature_cache "$hostname"
            ;;
        "url")
            test_url_cache "$hostname"
            ;;
        "hybrid")
            test_hybrid_cache "$hostname"
            ;;
        "ignore_nocache")
            test_ignore_nocache "$hostname"
            ;;
        "modifiers")
            test_modifiers "$hostname"
            ;;
    esac
    
    echo ""
}

function test_signature_cache() {
    local hostname=$1
    
    echo -e "${GREEN}[1/2] First request (cache miss)...${NC}"
    response=$(curl $CURL_OPTS -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/" 2>&1)
    if echo "$response" | grep -q "x-cache:"; then
        echo -e "${RED}❌ Unexpected cache hit on first request${NC}"
    else
        echo -e "${GREEN}✓ Cache miss (expected)${NC}"
    fi
    
    sleep 1
    
    echo -e "${GREEN}[2/2] Second request (should hit signature cache)...${NC}"
    response=$(curl $CURL_OPTS -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/" 2>&1)
    if echo "$response" | grep -q "x-cache: HIT-SIGNATURE"; then
        cache_key=$(echo "$response" | grep "x-sb-cache-key:" | sed 's/.*x-sb-cache-key: //' | tr -d '\r')
        echo -e "${GREEN}✓ Signature cache hit!${NC}"
        echo -e "  Cache key: ${cache_key}"
    else
        echo -e "${RED}❌ No signature cache hit${NC}"
    fi
}

function test_url_cache() {
    local hostname=$1
    
    echo -e "${GREEN}[1/3] First request (cache miss)...${NC}"
    curl -s -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/" > /dev/null
    echo -e "${GREEN}✓ Request completed${NC}"
    
    sleep 1
    
    echo -e "${GREEN}[2/3] Second request (should hit URL cache - fresh)...${NC}"
    response=$(curl $CURL_OPTS -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/" 2>&1)
    if echo "$response" | grep -q "x-cache: HIT"; then
        cache_key=$(echo "$response" | grep "x-sb-cache-key:" | sed 's/.*x-sb-cache-key: //' | tr -d '\r')
        echo -e "${GREEN}✓ URL cache hit (fresh)!${NC}"
        echo -e "  Cache key: ${cache_key}"
    else
        echo -e "${RED}❌ No URL cache hit${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}[3/3] Waiting for cache to become stale (this may take a while)...${NC}"
    echo "  Note: This test is optional. Press Ctrl+C to skip."
    echo "  TTL is configured in the config (typically 5m)"
}

function test_hybrid_cache() {
    local hostname=$1
    
    echo -e "${GREEN}[1/3] Request /news (cache miss)...${NC}"
    curl -s -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/news" > /dev/null
    echo -e "${GREEN}✓ Cached in both signature and URL cache${NC}"
    
    sleep 1
    
    echo -e "${GREEN}[2/3] Request /newest (different URL, should hit signature cache)...${NC}"
    response=$(curl $CURL_OPTS -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/newest" 2>&1)
    if echo "$response" | grep -q "x-cache: HIT-SIGNATURE"; then
        echo -e "${GREEN}✓ Signature cache hit on different URL!${NC}"
    else
        echo -e "${RED}❌ No signature cache hit${NC}"
    fi
    
    sleep 1
    
    echo -e "${GREEN}[3/3] Request /news again (should hit URL cache)...${NC}"
    response=$(curl $CURL_OPTS -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/news" 2>&1)
    if echo "$response" | grep -q "x-cache: HIT"; then
        echo -e "${GREEN}✓ URL cache hit on same URL!${NC}"
    else
        echo -e "${YELLOW}⚠ Expected URL cache hit${NC}"
    fi
}

function test_ignore_nocache() {
    local hostname=$1
    
    echo -e "${GREEN}[1/2] Warm cache...${NC}"
    curl -s -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/" > /dev/null
    echo -e "${GREEN}✓ Cache warmed${NC}"
    
    sleep 1
    
    echo -e "${GREEN}[2/2] Request with Cache-Control: no-cache (should still hit cache)...${NC}"
    response=$(curl $CURL_OPTS -H "Host: $hostname" $DEBUG_FLAG -H "Cache-Control: no-cache" "$BASE_URL/" 2>&1)
    if echo "$response" | grep -q "x-cache: HIT"; then
        echo -e "${GREEN}✓ Cache hit despite no-cache directive!${NC}"
        echo -e "  ignore_no_cache is working"
    else
        echo -e "${RED}❌ Cache was bypassed${NC}"
    fi
}

function test_modifiers() {
    local hostname=$1
    
    echo -e "${GREEN}[1/1] Request and check modified headers...${NC}"
    response=$(curl $CURL_OPTS -H "Host: $hostname" $DEBUG_FLAG "$BASE_URL/" 2>&1)
    
    if echo "$response" | grep -q "cache-control: public, max-age=300"; then
        echo -e "${GREEN}✓ Cache-Control header was modified!${NC}"
    else
        echo -e "${RED}❌ Cache-Control not modified${NC}"
    fi
    
    if echo "$response" | grep -q "set-cookie:"; then
        echo -e "${RED}❌ Set-Cookie header was not removed${NC}"
    else
        echo -e "${GREEN}✓ Set-Cookie header removed!${NC}"
    fi
}

# Main test execution
echo "Starting tests..."
echo ""

test_config "hn-signature.test" "Signature-based caching (HTML head)" "signature"
test_config "hn-url.test" "URL-based caching" "url"
test_config "hn-hybrid.test" "Hybrid caching (signature + URL)" "hybrid"
test_config "hn-ignore-nocache.test" "Ignore client no-cache directive" "ignore_nocache"
test_config "hn-modifiers.test" "Cache control header modification" "modifiers"

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Testing complete!${NC}"
echo ""
echo "Check proxy logs for detailed cache operation messages:"
echo "  grep 'chunk cache' /path/to/proxy/logs"

