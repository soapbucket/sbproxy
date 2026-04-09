# Examples

Quick-start configurations for sbproxy.

| Example | Description |
|---------|-------------|
| [minimal.yml](minimal.yml) | Simplest reverse proxy |
| [with-auth.yml](with-auth.yml) | API key authentication |
| [with-caching.yml](with-caching.yml) | Response caching |
| [ai-proxy.yml](ai-proxy.yml) | AI gateway with OpenAI + Anthropic |
| [load-balancer.yml](load-balancer.yml) | Weighted load balancing |

## Usage

    sbproxy serve -f examples/minimal.yml

Or with Docker:

    docker run -p 8080:8080 -v $(pwd)/examples/minimal.yml:/etc/sbproxy/sb.yml ghcr.io/soapbucket/sbproxy:latest
