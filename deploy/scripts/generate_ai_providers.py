#!/usr/bin/env python3
"""
Generate ai_providers.yml from model_pricing.json.
Extracts unique litellm_provider entries and creates a YAML configuration.

Usage:
    python3 generate_ai_providers.py [--input <path>] [--output <path>]

    Default input: proxy/data/model_pricing.json
    Default output: proxy/config/ai_providers.yml
"""

import json
import argparse
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

# Provider metadata - maps litellm_provider to display name and details
PROVIDER_METADATA = {
    'openai': {'name': 'OpenAI', 'description': 'OpenAI APIs (ChatGPT, GPT-4)', 'hostnames': ['api.openai.com', 'api-*.openai.com'], 'ports': [443]},
    'anthropic': {'name': 'Anthropic', 'description': 'Anthropic Claude API', 'hostnames': ['api.anthropic.com'], 'ports': [443]},
    'google': {'name': 'Google', 'description': 'Google Generative AI (Gemini)', 'hostnames': ['generativelanguage.googleapis.com'], 'ports': [443]},
    'gemini': {'name': 'Google Gemini', 'description': 'Google Gemini API', 'hostnames': ['generativelanguage.googleapis.com'], 'ports': [443]},
    'vertex_ai': {'name': 'Google Vertex AI', 'description': 'Google Vertex AI', 'hostnames': ['vertexai.googleapis.com'], 'ports': [443]},
    'cohere': {'name': 'Cohere', 'description': 'Cohere API', 'hostnames': ['api.cohere.ai'], 'ports': [443]},
    'mistral': {'name': 'Mistral', 'description': 'Mistral AI API', 'hostnames': ['api.mistral.ai'], 'ports': [443]},
    'groq': {'name': 'Groq', 'description': 'Groq API', 'hostnames': ['api.groq.com'], 'ports': [443]},
    'together_ai': {'name': 'Together AI', 'description': 'Together AI API', 'hostnames': ['api.together.xyz'], 'ports': [443]},
    'openrouter': {'name': 'OpenRouter', 'description': 'OpenRouter API', 'hostnames': ['openrouter.ai'], 'ports': [443]},
    'bedrock': {'name': 'AWS Bedrock', 'description': 'Amazon Bedrock', 'hostnames': ['bedrock.*.amazonaws.com'], 'ports': [443]},
    'azure': {'name': 'Azure OpenAI', 'description': 'Microsoft Azure OpenAI', 'hostnames': ['*.openai.azure.com'], 'ports': [443]},
    'ollama': {'name': 'Ollama', 'description': 'Ollama local models', 'hostnames': ['localhost', '127.0.0.1'], 'ports': [11434]},
    'deepseek': {'name': 'DeepSeek', 'description': 'DeepSeek API', 'hostnames': ['api.deepseek.com'], 'ports': [443]},
    'perplexity': {'name': 'Perplexity', 'description': 'Perplexity API', 'hostnames': ['api.perplexity.ai'], 'ports': [443]},
}

def load_pricing_data(input_path: str) -> Dict[str, Any]:
    """Load model pricing JSON file."""
    with open(input_path, 'r') as f:
        return json.load(f)

def extract_unique_providers(pricing_data: Dict[str, Any]) -> List[str]:
    """Extract unique litellm_provider values from pricing data."""
    providers = set()
    for key, value in pricing_data.items():
        if key != 'sample_spec' and isinstance(value, dict):
            if 'litellm_provider' in value:
                providers.add(value['litellm_provider'])
    return sorted(providers)

def generate_provider_config(provider_id: str) -> Dict[str, Any]:
    """Generate YAML configuration for a provider."""
    metadata = PROVIDER_METADATA.get(provider_id, {})

    config = {
        'type': provider_id,
        'name': metadata.get('name', provider_id.replace('_', ' ').title()),
        'description': metadata.get('description', f'{provider_id.replace("_", " ").title()} API'),
        'hostnames': metadata.get('hostnames', [f'{provider_id}.com']),
        'ports': metadata.get('ports', [443]),
    }

    return config

def generate_yaml(providers: List[str]) -> Dict[str, Any]:
    """Generate complete YAML structure."""
    provider_configs = []
    for provider_id in providers:
        config = generate_provider_config(provider_id)
        provider_configs.append(config)

    return {
        'providers': provider_configs
    }

def save_yaml(data: Dict[str, Any], output_path: str) -> None:
    """Save YAML file with custom formatting."""
    with open(output_path, 'w') as f:
        f.write('# Auto-generated from proxy/data/model_pricing.json\n')
        f.write('# Edit this file manually only if needed for custom provider configuration.\n')
        f.write('# Regenerate with: python3 scripts/generate_ai_providers.py\n\n')

        f.write('providers:\n')
        for provider in data['providers']:
            f.write(f"  - type: {provider['type']}\n")
            f.write(f"    name: {provider['name']}\n")
            f.write(f"    description: \"{provider['description']}\"\n")
            f.write(f"    hostnames:\n")
            for hostname in provider['hostnames']:
                f.write(f"      - {hostname}\n")
            f.write(f"    ports: {provider['ports']}\n")
            f.write('\n')

def main():
    parser = argparse.ArgumentParser(description='Generate ai_providers.yml from model_pricing.json')
    parser.add_argument('--input', default='proxy/data/model_pricing.json',
                        help='Path to model_pricing.json')
    parser.add_argument('--output', default='proxy/config/ai_providers.yml',
                        help='Path to output ai_providers.yml')

    args = parser.parse_args()

    # Convert to absolute paths if relative
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f'Error: {input_path} not found')
        return 1

    # Load pricing data
    pricing_data = load_pricing_data(str(input_path))

    # Extract unique providers
    providers = extract_unique_providers(pricing_data)
    print(f'Found {len(providers)} unique AI providers')

    # Generate YAML
    yaml_data = generate_yaml(providers)

    # Save YAML
    output_path.parent.mkdir(parents=True, exist_ok=True)
    save_yaml(yaml_data, str(output_path))

    print(f'Generated {output_path} with {len(providers)} providers')
    print(f'Provider count: {len(providers)}')

    return 0

if __name__ == '__main__':
    exit(main())
