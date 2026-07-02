"""LLM interface using LiteLLM — supports 100+ providers.

Provider catalog in providers.yaml defines all supported providers.
Users can reference providers by name or use LiteLLM model prefixes directly.
"""

import json
import os
from pathlib import Path

import yaml
import litellm

litellm.suppress_debug_info = True

_PROVIDERS_CACHE = None


def load_providers() -> dict:
    """Load the provider catalog from providers.yaml."""
    global _PROVIDERS_CACHE
    if _PROVIDERS_CACHE is not None:
        return _PROVIDERS_CACHE

    providers_path = Path(__file__).parent.parent / "providers.yaml"
    with open(providers_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    _PROVIDERS_CACHE = data.get("providers", {})
    return _PROVIDERS_CACHE


def get_provider(name: str) -> dict | None:
    """Get a provider config by name."""
    return load_providers().get(name)


def list_providers() -> list[dict]:
    """List all available providers."""
    providers = load_providers()
    return [
        {
            "id": pid,
            "name": p.get("name", pid),
            "type": p.get("type"),
            "base_url": p.get("base_url"),
            "api_key_env": p.get("api_key_env"),
            "models": p.get("models", []),
            "notes": p.get("notes", ""),
        }
        for pid, p in providers.items()
    ]


def resolve_model_config(provider_name: str, model_name: str, api_key: str = None) -> dict:
    """Resolve a provider + model name into a full LiteLLM config.

    Args:
        provider_name: Provider ID from providers.yaml (e.g., "ollama", "glm", "openai")
        model_name: Model name for that provider (e.g., "qwen2.5:7b", "glm-4-flash")
        api_key: Override API key. If None, uses env var from provider config.

    Returns:
        Dict with: name, api_base, api_key (ready for LLMInterface)
    """
    provider = get_provider(provider_name)
    if provider is None:
        raise ValueError(
            f"Unknown provider '{provider_name}'. "
            f"Available: {', '.join(load_providers().keys())}"
        )

    prefix = provider.get("litellm_prefix", "openai")
    full_model = f"{prefix}/{model_name}" if not model_name.startswith(f"{prefix}/") else model_name

    base_url = provider.get("base_url")

    if api_key is None:
        env_var = provider.get("api_key_env")
        api_key = os.environ.get(env_var, "") if env_var else ""
        if not api_key:
            api_key = provider.get("api_key_default", "")

    return {
        "name": full_model,
        "api_base": base_url,
        "api_key": api_key,
    }


# No providers use structured output mode — it causes JSON parsing errors
# with GLM (markdown wrapping, truncation) and Groq (tool_use_failed).
# Instead, ALL agents use prompt-based JSON + _parse_output() fallback.
# This is the pattern used by opencode, Claude Code, and other production agents.
_PROVIDERS_WITH_STRUCTURED_OUTPUT = set()


def supports_structured_output(provider_name: str) -> bool:
    """Always False — we use prompt-based JSON for all providers.

    This is the reliable pattern: tools return structured JSON (Python-generated),
    LLM returns free text with JSON, _parse_output() extracts it.
    No response_format, no strict schema, no parsing errors.
    """
    return False


class LLMInterface:
    """Unified LLM interface supporting 100+ providers via LiteLLM."""

    def __init__(self, model_config: dict):
        self.model = model_config["name"]
        self.api_base = model_config.get("api_base")
        self.api_key = model_config.get("api_key")
        self.temperature = model_config.get("temperature", 0.1)
        self.max_tokens = model_config.get("max_tokens", 4096)
        self.timeout = model_config.get("timeout", 120)

    def complete(self, prompt: str, system: str = None) -> str:
        """Send a completion request and return the text response."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
        }

        if self.api_base:
            kwargs["api_base"] = self.api_base
        if self.api_key:
            kwargs["api_key"] = self.api_key

        response = litellm.completion(**kwargs)
        return response.choices[0].message.content

    def complete_json(self, prompt: str, system: str = None) -> dict:
        """Send a completion request and parse the response as JSON."""
        text = self.complete(prompt, system)
        return self._parse_json(text)

    @staticmethod
    def _parse_json(text: str) -> dict:
        text = text.strip()
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start)
            text = text[start:end].strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            for i in range(len(text), 0, -1):
                try:
                    return json.loads(text[:i])
                except json.JSONDecodeError:
                    continue
            raise ValueError(f"Could not parse JSON: {text[:200]}...")
