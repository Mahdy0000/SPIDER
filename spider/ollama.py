"""Minimal Ollama client (stdlib only)."""
import json
import urllib.error
import urllib.request


class OllamaError(RuntimeError):
    pass


def chat(host, model, system, user, timeout=300):
    body = json.dumps({
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode()
    req = urllib.request.Request(host.rstrip("/") + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise OllamaError(f"Ollama HTTP {e.code}: {detail} (is the model pulled? try: ollama pull {model})")
    except (urllib.error.URLError, OSError) as e:
        raise OllamaError(f"Cannot reach Ollama at {host}: {e}. Start it with: ollama serve")
    try:
        return data["message"]["content"]
    except (KeyError, TypeError):
        raise OllamaError("Unexpected Ollama response shape")


FALLBACK_MODEL = "dolphinlabs/llama3.2-3b-uncensored"
TUNED_MODEL = "spider-reviewer"  # created by training/convert_to_ollama.sh


def default_model(host, env=None):
    """--model default: $SPIDER_MODEL, else the fine-tuned `spider-reviewer` if it is installed in Ollama, else the stock model."""
    import os
    env = os.environ if env is None else env
    if env.get("SPIDER_MODEL"):
        return env["SPIDER_MODEL"]
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=2) as r:
            names = [m.get("name", "") for m in json.loads(r.read()).get("models", [])]
        if any(n == TUNED_MODEL or n.startswith(TUNED_MODEL + ":") for n in names):
            return TUNED_MODEL
    except (urllib.error.URLError, OSError, ValueError, AttributeError):
        pass
    return FALLBACK_MODEL
