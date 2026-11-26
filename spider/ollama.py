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
