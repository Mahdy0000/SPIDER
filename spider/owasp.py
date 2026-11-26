"""OWASP Top 10 (2021) categories used to map findings."""

OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


def normalize_owasp(value):
    """Turn 'A03', 'a03:2021', 'A03:2021 - Injection' ... into 'A03:2021 - Injection'."""
    if not isinstance(value, str):
        return "Unmapped"
    v = value.strip().upper()
    code = v[:3]
    if code in OWASP_2021:
        return f"{code}:2021 - {OWASP_2021[code]}"
    return "Unmapped"


def _taxonomy():
    import json, os
    with open(os.path.join(os.path.dirname(__file__), "data", "taxonomy.json"), encoding="utf-8") as f:
        return json.load(f)


_TAX = None


def owasp_2025(owasp_2021_label, cwe=""):
    """OWASP Top 10:2025 label for a finding. Uses the CWE when the 2025 category lists contain it,
    otherwise the official 2021 to 2025 category crosswalk (SSRF moved into A01, and so on).
    Returns 'Unmapped' when neither applies."""
    import re
    global _TAX
    if _TAX is None:
        _TAX = _taxonomy()
    names = _TAX["owasp_2025"]["names"]
    m = re.search(r"(\d+)", cwe or "")
    if m:
        n = int(m.group(1))
        for code, cwes in _TAX["owasp_2025"]["cwes"].items():
            if n in cwes:
                return f"{code}:2025 - {names[code]}"
    code = normalize_owasp(owasp_2021_label)[:3]
    new = _TAX["owasp_2021_to_2025_category_crosswalk"].get(code)
    return f"{new}:2025 - {names[new]}" if new else "Unmapped"


def cwe_top25_years(cwe):
    """Years (2021-2025) in which the CWE appears in the MITRE CWE Top 25."""
    global _TAX
    if _TAX is None:
        _TAX = _taxonomy()
    return sorted(int(y) for y, e in _TAX["cwe_top25"]["editions"].items() if any(r["cwe"] == (cwe or "").strip() for r in e["top25"]))
