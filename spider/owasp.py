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
