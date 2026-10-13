"""Versioned framework data the atomics and rules map to.

Names are copied from the published sources so a typo in an atomic or a rule
tag fails validation instead of silently inventing a category.
"""

from __future__ import annotations

# OWASP Top 10 for Agentic Applications (2026), published December 2025.
OWASP_ASI_VERSION = "2026"
OWASP_ASI: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# OWASP Top 10 for LLM Applications (2025).
OWASP_LLM: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# MITRE ATLAS techniques used by the bundled atomics. IDs and names checked
# against atlas-data dist/ATLAS.yaml v5.6.0.
MITRE_ATLAS_VERSION = "5.6.0"
MITRE_ATLAS: dict[str, str] = {
    "AML.T0010.005": "AI Supply Chain Compromise: AI Agent Tool",
    "AML.T0011.003": "User Execution: Malicious Link",
    "AML.T0029": "Denial of AI Service",
    "AML.T0034.002": "Cost Harvesting: Agentic Resource Consumption",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0052": "Phishing",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0072": "Reverse Shell",
    "AML.T0073": "Impersonation",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0080.000": "AI Agent Context Poisoning: Memory",
    "AML.T0080.001": "AI Agent Context Poisoning: Thread",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0083": "Credentials from AI Agent Configuration",
    "AML.T0084": "Discover AI Agent Configuration",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0098": "AI Agent Tool Credential Harvesting",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
    "AML.T0103": "Deploy AI Agent",
    "AML.T0110": "AI Agent Tool Poisoning",
}

SEVERITIES = ("low", "medium", "high", "critical")
