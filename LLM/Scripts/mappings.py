"""
CWE to ISO 27001 and NIST CSF control mappings for security policy generation.
This module provides mappings between vulnerability themes and compliance frameworks.
"""

# CWE to vulnerability theme mapping
CWE_THEME = {
    # Injection vulnerabilities
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-78": "OS Command Injection",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Deserialization",
    
    # Authentication and Authorization
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication",
    "CWE-798": "Hard-coded Credentials",
    "CWE-521": "Weak Password Requirements",
    "CWE-284": "Improper Access Control",
    "CWE-639": "Authorization Bypass",
    
    # Cryptography
    "CWE-327": "Weak Cryptographic Algorithm",
    "CWE-330": "Weak Random Number Generation",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-311": "Missing Encryption",
    
    # Input Validation
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-434": "Unrestricted Upload",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    
    # Session Management
    "CWE-384": "Session Fixation",
    "CWE-613": "Insufficient Session Expiration",
    
    # Error Handling
    "CWE-209": "Information Disclosure",
    "CWE-200": "Information Exposure",
    
    # Dependency Vulnerabilities
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "XML External Entity (XXE)",
    
    # Default fallback
    "N/A": "General Security Vulnerability",
}

# Vulnerability theme to ISO 27001 and NIST CSF control mappings
THEME_MAPPINGS = {
    "Cross-Site Scripting (XSS)": {
        "iso27001": ["A.9.4.2", "A.14.1.3", "A.14.2.4", "A.14.2.5"],
        "nist_csf": ["PR.AC-1", "PR.DS-5", "DE.CM-1", "RS.CO-2"],
    },
    "SQL Injection": {
        "iso27001": ["A.9.4.2", "A.14.1.3", "A.14.2.1", "A.14.2.5"],
        "nist_csf": ["PR.AC-1", "PR.DS-5", "DE.CM-1", "DE.DP-4"],
    },
    "OS Command Injection": {
        "iso27001": ["A.9.4.2", "A.14.1.3", "A.14.2.1"],
        "nist_csf": ["PR.AC-1", "PR.DS-5", "DE.CM-1"],
    },
    "Improper Authentication": {
        "iso27001": ["A.9.2.1", "A.9.2.2", "A.9.2.4", "A.9.4.2"],
        "nist_csf": ["PR.AC-1", "PR.AC-7", "PR.DS-5", "DE.CM-1"],
    },
    "Weak Cryptographic Algorithm": {
        "iso27001": ["A.10.1.1", "A.10.1.2", "A.18.1.4"],
        "nist_csf": ["PR.DS-1", "PR.DS-2", "PR.DS-5"],
    },
    "Improper Input Validation": {
        "iso27001": ["A.14.1.3", "A.14.2.1", "A.14.2.4"],
        "nist_csf": ["PR.DS-5", "DE.CM-1", "DE.DP-4"],
    },
    "Cross-Site Request Forgery (CSRF)": {
        "iso27001": ["A.9.4.2", "A.14.2.4", "A.14.2.5"],
        "nist_csf": ["PR.AC-1", "DE.CM-1", "RS.CO-2"],
    },
    "Session Fixation": {
        "iso27001": ["A.9.4.2", "A.14.1.3"],
        "nist_csf": ["PR.AC-1", "PR.DS-5"],
    },
    "Information Disclosure": {
        "iso27001": ["A.9.4.2", "A.14.2.4", "A.18.1.4"],
        "nist_csf": ["PR.DS-5", "DE.CM-1", "RS.CO-2"],
    },
    "Dependency Vulnerability": {
        "iso27001": ["A.12.6.1", "A.14.1.3", "A.14.2.1"],
        "nist_csf": ["PR.DS-1", "DE.CM-1", "DE.DP-4"],
    },
    "General Security Vulnerability": {
        "iso27001": ["A.9.4.2", "A.14.1.3", "A.14.2.1"],
        "nist_csf": ["PR.DS-5", "DE.CM-1", "DE.DP-4"],
    },
}

# Suggested controls for each theme (seed for LLM prompts)
THEME_CONTROLS = {
    "Cross-Site Scripting (XSS)": [
        "Implement Content Security Policy (CSP) headers",
        "Sanitize all user inputs and outputs",
        "Use parameterized queries and output encoding",
        "Regular security testing for XSS vulnerabilities",
    ],
    "SQL Injection": [
        "Use parameterized queries and prepared statements",
        "Implement input validation and sanitization",
        "Apply principle of least privilege for database access",
        "Regular code reviews and security testing",
    ],
    "OS Command Injection": [
        "Avoid direct command execution from user input",
        "Use safe APIs and parameterized commands",
        "Validate and sanitize all inputs",
        "Implement command execution monitoring",
    ],
    "Improper Authentication": [
        "Implement strong password policies",
        "Use multi-factor authentication (MFA)",
        "Enforce session timeout and secure session management",
        "Regular authentication security audits",
    ],
    "Weak Cryptographic Algorithm": [
        "Use approved cryptographic algorithms and key lengths",
        "Implement secure key management practices",
        "Regular cryptographic algorithm reviews and updates",
        "Ensure proper encryption for data at rest and in transit",
    ],
    "Improper Input Validation": [
        "Validate all inputs at system boundaries",
        "Implement whitelist validation where possible",
        "Sanitize outputs to prevent injection attacks",
        "Regular input validation security testing",
    ],
    "Cross-Site Request Forgery (CSRF)": [
        "Implement CSRF tokens for state-changing operations",
        "Use SameSite cookie attributes",
        "Validate origin headers for sensitive operations",
        "Regular CSRF protection testing",
    ],
    "Session Fixation": [
        "Regenerate session IDs after authentication",
        "Implement secure session configuration",
        "Enforce session timeout policies",
        "Monitor for session-related attacks",
    ],
    "Information Disclosure": [
        "Implement proper error handling without exposing sensitive data",
        "Secure logging practices (no sensitive data in logs)",
        "Proper data classification and handling",
        "Regular security reviews of error messages and logs",
    ],
    "Dependency Vulnerability": [
        "Maintain inventory of all dependencies",
        "Regular dependency vulnerability scanning",
        "Keep dependencies up to date",
        "Implement dependency update and patch management processes",
    ],
    "General Security Vulnerability": [
        "Implement defense in depth security controls",
        "Regular security assessments and penetration testing",
        "Maintain security awareness and training",
        "Implement continuous monitoring and incident response",
    ],
}

def get_theme_from_cwe(cwe: str) -> str:
    """Get vulnerability theme from CWE identifier"""
    if not cwe or cwe == "N/A":
        return "General Security Vulnerability"
    
    # Extract CWE number (e.g., "CWE-79" from "CWE-79: XSS")
    cwe_clean = cwe.upper().strip()
    if "CWE-" in cwe_clean:
        cwe_num = cwe_clean.split("CWE-")[1].split()[0].split(":")[0]
        cwe_key = f"CWE-{cwe_num}"
        return CWE_THEME.get(cwe_key, "General Security Vulnerability")
    
    return CWE_THEME.get(cwe_clean, "General Security Vulnerability")

def get_iso27001_controls(theme: str) -> list:
    """Get ISO 27001 control mappings for a vulnerability theme"""
    return THEME_MAPPINGS.get(theme, THEME_MAPPINGS["General Security Vulnerability"])["iso27001"]

def get_nist_csf_controls(theme: str) -> list:
    """Get NIST CSF control mappings for a vulnerability theme"""
    return THEME_MAPPINGS.get(theme, THEME_MAPPINGS["General Security Vulnerability"])["nist_csf"]

def get_suggested_controls(theme: str) -> list:
    """Get suggested controls for a vulnerability theme"""
    return THEME_CONTROLS.get(theme, THEME_CONTROLS["General Security Vulnerability"])

