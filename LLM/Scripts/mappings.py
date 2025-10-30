# llm/mappings.py

# theme par cwe
CWE_THEME = {
    "79":  "XSS",
    "89":  "SQL Injection",
    "352": "CSRF",
    "200": "Sensitive Data Exposure",
    "22":  "Path Traversal",
    "78":  "Command Injection",
    "287": "Auth Bypass",
    "434": "Unrestricted File Upload",
    "937": "Use of Vulnerable Components",  # défaut SCA
}

# mappage theme -> ISO/NIST
THEME_MAPPINGS = {
    "SQL Injection": {
        "iso27001": ["A.14.2.5", "A.12.1.2"],
        "nist_csf": ["PR.AC-3", "PR.DS-6", "DE.AE-2"]
    },
    "XSS": {
        "iso27001": ["A.14.2.5"],
        "nist_csf": ["PR.DS-6", "DE.CM-7"]
    },
    "CSRF": {
        "iso27001": ["A.14.2.5"],
        "nist_csf": ["PR.AC-1", "PR.AC-3"]
    },
    "Sensitive Data Exposure": {
        "iso27001": ["A.10.1", "A.18.1.4"],
        "nist_csf": ["PR.DS-1", "PR.DS-5"]
    },
    "Path Traversal": {
        "iso27001": ["A.14.2.5"],
        "nist_csf": ["PR.DS-6"]
    },
    "Command Injection": {
        "iso27001": ["A.14.2.5"],
        "nist_csf": ["PR.IP-1", "PR.DS-6"]
    },
    "Auth Bypass": {
        "iso27001": ["A.9.2.1", "A.9.4.2"],
        "nist_csf": ["PR.AC-1", "PR.AC-7"]
    },
    "Unrestricted File Upload": {
        "iso27001": ["A.14.2.5"],
        "nist_csf": ["PR.DS-6"]
    },
    "Use of Vulnerable Components": {
        "iso27001": ["A.12.6.1", "A.15.1.1"],  # gestion vulnérabilités + supply chain
        "nist_csf": ["ID.RA-1", "PR.IP-12", "PR.DS-7"]
    },
    "Default": {
        "iso27001": ["A.14.2.5"],
        "nist_csf": ["PR.DS-6"]
    }
}

# contrôles suggérés par thème (seed pour le LLM)
THEME_CONTROLS = {
    "SQL Injection": [
        "Utiliser des requêtes paramétrées / ORM",
        "Valider/encoder les entrées",
        "Bloquer les erreurs SQL détaillées"
    ],
    "XSS": [
        "Encoder les sorties (HTML/JS/CSS)",
        "CSP restrictive",
        "Validation côté serveur"
    ],
    "Use of Vulnerable Components": [
        "SBOM + scan SCA en CI",
        "Politique de mise à jour des dépendances",
        "Blocage des versions interdites"
    ],
}
