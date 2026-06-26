TOOLS = {
    "dns_lookup": {
        "description": "Resolve DNS records and IP addresses.",
        "category": "recon",
        "risk": "safe",
        "requires_scope": False,
    },

    "http_probe": {
        "description": "Retrieve HTTP status, headers and server information.",
        "category": "recon",
        "risk": "safe",
        "requires_scope": True,
    },

    "security_headers_checker": {
        "description": "Check important HTTP security headers.",
        "category": "analysis",
        "risk": "safe",
        "requires_scope": True,
    },

    "katana_crawl": {
        "description": "Crawl the target website and discover endpoints.",
        "category": "recon",
        "risk": "safe",
        "requires_scope": True,
    },

    "misconfiguration_detector": {
        "description": "Identify development artifacts, placeholder domains and configuration issues.",
        "category": "analysis",
        "risk": "safe",
        "requires_scope": True,
    },

    "js_secret_scanner": {
        "description": "Search JavaScript and assets for secrets and sensitive references.",
        "category": "analysis",
        "risk": "safe",
        "requires_scope": True,
    },

    "parameter_analyzer": {
        "description": "Analyze discovered parameters for potential security testing opportunities.",
        "category": "analysis",
        "risk": "safe",
        "requires_scope": True,
    },

    "authz_test_planner": {
        "description": "Generate manual authorization testing ideas.",
        "category": "planning",
        "risk": "safe",
        "requires_scope": False,
    },

    "nuclei_scan": {
        "description": "Run approved Nuclei templates.",
        "category": "active",
        "risk": "active",
        "requires_scope": True,
    },


    "ai_report_writer": {
        "description": "Generate a professional AI-written Markdown security report from scan results.",
        "category": "reporting",
        "risk": "safe",
        "requires_scope": False,
    }
}
