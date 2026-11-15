"""
Realistic Mock Data Provider for Veracode Platform Sandbox Simulation.
Complies with Veracode AppSec REST and Findings v2 schemas.
Includes rich multi-sandbox data, mitigation statuses, descriptions, and dates.
"""
from typing import Dict, List, Any

MOCK_APPLICATIONS = [
    {
        "guid": "a1111111-2222-3333-4444-555555555551",
        "id": 100101,
        "name": "Payments Core Gateway API",
        "business_criticality": "Very High",
        "teams": ["Security-Fintech", "Core-Banking"],
        "policy_name": "PCI-DSS 4.0 Standard Policy",
        "last_completed_scan_date": "2026-11-12T08:30:00Z",
        "modified": "2026-11-14T14:20:00Z"
    },
    {
        "guid": "a1111111-2222-3333-4444-555555555552",
        "id": 100102,
        "name": "Customer Identity & Access Portal",
        "business_criticality": "High",
        "teams": ["IAM-Identity", "Frontline-Dev"],
        "policy_name": "Veracode Standard Flaw Policy",
        "last_completed_scan_date": "2026-11-10T16:45:00Z",
        "modified": "2026-11-13T09:15:00Z"
    },
    {
        "guid": "a1111111-2222-3333-4444-555555555553",
        "id": 100103,
        "name": "Supply Chain & Inventory Management",
        "business_criticality": "Medium",
        "teams": ["Operations-Logistics"],
        "policy_name": "Standard Enterprise Policy",
        "last_completed_scan_date": "2026-11-08T11:00:00Z",
        "modified": "2026-11-11T18:00:00Z"
    }
]

MOCK_SANDBOXES = {
    "a1111111-2222-3333-4444-555555555551": [
        {
            "guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "id": 5001,
            "name": "feature/jwt-rotation-hardening",
            "owner": "alice.security@enterprise.org",
            "created": "2026-10-20T10:00:00Z",
            "modified": "2026-11-14T19:35:00Z",
            "auto_recreate": False,
            "status": "READY",
            "application_id": 100101,
            "application_guid": "a1111111-2222-3333-4444-555555555551"
        },
        {
            "guid": "sb000001-aaaa-bbbb-cccc-222222222222",
            "id": 5002,
            "name": "dev-sprint-44-pci",
            "owner": "bob.developer@enterprise.org",
            "created": "2026-11-01T09:30:00Z",
            "modified": "2026-11-15T04:12:00Z",
            "auto_recreate": True,
            "status": "READY",
            "application_id": 100101,
            "application_guid": "a1111111-2222-3333-4444-555555555551"
        },
        {
            "guid": "sb000001-aaaa-bbbb-cccc-333333333333",
            "id": 5003,
            "name": "pr-892-crypto-upgrade",
            "owner": "carol.lead@enterprise.org",
            "created": "2026-11-13T12:00:00Z",
            "modified": "2026-11-15T09:20:00Z",
            "auto_recreate": False,
            "status": "SCANNING",
            "application_id": 100101,
            "application_guid": "a1111111-2222-3333-4444-555555555551"
        }
    ],
    "a1111111-2222-3333-4444-555555555552": [
        {
            "guid": "sb000002-aaaa-bbbb-cccc-111111111111",
            "id": 6001,
            "name": "mfa-webauthn-integration",
            "owner": "david.iam@enterprise.org",
            "created": "2026-10-15T14:00:00Z",
            "modified": "2026-11-12T11:45:00Z",
            "auto_recreate": True,
            "status": "READY",
            "application_id": 100102,
            "application_guid": "a1111111-2222-3333-4444-555555555552"
        }
    ],
    "a1111111-2222-3333-4444-555555555553": [
        {
            "guid": "sb000003-aaaa-bbbb-cccc-111111111111",
            "id": 7001,
            "name": "warehouse-rfid-sync",
            "owner": "eva.ops@enterprise.org",
            "created": "2026-11-05T08:00:00Z",
            "modified": "2026-11-11T17:30:00Z",
            "auto_recreate": False,
            "status": "READY",
            "application_id": 100103,
            "application_guid": "a1111111-2222-3333-4444-555555555553"
        }
    ]
}

MOCK_SANDBOX_STATUS = {
    "sb000001-aaaa-bbbb-cccc-111111111111": {
        "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
        "sandbox_name": "feature/jwt-rotation-hardening",
        "application_guid": "a1111111-2222-3333-4444-555555555551",
        "scan_status": "Results Ready",
        "lifecycle_stage": "Results Ready",
        "last_scan_date": "2026-11-14T19:35:12Z",
        "build_id": "9421038",
        "version": "v3.12.0-sbx-jwt-build-14",
        "is_scan_in_progress": False,
        "details": "Static & SCA scans completed successfully. No policy evaluation conducted (Sandbox Scope)."
    },
    "sb000001-aaaa-bbbb-cccc-222222222222": {
        "sandbox_guid": "sb000001-aaaa-bbbb-cccc-222222222222",
        "sandbox_name": "dev-sprint-44-pci",
        "application_guid": "a1111111-2222-3333-4444-555555555551",
        "scan_status": "Results Ready",
        "lifecycle_stage": "Results Ready",
        "last_scan_date": "2026-11-15T04:12:00Z",
        "build_id": "9421099",
        "version": "v3.12.1-sprint44-build-8",
        "is_scan_in_progress": False,
        "details": "Latest sandbox scan results compiled."
    },
    "sb000001-aaaa-bbbb-cccc-333333333333": {
        "sandbox_guid": "sb000001-aaaa-bbbb-cccc-333333333333",
        "sandbox_name": "pr-892-crypto-upgrade",
        "application_guid": "a1111111-2222-3333-4444-555555555551",
        "scan_status": "Scanning / Analysis in Progress",
        "lifecycle_stage": "Static Analysis Running (82%)",
        "last_scan_date": "2026-11-15T09:20:00Z",
        "build_id": "9421155",
        "version": "v3.13.0-pr892-build-1",
        "is_scan_in_progress": True,
        "details": "Engine is currently executing data-flow security rules across compiled bytecode."
    },
    "sb000002-aaaa-bbbb-cccc-111111111111": {
        "sandbox_guid": "sb000002-aaaa-bbbb-cccc-111111111111",
        "sandbox_name": "mfa-webauthn-integration",
        "application_guid": "a1111111-2222-3333-4444-555555555552",
        "scan_status": "Results Ready",
        "lifecycle_stage": "Results Ready",
        "last_scan_date": "2026-11-12T11:45:00Z",
        "build_id": "9419821",
        "version": "v2.4.0-webauthn-rc3",
        "is_scan_in_progress": False,
        "details": "Static & SCA scans completed."
    },
    "sb000003-aaaa-bbbb-cccc-111111111111": {
        "sandbox_guid": "sb000003-aaaa-bbbb-cccc-111111111111",
        "sandbox_name": "warehouse-rfid-sync",
        "application_guid": "a1111111-2222-3333-4444-555555555553",
        "scan_status": "Results Ready",
        "lifecycle_stage": "Results Ready",
        "last_scan_date": "2026-11-11T17:30:00Z",
        "build_id": "9417203",
        "version": "v1.8.0-rfid-build-22",
        "is_scan_in_progress": False,
        "details": "Completed sandbox scan."
    }
}

MOCK_FINDINGS = {
    # Sandbox 1: feature/jwt-rotation-hardening
    "sb000001-aaaa-bbbb-cccc-111111111111": [
        {
            "issue_id": 40101,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 5,
            "severity_label": "Very High",
            "category": "SQL Injection",
            "cwe_id": 89,
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": True,
            "file_path": "src/main/java/com/enterprise/payment/dao/TransactionDao.java",
            "file_name": "TransactionDao.java",
            "line_number": 142,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "User controlled string parameter 'accountNumber' is directly concatenated into a dynamic SQL query without parameterization.",
            "remediation_advice": "Use parameterized queries (PreparedStatement in Java or ORM query bindings) to neutralize special SQL characters.",
            "first_found_date": "2026-11-14T19:35:12Z"
        },
        {
            "issue_id": 40102,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 4,
            "severity_label": "High",
            "category": "Cross-Site Scripting (XSS)",
            "cwe_id": 79,
            "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Mitigation Proposed",
            "resolution_status": "PROPOSED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/payment/controller/ReceiptViewController.java",
            "file_name": "ReceiptViewController.java",
            "line_number": 88,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "Unescaped merchant notes parameter rendered directly to HTML response output.",
            "remediation_advice": "Employ contextual HTML entity encoding or standard template engine automated escaping.",
            "first_found_date": "2026-10-22T14:10:00Z"
        },
        {
            "issue_id": 40103,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 4,
            "severity_label": "High",
            "category": "Insecure Deserialization",
            "cwe_id": 502,
            "cwe_name": "Deserialization of Untrusted Data",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": True,
            "file_path": "src/main/java/com/enterprise/payment/util/ObjectPayloadSerializer.java",
            "file_name": "ObjectPayloadSerializer.java",
            "line_number": 64,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "ObjectInputStream.readObject() invoked on untrusted network stream without Look-Ahead Object validation.",
            "remediation_advice": "Use safer serialization formats (JSON with strict schema) or implement ValidatingObjectInputStream.",
            "first_found_date": "2026-11-14T19:35:12Z"
        },
        {
            "issue_id": 40104,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 3,
            "severity_label": "Medium",
            "category": "Path Traversal",
            "cwe_id": 22,
            "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Mitigation Approved",
            "resolution_status": "APPROVED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/payment/storage/ReceiptStorageService.java",
            "file_name": "ReceiptStorageService.java",
            "line_number": 215,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "File path constructed with user-supplied filename parameter allows parent directory traversal ('..').",
            "remediation_advice": "Normalize path using Path.normalize() and verify canonical path starts with intended base folder.",
            "first_found_date": "2026-11-02T11:20:00Z"
        },
        {
            "issue_id": 40105,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 3,
            "severity_label": "Medium",
            "category": "Cryptographic Issues",
            "cwe_id": 327,
            "cwe_name": "Use of a Broken or Risky Cryptographic Algorithm",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Mitigation Rejected",
            "resolution_status": "REJECTED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/payment/crypto/LegacyTokenHasher.java",
            "file_name": "LegacyTokenHasher.java",
            "line_number": 37,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "MessageDigest.getInstance('MD5') utilized for token signature verification.",
            "remediation_advice": "Migrate to SHA-256 or SHA-512 with HMAC, or key-derivation algorithms like Argon2/PBKDF2.",
            "first_found_date": "2026-10-20T10:00:00Z"
        },
        {
            "issue_id": 40106,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 2,
            "severity_label": "Low",
            "category": "Information Exposure",
            "cwe_id": 209,
            "cwe_name": "Generation of Error Message Containing Sensitive Information",
            "cve_id": None,
            "cvss": None,
            "status": "CLOSED",
            "mitigation_status": "Fixed / Resolved",
            "resolution_status": "RESOLVED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/payment/controller/GlobalExceptionHandler.java",
            "file_name": "GlobalExceptionHandler.java",
            "line_number": 49,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "Exception.printStackTrace() outputs internal server classpaths and system properties to client body.",
            "remediation_advice": "Catch exceptions and output sanitized generic error messages, routing detailed traces to protected logs.",
            "first_found_date": "2026-10-25T16:00:00Z"
        },
        {
            "issue_id": 40107,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 1,
            "severity_label": "Very Low",
            "category": "Code Quality",
            "cwe_id": 563,
            "cwe_name": "Assignment to Variable without Use ('Unused Variable')",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/payment/util/ValidationHelper.java",
            "file_name": "ValidationHelper.java",
            "line_number": 112,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "Intermediate payment confirmation flag initialized but never referenced.",
            "remediation_advice": "Remove dead code and unused variables.",
            "first_found_date": "2026-10-20T10:00:00Z"
        },
        {
            "issue_id": 40108,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SAST",
            "severity": 0,
            "severity_label": "Informational",
            "category": "Security Best Practice",
            "cwe_id": 1004,
            "cwe_name": "Sensitive Cookie Without 'HttpOnly' Flag",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/payment/config/CookieConfiguration.java",
            "file_name": "CookieConfiguration.java",
            "line_number": 28,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "Session tracking cookie generated without explicit HttpOnly attribute declaration.",
            "remediation_advice": "Set cookie.setHttpOnly(true) and cookie.setSecure(true).",
            "first_found_date": "2026-10-20T10:00:00Z"
        },

        # SCA Flaws (Software Composition Analysis)
        {
            "issue_id": 40201,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SCA",
            "severity": 5,
            "severity_label": "Very High",
            "category": "Vulnerable Third-Party Component",
            "cwe_id": 937,
            "cwe_name": "Using Components with Known Vulnerabilities",
            "cve_id": "CVE-2021-44228",
            "cvss": 10.0,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": False,
            "file_path": "pom.xml",
            "file_name": "log4j-core-2.14.1.jar",
            "line_number": None,
            "component_filename": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP endpoints (Log4Shell).",
            "remediation_advice": "Upgrade org.apache.logging.log4j:log4j-core to version 2.17.1 or higher.",
            "first_found_date": "2026-10-20T10:00:00Z"
        },
        {
            "issue_id": 40202,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SCA",
            "severity": 5,
            "severity_label": "Very High",
            "category": "Vulnerable Third-Party Component",
            "cwe_id": 937,
            "cwe_name": "Using Components with Known Vulnerabilities",
            "cve_id": "CVE-2022-22965",
            "cvss": 9.8,
            "status": "OPEN",
            "mitigation_status": "Mitigation Proposed",
            "resolution_status": "PROPOSED",
            "is_new": False,
            "file_path": "pom.xml",
            "file_name": "spring-beans-5.3.17.jar",
            "line_number": None,
            "component_filename": "org.springframework:spring-beans",
            "version": "5.3.17",
            "description": "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell) allows remote code execution via classloader manipulation.",
            "remediation_advice": "Upgrade org.springframework:spring-framework dependencies to version 5.3.18 / 5.2.20 or newer.",
            "first_found_date": "2026-10-20T10:00:00Z"
        },
        {
            "issue_id": 40203,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SCA",
            "severity": 4,
            "severity_label": "High",
            "category": "Vulnerable Third-Party Component",
            "cwe_id": 937,
            "cwe_name": "Using Components with Known Vulnerabilities",
            "cve_id": "CVE-2020-36187",
            "cvss": 7.5,
            "status": "OPEN",
            "mitigation_status": "Mitigation Approved",
            "resolution_status": "APPROVED",
            "is_new": True,
            "file_path": "pom.xml",
            "file_name": "jackson-databind-2.10.5.jar",
            "line_number": None,
            "component_filename": "com.fasterxml.jackson.core:jackson-databind",
            "version": "2.10.5",
            "description": "FasterXML jackson-databind mishandles the interaction between serialization gadgets and typing.",
            "remediation_advice": "Upgrade com.fasterxml.jackson.core:jackson-databind to 2.12.7.1 or 2.13.4.2.",
            "first_found_date": "2026-11-14T19:35:12Z"
        },
        {
            "issue_id": 40204,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SCA",
            "severity": 3,
            "severity_label": "Medium",
            "category": "Vulnerable Third-Party Component",
            "cwe_id": 937,
            "cwe_name": "Using Components with Known Vulnerabilities",
            "cve_id": "CVE-2021-3749",
            "cvss": 5.3,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": False,
            "file_path": "package.json",
            "file_name": "axios-0.21.1.tgz",
            "line_number": None,
            "component_filename": "axios",
            "version": "0.21.1",
            "description": "axios is vulnerable to Inefficient Regular Expression Complexity via the trim function.",
            "remediation_advice": "Upgrade axios to version >= 0.21.4.",
            "first_found_date": "2026-11-01T09:30:00Z"
        },
        {
            "issue_id": 40205,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "feature/jwt-rotation-hardening",
            "scan_type": "SCA",
            "severity": 2,
            "severity_label": "Low",
            "category": "Vulnerable Third-Party Component",
            "cwe_id": 937,
            "cwe_name": "Using Components with Known Vulnerabilities",
            "cve_id": "CVE-2022-25883",
            "cvss": 3.7,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": False,
            "file_path": "package.json",
            "file_name": "semver-7.3.5.tgz",
            "line_number": None,
            "component_filename": "semver",
            "version": "7.3.5",
            "description": "Regular Expression Denial of Service (ReDoS) vulnerability in semver.",
            "remediation_advice": "Upgrade semver to version 7.5.2 or above.",
            "first_found_date": "2026-10-20T10:00:00Z"
        }
    ],

    # Sandbox 2: dev-sprint-44-pci
    "sb000001-aaaa-bbbb-cccc-222222222222": [
        {
            "issue_id": 40301,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-222222222222",
            "sandbox_name": "dev-sprint-44-pci",
            "scan_type": "SAST",
            "severity": 4,
            "severity_label": "High",
            "category": "Hardcoded Credentials",
            "cwe_id": 798,
            "cwe_name": "Use of Hard-coded Credentials",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": True,
            "file_path": "src/main/resources/application-sandbox.properties",
            "file_name": "application-sandbox.properties",
            "line_number": 19,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "Hardcoded database password assigned directly in configuration file without vault integration.",
            "remediation_advice": "Extract credentials into an environment secret or Azure Key Vault / AWS Secrets Manager.",
            "first_found_date": "2026-11-15T04:12:00Z"
        },
        {
            "issue_id": 40302,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-222222222222",
            "sandbox_name": "dev-sprint-44-pci",
            "scan_type": "SAST",
            "severity": 3,
            "severity_label": "Medium",
            "category": "Improper Restriction of XML External Entity Reference ('XXE')",
            "cwe_id": 611,
            "cwe_name": "Improper Restriction of XML External Entity Reference",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Mitigation Proposed",
            "resolution_status": "PROPOSED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/payment/xml/PaymentXmlParser.java",
            "file_name": "PaymentXmlParser.java",
            "line_number": 53,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "XML parser configured without explicitly disabling DOCTYPE declarations and external DTDs.",
            "remediation_advice": "Configure DocumentBuilderFactory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true).",
            "first_found_date": "2026-11-05T12:00:00Z"
        },
        {
            "issue_id": 40303,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-222222222222",
            "sandbox_name": "dev-sprint-44-pci",
            "scan_type": "SCA",
            "severity": 4,
            "severity_label": "High",
            "category": "Vulnerable Third-Party Component",
            "cwe_id": 937,
            "cwe_name": "Using Components with Known Vulnerabilities",
            "cve_id": "CVE-2023-44487",
            "cvss": 7.5,
            "status": "OPEN",
            "mitigation_status": "Mitigation Approved",
            "resolution_status": "APPROVED",
            "is_new": False,
            "file_path": "pom.xml",
            "file_name": "netty-codec-http2-4.1.94.Final.jar",
            "line_number": None,
            "component_filename": "io.netty:netty-codec-http2",
            "version": "4.1.94.Final",
            "description": "HTTP/2 Rapid Reset attack (CVE-2023-44487) enables DDoS against server infrastructure.",
            "remediation_advice": "Update io.netty:netty-codec-http2 to 4.1.100.Final or newer.",
            "first_found_date": "2026-11-01T09:30:00Z"
        }
    ],

    # Sandbox 3: pr-892-crypto-upgrade
    "sb000001-aaaa-bbbb-cccc-333333333333": [
        {
            "issue_id": 40401,
            "sandbox_guid": "sb000001-aaaa-bbbb-cccc-333333333333",
            "sandbox_name": "pr-892-crypto-upgrade",
            "scan_type": "SAST",
            "severity": 3,
            "severity_label": "Medium",
            "category": "Cryptographic Issues",
            "cwe_id": 326,
            "cwe_name": "Inadequate Encryption Strength",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": True,
            "file_path": "src/main/java/com/enterprise/payment/crypto/KeyGeneratorUtil.java",
            "file_name": "KeyGeneratorUtil.java",
            "line_number": 24,
            "component_filename": "payment-core.jar",
            "version": None,
            "description": "RSA key length generated with 1024-bit modulus, which falls below NIST and PCI-DSS requirements.",
            "remediation_advice": "Enforce minimum RSA key size of 2048 or 4096 bits.",
            "first_found_date": "2026-11-15T09:20:00Z"
        }
    ],

    # Sandbox 4: mfa-webauthn-integration (in Customer Identity & Access Portal)
    "sb000002-aaaa-bbbb-cccc-111111111111": [
        {
            "issue_id": 50101,
            "application_guid": "a1111111-2222-3333-4444-555555555552",
            "application_name": "Customer Identity & Access Portal",
            "sandbox_guid": "sb000002-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "mfa-webauthn-integration",
            "scan_type": "SAST",
            "severity": 4,
            "severity_label": "High",
            "category": "Open Redirect",
            "cwe_id": 601,
            "cwe_name": "URL Redirection to Untrusted Site ('Open Redirect')",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": False,
            "file_path": "src/main/java/com/enterprise/iam/controller/LoginController.java",
            "file_name": "LoginController.java",
            "line_number": 118,
            "component_filename": "iam-portal.war",
            "version": None,
            "description": "User supplied redirect_uri parameter is forwarded without domain allowlist validation.",
            "remediation_advice": "Validate target redirect against an exact allowlist of domain URLs before redirecting.",
            "first_found_date": "2026-10-18T09:00:00Z"
        },
        {
            "issue_id": 50201,
            "application_guid": "a1111111-2222-3333-4444-555555555552",
            "application_name": "Customer Identity & Access Portal",
            "sandbox_guid": "sb000002-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "mfa-webauthn-integration",
            "scan_type": "SCA",
            "severity": 3,
            "severity_label": "Medium",
            "category": "Vulnerable Third-Party Component",
            "cwe_id": 937,
            "cwe_name": "Using Components with Known Vulnerabilities",
            "cve_id": "CVE-2023-34462",
            "cvss": 6.5,
            "status": "OPEN",
            "mitigation_status": "Mitigation Proposed",
            "resolution_status": "PROPOSED",
            "is_new": False,
            "file_path": "pom.xml",
            "file_name": "netty-handler-4.1.92.Final.jar",
            "line_number": None,
            "component_filename": "io.netty:netty-handler",
            "version": "4.1.92.Final",
            "description": "Netty SniHandler allocates excessive buffers upon receiving invalid client hellos causing potential DoS.",
            "remediation_advice": "Upgrade io.netty:netty-handler to 4.1.94.Final or later.",
            "first_found_date": "2026-10-22T15:30:00Z"
        }
    ],

    # Sandbox 5: warehouse-rfid-sync (in Supply Chain & Inventory Management)
    "sb000003-aaaa-bbbb-cccc-111111111111": [
        {
            "issue_id": 60101,
            "application_guid": "a1111111-2222-3333-4444-555555555553",
            "application_name": "Supply Chain & Inventory Management",
            "sandbox_guid": "sb000003-aaaa-bbbb-cccc-111111111111",
            "sandbox_name": "warehouse-rfid-sync",
            "scan_type": "SAST",
            "severity": 4,
            "severity_label": "High",
            "category": "Command Injection",
            "cwe_id": 78,
            "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "cve_id": None,
            "cvss": None,
            "status": "OPEN",
            "mitigation_status": "Unmitigated",
            "resolution_status": "UNRESOLVED",
            "is_new": True,
            "file_path": "src/services/rfid_scanner.py",
            "file_name": "rfid_scanner.py",
            "line_number": 42,
            "component_filename": "rfid-agent",
            "version": None,
            "description": "Device serial ID passed directly to subprocess.Popen(..., shell=True) without argument escaping.",
            "remediation_advice": "Pass arguments as a list with shell=False or use shlex.quote().",
            "first_found_date": "2026-11-11T17:30:00Z"
        }
    ]
}

def get_mock_applications() -> List[Dict]:
    return MOCK_APPLICATIONS

def get_mock_sandboxes(app_guid: str) -> List[Dict]:
    return MOCK_SANDBOXES.get(app_guid, [
        {
            "guid": f"sb-default-{app_guid[:8]}",
            "id": 9901,
            "name": "default-dev-sandbox",
            "owner": "engineer@enterprise.org",
            "created": "2026-11-01T10:00:00Z",
            "modified": "2026-11-14T12:00:00Z",
            "auto_recreate": False,
            "status": "READY",
            "application_id": 99999,
            "application_guid": app_guid
        }
    ])

def get_mock_sandbox_status(sandbox_guid: str, app_guid: str) -> Dict[str, Any]:
    if sandbox_guid in MOCK_SANDBOX_STATUS:
        return MOCK_SANDBOX_STATUS[sandbox_guid]
    return {
        "sandbox_guid": sandbox_guid,
        "sandbox_name": "sandbox",
        "application_guid": app_guid,
        "scan_status": "Results Ready",
        "lifecycle_stage": "Results Ready",
        "last_scan_date": "2026-11-14T18:00:00Z",
        "build_id": "9421000",
        "version": "v1.0.0-sandbox-build",
        "is_scan_in_progress": False,
        "details": "Latest sandbox scan completed. SAST & SCA results available."
    }

def get_mock_findings(sandbox_guid: str, scan_type: str = "ALL") -> List[Dict]:
    raw_list = MOCK_FINDINGS.get(sandbox_guid, MOCK_FINDINGS.get("sb000001-aaaa-bbbb-cccc-111111111111", []))
    default_module_map = {
        "sb000001-aaaa-bbbb-cccc-111111111111": "payment-core.jar",
        "sb000001-aaaa-bbbb-cccc-222222222222": "payment-api.war",
        "sb000001-aaaa-bbbb-cccc-333333333333": "payment-core.jar",
        "sb000002-aaaa-bbbb-cccc-111111111111": "iam-portal.war",
        "sb000003-aaaa-bbbb-cccc-111111111111": "rfid-inventory-agent.jar"
    }
    def_mod = default_module_map.get(sandbox_guid, "core-module.jar")
    
    findings = []
    for orig in raw_list:
        f = dict(orig)
        f["module"] = orig.get("module") or def_mod
        findings.append(f)

    if scan_type.upper() in ("STATIC", "SAST"):
        return [f for f in findings if f["scan_type"] == "SAST"]
    elif scan_type.upper() in ("SCA", "SOFTWARE_COMPOSITION_ANALYSIS"):
        return [f for f in findings if f["scan_type"] == "SCA"]
    return findings

def get_multi_mock_findings(sandbox_guids: List[str], scan_type: str = "ALL") -> List[Dict]:
    combined = []
    for s_guid in sandbox_guids:
        raw = get_mock_findings(s_guid, scan_type=scan_type)
        combined.extend(raw)
    return combined
