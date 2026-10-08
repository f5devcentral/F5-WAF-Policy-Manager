"""
F5 WAF for NGINX schema constants, violation catalogs,
server technologies, and metadata helpers.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

# Supported base templates in F5 WAF for NGINX
BASE_TEMPLATES = [
    "POLICY_TEMPLATE_NGINX_BASE",
    "POLICY_TEMPLATE_NGINX_STRICT",
]

# Supported violation categories for filtering and grouping
VIOLATION_CATEGORIES = [
    "All Categories",
    "Threats & Signatures",
    "HTTP Compliance",
    "Buffer & Sizing",
    "URLs & Routing",
    "Parameters & Input",
    "Cookies & Headers",
    "API & Formats",
    "gRPC & Protocol Buffers",
    "Data Privacy",
    "Access Control",
    "Violation Rating",
]

# Supported enforcement modes
ENFORCEMENT_MODES = ["blocking", "transparent"]

# Standard HTTP methods checked by F5 WAF
SUPPORTED_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
]

# Character encodings supported by F5 WAF
SUPPORTED_ENCODINGS = [
    "utf-8",
    "iso-8859-1",
    "iso-8859-2",
    "iso-8859-3",
    "iso-8859-4",
    "iso-8859-5",
    "iso-8859-6",
    "iso-8859-7",
    "iso-8859-8",
    "iso-8859-9",
    "iso-8859-10",
    "iso-8859-13",
    "iso-8859-15",
    "iso-8859-16",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-874",
    "big5",
    "gb2312",
    "gbk",
    "gb18030",
    "euc-jp",
    "euc-kr",
    "shift_jis",
    "koi8-r",
]

# Official 73 Server Technologies supported by F5 WAF for NGINX / Declarative WAF
OFFICIAL_SERVER_TECHNOLOGIES: List[str] = [
    "ASP",
    "ASP.NET",
    "AngularJS",
    "Apache Struts",
    "Apache Tomcat",
    "Apache/NCSA HTTP Server",
    "BEA Systems WebLogic Server",
    "Backbone.js",
    "CGI",
    "Cisco",
    "Citrix",
    "CodeIgniter",
    "CouchDB",
    "Django",
    "Elasticsearch",
    "Ember.js",
    "Express.js",
    "Front Page Server Extensions (FPSE)",
    "Google Web Toolkit",
    "GraphQL",
    "Handlebars",
    "IBM DB2",
    "IIS",
    "JBoss",
    "Java Servlets/JSP",
    "JavaScript",
    "JavaServer Faces (JSF)",
    "Jenkins",
    "Jetty",
    "Joomla",
    "Laravel",
    "Lotus Domino",
    "Macromedia ColdFusion",
    "Macromedia JRun",
    "Microsoft SQL Server",
    "Microsoft Windows",
    "MongoDB",
    "MooTools",
    "Mustache",
    "MySQL",
    "Nginx",
    "Node.js",
    "Novell",
    "Oracle",
    "Oracle Application Server",
    "Oracle Identity Manager",
    "Outlook Web Access",
    "PHP",
    "PostgreSQL",
    "Prototype",
    "Proxy Servers",
    "Python",
    "React",
    "Redis",
    "RequireJS",
    "Ruby",
    "SQLite",
    "SSI (Server Side Includes)",
    "SharePoint",
    "Spring Boot",
    "Sybase/ASE",
    "TYPO3 CMS",
    "UIKit",
    "Underscore.js",
    "Unix/Linux",
    "Vue.js",
    "WebDAV",
    "WordPress",
    "XML",
    "ZURB Foundation",
    "Zend",
    "ef.js",
    "jQuery",
]

OFFICIAL_SERVER_TECHNOLOGY_LOOKUP: Dict[str, str] = {
    name.lower(): name for name in OFFICIAL_SERVER_TECHNOLOGIES
}

SERVER_TECHNOLOGY_ALIASES: Dict[str, str] = {
    # Apache HTTP Server aliases
    "apache": "Apache/NCSA HTTP Server",
    "apache http server": "Apache/NCSA HTTP Server",
    "apache web server": "Apache/NCSA HTTP Server",
    "apache httpserver": "Apache/NCSA HTTP Server",
    "apache/ncsa": "Apache/NCSA HTTP Server",
    "apache ncsa": "Apache/NCSA HTTP Server",
    "httpd": "Apache/NCSA HTTP Server",
    "ncsa": "Apache/NCSA HTTP Server",
    # Microsoft IIS aliases
    "microsoft iis": "IIS",
    "ms iis": "IIS",
    "ms-iis": "IIS",
    "internet information services": "IIS",
    "microsoft internet information services": "IIS",
    # OS aliases
    "windows": "Microsoft Windows",
    "ms windows": "Microsoft Windows",
    "microsoft windows": "Microsoft Windows",
    "win": "Microsoft Windows",
    "linux": "Unix/Linux",
    "unix": "Unix/Linux",
    "linux/unix": "Unix/Linux",
    "unix-linux": "Unix/Linux",
    # Databases
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "mssql": "Microsoft SQL Server",
    "ms sql": "Microsoft SQL Server",
    "ms sql server": "Microsoft SQL Server",
    "sql server": "Microsoft SQL Server",
    "db2": "IBM DB2",
    "sybase": "Sybase/ASE",
    "oracle db": "Oracle",
    "oracle database": "Oracle",
    "elastic search": "Elasticsearch",
    "couchdb": "CouchDB",
    "sqlite": "SQLite",
    # Languages / Runtimes / Frameworks
    "node": "Node.js",
    "nodejs": "Node.js",
    "node js": "Node.js",
    "reactjs": "React",
    "react.js": "React",
    "vue": "Vue.js",
    "vuejs": "Vue.js",
    "angular": "AngularJS",
    "angular.js": "AngularJS",
    "backbone": "Backbone.js",
    "ember": "Ember.js",
    "express": "Express.js",
    "underscore": "Underscore.js",
    "tomcat": "Apache Tomcat",
    "struts": "Apache Struts",
    "spring": "Spring Boot",
    "springboot": "Spring Boot",
    "coldfusion": "Macromedia ColdFusion",
    "jrun": "Macromedia JRun",
    "weblogic": "BEA Systems WebLogic Server",
    "weblogic server": "BEA Systems WebLogic Server",
    "java": "Java Servlets/JSP",
    "jsp": "Java Servlets/JSP",
    "jsf": "JavaServer Faces (JSF)",
    "typo3": "TYPO3 CMS",
    "owa": "Outlook Web Access",
    "sharepoint": "SharePoint",
}

# Violations that cannot be configured directly under blocking-settings.violations in F5 WAF for NGINX
NON_CONFIGURABLE_VIOLATIONS: Set[str] = {
    "VIOL_ATTACK_SIGNATURE",
    "VIOL_BOT_CLIENT",
}

# Server Technologies recognized by F5 WAF for NGINX (with categories for UI catalog)
SERVER_TECHNOLOGIES = [
    {"name": "Apache/NCSA HTTP Server", "category": "Web Servers"},
    {"name": "IIS", "category": "Web Servers"},
    {"name": "Nginx", "category": "Web Servers"},
    {"name": "CGI", "category": "Web Servers"},
    {"name": "Proxy Servers", "category": "Web Servers"},
    {"name": "SSI (Server Side Includes)", "category": "Web Servers"},
    {"name": "WebDAV", "category": "Web Servers"},
    {"name": "Apache Tomcat", "category": "Application Servers"},
    {"name": "Apache Struts", "category": "Application Servers"},
    {"name": "BEA Systems WebLogic Server", "category": "Application Servers"},
    {"name": "JBoss", "category": "Application Servers"},
    {"name": "Jetty", "category": "Application Servers"},
    {"name": "Macromedia JRun", "category": "Application Servers"},
    {"name": "Macromedia ColdFusion", "category": "Application Servers"},
    {"name": "Oracle Application Server", "category": "Application Servers"},
    {"name": "ASP", "category": "Frameworks / Runtimes"},
    {"name": "ASP.NET", "category": "Frameworks / Runtimes"},
    {"name": "Django", "category": "Frameworks / Runtimes"},
    {"name": "Express.js", "category": "Frameworks / Runtimes"},
    {"name": "GraphQL", "category": "Frameworks / Runtimes"},
    {"name": "Java Servlets/JSP", "category": "Languages / Runtimes"},
    {"name": "JavaServer Faces (JSF)", "category": "Frameworks / Runtimes"},
    {"name": "Laravel", "category": "Frameworks / Runtimes"},
    {"name": "Node.js", "category": "Frameworks / Runtimes"},
    {"name": "PHP", "category": "Languages / Runtimes"},
    {"name": "Python", "category": "Languages / Runtimes"},
    {"name": "Ruby", "category": "Languages / Runtimes"},
    {"name": "Spring Boot", "category": "Frameworks / Runtimes"},
    {"name": "XML", "category": "Frameworks / Runtimes"},
    {"name": "Zend", "category": "Frameworks / Runtimes"},
    {"name": "AngularJS", "category": "Frontend Libraries"},
    {"name": "Backbone.js", "category": "Frontend Libraries"},
    {"name": "CodeIgniter", "category": "Frameworks / Runtimes"},
    {"name": "Ember.js", "category": "Frontend Libraries"},
    {"name": "Google Web Toolkit", "category": "Frameworks / Runtimes"},
    {"name": "Handlebars", "category": "Frontend Libraries"},
    {"name": "JavaScript", "category": "Languages / Runtimes"},
    {"name": "jQuery", "category": "Frontend Libraries"},
    {"name": "MooTools", "category": "Frontend Libraries"},
    {"name": "Mustache", "category": "Frontend Libraries"},
    {"name": "Prototype", "category": "Frontend Libraries"},
    {"name": "React", "category": "Frontend Libraries"},
    {"name": "RequireJS", "category": "Frontend Libraries"},
    {"name": "UIKit", "category": "Frontend Libraries"},
    {"name": "Underscore.js", "category": "Frontend Libraries"},
    {"name": "Vue.js", "category": "Frontend Libraries"},
    {"name": "ZURB Foundation", "category": "Frontend Libraries"},
    {"name": "ef.js", "category": "Frontend Libraries"},
    {"name": "CouchDB", "category": "Databases"},
    {"name": "Elasticsearch", "category": "Databases"},
    {"name": "IBM DB2", "category": "Databases"},
    {"name": "Microsoft SQL Server", "category": "Databases"},
    {"name": "MongoDB", "category": "Databases"},
    {"name": "MySQL", "category": "Databases"},
    {"name": "Oracle", "category": "Databases"},
    {"name": "PostgreSQL", "category": "Databases"},
    {"name": "Redis", "category": "Databases"},
    {"name": "SQLite", "category": "Databases"},
    {"name": "Sybase/ASE", "category": "Databases"},
    {"name": "Cisco", "category": "Operating Systems & Networking"},
    {"name": "Citrix", "category": "Operating Systems & Networking"},
    {"name": "Microsoft Windows", "category": "Operating Systems"},
    {"name": "Novell", "category": "Operating Systems & Networking"},
    {"name": "Unix/Linux", "category": "Operating Systems"},
    {"name": "Front Page Server Extensions (FPSE)", "category": "CMS & Applications"},
    {"name": "Jenkins", "category": "CMS & Applications"},
    {"name": "Joomla", "category": "CMS & Applications"},
    {"name": "Lotus Domino", "category": "CMS & Applications"},
    {"name": "Oracle Identity Manager", "category": "CMS & Applications"},
    {"name": "Outlook Web Access", "category": "CMS & Applications"},
    {"name": "SharePoint", "category": "CMS & Applications"},
    {"name": "TYPO3 CMS", "category": "CMS & Applications"},
    {"name": "WordPress", "category": "CMS & Applications"},
]

# Standard Attack Signature Sets supported by F5 WAF for NGINX
VALID_URL_CONTENT_PROFILE_TYPES: List[str] = [
    "json",
    "xml",
    "graphql",
    "grpc",
    "form-data",
    "gwt",
    "do-nothing",
]

DEFAULT_URL_CONTENT_PROFILE_PRESETS: Dict[str, Dict[str, Any]] = {
    "json": {
        "type": "json",
        "headerName": "Content-Type",
        "headerValue": "*json*",
        "headerOrder": "default",
        "contentProfile": {"name": "Default"},
    },
    "xml": {
        "type": "xml",
        "headerName": "Content-Type",
        "headerValue": "*xml*",
        "headerOrder": "default",
        "contentProfile": {"name": "Default"},
    },
    "graphql": {
        "type": "graphql",
        "headerName": "Content-Type",
        "headerValue": "*graphql*",
        "headerOrder": "default",
        "contentProfile": {"name": "Default"},
    },
    "grpc": {
        "type": "grpc",
        "headerName": "Content-Type",
        "headerValue": "*application/grpc*",
        "headerOrder": "default",
        "contentProfile": {"name": "Default"},
    },
    "form_data": {
        "type": "form-data",
        "headerName": "*",
        "headerValue": "*",
        "headerOrder": "default",
    },
    "do_nothing": {
        "type": "do-nothing",
        "headerName": "Content-Type",
        "headerValue": "*",
        "headerOrder": "default",
    },
}

STANDARD_SIGNATURE_SETS: List[Dict[str, Any]] = [
    # --- Default Template Predefined Signature Sets (18) ---
    {
        "name": "Command Execution Signatures",
        "category": "System & OS Attacks",
        "description": "Protects against OS command execution and shell invocation exploits (sh, bash, cmd.exe, PowerShell).",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "Cross Site Scripting Signatures",
        "category": "Application Attacks",
        "description": "Protects against reflected, stored, and DOM-based Cross-Site Scripting (XSS) payload injections.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "Directory Indexing Signatures",
        "category": "Information Gathering",
        "description": "Detects requests targeting server directory listings and indexing vulnerabilities.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "Information Leakage Signatures",
        "category": "Data Protection",
        "description": "Detects backend error exposures, database stack traces, and internal server leakages.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "OS Command Injection Signatures",
        "category": "System & OS Attacks",
        "description": "Detects command injection patterns and metacharacters targeting underlying operating system interpreters.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "Path Traversal Signatures",
        "category": "File & Resource Attacks",
        "description": "Detects path traversal sequences (../, %2e%2e, unicode variations) aiming to access restricted filesystem paths.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "Predictable Resource Location Signatures",
        "category": "Information Gathering",
        "description": "Detects scanners and crawlers searching for hidden administrative paths, backup files, and git repositories.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "Remote File Include Signatures",
        "category": "File & Resource Attacks",
        "description": "Detects attempts to include external remote malicious files or PHP wrapper streams.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "SQL Injection Signatures",
        "category": "Application Attacks",
        "description": "Protects against classic, union-based, stacked, error-based, and blind SQL injection exploits.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "Authentication/Authorization Attack Signatures",
        "category": "Access Control",
        "description": "Detects credential stuffing, broken authentication patterns, and privilege escalation payloads.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "XML External Entities (XXE) Signatures",
        "category": "XML & Web Services",
        "description": "Detects malicious XML entity expansion and external DTD references causing SSRF or data exfiltration.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "XPath Injection Signatures",
        "category": "XML & Web Services",
        "description": "Protects against XML query manipulation and XPath parameter injections.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "Buffer Overflow Signatures",
        "category": "System & OS Attacks",
        "description": "Detects oversized payload buffers and memory corruption attempts targeting web servers and modules.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "Denial of Service Signatures",
        "category": "Availability & DoS",
        "description": "Detects algorithmic complexity attacks, resource exhaustion, and application DoS patterns.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "Vulnerability Scan Signatures",
        "category": "Information Gathering",
        "description": "Detects reconnaissance activity from vulnerability scanners (e.g. Nessus, Qualys, Nikto, Acunetix, Burp).",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },
    {
        "name": "High Accuracy Signatures",
        "category": "Accuracy Levels",
        "description": "Signatures with high accuracy and very low risk of false positives. Recommended for active blocking in all production policies.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "Server Side Code Injection Signatures",
        "category": "Application Attacks",
        "description": "Detects unauthorized server-side code execution in PHP, Python, Java, Node.js, and Ruby.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": True,
    },
    {
        "name": "CVE Signatures",
        "category": "Vulnerability & CVE",
        "description": "Signatures mapped to specific Common Vulnerabilities and Exposures (CVEs) across common web platforms.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": True,
    },

    # --- Additional Official Predefined Signature Sets (12) ---
    {
        "name": "All Response Signatures",
        "category": "Response Protection",
        "description": "Comprehensive inspection of backend server responses for data leakage and error disclosure.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "All Signatures",
        "category": "Comprehensive Protection",
        "description": "Full collection of all attack signatures bundled in the F5 WAF compiler database.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "Generic Detection Signatures",
        "category": "Generic Threat Detection",
        "description": "Signatures detecting suspicious character sets, hex encodings, and common evasion sequences.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "Generic Detection Signatures (High Accuracy)",
        "category": "Generic Threat Detection",
        "description": "High-confidence generic threat detection signatures with minimal false positive risk.",
        "defaultAlarm": True,
        "defaultBlock": True,
        "templateDefault": False,
    },
    {
        "name": "Generic Detection Signatures (High/Medium Accuracy)",
        "category": "Generic Threat Detection",
        "description": "Broad generic detection signatures covering both high and medium accuracy threat patterns.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "Low Accuracy Signatures",
        "category": "Accuracy Levels",
        "description": "Broad heuristic pattern signatures with potential for higher false-positive rates.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "Medium Accuracy Signatures",
        "category": "Accuracy Levels",
        "description": "Signatures with balanced accuracy against known common attack vectors.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "OWA Signatures",
        "category": "Application Specific",
        "description": "Targeted attack signatures for Microsoft Outlook Web Access / Exchange applications.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "WebSphere signatures",
        "category": "Application Specific",
        "description": "Targeted attack signatures for IBM WebSphere Application Server environments.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "HTTP Response Splitting Signatures",
        "category": "Protocol & Parsing",
        "description": "Detects carriage return and line feed (CRLF) injection aiming at HTTP response splitting and cache poisoning.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "Other Application Attacks Signatures",
        "category": "Application Attacks",
        "description": "Signatures covering serialization exploits, WebDAV tampering, and general application-level threats.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
    {
        "name": "High Accuracy Detection Evasion Signatures",
        "category": "Evasion Techniques",
        "description": "Detects advanced obfuscation and evasive payload encoding with high accuracy.",
        "defaultAlarm": True,
        "defaultBlock": False,
        "templateDefault": False,
    },
]

# Set of all 30 officially recognized predefined signature set names in F5 WAF for NGINX
OFFICIAL_SIGNATURE_SET_NAMES: set[str] = {s["name"] for s in STANDARD_SIGNATURE_SETS}
OFFICIAL_SIGNATURE_SET_LOOKUP: dict[str, str] = {s["name"].lower(): s["name"] for s in STANDARD_SIGNATURE_SETS}

# Mapping of legacy / BIG-IP / colloquial aliases to official F5 WAF for NGINX names
SIGNATURE_SET_NAME_ALIASES: dict[str, str] = {
    # Directory Traversal
    "directory traversal signatures": "Path Traversal Signatures",
    "directory traversal": "Path Traversal Signatures",
    "path traversal": "Path Traversal Signatures",
    # Cross Site Scripting (hyphenated, unhyphenated, and parenthetical)
    "cross-site scripting signatures": "Cross Site Scripting Signatures",
    "cross-site scripting": "Cross Site Scripting Signatures",
    "cross site scripting": "Cross Site Scripting Signatures",
    "cross site scripting (xss) signatures": "Cross Site Scripting Signatures",
    "cross-site scripting (xss) signatures": "Cross Site Scripting Signatures",
    "xss signatures": "Cross Site Scripting Signatures",
    "xss": "Cross Site Scripting Signatures",
    # SQL Injection
    "sql-injection signatures": "SQL Injection Signatures",
    "sql-injection": "SQL Injection Signatures",
    "sql injection": "SQL Injection Signatures",
    "sqli signatures": "SQL Injection Signatures",
    "sqli": "SQL Injection Signatures",
    "sql-injection attacks": "SQL Injection Signatures",
    "sql injection attacks": "SQL Injection Signatures",
    # Server Side Code Injection & SSRF
    "server-side code injection signatures": "Server Side Code Injection Signatures",
    "server-side code injection": "Server Side Code Injection Signatures",
    "server side code injection": "Server Side Code Injection Signatures",
    "ssrf": "Server Side Code Injection Signatures",
    "server side request forgery": "Server Side Code Injection Signatures",
    "server-side request forgery": "Server Side Code Injection Signatures",
    # OS Command Injection
    "operating system command injection signatures": "OS Command Injection Signatures",
    "operating system command injection": "OS Command Injection Signatures",
    "os command injection": "OS Command Injection Signatures",
    "command execution": "Command Execution Signatures",
    # XML External Entities
    "xml external entity (xxe) signatures": "XML External Entities (XXE) Signatures",
    "xml external entity signatures": "XML External Entities (XXE) Signatures",
    "xml external entities signatures": "XML External Entities (XXE) Signatures",
    "xxe signatures": "XML External Entities (XXE) Signatures",
    "xxe": "XML External Entities (XXE) Signatures",
    # Authentication / Authorization
    "authentication / authorization attacks": "Authentication/Authorization Attack Signatures",
    "authentication/authorization attacks": "Authentication/Authorization Attack Signatures",
    "authentication and authorization attacks": "Authentication/Authorization Attack Signatures",
    "authentication/authorization attack": "Authentication/Authorization Attack Signatures",
    # WebSphere / OWA
    "websphere signatures": "WebSphere signatures",
    "websphere": "WebSphere signatures",
    "owa": "OWA Signatures",
    # Generic & Parser
    "high accuracy evasion signatures": "High Accuracy Detection Evasion Signatures",
    "http parser attack signatures": "Generic Detection Signatures",
    "http parser attacks": "Generic Detection Signatures",
    "http parser attack": "Generic Detection Signatures",
    "http response splitting": "HTTP Response Splitting Signatures",
    "other application attacks": "Other Application Attacks Signatures",
    "ldap injection": "Other Application Attacks Signatures",
    "ldap injection signatures": "Other Application Attacks Signatures",
    # Short names and abbreviations
    "directory indexing": "Directory Indexing Signatures",
    "information leakage": "Information Leakage Signatures",
    "remote file include": "Remote File Include Signatures",
    "remote file include (rfi) signatures": "Remote File Include Signatures",
    "remote file inclusion": "Remote File Include Signatures",
    "remote file inclusion signatures": "Remote File Include Signatures",
    "rfi signatures": "Remote File Include Signatures",
    "rfi": "Remote File Include Signatures",
    "predictable resource location": "Predictable Resource Location Signatures",
    "buffer overflow": "Buffer Overflow Signatures",
    "denial of service": "Denial of Service Signatures",
    "denial of service (dos) signatures": "Denial of Service Signatures",
    "dos signatures": "Denial of Service Signatures",
    "dos": "Denial of Service Signatures",
    "vulnerability scan": "Vulnerability Scan Signatures",
    "high accuracy": "High Accuracy Signatures",
    "low accuracy": "Low Accuracy Signatures",
    "medium accuracy": "Medium Accuracy Signatures",
    "cve": "CVE Signatures",
    "cve signatures": "CVE Signatures",
    "xpath injection": "XPath Injection Signatures",
    "all signatures": "All Signatures",
    "all response signatures": "All Response Signatures",
}


# Full catalog of F5 WAF for NGINX violations
VIOLATIONS_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "VIOL_ATTACK_SIGNATURE",
        "title": "Attack signature detected",
        "category": "Threats & Signatures",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": False,
        "description": "Examines HTTP messages for known attacks by matching against signature sets (OWASP Top 10, CVEs).",
    },
    {
        "name": "VIOL_THREAT_CAMPAIGN",
        "title": "Threat Campaign detected",
        "category": "Threats & Signatures",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Detects high-confidence active threat campaign attack patterns with near-zero false positives.",
    },
    {
        "name": "VIOL_BOT_CLIENT",
        "title": "Bot Client Detected",
        "category": "Threats & Signatures",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": False,
        "description": "Detects automated clients, scrapers, and classifies bot types.",
    },
    {
        "name": "VIOL_EVASION",
        "title": "Evasion technique detected",
        "category": "Threats & Signatures",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Detects evasion techniques such as directory traversal, multiple decoding, and bad escaped characters.",
    },
    {
        "name": "VIOL_RATING_THREAT",
        "title": "Request is likely a threat",
        "category": "Violation Rating",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Triggered when request violation rating is malicious (4 or 5). Blocks the request.",
    },
    {
        "name": "VIOL_RATING_NEED_EXAMINATION",
        "title": "Request needs further examination",
        "category": "Violation Rating",
        "defaultAlarm": False,
        "defaultBlock": False,
        "configurable": True,
        "description": "Triggered when request violation rating is suspicious (3). Enabled for strict environments.",
    },
    {
        "name": "VIOL_HTTP_PROTOCOL",
        "title": "HTTP protocol compliance failed",
        "category": "HTTP Compliance",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Validates RFC compliance for HTTP requests (GET with body, POST without length, bad headers).",
    },
    {
        "name": "VIOL_METHOD",
        "title": "Illegal method",
        "category": "HTTP Compliance",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Ensures HTTP method is in the allowed methods list defined in the policy.",
    },
    {
        "name": "VIOL_HTTP_RESPONSE_STATUS",
        "title": "Illegal HTTP response status",
        "category": "HTTP Compliance",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks server response status codes against permitted status code ranges.",
    },
    {
        "name": "VIOL_REQUEST_MAX_LENGTH",
        "title": "Request length exceeds buffer size",
        "category": "Buffer & Sizing",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests exceeding maximum buffer size (default 10 MB) to protect memory.",
    },
    {
        "name": "VIOL_REQUEST_LENGTH",
        "title": "Illegal request length",
        "category": "Buffer & Sizing",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks total request length against limits specified per file type.",
    },
    {
        "name": "VIOL_HEADER_LENGTH",
        "title": "Illegal header length",
        "category": "Buffer & Sizing",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Enforces upper limits on individual or total HTTP header lengths (default 4 KB).",
    },
    {
        "name": "VIOL_POST_DATA_LENGTH",
        "title": "Illegal POST data length",
        "category": "Buffer & Sizing",
        "defaultAlarm": False,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks that POST request body does not exceed configured size limits.",
    },
    {
        "name": "VIOL_QUERY_STRING_LENGTH",
        "title": "Illegal query string length",
        "category": "Buffer & Sizing",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks that query string does not exceed configured size (default 2 KB).",
    },
    {
        "name": "VIOL_URL_LENGTH",
        "title": "Illegal URL length",
        "category": "Buffer & Sizing",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks that the requested URL path does not exceed configured length limit.",
    },
    {
        "name": "VIOL_URL",
        "title": "Illegal URL",
        "category": "URLs & Routing",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Ensures requested URL is explicitly or wildcard permitted in the policy.",
    },
    {
        "name": "VIOL_URL_METACHAR",
        "title": "Illegal meta character in URL",
        "category": "URLs & Routing",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks that URL contains only allowed characters, blocking illegal metacharacters.",
    },
    {
        "name": "VIOL_FILETYPE",
        "title": "Illegal file type",
        "category": "URLs & Routing",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Blocks disallowed file extensions or enforces strict filetype allowlists.",
    },
    {
        "name": "VIOL_PARAMETER",
        "title": "Illegal parameter",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks that request parameters are defined in the policy parameter allowlist.",
    },
    {
        "name": "VIOL_PARAMETER_NAME_METACHAR",
        "title": "Illegal meta character in parameter name",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks parameter names for disallowed metacharacters (e.g. quotes, semicolons, control chars).",
    },
    {
        "name": "VIOL_PARAMETER_VALUE_METACHAR",
        "title": "Illegal meta character in value",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks parameter and element values for disallowed input characters.",
    },
    {
        "name": "VIOL_PARAMETER_DATA_TYPE",
        "title": "Illegal parameter data type",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Enforces defined data types (integer, email, phone) on parameter values.",
    },
    {
        "name": "VIOL_PARAMETER_VALUE_REGEXP",
        "title": "Parameter value does not comply with regex",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Enforces regex patterns configured for specific parameter validation.",
    },
    {
        "name": "VIOL_MANDATORY_PARAMETER",
        "title": "Mandatory parameter is missing",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Ensures parameters flagged as required are present in the request.",
    },
    {
        "name": "VIOL_PARAMETER_REPEATED",
        "title": "Illegal repeated parameter name",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Detects HTTP Parameter Pollution (HPP) when identical parameter names repeat.",
    },
    {
        "name": "VIOL_COOKIE_MALFORMED",
        "title": "Cookie not RFC-compliant",
        "category": "Cookies & Headers",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests containing malformed cookies (spaces, misplaced equals, control chars).",
    },
    {
        "name": "VIOL_COOKIE_MODIFIED",
        "title": "Modified domain cookie",
        "category": "Cookies & Headers",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Enforces cookie integrity on protected/enforced application cookies.",
    },
    {
        "name": "VIOL_ASM_COOKIE_MODIFIED",
        "title": "Modified ASM cookie",
        "category": "Cookies & Headers",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests where the WAF's internal tracking cookie has been tampered with.",
    },
    {
        "name": "VIOL_HEADER_METACHAR",
        "title": "Illegal meta character in header",
        "category": "Cookies & Headers",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Checks header names and values for malicious carriage returns or forbidden characters.",
    },
    {
        "name": "VIOL_JSON_MALFORMED",
        "title": "Malformed JSON data",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests with invalid or corrupted JSON payloads.",
    },
    {
        "name": "VIOL_JSON_FORMAT",
        "title": "JSON data does not comply with format settings",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Enforces JSON profile restrictions: depth limits, array counts, string lengths.",
    },
    {
        "name": "VIOL_JSON_SCHEMA",
        "title": "JSON data does not comply with JSON schema",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Enforces strict JSON schema validation for API endpoints.",
    },
    {
        "name": "VIOL_XML_MALFORMED",
        "title": "Malformed XML data",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests containing unparsable XML, entity expansion, or XML bombs.",
    },
    {
        "name": "VIOL_XML_FORMAT",
        "title": "XML data does not comply with format settings",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Enforces XML depth, maximum node count, and document length limits.",
    },
    {
        "name": "VIOL_GRAPHQL_MALFORMED",
        "title": "Malformed GraphQL data",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks syntax errors in GraphQL queries or variables.",
    },
    {
        "name": "VIOL_GRAPHQL_FORMAT",
        "title": "GraphQL format does not comply with settings",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Enforces GraphQL query depth, payload length, and batch query limits.",
    },
    {
        "name": "VIOL_GRPC_MALFORMED",
        "title": "Malformed gRPC data",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks unparsable or malformed Protocol Buffer / gRPC payloads.",
    },
    {
        "name": "VIOL_DATA_GUARD",
        "title": "Data Guard: Information leakage detected",
        "category": "Data Privacy",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Detects and masks sensitive data in responses (Credit Card Numbers, SSNs, custom regex).",
    },
    {
        "name": "VIOL_BLACKLISTED_IP",
        "title": "IP is in the deny list",
        "category": "Access Control",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks traffic from IP addresses or CIDR ranges configured in the IP deny list.",
    },
    {
        "name": "VIOL_GEOLOCATION",
        "title": "Disallowed Geolocations",
        "category": "Access Control",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests originating from prohibited country codes.",
    },
    {
        "name": "VIOL_ACCESS_INVALID",
        "title": "Access token does not comply with requirements",
        "category": "Access Control",
        "defaultAlarm": True,
        "defaultBlock": False,
        "configurable": True,
        "description": "Validates API access tokens and JWT structures according to access profiles.",
    },
    # OpenAPI / REST API specific violations
    {
        "name": "VIOL_MANDATORY_REQUEST_BODY",
        "title": "Mandatory request body is missing",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests where the OpenAPI schema specifies a required request body, but none was sent.",
    },
    {
        "name": "VIOL_PARAMETER_LOCATION",
        "title": "Illegal parameter location",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Triggered when a parameter arrives in an unexpected HTTP location (e.g. body instead of query or path).",
    },
    {
        "name": "VIOL_PARAMETER_NUMERIC_VALUE",
        "title": "Illegal parameter numeric value",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Enforces minimum, maximum, and multipleOf constraints defined in the OpenAPI schema on numbers.",
    },
    {
        "name": "VIOL_PARAMETER_VALUE_LENGTH",
        "title": "Illegal parameter value length",
        "category": "Buffer & Sizing",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Enforces minLength and maxLength constraints on parameter string values per OpenAPI schema.",
    },
    {
        "name": "VIOL_PARAMETER_STATIC_VALUE",
        "title": "Illegal static parameter value",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Enforces enum and static value restrictions specified for parameters in the OpenAPI schema.",
    },
    {
        "name": "VIOL_PARAMETER_EMPTY_VALUE",
        "title": "Illegal empty parameter value",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks empty values for parameters that specify allowEmptyValue: false in the OpenAPI schema.",
    },
    {
        "name": "VIOL_PARAMETER_ARRAY_VALUE",
        "title": "Illegal parameter array value",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Enforces minItems, maxItems, and uniqueItems constraints on parameter arrays in the OpenAPI schema.",
    },
    {
        "name": "VIOL_PARAMETER_VALUE_BASE64",
        "title": "Illegal Base64 value",
        "category": "Parameters & Input",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Validates that parameters specified as byte / base64 encoded comply with RFC 4648 encoding.",
    },
    {
        "name": "VIOL_URL_CONTENT_TYPE",
        "title": "Illegal request content type",
        "category": "URLs & Routing",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks requests whose Content-Type header does not match the consumes / media types defined in the OpenAPI schema.",
    },
    {
        "name": "VIOL_FILE_UPLOAD",
        "title": "Disallowed file upload content detected",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks file upload contents not conforming to permitted binary media types in the OpenAPI schema.",
    },
    {
        "name": "VIOL_FILE_UPLOAD_IN_BODY",
        "title": "Disallowed file upload content detected in body",
        "category": "API & Formats",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Blocks multipart and binary payloads detected where standard JSON or urlencoded data was expected.",
    },
    {
        "name": "VIOL_GRPC_MALFORMED",
        "title": "Malformed gRPC data detected",
        "category": "gRPC & Protocol Buffers",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Triggered when a gRPC message cannot be parsed according to expected protobuf definitions, unsupported compression, or exceeding 10MB buffer limit.",
    },
    {
        "name": "VIOL_GRPC_FORMAT",
        "title": "gRPC format or defense attributes violation",
        "category": "gRPC & Protocol Buffers",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Triggered when restrictions in the profile defenseAttributes (e.g. maximumDataLength exceeded or unauthorized unknown fields) are violated.",
    },
    {
        "name": "VIOL_GRPC_METHOD",
        "title": "Illegal or unlisted gRPC method",
        "category": "gRPC & Protocol Buffers",
        "defaultAlarm": True,
        "defaultBlock": True,
        "configurable": True,
        "description": "Triggered when a requested gRPC method is unrecognized or not present in the configured IDL (.proto) files.",
    },
]

# Standard OpenAPI recommended violations per F5 WAF for NGINX documentation
OPENAPI_RECOMMENDED_VIOLATIONS = [
    {"name": "VIOL_URL", "alarm": True, "block": True, "description": "Illegal URL"},
    {"name": "VIOL_METHOD", "alarm": True, "block": True, "description": "Illegal method"},
    {"name": "VIOL_PARAMETER", "alarm": True, "block": True, "description": "Illegal parameter"},
    {"name": "VIOL_PARAMETER_LOCATION", "alarm": True, "block": True, "description": "Illegal parameter location"},
    {"name": "VIOL_MANDATORY_PARAMETER", "alarm": True, "block": True, "description": "Mandatory parameter is missing"},
    {"name": "VIOL_MANDATORY_REQUEST_BODY", "alarm": True, "block": True, "description": "Mandatory request body is missing"},
    {"name": "VIOL_JSON_SCHEMA", "alarm": True, "block": True, "description": "JSON data does not comply with JSON schema"},
    {"name": "VIOL_PARAMETER_DATA_TYPE", "alarm": True, "block": True, "description": "Illegal parameter data type"},
    {"name": "VIOL_PARAMETER_NUMERIC_VALUE", "alarm": True, "block": True, "description": "Illegal parameter numeric value"},
    {"name": "VIOL_PARAMETER_VALUE_LENGTH", "alarm": True, "block": True, "description": "Illegal parameter value length"},
    {"name": "VIOL_PARAMETER_STATIC_VALUE", "alarm": True, "block": True, "description": "Illegal static parameter value"},
    {"name": "VIOL_PARAMETER_VALUE_REGEXP", "alarm": True, "block": True, "description": "Parameter value does not comply with regular expression"},
    {"name": "VIOL_PARAMETER_EMPTY_VALUE", "alarm": True, "block": True, "description": "Illegal empty parameter value"},
    {"name": "VIOL_PARAMETER_REPEATED", "alarm": True, "block": True, "description": "Illegal repeated parameter name"},
    {"name": "VIOL_PARAMETER_ARRAY_VALUE", "alarm": True, "block": True, "description": "Illegal parameter array value"},
    {"name": "VIOL_PARAMETER_VALUE_BASE64", "alarm": True, "block": True, "description": "Illegal Base64 value"},
    {"name": "VIOL_URL_CONTENT_TYPE", "alarm": True, "block": True, "description": "Illegal request content type"},
    {"name": "VIOL_FILE_UPLOAD", "alarm": True, "block": True, "description": "Disallowed file upload content detected"},
    {"name": "VIOL_FILE_UPLOAD_IN_BODY", "alarm": True, "block": True, "description": "Disallowed file upload content detected in body"},
]

# Standard gRPC recommended violations per F5 WAF for NGINX documentation
GRPC_RECOMMENDED_VIOLATIONS = [
    {"name": "VIOL_GRPC_MALFORMED", "alarm": True, "block": True, "description": "Malformed gRPC data detected"},
    {"name": "VIOL_GRPC_FORMAT", "alarm": True, "block": True, "description": "gRPC format or defense attributes violation"},
    {"name": "VIOL_GRPC_METHOD", "alarm": True, "block": True, "description": "Illegal or unlisted gRPC method"},
    {"name": "VIOL_METHOD", "alarm": True, "block": True, "description": "Illegal HTTP method (gRPC requires POST)"},
]


def extract_policy_metadata(raw_dict: Dict[str, Any], raw_size: int = 0) -> Dict[str, Any]:
    """Helper to extract high-level summary info from an F5 WAF policy dictionary."""
    policy_body = raw_dict.get("policy", {})
    if not isinstance(policy_body, dict):
        policy_body = {}

    name = policy_body.get("name") or "unnamed_policy"
    description = policy_body.get("description", "")
    
    template_obj = policy_body.get("template", {})
    template_name = template_obj.get("name", "POLICY_TEMPLATE_NGINX_BASE") if isinstance(template_obj, dict) else str(template_obj)
    
    enforcement_mode = policy_body.get("enforcementMode", "blocking")
    app_language = policy_body.get("applicationLanguage", "utf-8")
    
    blocking_settings = policy_body.get("blocking-settings", {})
    violations = blocking_settings.get("violations", []) if isinstance(blocking_settings, dict) else []
    
    signatures = policy_body.get("signatures", [])
    signature_sets = policy_body.get("signature-sets", [])
    server_technologies = policy_body.get("server-technologies", [])
    urls = policy_body.get("urls", [])
    parameters = policy_body.get("parameters", [])
    cookies = policy_body.get("cookies", [])
    data_guard = policy_body.get("data-guard", {})
    data_guard_enabled = data_guard.get("enabled", False) if isinstance(data_guard, dict) else False

    # Check Bot Defense
    bot_defense = policy_body.get("bot-defense") or policy_body.get("botDefense") or {}
    bot_defense_enabled = False
    if isinstance(bot_defense, dict):
        settings = bot_defense.get("settings", {})
        if isinstance(settings, dict):
            bot_defense_enabled = bool(settings.get("isEnabled", settings.get("enabled", False)))
        elif "isEnabled" in bot_defense:
            bot_defense_enabled = bool(bot_defense["isEnabled"])
        elif "enabled" in bot_defense:
            bot_defense_enabled = bool(bot_defense["enabled"])
    elif isinstance(bot_defense, bool):
        bot_defense_enabled = bot_defense

    # Check OpenAPI external references
    open_api_files = policy_body.get("open-api-files", [])
    open_api_ref = policy_body.get("openApiFileReference", {})
    has_openapi = False
    openapi_link = None
    openapi_type = None

    if isinstance(open_api_files, list) and len(open_api_files) > 0 and isinstance(open_api_files[0], dict):
        openapi_link = open_api_files[0].get("link")
        if openapi_link:
            has_openapi = True
    elif isinstance(open_api_ref, dict) and open_api_ref.get("link"):
        openapi_link = open_api_ref.get("link")
        has_openapi = True

    if openapi_link and isinstance(openapi_link, str):
        if openapi_link.startswith("file://"):
            openapi_type = "file"
        elif openapi_link.startswith(("http://", "https://")):
            openapi_type = "url"
        else:
            openapi_type = "unknown"

    # Check gRPC profiles & IDL files
    grpc_profiles = policy_body.get("grpc-profiles", [])
    idl_files = policy_body.get("idl-files", [])
    has_grpc = False
    grpc_primary_idl = None
    grpc_file_type = None

    if isinstance(grpc_profiles, list) and len(grpc_profiles) > 0:
        has_grpc = True
        first_prof = grpc_profiles[0]
        if isinstance(first_prof, dict):
            idls = first_prof.get("idlFiles", [])
            if isinstance(idls, list) and len(idls) > 0 and isinstance(idls[0], dict):
                first_idl = idls[0]
                idl_file = first_idl.get("idlFile", {})
                if isinstance(idl_file, dict):
                    grpc_primary_idl = idl_file.get("$ref") or idl_file.get("link") or idl_file.get("fileName")
                if first_idl.get("primaryIdlFileName"):
                    grpc_file_type = "archive"
                elif grpc_primary_idl and any(str(grpc_primary_idl).lower().endswith(ext) for ext in [".tar", ".tgz", ".tar.gz"]):
                    grpc_file_type = "archive"
                elif grpc_primary_idl and str(grpc_primary_idl).lower().endswith(".proto"):
                    grpc_file_type = "proto"
    elif isinstance(idl_files, list) and len(idl_files) > 0:
        has_grpc = True
        first_idl = idl_files[0]
        if isinstance(first_idl, dict):
            grpc_primary_idl = first_idl.get("link") or first_idl.get("fileName")
            if grpc_primary_idl and str(grpc_primary_idl).lower().endswith(".proto"):
                grpc_file_type = "proto"

    url_content_profiles_count = 0
    if isinstance(urls, list):
        for u in urls:
            if isinstance(u, dict) and isinstance(u.get("urlContentProfiles"), list):
                url_content_profiles_count += len(u["urlContentProfiles"])

    return {
        "name": name,
        "description": description,
        "template": template_name,
        "enforcementMode": enforcement_mode,
        "applicationLanguage": app_language,
        "violationsCount": len(violations) if isinstance(violations, list) else 0,
        "signaturesCount": len(signatures) if isinstance(signatures, list) else 0,
        "signatureSetsCount": len(signature_sets) if isinstance(signature_sets, list) else 0,
        "serverTechCount": len(server_technologies) if isinstance(server_technologies, list) else 0,
        "urlsCount": len(urls) if isinstance(urls, list) else 0,
        "urlContentProfilesCount": url_content_profiles_count,
        "parametersCount": len(parameters) if isinstance(parameters, list) else 0,
        "cookiesCount": len(cookies) if isinstance(cookies, list) else 0,
        "hasCookies": bool(isinstance(cookies, list) and len(cookies) > 0),
        "dataGuardEnabled": bool(data_guard_enabled),
        "botDefenseEnabled": bool(bot_defense_enabled),
        "hasOpenApi": bool(has_openapi),
        "openApiLink": openapi_link,
        "openApiType": openapi_type,
        "hasGrpc": bool(has_grpc),
        "grpcProfilesCount": len(grpc_profiles) if isinstance(grpc_profiles, list) else 0,
        "grpcPrimaryIdl": grpc_primary_idl,
        "grpcFileType": grpc_file_type,
        "sizeBytes": raw_size,
    }


def sanitize_waf_policy(policy_dict: Any, for_compilation: bool = False) -> Any:
    """Sanitize and normalize WAF policy structure to ensure clean compilation.
    Handles polymorphic nesting (recursively unwraps {"policy": {"policy": ...}}),
    strips non-standard fields like basicAuth under OpenAPI references,
    normalizes data-guard fields (creditCardNumbers, usSocialSecurityNumbers, maskData),
    strictly canonicalizes signature-sets (migrates Threat Campaigns to VIOL_THREAT_CAMPAIGN,
    maps aliases to official names, validates custom sets, and strips unknown predefined sets
    to prevent SQLite PLC.NEGSIG_SET_SIGNATURES foreign key failures in apcompile),
    filters out non-configurable violations (VIOL_ATTACK_SIGNATURE, VIOL_BOT_CLIENT) from blocking-settings,
    and normalizes server-technologies (maps aliases such as 'Apache' -> 'Apache/NCSA HTTP Server',
    'Microsoft IIS' -> 'IIS', and prunes unrecognized names to prevent SQLite PL_SERVER_TECHNOLOGIES NOT NULL failures).
    If for_compilation is True, also strips non-declarative fields (custom-signatures, user-defined-signatures)
    which must be passed as separate user-signatures files via '-s' to apcompile.
    """
    if not isinstance(policy_dict, dict):
        return policy_dict

    had_wrapper = "policy" in policy_dict and isinstance(policy_dict["policy"], dict)
    pol = policy_dict
    while isinstance(pol, dict) and "policy" in pol and isinstance(pol["policy"], dict):
        pol = pol["policy"]

    if not isinstance(pol, dict):
        return policy_dict

    if for_compilation:
        pol.pop("custom-signatures", None)
        pol.pop("user-defined-signatures", None)

    if "open-api-files" in pol and isinstance(pol["open-api-files"], list):
        for item in pol["open-api-files"]:
            if isinstance(item, dict):
                item.pop("basicAuth", None)
    if "openApiFileReference" in pol and isinstance(pol["openApiFileReference"], dict):
        pol["openApiFileReference"].pop("basicAuth", None)

    # Normalize data-guard
    if "data-guard" in pol and isinstance(pol["data-guard"], dict):
        dg = pol["data-guard"]
        if "maskCreditCardNumbersInResponse" in dg:
            legacy_val = dg.pop("maskCreditCardNumbersInResponse")
            if "creditCardNumbers" not in dg:
                dg["creditCardNumbers"] = bool(legacy_val)
        if "maskUssnInResponse" in dg:
            legacy_val = dg.pop("maskUssnInResponse")
            if "usSocialSecurityNumbers" not in dg:
                dg["usSocialSecurityNumbers"] = bool(legacy_val)
        if isinstance(dg.get("customPatterns"), list):
            patterns = dg.pop("customPatterns")
            if "customPatternsList" not in dg:
                dg["customPatternsList"] = patterns
            dg["customPatterns"] = len(patterns) > 0
        if "maskData" not in dg and dg.get("enabled"):
            dg["maskData"] = True
        if "enforcementMode" not in dg and dg.get("enabled"):
            dg["enforcementMode"] = "ignore-urls-in-list"
        if "enforcementUrls" not in dg and dg.get("enabled"):
            dg["enforcementUrls"] = []

    # Normalize signature-sets
    if "signature-sets" in pol and isinstance(pol["signature-sets"], list):
        sanitized_sets = []
        for sset in pol["signature-sets"]:
            if not isinstance(sset, dict):
                continue
            s_name = (sset.get("name") or "").strip()
            if not s_name:
                continue

            # If 'Threat Campaigns' was incorrectly added to signature-sets,
            # remove it and enable VIOL_THREAT_CAMPAIGN in blocking-settings
            s_name_norm = s_name.lower().replace("-", " ").replace("_", " ")
            if s_name_norm in ("threat campaigns", "threat campaign"):
                bs = pol.setdefault("blocking-settings", {})
                if isinstance(bs, dict):
                    viols = bs.setdefault("violations", [])
                    if isinstance(viols, list):
                        tc_viol = next(
                            (v for v in viols if isinstance(v, dict) and v.get("name") == "VIOL_THREAT_CAMPAIGN"),
                            None,
                        )
                        if tc_viol:
                            tc_viol["alarm"] = bool(sset.get("alarm", True))
                            tc_viol["block"] = bool(sset.get("block", True))
                        else:
                            viols.append({
                                "name": "VIOL_THREAT_CAMPAIGN",
                                "alarm": bool(sset.get("alarm", True)),
                                "block": bool(sset.get("block", True)),
                            })
                continue

            # If HTTP Parser Attack Signatures was used, map to Generic Detection Signatures
            if s_name.lower() in ("http parser attack signatures", "http parser attack", "http parser attacks"):
                s_name = "Generic Detection Signatures"

            # Normalize alias names to official predefined names (with case-insensitive resolution)
            s_lower = s_name.lower()
            if s_lower in SIGNATURE_SET_NAME_ALIASES:
                s_name = SIGNATURE_SET_NAME_ALIASES[s_lower]
            elif s_lower in OFFICIAL_SIGNATURE_SET_LOOKUP:
                s_name = OFFICIAL_SIGNATURE_SET_LOOKUP[s_lower]
            sset["name"] = s_name

            # If signatures or filter was placed directly at root of sset, move into signatureSet
            if "signatureSet" not in sset and ("filter" in sset or "signatures" in sset):
                sset["signatureSet"] = {}
                if "filter" in sset:
                    sset["signatureSet"]["filter"] = sset.pop("filter")
                if "signatures" in sset:
                    sset["signatureSet"]["signatures"] = sset.pop("signatures")

            # If custom signatureSet is present, ensure type is inferred if missing
            if "signatureSet" in sset and isinstance(sset["signatureSet"], dict):
                cs = sset["signatureSet"]
                if not cs.get("type"):
                    if "filter" in cs:
                        cs["type"] = "filter-based"
                    elif "signatures" in cs:
                        cs["type"] = "manual"

                # Normalize attackType in filter if it's a string
                if isinstance(cs.get("filter"), dict):
                    f = cs["filter"]
                    if "attackType" in f and isinstance(f["attackType"], str):
                        f["attackType"] = {"name": f["attackType"]}

                # Normalize signatures in manual set
                if isinstance(cs.get("signatures"), list):
                    normalized_sigs = []
                    for item in cs["signatures"]:
                        if isinstance(item, dict) and "signatureId" in item:
                            try:
                                normalized_sigs.append({"signatureId": int(item["signatureId"])})
                            except (ValueError, TypeError):
                                pass
                        elif isinstance(item, (int, str)):
                            try:
                                normalized_sigs.append({"signatureId": int(item)})
                            except (ValueError, TypeError):
                                pass
                    cs["signatures"] = normalized_sigs

                # Strip incomplete or empty custom signatureSet objects that would fail compilation
                if not cs.get("filter") and not cs.get("signatures"):
                    continue
            elif s_name not in OFFICIAL_SIGNATURE_SET_NAMES:
                # Predefined set with unknown name will fail SQLite foreign key insert in apcompile
                # (DBD::SQLite::db do failed: FOREIGN KEY constraint failed at BatchInsert.pm line 243)
                # Omit invalid predefined set so the policy compiles cleanly
                continue

            sanitized_sets.append(sset)
        pol["signature-sets"] = sanitized_sets

    # Normalize blocking-settings violations (strip non-configurable violations)
    if "blocking-settings" in pol and isinstance(pol["blocking-settings"], dict):
        bs = pol["blocking-settings"]
        if "violations" in bs and isinstance(bs["violations"], list):
            bs["violations"] = [
                v for v in bs["violations"]
                if not (isinstance(v, dict) and v.get("name") in NON_CONFIGURABLE_VIOLATIONS)
            ]

    # Normalize server-technologies (resolve aliases and omit unrecognized names that fail SQLite NOT NULL constraint)
    if "server-technologies" in pol and isinstance(pol["server-technologies"], list):
        sanitized_techs = []
        seen_tech_names = set()
        for item in pol["server-technologies"]:
            t_name = ""
            if isinstance(item, str):
                t_name = item.strip()
            elif isinstance(item, dict):
                t_name = (item.get("serverTechnologyName") or item.get("name") or "").strip()
            if not t_name:
                continue
            t_lower = t_name.lower()
            if t_lower in SERVER_TECHNOLOGY_ALIASES:
                t_name = SERVER_TECHNOLOGY_ALIASES[t_lower]
            elif t_lower in OFFICIAL_SERVER_TECHNOLOGY_LOOKUP:
                t_name = OFFICIAL_SERVER_TECHNOLOGY_LOOKUP[t_lower]

            if t_name in OFFICIAL_SERVER_TECHNOLOGIES:
                if t_name not in seen_tech_names:
                    seen_tech_names.add(t_name)
                    sanitized_techs.append({"serverTechnologyName": t_name})
            else:
                # Omit unrecognized server technology to avoid SQLite NOT NULL constraint failure:
                # PL_SERVER_TECHNOLOGIES.server_technology_id
                pass
        pol["server-technologies"] = sanitized_techs

    # Normalize cookies
    if "cookies" in pol and isinstance(pol["cookies"], list):
        sanitized_cookies = []
        for c in pol["cookies"]:
            if not isinstance(c, dict):
                continue
            c_name = (c.get("name") or "").strip()
            if not c_name:
                continue
            item = {"name": c_name}
            # Auto-infer wildcard type if '*' is in name
            c_type = c.get("type")
            if c_type in ("explicit", "wildcard"):
                item["type"] = c_type
            elif "*" in c_name:
                item["type"] = "wildcard"
            else:
                item["type"] = "explicit"

            enf = str(c.get("enforcementType", "")).strip().lower()
            if enf in ("enforce", "allow"):
                item["enforcementType"] = enf
            if "attackSignaturesCheck" in c:
                item["attackSignaturesCheck"] = bool(c["attackSignaturesCheck"])
            if "maskValueInLogs" in c:
                item["maskValueInLogs"] = bool(c["maskValueInLogs"])
            if "accessibleOnlyThroughTheHttpProtocol" in c:
                item["accessibleOnlyThroughTheHttpProtocol"] = bool(c["accessibleOnlyThroughTheHttpProtocol"])
            sanitized_cookies.append(item)
        pol["cookies"] = sanitized_cookies

    # Normalize cookie-settings
    if "cookie-settings" in pol and isinstance(pol["cookie-settings"], dict):
        cs = pol["cookie-settings"]
        if "maximumCookieHeaderLength" in cs:
            try:
                cs["maximumCookieHeaderLength"] = int(cs["maximumCookieHeaderLength"])
            except (ValueError, TypeError):
                pass

    return {"policy": pol} if had_wrapper else pol


# Catalog of authentic F5 WAF attack signatures
ATTACK_SIGNATURES_CATALOG: List[Dict[str, Any]] = [
    # --- SQL Injection ---
    {
        "signatureId": 200001475,
        "name": "SQL-Injection in URI - UNION SELECT",
        "attackType": "SQL-Injection",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Generic", "MySQL", "PostgreSQL", "Oracle"],
        "cve": None,
        "description": "Detects UNION SELECT payload structures in request URI attempting to extract data from arbitrary tables.",
        "signatureSets": ["High Accuracy Signatures", "SQL Injection Signatures"],
    },
    {
        "signatureId": 200000012,
        "name": "SQL-Injection in parameter - stacked queries",
        "attackType": "SQL-Injection",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Generic", "MSSQL", "PostgreSQL"],
        "cve": None,
        "description": "Detects semicolon followed by DDL/DML commands (DROP, ALTER, UPDATE) enabling stacked SQL statement execution.",
        "signatureSets": ["High Accuracy Signatures", "SQL Injection Signatures"],
    },
    {
        "signatureId": 200000019,
        "name": "SQL-Injection - Boolean-based blind (OR 1=1 / AND 1=1)",
        "attackType": "SQL-Injection",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects tautological boolean conditions used to manipulate query logic and extract data bit-by-bit.",
        "signatureSets": ["High Accuracy Signatures", "SQL Injection Signatures"],
    },
    {
        "signatureId": 200000025,
        "name": "SQL-Injection - Time-based blind delay (WAITFOR DELAY / SLEEP)",
        "attackType": "SQL-Injection",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic", "MSSQL", "PostgreSQL", "MySQL"],
        "cve": None,
        "description": "Detects conditional delay functions (SLEEP, WAITFOR DELAY, pg_sleep) in SQL payloads.",
        "signatureSets": ["High Accuracy Signatures", "SQL Injection Signatures"],
    },
    {
        "signatureId": 200001480,
        "name": "SQL-Injection - Error-based extractvalue / updatexml",
        "attackType": "SQL-Injection",
        "accuracy": "Medium",
        "risk": "High",
        "systems": ["MySQL"],
        "cve": None,
        "description": "Detects XML manipulation functions in MySQL deliberately fed invalid XPath syntax to leak database contents.",
        "signatureSets": ["Medium Accuracy Signatures", "SQL Injection Signatures"],
    },
    {
        "signatureId": 200001488,
        "name": "SQL-Injection - Hex-encoded SQL payload in parameter",
        "attackType": "SQL-Injection",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects hex notation sequences (0x...) representing encoded keywords or strings to bypass naive filters.",
        "signatureSets": ["Medium Accuracy Signatures", "SQL Injection Signatures"],
    },
    {
        "signatureId": 200001499,
        "name": "SQL-Injection - Quotation mark and comment heuristics",
        "attackType": "SQL-Injection",
        "accuracy": "Low",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Heuristic check for unpaired quotation marks followed by SQL comment markers (-- or /*). Higher potential for false positives.",
        "signatureSets": ["Low Accuracy Signatures", "SQL Injection Signatures"],
    },

    # --- Cross Site Scripting (XSS) ---
    {
        "signatureId": 200000098,
        "name": "Cross Site Scripting (XSS) in query parameter - script tag",
        "attackType": "Cross Site Scripting (XSS)",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects raw or encoded <script> HTML tags inside request query parameters or POST bodies.",
        "signatureSets": ["High Accuracy Signatures", "Cross Site Scripting Signatures"],
    },
    {
        "signatureId": 200000101,
        "name": "Cross Site Scripting (XSS) - Inline DOM event handlers",
        "attackType": "Cross Site Scripting (XSS)",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects HTML attributes with JavaScript handlers (onload, onerror, onmouseover, onclick) injected into inputs.",
        "signatureSets": ["High Accuracy Signatures", "Cross Site Scripting Signatures"],
    },
    {
        "signatureId": 200000115,
        "name": "Cross Site Scripting (XSS) - javascript: pseudo-protocol",
        "attackType": "Cross Site Scripting (XSS)",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects the javascript: pseudo-protocol in href, src, or action attributes in requests.",
        "signatureSets": ["High Accuracy Signatures", "Cross Site Scripting Signatures"],
    },
    {
        "signatureId": 200000122,
        "name": "Cross Site Scripting (XSS) - SVG / XML embedded script injection",
        "attackType": "Cross Site Scripting (XSS)",
        "accuracy": "Medium",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects SVG vectors containing CDATA blocks or embedded script payloads.",
        "signatureSets": ["Medium Accuracy Signatures", "Cross Site Scripting Signatures"],
    },
    {
        "signatureId": 200000130,
        "name": "Cross Site Scripting (XSS) - Base64 encoded payload in data: URL",
        "attackType": "Cross Site Scripting (XSS)",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects data:text/html;base64 payloads designed to execute client-side scripts in modern browsers.",
        "signatureSets": ["Medium Accuracy Signatures", "Cross Site Scripting Signatures"],
    },
    {
        "signatureId": 200000139,
        "name": "Cross Site Scripting (XSS) - Generic HTML angle bracket heuristic",
        "attackType": "Cross Site Scripting (XSS)",
        "accuracy": "Low",
        "risk": "Low",
        "systems": ["Generic"],
        "cve": None,
        "description": "Broad heuristic pattern detecting unescaped angle brackets (< and >) in text fields.",
        "signatureSets": ["Low Accuracy Signatures", "Cross Site Scripting Signatures"],
    },

    # --- Command Execution ---
    {
        "signatureId": 200002011,
        "name": "OS Command Injection - /bin/sh or /bin/bash shell invocation",
        "attackType": "Command Execution",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Unix/Linux"],
        "cve": None,
        "description": "Detects direct invocation of Unix shell interpreters (/bin/sh, /bin/bash, /bin/dash) in input parameters.",
        "signatureSets": ["High Accuracy Signatures", "Command Execution Signatures"],
    },
    {
        "signatureId": 200002015,
        "name": "OS Command Injection - cmd.exe / powershell.exe execution",
        "attackType": "Command Execution",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Windows"],
        "cve": None,
        "description": "Detects Windows command line or PowerShell executable invocations in request parameters.",
        "signatureSets": ["High Accuracy Signatures", "Command Execution Signatures"],
    },
    {
        "signatureId": 200002022,
        "name": "OS Command Injection - Pipe and command chaining (| ; ` &)",
        "attackType": "Command Execution",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects shell command separator characters followed by common system utilities (id, whoami, uname, cat).",
        "signatureSets": ["High Accuracy Signatures", "Command Execution Signatures"],
    },
    {
        "signatureId": 200002030,
        "name": "OS Command Injection - Wget / cURL remote payload download",
        "attackType": "Command Execution",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Unix/Linux"],
        "cve": None,
        "description": "Detects wget or curl commands fetching remote files and piping directly to shell execution (curl | sh).",
        "signatureSets": ["High Accuracy Signatures", "Command Execution Signatures"],
    },
    {
        "signatureId": 200002045,
        "name": "OS Command Injection - Reverse shell netcat / socat payload",
        "attackType": "Command Execution",
        "accuracy": "Medium",
        "risk": "Critical",
        "systems": ["Unix/Linux"],
        "cve": None,
        "description": "Detects netcat (-e /bin/sh) or socat commands configured to spawn interactive reverse shells.",
        "signatureSets": ["Medium Accuracy Signatures", "Command Execution Signatures"],
    },

    # --- Directory Traversal ---
    {
        "signatureId": 200000104,
        "name": "Directory Traversal - /../ or ..\\ sequence",
        "attackType": "Directory Traversal",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects standard path traversal sequences attempting to break out of web application document root directories.",
        "signatureSets": ["High Accuracy Signatures", "Path Traversal Signatures"],
    },
    {
        "signatureId": 200000108,
        "name": "Directory Traversal - Encoded dot-dot-slash (%2e%2e%2f)",
        "attackType": "Directory Traversal",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects URL-encoded or double-encoded path traversal characters used to bypass normalizers.",
        "signatureSets": ["High Accuracy Signatures", "Path Traversal Signatures"],
    },
    {
        "signatureId": 200000112,
        "name": "Directory Traversal - /etc/passwd or /etc/shadow access attempt",
        "attackType": "Directory Traversal",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Unix/Linux"],
        "cve": None,
        "description": "Detects direct file retrieval paths aiming at Unix sensitive authentication and user databases.",
        "signatureSets": ["High Accuracy Signatures", "Path Traversal Signatures"],
    },
    {
        "signatureId": 200000118,
        "name": "Directory Traversal - Windows C:\\Windows\\win.ini or boot.ini access",
        "attackType": "Directory Traversal",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Windows"],
        "cve": None,
        "description": "Detects attempts to read foundational Windows configuration and system state files.",
        "signatureSets": ["High Accuracy Signatures", "Path Traversal Signatures"],
    },
    {
        "signatureId": 200000125,
        "name": "Directory Traversal - Relative path traversal with null byte (%00)",
        "attackType": "Directory Traversal",
        "accuracy": "Medium",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects null byte poisoning (%00) combined with relative path traversal to bypass file extension checks.",
        "signatureSets": ["Medium Accuracy Signatures", "Path Traversal Signatures"],
    },

    # --- Threat Campaigns (Zero-Day & High Confidence) ---
    {
        "signatureId": 300001001,
        "name": "Apache Log4j Remote Code Execution JNDI Lookup (CVE-2021-44228)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Java"],
        "cve": "CVE-2021-44228",
        "description": "Detects Log4j JNDI lookup strings (${jndi:ldap://, ${jndi:rmi://) across URIs, headers, and request bodies.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures"],
    },
    {
        "signatureId": 300001002,
        "name": "Spring4Shell DataBinder Class Loader RCE (CVE-2022-22965)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Java", "Spring"],
        "cve": "CVE-2022-22965",
        "description": "Detects class.module.classLoader property manipulation targeting Spring Framework running on Tomcat.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures"],
    },
    {
        "signatureId": 300001003,
        "name": "MOVEit Transfer SQLi / Remote Code Execution (CVE-2023-34362)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Windows", "IIS"],
        "cve": "CVE-2023-34362",
        "description": "Detects HTTP headers and parameter exploits targeting the Progress MOVEit Transfer SQL injection flaw.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures", "SQL Injection Signatures"],
    },
    {
        "signatureId": 300001004,
        "name": "Citrix Bleed Sensitive Information Disclosure (CVE-2023-4966)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Citrix", "Web Servers"],
        "cve": "CVE-2023-4966",
        "description": "Detects buffer overflow requests targeting NetScaler / Citrix Gateway leading to session token leakage.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures"],
    },
    {
        "signatureId": 300001005,
        "name": "F5 BIG-IP iControl REST Remote Code Execution (CVE-2022-1388)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["F5 BIG-IP"],
        "cve": "CVE-2022-1388",
        "description": "Detects authorization header manipulation (X-F5-Auth-Token, Connection: keep-alive) exploiting iControl REST.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures"],
    },
    {
        "signatureId": 300001006,
        "name": "Atlassian Confluence OGNL Expression Injection (CVE-2022-26134)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Java"],
        "cve": "CVE-2022-26134",
        "description": "Detects unauthenticated OGNL expression payloads in Confluence URL paths enabling command execution.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures"],
    },
    {
        "signatureId": 300001007,
        "name": "OpenSSL Bleichenbacher RSA Bleed (CVE-2023-44487)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "High",
        "systems": ["OpenSSL"],
        "cve": "CVE-2023-44487",
        "description": "Detects malformed TLS negotiation sequences attempting padding oracle decryption.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures"],
    },
    {
        "signatureId": 300001008,
        "name": "Apache Struts Jakarta Multipart Parser RCE (CVE-2017-5638)",
        "attackType": "Threat Campaigns",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Apache", "Java"],
        "cve": "CVE-2017-5638",
        "description": "Detects OGNL commands in Content-Type headers exploiting Struts 2 multipart file upload parsing.",
        "signatureSets": ["High Accuracy Signatures", "CVE Signatures"],
    },

    # --- Predictable Resource Location ---
    {
        "signatureId": 200000215,
        "name": "Predictable Resource Location - .git/config access attempt",
        "attackType": "Predictable Resource Location",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects HTTP probes requesting exposed Git repository metadata files (.git/config, .git/HEAD).",
        "signatureSets": ["High Accuracy Signatures", "Predictable Resource Location Signatures"],
    },
    {
        "signatureId": 200000220,
        "name": "Predictable Resource Location - .env / configuration backup file exposure",
        "attackType": "Predictable Resource Location",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects requests targeting .env, settings.py, or web.config backup files containing secrets.",
        "signatureSets": ["High Accuracy Signatures", "Predictable Resource Location Signatures"],
    },
    {
        "signatureId": 200000225,
        "name": "Predictable Resource Location - Admin console paths (/phpmyadmin, /wp-admin)",
        "attackType": "Predictable Resource Location",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["PHP", "Apache", "Nginx"],
        "cve": None,
        "description": "Detects crawlers scanning for unhardened database administration tools and CMS backends.",
        "signatureSets": ["Medium Accuracy Signatures", "Predictable Resource Location Signatures"],
    },
    {
        "signatureId": 200000230,
        "name": "Predictable Resource Location - Source code backup (.bak, .old, .swp)",
        "attackType": "Predictable Resource Location",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects requests for editor temporary swap files and manual archive files (.zip, .tar.gz).",
        "signatureSets": ["Medium Accuracy Signatures", "Predictable Resource Location Signatures"],
    },

    # --- HTTP Parser Attack ---
    {
        "signatureId": 200001880,
        "name": "HTTP Request Smuggling - Transfer-Encoding vs Content-Length conflict",
        "attackType": "HTTP Parser Attack",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Web Servers"],
        "cve": None,
        "description": "Detects requests containing conflicting Transfer-Encoding and Content-Length headers (TE.CL / CL.TE).",
        "signatureSets": ["High Accuracy Signatures", "Generic Detection Signatures"],
    },
    {
        "signatureId": 200001885,
        "name": "HTTP Request Smuggling - Dual Transfer-Encoding header obfuscation",
        "attackType": "HTTP Parser Attack",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Web Servers"],
        "cve": None,
        "description": "Detects duplicate Transfer-Encoding headers with trailing whitespace or casing evasion.",
        "signatureSets": ["High Accuracy Signatures", "Generic Detection Signatures"],
    },
    {
        "signatureId": 200001890,
        "name": "HTTP Header Injection - CRLF / Response Splitting in headers",
        "attackType": "HTTP Parser Attack",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects carriage return and line feed characters (\\r\\n / %0d%0a) injected into header values.",
        "signatureSets": ["High Accuracy Signatures", "HTTP Response Splitting Signatures"],
    },
    {
        "signatureId": 200001895,
        "name": "HTTP Request Smuggling - Chunked transfer extension evasion",
        "attackType": "HTTP Parser Attack",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Web Servers"],
        "cve": None,
        "description": "Detects non-standard chunk extensions designed to desynchronize frontend proxy and backend servers.",
        "signatureSets": ["Medium Accuracy Signatures", "Generic Detection Signatures"],
    },

    # --- Server Side Code Injection ---
    {
        "signatureId": 200003001,
        "name": "PHP Code Injection - eval() / assert() execution",
        "attackType": "Server Side Code Injection",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["PHP"],
        "cve": None,
        "description": "Detects arbitrary PHP code execution payloads calling eval(), assert(), or preg_replace with /e modifier.",
        "signatureSets": ["High Accuracy Signatures", "Server Side Code Injection Signatures"],
    },
    {
        "signatureId": 200003010,
        "name": "Python Code Injection - __import__ / os.system execution",
        "attackType": "Server Side Code Injection",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Python"],
        "cve": None,
        "description": "Detects Python code injection payloads invoking builtins (__import__, getattr, eval, subprocess).",
        "signatureSets": ["High Accuracy Signatures", "Server Side Code Injection Signatures"],
    },
    {
        "signatureId": 200003020,
        "name": "Java Expression Language (EL) Injection (${...} / #{...})",
        "attackType": "Server Side Code Injection",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Java"],
        "cve": None,
        "description": "Detects Java EL expressions evaluating Runtime.getRuntime().exec() via reflected class loaders.",
        "signatureSets": ["High Accuracy Signatures", "Server Side Code Injection Signatures"],
    },
    {
        "signatureId": 200003030,
        "name": "Node.js Code Injection - child_process.exec invocation",
        "attackType": "Server Side Code Injection",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Node.js"],
        "cve": None,
        "description": "Detects JavaScript expressions inside inputs executing process.mainModule.require('child_process').",
        "signatureSets": ["High Accuracy Signatures", "Server Side Code Injection Signatures"],
    },

    # --- Information Leakage ---
    {
        "signatureId": 200004001,
        "name": "Database Error Leakage - MySQL / Postgres syntax error in response",
        "attackType": "Information Leakage",
        "accuracy": "High",
        "risk": "Medium",
        "systems": ["MySQL", "PostgreSQL"],
        "cve": None,
        "description": "Detects responses containing database engine error messages and SQL syntax disclosures.",
        "signatureSets": ["High Accuracy Signatures", "Information Leakage Signatures"],
    },
    {
        "signatureId": 200004010,
        "name": "Stack Trace Exposure - Java / .NET unhandled exception trace",
        "attackType": "Information Leakage",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Java", "ASP.NET"],
        "cve": None,
        "description": "Detects application stack traces leaking code paths, frameworks, and database schema names.",
        "signatureSets": ["Medium Accuracy Signatures", "Information Leakage Signatures"],
    },
    {
        "signatureId": 200004020,
        "name": "Server Version Banner Leakage - Sensitive X-Powered-By tokens",
        "attackType": "Information Leakage",
        "accuracy": "Medium",
        "risk": "Low",
        "systems": ["Apache", "Nginx", "IIS"],
        "cve": None,
        "description": "Detects specific server software version disclosure banners in responses.",
        "signatureSets": ["Medium Accuracy Signatures", "Information Leakage Signatures"],
    },

    # --- XPath Injection ---
    {
        "signatureId": 200005001,
        "name": "XPath Injection - ' or '1'='1 in XML search query",
        "attackType": "XPath Injection",
        "accuracy": "High",
        "risk": "High",
        "systems": ["XML & Web Services"],
        "cve": None,
        "description": "Detects boolean manipulation in XPath expressions targeting XML document repositories.",
        "signatureSets": ["High Accuracy Signatures", "XPath Injection Signatures"],
    },
    {
        "signatureId": 200005010,
        "name": "XPath Injection - Malicious count() or substring() boolean extraction",
        "attackType": "XPath Injection",
        "accuracy": "Medium",
        "risk": "High",
        "systems": ["XML & Web Services"],
        "cve": None,
        "description": "Detects XPath node counting and character extraction functions used for blind XML data extraction.",
        "signatureSets": ["Medium Accuracy Signatures", "XPath Injection Signatures"],
    },

    # --- XML External Entity (XXE) ---
    {
        "signatureId": 200002441,
        "name": "XML External Entity (XXE) - SYSTEM entity referencing local file URI",
        "attackType": "XML External Entity (XXE)",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["XML & Web Services"],
        "cve": None,
        "description": "Detects DOCTYPE declarations declaring external SYSTEM entities pointing to local files (file:///etc/passwd).",
        "signatureSets": ["High Accuracy Signatures", "XML External Entities (XXE) Signatures"],
    },
    {
        "signatureId": 200002445,
        "name": "XML External Entity (XXE) - Parameter entity out-of-band SSRF",
        "attackType": "XML External Entity (XXE)",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["XML & Web Services"],
        "cve": None,
        "description": "Detects XML parameter entities (% entity) used for out-of-band data exfiltration over HTTP/DNS.",
        "signatureSets": ["High Accuracy Signatures", "XML External Entities (XXE) Signatures"],
    },
    {
        "signatureId": 200002450,
        "name": "XML Entity Expansion - Billion Laughs Denial of Service (BOMB)",
        "attackType": "XML External Entity (XXE)",
        "accuracy": "High",
        "risk": "High",
        "systems": ["XML & Web Services"],
        "cve": None,
        "description": "Detects nested recursive XML entity declarations designed to cause parser memory exhaustion.",
        "signatureSets": ["High Accuracy Signatures", "XML External Entities (XXE) Signatures"],
    },

    # --- Authentication / Authorization Attacks ---
    {
        "signatureId": 200006001,
        "name": "JWT Signature Stripping - alg: none token tampering",
        "attackType": "Authentication / Authorization",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects JSON Web Tokens in headers modified with algorithm none to bypass signature verification.",
        "signatureSets": ["High Accuracy Signatures", "Authentication/Authorization Attack Signatures"],
    },
    {
        "signatureId": 200006010,
        "name": "Credential Stuffing Tool Pattern in login parameters",
        "attackType": "Authentication / Authorization",
        "accuracy": "Medium",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects automated credential dictionary and wordlist attack formats in authentication requests.",
        "signatureSets": ["Medium Accuracy Signatures", "Authentication/Authorization Attack Signatures"],
    },
    {
        "signatureId": 200006020,
        "name": "HTTP Authorization Header Spoofing / brute-force probe",
        "attackType": "Authentication / Authorization",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects sequential default credentials or malformed Basic Auth payloads.",
        "signatureSets": ["Medium Accuracy Signatures", "Authentication/Authorization Attack Signatures"],
    },

    # --- Remote File Include ---
    {
        "signatureId": 200001923,
        "name": "PHP Remote File Inclusion - http:// or ftp:// in include parameter",
        "attackType": "Remote File Include",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["PHP"],
        "cve": None,
        "description": "Detects remote URL schemes passed into file-inclusion parameters (include, require, load).",
        "signatureSets": ["High Accuracy Signatures", "Remote File Include Signatures"],
    },
    {
        "signatureId": 200001930,
        "name": "PHP Stream Wrapper - php://input or php://filter injection",
        "attackType": "Remote File Include",
        "accuracy": "High",
        "risk": "High",
        "systems": ["PHP"],
        "cve": None,
        "description": "Detects attempts to execute raw POST data via php://input or leak source code using php://filter.",
        "signatureSets": ["High Accuracy Signatures", "Remote File Include Signatures"],
    },
    {
        "signatureId": 200001940,
        "name": "Data URI Remote Code Inclusion - data:text/plain;base64",
        "attackType": "Remote File Include",
        "accuracy": "Medium",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects data: stream wrappers used to execute encoded server-side code.",
        "signatureSets": ["Medium Accuracy Signatures", "Remote File Include Signatures"],
    },

    # --- Vulnerability Scan ---
    {
        "signatureId": 200000340,
        "name": "Vulnerability Scanner User-Agent - Nikto / OpenVAS / Nessus / Qualys",
        "attackType": "Vulnerability Scan",
        "accuracy": "High",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects scanner identities and probe signatures from commercial and open-source vulnerability scanners.",
        "signatureSets": ["High Accuracy Signatures", "Vulnerability Scan Signatures"],
    },
    {
        "signatureId": 200000345,
        "name": "Web Application Scanner - Acunetix / AppScan / Netsparker probes",
        "attackType": "Vulnerability Scan",
        "accuracy": "High",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects proprietary audit tokens and test payload formats generated by DAST scanners.",
        "signatureSets": ["High Accuracy Signatures", "Vulnerability Scan Signatures"],
    },
    {
        "signatureId": 200000350,
        "name": "Exploit Framework Tool - sqlmap / Metasploit automated headers",
        "attackType": "Vulnerability Scan",
        "accuracy": "High",
        "risk": "High",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects automated exploit toolkit headers and fingerprinting sequences.",
        "signatureSets": ["High Accuracy Signatures", "Vulnerability Scan Signatures"],
    },

    # --- Other Application Attacks ---
    {
        "signatureId": 200007001,
        "name": "Insecure Deserialization - Java ysoserial gadget payload",
        "attackType": "Other Application Attacks",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Java"],
        "cve": None,
        "description": "Detects serialized Java gadget chains (CommonsCollections, Spring, Jackson) causing remote code execution.",
        "signatureSets": ["High Accuracy Signatures", "Other Application Attacks Signatures"],
    },
    {
        "signatureId": 200007010,
        "name": "WebDAV HTTP Method Tampering (PROPFIND / SEARCH / MKCOL)",
        "attackType": "Other Application Attacks",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Web Servers"],
        "cve": None,
        "description": "Detects abuse of WebDAV extensions to traverse file systems or upload unauthorized executable assets.",
        "signatureSets": ["Medium Accuracy Signatures", "Other Application Attacks Signatures"],
    },
    {
        "signatureId": 200007020,
        "name": "Server-Side Request Forgery (SSRF) - Cloud Metadata 169.254.169.254 query",
        "attackType": "Other Application Attacks",
        "accuracy": "High",
        "risk": "Critical",
        "systems": ["Cloud / AWS / GCP / Azure"],
        "cve": None,
        "description": "Detects requests targeting internal link-local cloud instance metadata services to harvest IAM credentials.",
        "signatureSets": ["High Accuracy Signatures", "Other Application Attacks Signatures"],
    },

    # --- Generic Threat Detection ---
    {
        "signatureId": 200008001,
        "name": "Generic Suspicious Hex Encoding Sequence (%00 null byte injection)",
        "attackType": "Generic Detection",
        "accuracy": "High",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects null byte characters (%00) used to terminate C-strings in native application layers.",
        "signatureSets": ["High Accuracy Signatures", "Generic Detection Signatures"],
    },
    {
        "signatureId": 200008010,
        "name": "Generic Multiple URL Encoding Evasion",
        "attackType": "Generic Detection",
        "accuracy": "Medium",
        "risk": "Medium",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects layered or double URL encoding patterns intended to evade pattern inspection engines.",
        "signatureSets": ["Medium Accuracy Signatures", "Generic Detection Signatures"],
    },
    {
        "signatureId": 200008020,
        "name": "Excessive Non-ASCII Character Density in URI",
        "attackType": "Generic Detection",
        "accuracy": "Low",
        "risk": "Low",
        "systems": ["Generic"],
        "cve": None,
        "description": "Detects URI paths with an abnormal ratio of non-printable or high-byte ASCII characters.",
        "signatureSets": ["Low Accuracy Signatures", "Generic Detection Signatures"],
    },
]


def get_signatures_for_set(set_name: str, filter_criteria: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Return all attack signatures belonging to a specific signature set or matching filter criteria."""
    name_clean = (set_name or "").strip()
    name_lower = name_clean.lower()

    # 1. If filter criteria is provided (e.g. custom signature set)
    if filter_criteria and isinstance(filter_criteria, dict):
        results = []
        tag_val = (filter_criteria.get("tagValue") or "").strip().lower()
        attack_type_obj = filter_criteria.get("attackType") or {}
        attack_type_val = ""
        if isinstance(attack_type_obj, dict):
            attack_type_val = (attack_type_obj.get("name") or "").strip().lower()
        elif isinstance(attack_type_obj, str):
            attack_type_val = attack_type_obj.strip().lower()

        for sig in ATTACK_SIGNATURES_CATALOG:
            match = True
            if tag_val:
                sig_cve = (sig.get("cve") or "").lower()
                sig_name = sig.get("name", "").lower()
                sig_desc = sig.get("description", "").lower()
                if tag_val not in sig_cve and tag_val not in sig_name and tag_val not in sig_desc:
                    match = False
            if match and attack_type_val:
                sig_type = sig.get("attackType", "").lower()
                if attack_type_val not in sig_type:
                    match = False
            if match:
                results.append(sig)
        if results:
            return results

    # 2. Match standard signature sets
    matches: List[Dict[str, Any]] = []

    # Accuracy sets
    if name_lower == "high accuracy signatures":
        return [s for s in ATTACK_SIGNATURES_CATALOG if s.get("accuracy") == "High"]
    if name_lower == "medium accuracy signatures":
        return [s for s in ATTACK_SIGNATURES_CATALOG if s.get("accuracy") in ("High", "Medium")]
    if name_lower == "low accuracy signatures":
        return [s for s in ATTACK_SIGNATURES_CATALOG if s.get("accuracy") == "Low"]

    # Explicit signatureSets mapping
    for sig in ATTACK_SIGNATURES_CATALOG:
        assigned_sets = [s.lower() for s in sig.get("signatureSets", [])]
        if name_lower in assigned_sets:
            matches.append(sig)

    if matches:
        return matches

    # Substring heuristic match on attackType or set name
    for sig in ATTACK_SIGNATURES_CATALOG:
        attack_type_lower = sig.get("attackType", "").lower()
        # strip "signatures" from name for relaxed matching
        stem = name_lower.replace("signatures", "").strip()
        if stem and (stem in attack_type_lower or stem in sig.get("name", "").lower()):
            matches.append(sig)

    return matches


# =============================================================================
# User-Defined Signatures (Custom Signatures) Official Definitions & Templates
# Official documentation: https://docs.nginx.com/waf/policies/user-signatures/#signatures
# =============================================================================

DEFAULT_USER_SIGNATURE_DEFINITIONS: Dict[str, Any] = {
    "softwareVersion": "15.1.0",
    "tag": "Fruits",
    "revisionDatetime": "2020-01-22T18:32:02Z",
    "signatures": [
        {
            "name": "Apple_medium_acc",
            "rule": 'content:"apple"; nocase;',
            "signatureType": "request",
            "attackType": {"name": "Buffer Overflow"},
            "systems": [
                {"name": "Microsoft Windows"},
                {"name": "Unix/Linux"},
            ],
            "risk": "medium",
            "accuracy": "medium",
            "description": "Medium accuracy user defined signature with tag (Fruits)",
        },
        {
            "name": "Banana_high_acc",
            "rule": 'content:"banana"; nocase;',
            "signatureType": "request",
            "attackType": {"name": "Command Execution"},
            "systems": [
                {"name": "Unix/Linux"},
            ],
            "risk": "high",
            "accuracy": "high",
            "description": "High accuracy user defined signature detecting banana exploit pattern",
        },
    ],
}

SNORT_RULE_TEMPLATES: List[Dict[str, str]] = [
    {
        "name": "Simple String Match (Official Fruits Example)",
        "description": "Scans payload or URI for specific string ignoring letter case (official documentation sample).",
        "snippet": 'content:"apple"; nocase;',
    },
    {
        "name": "URI Path Match (uricontent + objonly)",
        "description": "Inspects normalized URI path exclusively, ignoring query string parameters.",
        "snippet": 'uricontent:"/admin/debug"; objonly; nocase;',
    },
    {
        "name": "HTTP Header Inspection (headercontent)",
        "description": "Examines incoming HTTP request headers for specific attack indicators or auth tokens.",
        "snippet": 'headercontent:"X-Debug-Probe"; nocase;',
    },
    {
        "name": "Bot User-Agent Detection (useragentonly)",
        "description": "Narrows header inspection strictly to the HTTP User-Agent header for bot identification.",
        "snippet": 'headercontent:"MyMaliciousBot"; useragentonly; nocase;',
    },
    {
        "name": "Parameter Value with Evasion Normalization (valuecontent + norm)",
        "description": "Matches within user-input parameters and applies anti-evasion normalization (XSS/SQLi).",
        "snippet": 'valuecontent:"union select"; norm; nocase;',
    },
    {
        "name": "Regular Expression (PCRE)",
        "description": "Applies Perl-Compatible Regular Expression (PCRE) with case-insensitive matching.",
        "snippet": 'pcre:"/(?:select|union|insert).*(?:from|into)/i";',
    },
    {
        "name": "High-Performance RE2 Regular Expression",
        "description": "Applies Google RE2 regex syntax optimized for high-throughput pattern matching.",
        "snippet": 're2:"/soda;\\s+bar/i";',
    },
    {
        "name": "Special Character Escaping (Hex |20| |3B| |22|)",
        "description": "Uses pipe escaping (|XX|) to safely match spaces (|20|), semicolons (|3B|), or quotes (|22|).",
        "snippet": 'content:"SELECT|20|*|20|FROM"; nocase;',
    },
    {
        "name": "Chained Relative Tokens (distance & within)",
        "description": "Matches a second keyword within a bounded byte distance after the first keyword.",
        "snippet": 'content:"exec"; distance:0; within:60; content:"cmd.exe"; nocase;',
    },
    {
        "name": "Response Body Information Leakage",
        "description": "Inspects outbound HTTP responses for stack traces, database errors, or secret leaks.",
        "snippet": 'content:"Fatal error: Uncaught exception"; nocase;',
    },
]


CUSTOM_SIGNATURE_ATTACK_TYPES: List[str] = [
    "Buffer Overflow",
    "Command Execution",
    "Cross Site Scripting (XSS)",
    "SQL Injection",
    "Path Traversal",
    "Server-Side Request Forgery (SSRF)",
    "Brute Force Attack",
    "Authentication / Authorization Attacks",
    "Remote File Include",
    "XPath Injection",
    "XML External Entity (XXE)",
    "HTTP Parser Attack",
    "Information Leakage",
    "Server Side Code Injection",
    "Vulnerability Scan",
    "Predictable Resource Location",
    "Other Application Attacks",
    "Generic Detection",
]


def extract_custom_signatures_metadata(doc: Optional[Dict[str, Any]], size_bytes: int = 0) -> Dict[str, Any]:
    """Extract summary metadata for a user-defined signatures definition file."""
    if not isinstance(doc, dict):
        return {
            "tag": "unnamed",
            "signatures_count": 0,
            "revisionDatetime": "",
            "softwareVersion": "",
            "size_bytes": size_bytes,
            "attack_types": [],
            "systems": [],
        }

    tag = doc.get("tag") or "user-defined-signatures"
    sigs = doc.get("signatures", []) if isinstance(doc.get("signatures"), list) else []
    rev = doc.get("revisionDatetime", "")
    version = doc.get("softwareVersion", "")

    attack_types = set()
    systems = set()
    for s in sigs:
        if isinstance(s, dict):
            at = s.get("attackType")
            if isinstance(at, dict) and at.get("name"):
                attack_types.add(at["name"])
            elif isinstance(at, str) and at:
                attack_types.add(at)
            for sys in s.get("systems", []):
                if isinstance(sys, dict) and sys.get("name"):
                    systems.add(sys["name"])
                elif isinstance(sys, str) and sys:
                    systems.add(sys)

    return {
        "tag": tag,
        "signatures_count": len(sigs),
        "revisionDatetime": rev,
        "softwareVersion": version,
        "size_bytes": size_bytes,
        "attack_types": sorted(list(attack_types)),
        "systems": sorted(list(systems)),
    }


# =========================================================================
# EVASION TECHNIQUES CONSTANTS & METADATA
# https://docs.nginx.com/waf/policies/evasion-techniques/
# =========================================================================
STANDARD_EVASION_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "description": "Bad unescape",
        "title": "Bad Unescape",
        "details": "Detects invalid or malformed URL escape sequences (%XX) that may confuse HTTP parsers.",
        "enabled": True,
        "learn": False,
    },
    {
        "description": "Directory traversals",
        "title": "Directory Traversals",
        "details": "Detects directory navigation attempts such as '../', '..\\', or multi-encoded dot-dot-slash patterns.",
        "enabled": True,
        "learn": False,
    },
    {
        "description": "Bare byte decoding",
        "title": "Bare Byte Decoding",
        "details": "Detects non-standard high-order characters in URI path components (characters > 0x7F).",
        "enabled": True,
        "learn": False,
    },
    {
        "description": "Apache whitespace",
        "title": "Apache Whitespace",
        "details": "Detects tab characters (%09) or multiple whitespaces designed to exploit Apache HTTP parsing behaviors.",
        "enabled": True,
        "learn": False,
    },
    {
        "description": "Multiple decoding",
        "title": "Multiple Decoding",
        "details": "Detects multi-pass URL encoding where decoding once reveals further encoded sequences.",
        "enabled": True,
        "learn": False,
        "maxDecodingPasses": 2,
    },
    {
        "description": "IIS Unicode codepoints",
        "title": "IIS Unicode Codepoints",
        "details": "Detects IIS-specific non-standard Unicode or UTF-8 overlong encodings.",
        "enabled": True,
        "learn": False,
    },
    {
        "description": "IIS backslashes",
        "title": "IIS Backslashes",
        "details": "Detects backslashes ('\\') used as path separators in place of forward slashes ('/').",
        "enabled": True,
        "learn": False,
    },
    {
        "description": "%u decoding",
        "title": "%u Decoding",
        "details": "Detects Microsoft %uXXXX 16-bit wide character encoding in URI and parameter inputs.",
        "enabled": True,
        "learn": False,
    },
]

STANDARD_EVASION_DESCRIPTIONS = {t["description"] for t in STANDARD_EVASION_TECHNIQUES}


# =========================================================================
# IP ADDRESS LISTS CONSTANTS
# https://docs.nginx.com/waf/policies/ip-address-lists/
# =========================================================================
IP_BLOCK_REQUESTS_ACTIONS = [
    "policy-default",  # Standard policy evaluation applies
    "never",           # Always allowed (whitelist/bypass violations)
    "always",          # Always blocked (blacklist)
]

DEFAULT_IP_ADDRESS_LIST_TEMPLATES: List[Dict[str, Any]] = [
    {
        "name": "Trusted_Partners",
        "description": "List of trusted partner IP addresses and monitoring probes (never block)",
        "blockRequests": "never",
        "setGeolocation": "US",
        "ipAddresses": [
            {"ipAddress": "192.0.2.1/32"},
            {"ipAddress": "198.51.100.0/24"},
        ],
    },
    {
        "name": "Malicious_Ranges",
        "description": "Threat intelligence known attacker IPs and malicious scanners (always block)",
        "blockRequests": "always",
        "ipAddresses": [
            {"ipAddress": "203.0.113.50/32"},
            {"ipAddress": "198.18.0.0/15"},
        ],
    },
]


# =========================================================================
# RESPONSE SIGNATURES & INSPECTION SETTINGS
# https://docs.nginx.com/waf/policies/response-signatures/
# =========================================================================
DEFAULT_ALLOWED_RESPONSE_CODES = [200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 500, 502, 503]
DEFAULT_RESPONSE_CHECK_LENGTH = 20000




