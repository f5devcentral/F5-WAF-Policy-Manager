/**
 * F5 WAF Schema Catalog & Presets
 */

window.WAF_CATALOG = {
  categories: [
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
    "Violation Rating"
  ],

  violations: [
    {
      name: "VIOL_ATTACK_SIGNATURE",
      title: "Attack signature detected",
      category: "Threats & Signatures",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: false,
      rating: 3,
      description: "Examines HTTP messages for known attacks by matching against signature sets (OWASP Top 10, CVEs)."
    },
    {
      name: "VIOL_THREAT_CAMPAIGN",
      title: "Threat Campaign detected",
      category: "Threats & Signatures",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Detects high-confidence active threat campaign attack patterns with near-zero false positives."
    },
    {
      name: "VIOL_BOT_CLIENT",
      title: "Bot Client Detected",
      category: "Threats & Signatures",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: false,
      rating: 3,
      description: "Detects automated clients, scrapers, and classifies bot types."
    },
    {
      name: "VIOL_EVASION",
      title: "Evasion technique detected",
      category: "Threats & Signatures",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Detects evasion techniques such as directory traversal, multiple decoding, and bad escaped characters."
    },
    {
      name: "VIOL_RATING_THREAT",
      title: "Request is likely a threat",
      category: "Violation Rating",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Triggered when request violation rating is malicious (4 or 5). Blocks the request."
    },
    {
      name: "VIOL_RATING_NEED_EXAMINATION",
      title: "Request needs further examination",
      category: "Violation Rating",
      defaultAlarm: false,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Triggered when request violation rating is suspicious (3). Enabled for strict environments."
    },
    {
      name: "VIOL_HTTP_PROTOCOL",
      title: "HTTP protocol compliance failed",
      category: "HTTP Compliance",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Validates RFC compliance for HTTP requests (GET with body, POST without length, bad headers)."
    },
    {
      name: "VIOL_METHOD",
      title: "Illegal method",
      category: "HTTP Compliance",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Ensures HTTP method is in the allowed methods list defined in the policy."
    },
    {
      name: "VIOL_HTTP_RESPONSE_STATUS",
      title: "Illegal HTTP response status",
      category: "HTTP Compliance",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks server response status codes against permitted status code ranges."
    },
    {
      name: "VIOL_REQUEST_MAX_LENGTH",
      title: "Request length exceeds buffer size",
      category: "Buffer & Sizing",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests exceeding maximum buffer size (default 10 MB) to protect memory."
    },
    {
      name: "VIOL_REQUEST_LENGTH",
      title: "Illegal request length",
      category: "Buffer & Sizing",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks total request length against limits specified per file type."
    },
    {
      name: "VIOL_HEADER_LENGTH",
      title: "Illegal header length",
      category: "Buffer & Sizing",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Enforces upper limits on individual or total HTTP header lengths (default 4 KB)."
    },
    {
      name: "VIOL_POST_DATA_LENGTH",
      title: "Illegal POST data length",
      category: "Buffer & Sizing",
      defaultAlarm: false,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks that POST request body does not exceed configured size limits."
    },
    {
      name: "VIOL_QUERY_STRING_LENGTH",
      title: "Illegal query string length",
      category: "Buffer & Sizing",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks that query string does not exceed configured size (default 2 KB)."
    },
    {
      name: "VIOL_URL_LENGTH",
      title: "Illegal URL length",
      category: "Buffer & Sizing",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks that the requested URL path does not exceed configured length limit."
    },
    {
      name: "VIOL_URL",
      title: "Illegal URL",
      category: "URLs & Routing",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Ensures requested URL is explicitly or wildcard permitted in the policy."
    },
    {
      name: "VIOL_URL_METACHAR",
      title: "Illegal meta character in URL",
      category: "URLs & Routing",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks that URL contains only allowed characters, blocking illegal metacharacters."
    },
    {
      name: "VIOL_FILETYPE",
      title: "Illegal file type",
      category: "URLs & Routing",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Blocks disallowed file extensions or enforces strict filetype allowlists."
    },
    {
      name: "VIOL_PARAMETER",
      title: "Illegal parameter",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks that request parameters are defined in the policy parameter allowlist."
    },
    {
      name: "VIOL_PARAMETER_NAME_METACHAR",
      title: "Illegal meta character in parameter name",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks parameter names for disallowed metacharacters (e.g. quotes, semicolons, control chars)."
    },
    {
      name: "VIOL_PARAMETER_VALUE_METACHAR",
      title: "Illegal meta character in value",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks parameter and element values for disallowed input characters."
    },
    {
      name: "VIOL_PARAMETER_DATA_TYPE",
      title: "Illegal parameter data type",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Enforces defined data types (integer, email, phone) on parameter values."
    },
    {
      name: "VIOL_PARAMETER_VALUE_REGEXP",
      title: "Parameter value does not comply with regex",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Enforces regex patterns configured for specific parameter validation."
    },
    {
      name: "VIOL_MANDATORY_PARAMETER",
      title: "Mandatory parameter is missing",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Ensures parameters flagged as required are present in the request."
    },
    {
      name: "VIOL_PARAMETER_REPEATED",
      title: "Illegal repeated parameter name",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Detects HTTP Parameter Pollution (HPP) when identical parameter names repeat."
    },
    {
      name: "VIOL_COOKIE_MALFORMED",
      title: "Cookie not RFC-compliant",
      category: "Cookies & Headers",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests containing malformed cookies (spaces, misplaced equals, control chars)."
    },
    {
      name: "VIOL_COOKIE_MODIFIED",
      title: "Modified domain cookie",
      category: "Cookies & Headers",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Enforces cookie integrity on protected/enforced application cookies."
    },
    {
      name: "VIOL_ASM_COOKIE_MODIFIED",
      title: "Modified ASM cookie",
      category: "Cookies & Headers",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests where the WAF's internal tracking cookie has been tampered with."
    },
    {
      name: "VIOL_HEADER_METACHAR",
      title: "Illegal meta character in header",
      category: "Cookies & Headers",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Checks header names and values for malicious carriage returns or forbidden characters."
    },
    {
      name: "VIOL_JSON_MALFORMED",
      title: "Malformed JSON data",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests with invalid or corrupted JSON payloads."
    },
    {
      name: "VIOL_JSON_FORMAT",
      title: "JSON data does not comply with format settings",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Enforces JSON profile restrictions: depth limits, array counts, string lengths."
    },
    {
      name: "VIOL_JSON_SCHEMA",
      title: "JSON data does not comply with JSON schema",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Enforces strict JSON schema validation for API endpoints."
    },
    {
      name: "VIOL_XML_MALFORMED",
      title: "Malformed XML data",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests containing unparsable XML, entity expansion, or XML bombs."
    },
    {
      name: "VIOL_XML_FORMAT",
      title: "XML data does not comply with format settings",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Enforces XML depth, maximum node count, and document length limits."
    },
    {
      name: "VIOL_GRAPHQL_MALFORMED",
      title: "Malformed GraphQL data",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks syntax errors in GraphQL queries or variables."
    },
    {
      name: "VIOL_GRAPHQL_FORMAT",
      title: "GraphQL format does not comply with settings",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Enforces GraphQL query depth, payload length, and batch query limits."
    },
    {
      name: "VIOL_GRPC_MALFORMED",
      title: "Malformed gRPC data",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks unparsable or malformed Protocol Buffer / gRPC payloads."
    },
    {
      name: "VIOL_DATA_GUARD",
      title: "Data Guard: Information leakage detected",
      category: "Data Privacy",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Detects and masks sensitive data in responses (Credit Card Numbers, SSNs, custom regex)."
    },
    {
      name: "VIOL_BLACKLISTED_IP",
      title: "IP is in the deny list",
      category: "Access Control",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks traffic from IP addresses or CIDR ranges configured in the IP deny list."
    },
    {
      name: "VIOL_GEOLOCATION",
      title: "Disallowed Geolocations",
      category: "Access Control",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests originating from prohibited country codes."
    },
    {
      name: "VIOL_ACCESS_INVALID",
      title: "Access token does not comply with requirements",
      category: "Access Control",
      defaultAlarm: true,
      defaultBlock: false,
      configurable: true,
      rating: 3,
      description: "Validates API access tokens and JWT structures according to access profiles."
    },
    {
      name: "VIOL_MANDATORY_REQUEST_BODY",
      title: "Mandatory request body is missing",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests where the OpenAPI schema specifies a required request body, but none was sent."
    },
    {
      name: "VIOL_PARAMETER_LOCATION",
      title: "Illegal parameter location",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Triggered when a parameter arrives in an unexpected HTTP location (e.g. body instead of query or path)."
    },
    {
      name: "VIOL_PARAMETER_NUMERIC_VALUE",
      title: "Illegal parameter numeric value",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Enforces minimum, maximum, and multipleOf constraints defined in the OpenAPI schema on numbers."
    },
    {
      name: "VIOL_PARAMETER_VALUE_LENGTH",
      title: "Illegal parameter value length",
      category: "Buffer & Sizing",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Enforces minLength and maxLength constraints on parameter string values per OpenAPI schema."
    },
    {
      name: "VIOL_PARAMETER_STATIC_VALUE",
      title: "Illegal static parameter value",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Enforces enum and static value restrictions specified for parameters in the OpenAPI schema."
    },
    {
      name: "VIOL_PARAMETER_EMPTY_VALUE",
      title: "Illegal empty parameter value",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks empty values for parameters that specify allowEmptyValue: false in the OpenAPI schema."
    },
    {
      name: "VIOL_PARAMETER_ARRAY_VALUE",
      title: "Illegal parameter array value",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Enforces minItems, maxItems, and uniqueItems constraints on parameter arrays in the OpenAPI schema."
    },
    {
      name: "VIOL_PARAMETER_VALUE_BASE64",
      title: "Illegal Base64 value",
      category: "Parameters & Input",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Validates that parameters specified as byte / base64 encoded comply with RFC 4648 encoding."
    },
    {
      name: "VIOL_URL_CONTENT_TYPE",
      title: "Illegal request content type",
      category: "URLs & Routing",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks requests whose Content-Type header does not match the consumes / media types defined in the OpenAPI schema."
    },
    {
      name: "VIOL_FILE_UPLOAD",
      title: "Disallowed file upload content detected",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks file upload contents not conforming to permitted binary media types in the OpenAPI schema."
    },
    {
      name: "VIOL_FILE_UPLOAD_IN_BODY",
      title: "Disallowed file upload content detected in body",
      category: "API & Formats",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Blocks multipart and binary payloads detected where standard JSON or urlencoded data was expected."
    },
    {
      name: "VIOL_GRPC_MALFORMED",
      title: "Malformed gRPC data detected",
      category: "gRPC & Protocol Buffers",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Triggered when a gRPC message cannot be parsed according to expected protobuf definitions, unsupported compression, or exceeding 10MB buffer limit."
    },
    {
      name: "VIOL_GRPC_FORMAT",
      title: "gRPC format or defense attributes violation",
      category: "gRPC & Protocol Buffers",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Triggered when restrictions in the profile defenseAttributes (e.g. maximumDataLength exceeded or unauthorized unknown fields) are violated."
    },
    {
      name: "VIOL_GRPC_METHOD",
      title: "Illegal or unlisted gRPC method",
      category: "gRPC & Protocol Buffers",
      defaultAlarm: true,
      defaultBlock: true,
      configurable: true,
      rating: 3,
      description: "Triggered when a requested gRPC method is unrecognized or not present in the configured IDL (.proto) files."
    }
  ],

  serverTechnologies: [
    { name: "Apache/NCSA HTTP Server", category: "Web Servers" },
    { name: "IIS", category: "Web Servers" },
    { name: "Nginx", category: "Web Servers" },
    { name: "CGI", category: "Web Servers" },
    { name: "Proxy Servers", category: "Web Servers" },
    { name: "SSI (Server Side Includes)", category: "Web Servers" },
    { name: "WebDAV", category: "Web Servers" },
    { name: "Apache Tomcat", category: "Application Servers" },
    { name: "Apache Struts", category: "Application Servers" },
    { name: "BEA Systems WebLogic Server", category: "Application Servers" },
    { name: "JBoss", category: "Application Servers" },
    { name: "Jetty", category: "Application Servers" },
    { name: "Macromedia JRun", category: "Application Servers" },
    { name: "Macromedia ColdFusion", category: "Application Servers" },
    { name: "Oracle Application Server", category: "Application Servers" },
    { name: "ASP", category: "Frameworks / Runtimes" },
    { name: "ASP.NET", category: "Frameworks / Runtimes" },
    { name: "Django", category: "Frameworks / Runtimes" },
    { name: "Express.js", category: "Frameworks / Runtimes" },
    { name: "GraphQL", category: "Frameworks / Runtimes" },
    { name: "Java Servlets/JSP", category: "Languages / Runtimes" },
    { name: "JavaServer Faces (JSF)", category: "Frameworks / Runtimes" },
    { name: "Laravel", category: "Frameworks / Runtimes" },
    { name: "Node.js", category: "Frameworks / Runtimes" },
    { name: "PHP", category: "Languages / Runtimes" },
    { name: "Python", category: "Languages / Runtimes" },
    { name: "Ruby", category: "Languages / Runtimes" },
    { name: "Spring Boot", category: "Frameworks / Runtimes" },
    { name: "XML", category: "Frameworks / Runtimes" },
    { name: "Zend", category: "Frameworks / Runtimes" },
    { name: "AngularJS", category: "Frontend Libraries" },
    { name: "Backbone.js", category: "Frontend Libraries" },
    { name: "CodeIgniter", category: "Frameworks / Runtimes" },
    { name: "Ember.js", category: "Frontend Libraries" },
    { name: "Google Web Toolkit", category: "Frameworks / Runtimes" },
    { name: "Handlebars", category: "Frontend Libraries" },
    { name: "JavaScript", category: "Languages / Runtimes" },
    { name: "jQuery", category: "Frontend Libraries" },
    { name: "MooTools", category: "Frontend Libraries" },
    { name: "Mustache", category: "Frontend Libraries" },
    { name: "Prototype", category: "Frontend Libraries" },
    { name: "React", category: "Frontend Libraries" },
    { name: "RequireJS", category: "Frontend Libraries" },
    { name: "UIKit", category: "Frontend Libraries" },
    { name: "Underscore.js", category: "Frontend Libraries" },
    { name: "Vue.js", category: "Frontend Libraries" },
    { name: "ZURB Foundation", category: "Frontend Libraries" },
    { name: "ef.js", category: "Frontend Libraries" },
    { name: "CouchDB", category: "Databases" },
    { name: "Elasticsearch", category: "Databases" },
    { name: "IBM DB2", category: "Databases" },
    { name: "Microsoft SQL Server", category: "Databases" },
    { name: "MongoDB", category: "Databases" },
    { name: "MySQL", category: "Databases" },
    { name: "Oracle", category: "Databases" },
    { name: "PostgreSQL", category: "Databases" },
    { name: "Redis", category: "Databases" },
    { name: "SQLite", category: "Databases" },
    { name: "Sybase/ASE", category: "Databases" },
    { name: "Cisco", category: "Operating Systems & Networking" },
    { name: "Citrix", category: "Operating Systems & Networking" },
    { name: "Microsoft Windows", category: "Operating Systems" },
    { name: "Novell", category: "Operating Systems & Networking" },
    { name: "Unix/Linux", category: "Operating Systems" },
    { name: "Front Page Server Extensions (FPSE)", category: "CMS & Applications" },
    { name: "Jenkins", category: "CMS & Applications" },
    { name: "Joomla", category: "CMS & Applications" },
    { name: "Lotus Domino", category: "CMS & Applications" },
    { name: "Oracle Identity Manager", category: "CMS & Applications" },
    { name: "Outlook Web Access", category: "CMS & Applications" },
    { name: "SharePoint", category: "CMS & Applications" },
    { name: "TYPO3 CMS", category: "CMS & Applications" },
    { name: "WordPress", category: "CMS & Applications" }
  ],

  signatureSets: [
    // --- Default Template Predefined Signature Sets (18) ---
    {
      name: "Command Execution Signatures",
      category: "System & OS Attacks",
      description: "Protects against OS command execution and shell invocation exploits (sh, bash, cmd.exe, PowerShell).",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "Cross Site Scripting Signatures",
      category: "Application Attacks",
      description: "Protects against reflected, stored, and DOM-based Cross-Site Scripting (XSS) payload injections.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "Directory Indexing Signatures",
      category: "Information Gathering",
      description: "Detects requests targeting server directory listings and indexing vulnerabilities.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "Information Leakage Signatures",
      category: "Data Protection",
      description: "Detects backend error exposures, database stack traces, and internal server leakages.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "OS Command Injection Signatures",
      category: "System & OS Attacks",
      description: "Detects command injection patterns and metacharacters targeting underlying operating system interpreters.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "Path Traversal Signatures",
      category: "File & Resource Attacks",
      description: "Detects path traversal sequences (../, %2e%2e, unicode variations) aiming to access restricted filesystem paths.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "Predictable Resource Location Signatures",
      category: "Information Gathering",
      description: "Detects scanners and crawlers searching for hidden administrative paths, backup files, and git repositories.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "Remote File Include Signatures",
      category: "File & Resource Attacks",
      description: "Detects attempts to include external remote malicious files or PHP wrapper streams.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "SQL Injection Signatures",
      category: "Application Attacks",
      description: "Protects against classic, union-based, stacked, error-based, and blind SQL injection exploits.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "Authentication/Authorization Attack Signatures",
      category: "Access Control",
      description: "Detects credential stuffing, broken authentication patterns, and privilege escalation payloads.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "XML External Entities (XXE) Signatures",
      category: "XML & Web Services",
      description: "Detects malicious XML entity expansion and external DTD references causing SSRF or data exfiltration.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "XPath Injection Signatures",
      category: "XML & Web Services",
      description: "Protects against XML query manipulation and XPath parameter injections.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "Buffer Overflow Signatures",
      category: "System & OS Attacks",
      description: "Detects oversized payload buffers and memory corruption attempts targeting web servers and modules.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "Denial of Service Signatures",
      category: "Availability & DoS",
      description: "Detects algorithmic complexity attacks, resource exhaustion, and application DoS patterns.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "Vulnerability Scan Signatures",
      category: "Information Gathering",
      description: "Detects reconnaissance activity from vulnerability scanners (e.g. Nessus, Qualys, Nikto, Acunetix, Burp).",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },
    {
      name: "High Accuracy Signatures",
      category: "Accuracy Levels",
      description: "Signatures with high accuracy and very low risk of false positives. Recommended for active blocking in all production policies.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "Server Side Code Injection Signatures",
      category: "Application Attacks",
      description: "Detects unauthorized server-side code execution in PHP, Python, Java, Node.js, and Ruby.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: true
    },
    {
      name: "CVE Signatures",
      category: "Vulnerability & CVE",
      description: "Signatures mapped to specific Common Vulnerabilities and Exposures (CVEs) across common web platforms.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: true
    },

    // --- Additional Official Predefined Signature Sets (12) ---
    {
      name: "All Response Signatures",
      category: "Response Protection",
      description: "Comprehensive inspection of backend server responses for data leakage and error disclosure.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "All Signatures",
      category: "Comprehensive Protection",
      description: "Full collection of all attack signatures bundled in the F5 WAF compiler database.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "Generic Detection Signatures",
      category: "Generic Threat Detection",
      description: "Signatures detecting suspicious character sets, hex encodings, and common evasion sequences.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "Generic Detection Signatures (High Accuracy)",
      category: "Generic Threat Detection",
      description: "High-confidence generic threat detection signatures with minimal false positive risk.",
      defaultAlarm: true,
      defaultBlock: true,
      templateDefault: false
    },
    {
      name: "Generic Detection Signatures (High/Medium Accuracy)",
      category: "Generic Threat Detection",
      description: "Broad generic detection signatures covering both high and medium accuracy threat patterns.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "Low Accuracy Signatures",
      category: "Accuracy Levels",
      description: "Broad heuristic pattern signatures with potential for higher false-positive rates.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "Medium Accuracy Signatures",
      category: "Accuracy Levels",
      description: "Signatures with balanced accuracy against known common attack vectors.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "OWA Signatures",
      category: "Application Specific",
      description: "Targeted attack signatures for Microsoft Outlook Web Access / Exchange applications.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "WebSphere signatures",
      category: "Application Specific",
      description: "Targeted attack signatures for IBM WebSphere Application Server environments.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "HTTP Response Splitting Signatures",
      category: "Protocol & Parsing",
      description: "Detects carriage return and line feed (CRLF) injection aiming at HTTP response splitting and cache poisoning.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "Other Application Attacks Signatures",
      category: "Application Attacks",
      description: "Signatures covering serialization exploits, WebDAV tampering, and general application-level threats.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    },
    {
      name: "High Accuracy Detection Evasion Signatures",
      category: "Evasion Techniques",
      description: "Detects advanced obfuscation and evasive payload encoding with high accuracy.",
      defaultAlarm: true,
      defaultBlock: false,
      templateDefault: false
    }
  ],

  attackSignatures: [
    // --- SQL Injection ---
    {
      signatureId: 200001475,
      name: "SQL-Injection in URI - UNION SELECT",
      attackType: "SQL-Injection",
      accuracy: "High",
      risk: "Critical",
      systems: ["Generic", "MySQL", "PostgreSQL", "Oracle"],
      cve: null,
      description: "Detects UNION SELECT payload structures in request URI attempting to extract data from arbitrary tables.",
      signatureSets: ["High Accuracy Signatures", "SQL Injection Signatures"]
    },
    {
      signatureId: 200000012,
      name: "SQL-Injection in parameter - stacked queries",
      attackType: "SQL-Injection",
      accuracy: "High",
      risk: "Critical",
      systems: ["Generic", "MSSQL", "PostgreSQL"],
      cve: null,
      description: "Detects semicolon followed by DDL/DML commands (DROP, ALTER, UPDATE) enabling stacked SQL statement execution.",
      signatureSets: ["High Accuracy Signatures", "SQL Injection Signatures"]
    },
    {
      signatureId: 200000019,
      name: "SQL-Injection - Boolean-based blind (OR 1=1 / AND 1=1)",
      attackType: "SQL-Injection",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects tautological boolean conditions used to manipulate query logic and extract data bit-by-bit.",
      signatureSets: ["High Accuracy Signatures", "SQL Injection Signatures"]
    },
    {
      signatureId: 200000025,
      name: "SQL-Injection - Time-based blind delay (WAITFOR DELAY / SLEEP)",
      attackType: "SQL-Injection",
      accuracy: "High",
      risk: "High",
      systems: ["Generic", "MSSQL", "PostgreSQL", "MySQL"],
      cve: null,
      description: "Detects conditional delay functions (SLEEP, WAITFOR DELAY, pg_sleep) in SQL payloads.",
      signatureSets: ["High Accuracy Signatures", "SQL Injection Signatures"]
    },
    {
      signatureId: 200001480,
      name: "SQL-Injection - Error-based extractvalue / updatexml",
      attackType: "SQL-Injection",
      accuracy: "Medium",
      risk: "High",
      systems: ["MySQL"],
      cve: null,
      description: "Detects XML manipulation functions in MySQL deliberately fed invalid XPath syntax to leak database contents.",
      signatureSets: ["Medium Accuracy Signatures", "SQL Injection Signatures"]
    },
    {
      signatureId: 200001488,
      name: "SQL-Injection - Hex-encoded SQL payload in parameter",
      attackType: "SQL-Injection",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects hex notation sequences (0x...) representing encoded keywords or strings to bypass naive filters.",
      signatureSets: ["Medium Accuracy Signatures", "SQL Injection Signatures"]
    },
    {
      signatureId: 200001499,
      name: "SQL-Injection - Quotation mark and comment heuristics",
      attackType: "SQL-Injection",
      accuracy: "Low",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Heuristic check for unpaired quotation marks followed by SQL comment markers (-- or /*). Higher potential for false positives.",
      signatureSets: ["Low Accuracy Signatures", "SQL Injection Signatures"]
    },

    // --- Cross Site Scripting (XSS) ---
    {
      signatureId: 200000098,
      name: "Cross Site Scripting (XSS) in query parameter - script tag",
      attackType: "Cross Site Scripting (XSS)",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects raw or encoded <script> HTML tags inside request query parameters or POST bodies.",
      signatureSets: ["High Accuracy Signatures", "Cross Site Scripting Signatures"]
    },
    {
      signatureId: 200000101,
      name: "Cross Site Scripting (XSS) - Inline DOM event handlers",
      attackType: "Cross Site Scripting (XSS)",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects HTML attributes with JavaScript handlers (onload, onerror, onmouseover, onclick) injected into inputs.",
      signatureSets: ["High Accuracy Signatures", "Cross Site Scripting Signatures"]
    },
    {
      signatureId: 200000115,
      name: "Cross Site Scripting (XSS) - javascript: pseudo-protocol",
      attackType: "Cross Site Scripting (XSS)",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects the javascript: pseudo-protocol in href, src, or action attributes in requests.",
      signatureSets: ["High Accuracy Signatures", "Cross Site Scripting Signatures"]
    },
    {
      signatureId: 200000122,
      name: "Cross Site Scripting (XSS) - SVG / XML embedded script injection",
      attackType: "Cross Site Scripting (XSS)",
      accuracy: "Medium",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects SVG vectors containing CDATA blocks or embedded script payloads.",
      signatureSets: ["Medium Accuracy Signatures", "Cross Site Scripting Signatures"]
    },
    {
      signatureId: 200000130,
      name: "Cross Site Scripting (XSS) - Base64 encoded payload in data: URL",
      attackType: "Cross Site Scripting (XSS)",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects data:text/html;base64 payloads designed to execute client-side scripts in modern browsers.",
      signatureSets: ["Medium Accuracy Signatures", "Cross Site Scripting Signatures"]
    },
    {
      signatureId: 200000139,
      name: "Cross Site Scripting (XSS) - Generic HTML angle bracket heuristic",
      attackType: "Cross Site Scripting (XSS)",
      accuracy: "Low",
      risk: "Low",
      systems: ["Generic"],
      cve: null,
      description: "Broad heuristic pattern detecting unescaped angle brackets (< and >) in text fields.",
      signatureSets: ["Low Accuracy Signatures", "Cross Site Scripting Signatures"]
    },

    // --- Command Execution ---
    {
      signatureId: 200002011,
      name: "OS Command Injection - /bin/sh or /bin/bash shell invocation",
      attackType: "Command Execution",
      accuracy: "High",
      risk: "Critical",
      systems: ["Unix/Linux"],
      cve: null,
      description: "Detects direct invocation of Unix shell interpreters (/bin/sh, /bin/bash, /bin/dash) in input parameters.",
      signatureSets: ["High Accuracy Signatures", "Command Execution Signatures"]
    },
    {
      signatureId: 200002015,
      name: "OS Command Injection - cmd.exe / powershell.exe execution",
      attackType: "Command Execution",
      accuracy: "High",
      risk: "Critical",
      systems: ["Windows"],
      cve: null,
      description: "Detects Windows command line or PowerShell executable invocations in request parameters.",
      signatureSets: ["High Accuracy Signatures", "Command Execution Signatures"]
    },
    {
      signatureId: 200002022,
      name: "OS Command Injection - Pipe and command chaining (| ; ` &)",
      attackType: "Command Execution",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects shell command separator characters followed by common system utilities (id, whoami, uname, cat).",
      signatureSets: ["High Accuracy Signatures", "Command Execution Signatures"]
    },
    {
      signatureId: 200002030,
      name: "OS Command Injection - Wget / cURL remote payload download",
      attackType: "Command Execution",
      accuracy: "High",
      risk: "High",
      systems: ["Unix/Linux"],
      cve: null,
      description: "Detects wget or curl commands fetching remote files and piping directly to shell execution (curl | sh).",
      signatureSets: ["High Accuracy Signatures", "Command Execution Signatures"]
    },
    {
      signatureId: 200002045,
      name: "OS Command Injection - Reverse shell netcat / socat payload",
      attackType: "Command Execution",
      accuracy: "Medium",
      risk: "Critical",
      systems: ["Unix/Linux"],
      cve: null,
      description: "Detects netcat (-e /bin/sh) or socat commands configured to spawn interactive reverse shells.",
      signatureSets: ["Medium Accuracy Signatures", "Command Execution Signatures"]
    },

    // --- Path Traversal ---
    {
      signatureId: 200000104,
      name: "Path Traversal - /../ or ..\\ sequence",
      attackType: "Path Traversal",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects standard path traversal sequences attempting to break out of web application document root directories.",
      signatureSets: ["High Accuracy Signatures", "Path Traversal Signatures"]
    },
    {
      signatureId: 200000108,
      name: "Path Traversal - Encoded dot-dot-slash (%2e%2e%2f)",
      attackType: "Path Traversal",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects URL-encoded or double-encoded path traversal characters used to bypass normalizers.",
      signatureSets: ["High Accuracy Signatures", "Path Traversal Signatures"]
    },
    {
      signatureId: 200000112,
      name: "Path Traversal - /etc/passwd or /etc/shadow access attempt",
      attackType: "Path Traversal",
      accuracy: "High",
      risk: "Critical",
      systems: ["Unix/Linux"],
      cve: null,
      description: "Detects direct file retrieval paths aiming at Unix sensitive authentication and user databases.",
      signatureSets: ["High Accuracy Signatures", "Path Traversal Signatures"]
    },
    {
      signatureId: 200000118,
      name: "Path Traversal - Windows C:\\Windows\\win.ini or boot.ini access",
      attackType: "Path Traversal",
      accuracy: "High",
      risk: "High",
      systems: ["Windows"],
      cve: null,
      description: "Detects attempts to read foundational Windows configuration and system state files.",
      signatureSets: ["High Accuracy Signatures", "Path Traversal Signatures"]
    },
    {
      signatureId: 200000125,
      name: "Path Traversal - Relative path traversal with null byte (%00)",
      attackType: "Path Traversal",
      accuracy: "Medium",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects null byte poisoning (%00) combined with relative path traversal to bypass file extension checks.",
      signatureSets: ["Medium Accuracy Signatures", "Path Traversal Signatures"]
    },

    // --- Threat Campaigns (Zero-Day & High Confidence) ---
    {
      signatureId: 300001001,
      name: "Apache Log4j Remote Code Execution JNDI Lookup (CVE-2021-44228)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "Critical",
      systems: ["Java"],
      cve: "CVE-2021-44228",
      description: "Detects Log4j JNDI lookup strings (${jndi:ldap://, ${jndi:rmi://) across URIs, headers, and request bodies.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures"]
    },
    {
      signatureId: 300001002,
      name: "Spring4Shell DataBinder Class Loader RCE (CVE-2022-22965)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "Critical",
      systems: ["Java", "Spring"],
      cve: "CVE-2022-22965",
      description: "Detects class.module.classLoader property manipulation targeting Spring Framework running on Tomcat.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures"]
    },
    {
      signatureId: 300001003,
      name: "MOVEit Transfer SQLi / Remote Code Execution (CVE-2023-34362)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "Critical",
      systems: ["Windows", "IIS"],
      cve: "CVE-2023-34362",
      description: "Detects HTTP headers and parameter exploits targeting the Progress MOVEit Transfer SQL injection flaw.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures", "SQL Injection Signatures"]
    },
    {
      signatureId: 300001004,
      name: "Citrix Bleed Sensitive Information Disclosure (CVE-2023-4966)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "Critical",
      systems: ["Citrix", "Web Servers"],
      cve: "CVE-2023-4966",
      description: "Detects buffer overflow requests targeting NetScaler / Citrix Gateway leading to session token leakage.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures"]
    },
    {
      signatureId: 300001005,
      name: "F5 BIG-IP iControl REST Remote Code Execution (CVE-2022-1388)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "Critical",
      systems: ["F5 BIG-IP"],
      cve: "CVE-2022-1388",
      description: "Detects authorization header manipulation (X-F5-Auth-Token, Connection: keep-alive) exploiting iControl REST.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures"]
    },
    {
      signatureId: 300001006,
      name: "Atlassian Confluence OGNL Expression Injection (CVE-2022-26134)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "Critical",
      systems: ["Java"],
      cve: "CVE-2022-26134",
      description: "Detects unauthenticated OGNL expression payloads in Confluence URL paths enabling command execution.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures"]
    },
    {
      signatureId: 300001007,
      name: "OpenSSL Bleichenbacher RSA Bleed (CVE-2023-44487)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "High",
      systems: ["OpenSSL"],
      cve: "CVE-2023-44487",
      description: "Detects malformed TLS negotiation sequences attempting padding oracle decryption.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures"]
    },
    {
      signatureId: 300001008,
      name: "Apache Struts Jakarta Multipart Parser RCE (CVE-2017-5638)",
      attackType: "Threat Campaigns",
      accuracy: "High",
      risk: "Critical",
      systems: ["Apache", "Java"],
      cve: "CVE-2017-5638",
      description: "Detects OGNL commands in Content-Type headers exploiting Struts 2 multipart file upload parsing.",
      signatureSets: ["High Accuracy Signatures", "CVE Signatures"]
    },

    // --- Predictable Resource Location ---
    {
      signatureId: 200000215,
      name: "Predictable Resource Location - .git/config access attempt",
      attackType: "Predictable Resource Location",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects HTTP probes requesting exposed Git repository metadata files (.git/config, .git/HEAD).",
      signatureSets: ["High Accuracy Signatures", "Predictable Resource Location Signatures"]
    },
    {
      signatureId: 200000220,
      name: "Predictable Resource Location - .env / configuration backup file exposure",
      attackType: "Predictable Resource Location",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects requests targeting .env, settings.py, or web.config backup files containing secrets.",
      signatureSets: ["High Accuracy Signatures", "Predictable Resource Location Signatures"]
    },
    {
      signatureId: 200000225,
      name: "Predictable Resource Location - Admin console paths (/phpmyadmin, /wp-admin)",
      attackType: "Predictable Resource Location",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["PHP", "Apache", "Nginx"],
      cve: null,
      description: "Detects crawlers scanning for unhardened database administration tools and CMS backends.",
      signatureSets: ["Medium Accuracy Signatures", "Predictable Resource Location Signatures"]
    },
    {
      signatureId: 200000230,
      name: "Predictable Resource Location - Source code backup (.bak, .old, .swp)",
      attackType: "Predictable Resource Location",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects requests for editor temporary swap files and manual archive files (.zip, .tar.gz).",
      signatureSets: ["Medium Accuracy Signatures", "Predictable Resource Location Signatures"]
    },

    // --- HTTP Parser Attack ---
    {
      signatureId: 200001880,
      name: "HTTP Request Smuggling - Transfer-Encoding vs Content-Length conflict",
      attackType: "HTTP Parser Attack",
      accuracy: "High",
      risk: "Critical",
      systems: ["Web Servers"],
      cve: null,
      description: "Detects requests containing conflicting Transfer-Encoding and Content-Length headers (TE.CL / CL.TE).",
      signatureSets: ["High Accuracy Signatures", "Generic Detection Signatures"]
    },
    {
      signatureId: 200001885,
      name: "HTTP Request Smuggling - Dual Transfer-Encoding header obfuscation",
      attackType: "HTTP Parser Attack",
      accuracy: "High",
      risk: "High",
      systems: ["Web Servers"],
      cve: null,
      description: "Detects duplicate Transfer-Encoding headers with trailing whitespace or casing evasion.",
      signatureSets: ["High Accuracy Signatures", "Generic Detection Signatures"]
    },
    {
      signatureId: 200001890,
      name: "HTTP Header Injection - CRLF / Response Splitting in headers",
      attackType: "HTTP Parser Attack",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects carriage return and line feed characters (\\r\\n / %0d%0a) injected into header values.",
      signatureSets: ["High Accuracy Signatures", "HTTP Response Splitting Signatures"]
    },
    {
      signatureId: 200001895,
      name: "HTTP Request Smuggling - Chunked transfer extension evasion",
      attackType: "HTTP Parser Attack",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Web Servers"],
      cve: null,
      description: "Detects non-standard chunk extensions designed to desynchronize frontend proxy and backend servers.",
      signatureSets: ["Medium Accuracy Signatures", "Generic Detection Signatures"]
    },

    // --- Server Side Code Injection ---
    {
      signatureId: 200003001,
      name: "PHP Code Injection - eval() / assert() execution",
      attackType: "Server Side Code Injection",
      accuracy: "High",
      risk: "Critical",
      systems: ["PHP"],
      cve: null,
      description: "Detects arbitrary PHP code execution payloads calling eval(), assert(), or preg_replace with /e modifier.",
      signatureSets: ["High Accuracy Signatures", "Server Side Code Injection Signatures"]
    },
    {
      signatureId: 200003010,
      name: "Python Code Injection - __import__ / os.system execution",
      attackType: "Server Side Code Injection",
      accuracy: "High",
      risk: "Critical",
      systems: ["Python"],
      cve: null,
      description: "Detects Python code injection payloads invoking builtins (__import__, getattr, eval, subprocess).",
      signatureSets: ["High Accuracy Signatures", "Server Side Code Injection Signatures"]
    },
    {
      signatureId: 200003020,
      name: "Java Expression Language (EL) Injection (${...} / #{...})",
      attackType: "Server Side Code Injection",
      accuracy: "High",
      risk: "Critical",
      systems: ["Java"],
      cve: null,
      description: "Detects Java EL expressions evaluating Runtime.getRuntime().exec() via reflected class loaders.",
      signatureSets: ["High Accuracy Signatures", "Server Side Code Injection Signatures"]
    },
    {
      signatureId: 200003030,
      name: "Node.js Code Injection - child_process.exec invocation",
      attackType: "Server Side Code Injection",
      accuracy: "High",
      risk: "Critical",
      systems: ["Node.js"],
      cve: null,
      description: "Detects JavaScript expressions inside inputs executing process.mainModule.require('child_process').",
      signatureSets: ["High Accuracy Signatures", "Server Side Code Injection Signatures"]
    },

    // --- Information Leakage ---
    {
      signatureId: 200004001,
      name: "Database Error Leakage - MySQL / Postgres syntax error in response",
      attackType: "Information Leakage",
      accuracy: "High",
      risk: "Medium",
      systems: ["MySQL", "PostgreSQL"],
      cve: null,
      description: "Detects responses containing database engine error messages and SQL syntax disclosures.",
      signatureSets: ["High Accuracy Signatures", "Information Leakage Signatures"]
    },
    {
      signatureId: 200004010,
      name: "Stack Trace Exposure - Java / .NET unhandled exception trace",
      attackType: "Information Leakage",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Java", "ASP.NET"],
      cve: null,
      description: "Detects application stack traces leaking code paths, frameworks, and database schema names.",
      signatureSets: ["Medium Accuracy Signatures", "Information Leakage Signatures"]
    },
    {
      signatureId: 200004020,
      name: "Server Version Banner Leakage - Sensitive X-Powered-By tokens",
      attackType: "Information Leakage",
      accuracy: "Medium",
      risk: "Low",
      systems: ["Apache", "Nginx", "IIS"],
      cve: null,
      description: "Detects specific server software version disclosure banners in responses.",
      signatureSets: ["Medium Accuracy Signatures", "Information Leakage Signatures"]
    },

    // --- XPath Injection ---
    {
      signatureId: 200005001,
      name: "XPath Injection - ' or '1'='1 in XML search query",
      attackType: "XPath Injection",
      accuracy: "High",
      risk: "High",
      systems: ["XML & Web Services"],
      cve: null,
      description: "Detects boolean manipulation in XPath expressions targeting XML document repositories.",
      signatureSets: ["High Accuracy Signatures", "XPath Injection Signatures"]
    },
    {
      signatureId: 200005010,
      name: "XPath Injection - Malicious count() or substring() boolean extraction",
      attackType: "XPath Injection",
      accuracy: "Medium",
      risk: "High",
      systems: ["XML & Web Services"],
      cve: null,
      description: "Detects XPath node counting and character extraction functions used for blind XML data extraction.",
      signatureSets: ["Medium Accuracy Signatures", "XPath Injection Signatures"]
    },

    // --- XML External Entity (XXE) ---
    {
      signatureId: 200002441,
      name: "XML External Entity (XXE) - SYSTEM entity referencing local file URI",
      attackType: "XML External Entity (XXE)",
      accuracy: "High",
      risk: "Critical",
      systems: ["XML & Web Services"],
      cve: null,
      description: "Detects DOCTYPE declarations declaring external SYSTEM entities pointing to local files (file:///etc/passwd).",
      signatureSets: ["High Accuracy Signatures", "XML External Entities (XXE) Signatures"]
    },
    {
      signatureId: 200002445,
      name: "XML External Entity (XXE) - Parameter entity out-of-band SSRF",
      attackType: "XML External Entity (XXE)",
      accuracy: "High",
      risk: "Critical",
      systems: ["XML & Web Services"],
      cve: null,
      description: "Detects XML parameter entities (% entity) used for out-of-band data exfiltration over HTTP/DNS.",
      signatureSets: ["High Accuracy Signatures", "XML External Entities (XXE) Signatures"]
    },
    {
      signatureId: 200002450,
      name: "XML Entity Expansion - Billion Laughs Denial of Service (BOMB)",
      attackType: "XML External Entity (XXE)",
      accuracy: "High",
      risk: "High",
      systems: ["XML & Web Services"],
      cve: null,
      description: "Detects nested recursive XML entity declarations designed to cause parser memory exhaustion.",
      signatureSets: ["High Accuracy Signatures", "XML External Entities (XXE) Signatures"]
    },

    // --- Authentication / Authorization Attacks ---
    {
      signatureId: 200006001,
      name: "JWT Signature Stripping - alg: none token tampering",
      attackType: "Authentication / Authorization",
      accuracy: "High",
      risk: "Critical",
      systems: ["Generic"],
      cve: null,
      description: "Detects JSON Web Tokens in headers modified with algorithm none to bypass signature verification.",
      signatureSets: ["High Accuracy Signatures", "Authentication/Authorization Attack Signatures"]
    },
    {
      signatureId: 200006010,
      name: "Credential Stuffing Tool Pattern in login parameters",
      attackType: "Authentication / Authorization",
      accuracy: "Medium",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects automated credential dictionary and wordlist attack formats in authentication requests.",
      signatureSets: ["Medium Accuracy Signatures", "Authentication/Authorization Attack Signatures"]
    },
    {
      signatureId: 200006020,
      name: "HTTP Authorization Header Spoofing / brute-force probe",
      attackType: "Authentication / Authorization",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects sequential default credentials or malformed Basic Auth payloads.",
      signatureSets: ["Medium Accuracy Signatures", "Authentication/Authorization Attack Signatures"]
    },

    // --- Remote File Include ---
    {
      signatureId: 200001923,
      name: "PHP Remote File Inclusion - http:// or ftp:// in include parameter",
      attackType: "Remote File Include",
      accuracy: "High",
      risk: "Critical",
      systems: ["PHP"],
      cve: null,
      description: "Detects remote URL schemes passed into file-inclusion parameters (include, require, load).",
      signatureSets: ["High Accuracy Signatures", "Remote File Include Signatures"]
    },
    {
      signatureId: 200001930,
      name: "PHP Stream Wrapper - php://input or php://filter injection",
      attackType: "Remote File Include",
      accuracy: "High",
      risk: "High",
      systems: ["PHP"],
      cve: null,
      description: "Detects attempts to execute raw POST data via php://input or leak source code using php://filter.",
      signatureSets: ["High Accuracy Signatures", "Remote File Include Signatures"]
    },
    {
      signatureId: 200001940,
      name: "Data URI Remote Code Inclusion - data:text/plain;base64",
      attackType: "Remote File Include",
      accuracy: "Medium",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects data: stream wrappers used to execute encoded server-side code.",
      signatureSets: ["Medium Accuracy Signatures", "Remote File Include Signatures"]
    },

    // --- Vulnerability Scan ---
    {
      signatureId: 200000340,
      name: "Vulnerability Scanner User-Agent - Nikto / OpenVAS / Nessus / Qualys",
      attackType: "Vulnerability Scan",
      accuracy: "High",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects scanner identities and probe signatures from commercial and open-source vulnerability scanners.",
      signatureSets: ["High Accuracy Signatures", "Vulnerability Scan Signatures"]
    },
    {
      signatureId: 200000345,
      name: "Web Application Scanner - Acunetix / AppScan / Netsparker probes",
      attackType: "Vulnerability Scan",
      accuracy: "High",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects proprietary audit tokens and test payload formats generated by DAST scanners.",
      signatureSets: ["High Accuracy Signatures", "Vulnerability Scan Signatures"]
    },
    {
      signatureId: 200000350,
      name: "Exploit Framework Tool - sqlmap / Metasploit automated headers",
      attackType: "Vulnerability Scan",
      accuracy: "High",
      risk: "High",
      systems: ["Generic"],
      cve: null,
      description: "Detects automated exploit toolkit headers and fingerprinting sequences.",
      signatureSets: ["High Accuracy Signatures", "Vulnerability Scan Signatures"]
    },

    // --- Other Application Attacks ---
    {
      signatureId: 200007001,
      name: "Insecure Deserialization - Java ysoserial gadget payload",
      attackType: "Other Application Attacks",
      accuracy: "High",
      risk: "Critical",
      systems: ["Java"],
      cve: null,
      description: "Detects serialized Java gadget chains (CommonsCollections, Spring, Jackson) causing remote code execution.",
      signatureSets: ["High Accuracy Signatures", "Other Application Attacks Signatures"]
    },
    {
      signatureId: 200007010,
      name: "WebDAV HTTP Method Tampering (PROPFIND / SEARCH / MKCOL)",
      attackType: "Other Application Attacks",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Web Servers"],
      cve: null,
      description: "Detects abuse of WebDAV extensions to traverse file systems or upload unauthorized executable assets.",
      signatureSets: ["Medium Accuracy Signatures", "Other Application Attacks Signatures"]
    },
    {
      signatureId: 200007020,
      name: "Server-Side Request Forgery (SSRF) - Cloud Metadata 169.254.169.254 query",
      attackType: "Other Application Attacks",
      accuracy: "High",
      risk: "Critical",
      systems: ["Cloud / AWS / GCP / Azure"],
      cve: null,
      description: "Detects requests targeting internal link-local cloud instance metadata services to harvest IAM credentials.",
      signatureSets: ["High Accuracy Signatures", "Other Application Attacks Signatures"]
    },

    // --- Generic Threat Detection ---
    {
      signatureId: 200008001,
      name: "Generic Suspicious Hex Encoding Sequence (%00 null byte injection)",
      attackType: "Generic Detection",
      accuracy: "High",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects null byte characters (%00) used to terminate C-strings in native application layers.",
      signatureSets: ["High Accuracy Signatures", "Generic Detection Signatures"]
    },
    {
      signatureId: 200008010,
      name: "Generic Multiple URL Encoding Evasion",
      attackType: "Generic Detection",
      accuracy: "Medium",
      risk: "Medium",
      systems: ["Generic"],
      cve: null,
      description: "Detects layered or double URL encoding patterns intended to evade pattern inspection engines.",
      signatureSets: ["Medium Accuracy Signatures", "Generic Detection Signatures"]
    },
    {
      signatureId: 200008020,
      name: "Excessive Non-ASCII Character Density in URI",
      attackType: "Generic Detection",
      accuracy: "Low",
      risk: "Low",
      systems: ["Generic"],
      cve: null,
      description: "Detects URI paths with an abnormal ratio of non-printable or high-byte ASCII characters.",
      signatureSets: ["Low Accuracy Signatures", "Generic Detection Signatures"]
    }
  ]
};

window.LOG_CATALOG = {
  requestTypes: [
    { value: "illegal", label: "Illegal Requests (Violations only - Recommended)", description: "Log only requests that triggered one or more security violations." },
    { value: "all", label: "All Requests (Legal and Illegal)", description: "Complete audit log recording every incoming request regardless of violation status." },
    { value: "blocked", label: "Blocked Requests Only", description: "Log only requests where enforcement action was actively taken (Block response issued)." }
  ],

  formats: [
    { value: "default", label: "Default F5 Key-Value", description: "Standard comma-separated key=value format for F5 WAF for NGINX." },
    { value: "splunk", label: "Splunk SIEM", description: "Optimized for Splunk Enterprise & Cloud F5 WAF for NGINX application add-on." },
    { value: "arcsight", label: "ArcSight (CEF)", description: "Formatted according to HP/Micro Focus ArcSight Common Event Format (CEF)." },
    { value: "grpc", label: "gRPC Protocol", description: "Tailored for gRPC communications with Base64 decoded payloads." },
    { value: "bigiq", label: "BIG-IQ Management", description: "Format tailored for F5 BIG-IQ Centralized Security Management." },
    { value: "user-defined", label: "User-Defined Custom Format", description: "Customizable format string using token placeholders (%attribute%)." }
  ],

  attributes: [
    { name: "attack_type", token: "%attack_type%", description: "Suspected attacks identified in transaction." },
    { name: "blocking_exception_reason", token: "%blocking_exception_reason%", description: "Reason why a violation was not blocked." },
    { name: "bot_anomalies", token: "%bot_anomalies%", description: "Anomalies detected in automated bot traffic." },
    { name: "bot_category", token: "%bot_category%", description: "Bot classification category." },
    { name: "bot_signature_name", token: "%bot_signature_name%", description: "Name of matched bot signature." },
    { name: "client_type", token: "%client_type%", description: "Client classification (browser, mobile, bot, etc.)." },
    { name: "date_time", token: "%date_time%", description: "Timestamp when request was processed." },
    { name: "dest_port", token: "%dest_port%", description: "Destination TCP/UDP port." },
    { name: "ip_client", token: "%ip_client%", description: "Client IP address (or X-Forwarded-For)." },
    { name: "is_truncated", token: "%is_truncated%", description: "Flag indicating if message was truncated due to size limits." },
    { name: "method", token: "%method%", description: "HTTP method (GET, POST, etc.)." },
    { name: "policy_name", token: "%policy_name%", description: "Active F5 WAF policy name." },
    { name: "protocol", token: "%protocol%", description: "HTTP protocol version (HTTP/1.1, HTTP/2)." },
    { name: "request", token: "%request%", description: "Full HTTP request headers and payload." },
    { name: "request_status", token: "%request_status%", description: "Request status (blocked, alerted, passed)." },
    { name: "response_code", token: "%response_code%", description: "HTTP status code sent to client." },
    { name: "route_domain", token: "%route_domain%", description: "Routing domain identifier." },
    { name: "server_entry", token: "%server_entry%", description: "Target server definition." },
    { name: "severity", token: "%severity%", description: "Log severity level." },
    { name: "sig_cves", token: "%sig_cves%", description: "Matched CVE identifiers." },
    { name: "sig_ids", token: "%sig_ids%", description: "IDs of attack signatures triggered." },
    { name: "sig_names", token: "%sig_names%", description: "Names of attack signatures triggered." },
    { name: "sig_set_names", token: "%sig_set_names%", description: "Signature sets containing triggered signatures." },
    { name: "src_port", token: "%src_port%", description: "Client source TCP port." },
    { name: "sub_violations", token: "%sub_violations%", description: "Detailed sub-violation flags." },
    { name: "support_id", token: "%support_id%", description: "Unique transaction correlation ID." },
    { name: "threat_campaign_names", token: "%threat_campaign_names%", description: "Names of matched Threat Campaigns." },
    { name: "unit_hostname", token: "%unit_hostname%", description: "Hostname of NGINX / WAF instance." },
    { name: "uri", token: "%uri%", description: "Normalized request URI path." },
    { name: "violation_details", token: "%violation_details%", description: "Granular XML/JSON violation details." },
    { name: "violation_rating", token: "%violation_rating%", description: "Calculated threat score (1 to 5)." },
    { name: "violations", token: "%violations%", description: "Names of all violations triggered." },
    { name: "x_forwarded_for_header_value", token: "%x_forwarded_for_header_value%", description: "Value of X-Forwarded-For header." }
  ],

  openApiSamples: [
    {
      name: "Example OpenAPI v3.0 (YAML)",
      description: "Generic example OpenAPI 3.0 specification in YAML",
      url: "https://example.com/openapi.yaml"
    },
    {
      name: "Example OpenAPI v3.0 (JSON)",
      description: "Generic example OpenAPI 3.0 specification in JSON format",
      url: "https://example.com/openapi.json"
    },
    {
      name: "Local Spec Reference (/etc/app_protect/conf/openapi.yaml)",
      description: "Local file reference on F5 WAF for NGINX host",
      url: "file:///etc/app_protect/conf/openapi.yaml"
    }
  ],

  grpcRecommendedViolations: [
    { name: "VIOL_GRPC_MALFORMED", alarm: true, block: true, description: "Malformed gRPC data detected" },
    { name: "VIOL_GRPC_FORMAT", alarm: true, block: true, description: "gRPC format or defense attributes violation" },
    { name: "VIOL_GRPC_METHOD", alarm: true, block: true, description: "Illegal or unlisted gRPC method" },
    { name: "VIOL_METHOD", alarm: true, block: true, description: "Illegal HTTP method (gRPC requires POST)" }
  ],

  grpcSamples: [
    {
      name: "Example gRPC Service Proto (Single .proto)",
      description: "Individual proto3 file defining Example gRPC service with RPC methods",
      link: "file:///examples/grpc/album.proto",
      fileType: "proto",
      isPrimary: true
    },
    {
      name: "Example gRPC Service Bundle (Tarball .tgz)",
      description: "Packaged .tgz archive containing multiple protos with dependency imports",
      link: "file:///examples/grpc/album_service_files.tgz",
      fileType: "archive",
      primaryIdlFileName: "album_service.proto"
    },
    {
      name: "RouteGuide Service Proto (Remote URL)",
      description: "Standard official gRPC sample service loaded over HTTPS",
      link: "https://raw.githubusercontent.com/grpc/grpc/master/examples/protos/route_guide.proto",
      fileType: "proto",
      isPrimary: true
    }
  ]
};
