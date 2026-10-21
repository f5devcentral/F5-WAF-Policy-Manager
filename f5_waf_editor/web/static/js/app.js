/**
 * F5 WAF Policy & Logging Profile Manager - Main Alpine.js Application Controller
 */

const DEFAULT_LOG_ATTRIBUTES = [
  { name: "attack_type", token: "%attack_type%", description: "Suspected attacks identified in the transaction (comma-separated)." },
  { name: "blocking_exception_reason", token: "%blocking_exception_reason%", description: "Reason when a configured violation was not blocked." },
  { name: "bot_anomalies", token: "%bot_anomalies%", description: "Anomalies detected in automated bot traffic." },
  { name: "bot_category", token: "%bot_category%", description: "Classification category of the detected bot client." },
  { name: "bot_signature_name", token: "%bot_signature_name%", description: "Name of matching bot signature." },
  { name: "client_type", token: "%client_type%", description: "Client classification (browser, mobile, bot, etc.)." },
  { name: "date_time", token: "%date_time%", description: "Timestamp when the request was processed (YYYY-MM-DD HH:MM:SS)." },
  { name: "dest_port", token: "%dest_port%", description: "Destination TCP/UDP port on the server." },
  { name: "geo_location", token: "%geo_location%", description: "Two-letter ISO country code of the client IP." },
  { name: "grpc_method", token: "%grpc_method%", description: "The gRPC method invoked in the request." },
  { name: "grpc_service", token: "%grpc_service%", description: "The gRPC service invoked in the request." },
  { name: "grpc_status", token: "%grpc_status%", description: "The gRPC response status code returned to client." },
  { name: "ip_address", token: "%ip_address%", description: "IP address of the protected server receiving the request." },
  { name: "ip_client", token: "%ip_client%", description: "Source client IP address sending the HTTP request." },
  { name: "method", token: "%method%", description: "HTTP method used in the request (GET, POST, etc.)." },
  { name: "policy_name", token: "%policy_name%", description: "Name of the active F5 WAF security policy." },
  { name: "protocol", token: "%protocol%", description: "HTTP protocol version (HTTP/1.1, HTTP/2.0)." },
  { name: "request", token: "%request%", description: "Captured portion of raw request up to max_request_size." },
  { name: "request_status", token: "%request_status%", description: "Final disposition: 'blocked', 'alerted', or 'passed'." },
  { name: "response_code", token: "%response_code%", description: "HTTP response status code returned to client." },
  { name: "route_domain", token: "%route_domain%", description: "Route domain ID associated with the transaction." },
  { name: "severity", token: "%severity%", description: "Highest severity level among all triggered violations." },
  { name: "sig_cves", token: "%sig_cves%", description: "CVE identifiers associated with triggered signatures." },
  { name: "sig_names", token: "%sig_names%", description: "Names of triggered attack signatures (comma-separated)." },
  { name: "sub_violations", token: "%sub_violations%", description: "Detailed sub-violation flags for compound violations." },
  { name: "support_id", token: "%support_id%", description: "Unique numeric identifier for tracking the request." },
  { name: "threat_campaign_names", token: "%threat_campaign_names%", description: "Active threat campaigns matched in the request." },
  { name: "unit_hostname", token: "%unit_hostname%", description: "Hostname of the NGINX instance executing F5 WAF." },
  { name: "uri", token: "%uri%", description: "Normalized URI path requested by the client." },
  { name: "violation_details", token: "%violation_details%", description: "XML/JSON-encoded violation diagnostics data." },
  { name: "violation_rating", token: "%violation_rating%", description: "Numerical threat score assessed for the transaction (0-5)." },
  { name: "violations", token: "%violations%", description: "List of all triggered violation names." },
  { name: "vs_name", token: "%vs_name%", description: "Virtual server or NGINX location block identifier." },
  { name: "x_forwarded_for_header_value", token: "%x_forwarded_for_header_value%", description: "Value of the X-Forwarded-For HTTP request header." },
];

document.addEventListener("alpine:init", () => {
  Alpine.data("wafApp", () => ({
    // Application Section & Theme
    activeSection: "waf", // 'waf' | 'logging'
    theme: "dark", // 'dark' | 'light'

    // WAF Policy Application State
    view: "dashboard", // 'dashboard' | 'editor'
    editorMode: "visual", // 'visual' | 'json'
    activeTab: "general", // subtab in visual editor
    loading: false,
    toast: { show: false, message: "", type: "info" },

    // WAF Policy Data
    policies: [],
    searchQuery: "",
    modeFilter: "all",
    currentPolicy: null,
    currentPolicyOriginal: null,
    originalPolicyName: null,
    currentPolicyName: null,
    isDirty: false,
    rawJsonString: "",
    jsonErrors: [],
    jsonWarnings: [],

    // WAF Diff State
    showDiffModal: false,
    computedDiff: [],

    // Catalogs & Reference Data
    catalog: window.WAF_CATALOG || {
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
      violations: [],
      serverTechnologies: [],
      signatureSets: [],
      attackSignatures: (window.WAF_CATALOG && window.WAF_CATALOG.attackSignatures) || []
    },
    templates: [],
    violationsSearch: "",
    violationsCategory: "All Categories",

    // Storage & Backend Health (GitHub, Redis, In-Memory)
    storageHealth: {
      status: "loading",
      backend: "unknown",
      connected: false,
      owner: "",
      repo: "",
      branch: "main",
      host: "localhost",
      port: 6379,
      latency_ms: 0,
      total_policies: 0,
      policies_path: "policies",
      log_profiles_path: "log-profiles",
      custom_sigs_path: "custom-signatures",
    },
    // Backwards compatibility alias
    redisHealth: {
      status: "loading",
      backend: "unknown",
      connected: false,
      host: "localhost",
      port: 6379,
      latency_ms: 0,
      total_policies: 0,
    },

    // Storage Backend Modal & Forms
    storageBackendTab: "redis", // 'github' | 'redis' | 'memory'
    storageBackendTabInitialized: false,
    showStorageModal: false,
    githubForm: {
      owner: "",
      repo: "",
      token: "",
      branch: "main",
      api_url: "https://api.github.com",
      disable_ssl_verify: false,
      policies_path: "policies",
      log_profiles_path: "log-profiles",
      custom_sigs_path: "custom-signatures",
      showToken: false,
      showAdvanced: false,
    },

    // WAF Modals
    showCreateModal: false,
    showCloneModal: false,
    showDeleteModal: false,
    showRedisModal: false,
    showImportModal: false,

    // GitOps Push to GitHub Modal State
    showGitHubCommitModal: false,
    githubPulling: false,
    githubCommitTarget: {
      type: "policy", // 'policy' | 'logging' | 'custom_signatures'
      name: "",
      message: "",
      isSubmitting: false,
    },

    // GitHub Pull Conflict Resolution State
    showPullConflictModal: false,
    pullConflicts: [],
    pullResolutions: {},
    pullConflictSubmitting: false,

    // BIG-IP WAF Policy Converter State
    showBigIpModal: false,
    bigIpLoading: false,
    bigIpFile: null,
    bigIpFileName: "",
    bigIpFileSize: 0,
    bigIpForm: {
      targetName: "",
      fullExport: true,
      keepFullConfiguration: false,
      includeAllSignatures: false,
      saveToStorage: true,
    },
    bigIpResult: null,

    // F5 WAF Compiler Tester State
    showCompilerModal: false,
    compilerLoading: false,
    compilerStatus: {
      cli_available: false,
      compiler_bin: null,
      engine: "loading...",
      version: "5.15.0",
    },
    compilerForm: {
      targetType: "policy", // 'policy' | 'log_profile'
      targetSource: "editor", // 'editor' | 'storage'
      selectedName: "",
      includeSource: false,
      fullExport: false,
      globalSettingsJson: "",
    },
    compilerResult: null,
    showCompilerRawOutput: false,


    // Form inputs for WAF modals
    newPolicyForm: {
      name: "",
      template_id: "default",
      description: "",
      enforcementMode: "blocking",
    },
    cloneTargetName: "",
    policyToDelete: null,
    redisForm: {
      host: "localhost",
      port: 6379,
      db: 0,
      password: "",
      ssl: false,
      key_prefix: "",
      force_memory: false,
    },

    // Signature sets & exceptions state
    sigSetCatalogSelect: "",
    sigSetSearch: "",
    showAddCustomSigSetModal: false,
    showDeleteSigSetModal: false,
    showMassDeleteSigSetModal: false,
    selectedSigSets: [],
    sigSetToDelete: null,
    sigSetToDeleteIndex: null,
    editingSigSetIndex: null,
    showSigSetInspectorModal: false,
    inspectedSigSet: null,
    sigInspectorSearch: "",
    sigInspectorAccuracyFilter: "all",
    sigInspectorRiskFilter: "all",
    customSigSetForm: {
      name: "",
      alarm: true,
      block: true,
      type: "filter-based", // 'filter-based' | 'manual'
      tagFilter: "eq",
      tagValue: "",
      riskFilter: "all",
      riskValue: "all",
      accuracyFilter: "all",
      accuracyValue: "all",
      signatureType: "all",
      hasCve: "all",
      attackType: "",
      manualSignaturesInput: "",
    },
    tempSigException: {
      mode: "builtin", // 'builtin' | 'custom'
      signatureId: "",
      customName: "",
      customTag: "",
      selectedCustomSig: "",
      enabled: false,
      tag: "",
    },

    // User-Defined Signatures (Custom Signatures) State
    showCustomSigModal: false,
    showSnortHelperModal: false,
    showSigReqModal: false,
    customSigFiles: [],
    customSigCatalog: {
      snortTemplates: [],
      attackTypes: [],
      systems: [],
      defaultTemplate: null,
    },
    customSigTab: "rule", // 'rule' | 'tester'
    snortValidationStatus: {
      checked: false,
      valid: true,
      errors: [],
      warnings: [],
      parsed: null,
    },
    snortRuleDebounceTimer: null,
    snortTestForm: {
      method: "GET",
      uri: "/store/basket?fruit=apple",
      headers: "User-Agent: Mozilla/5.0\nAccept: application/json",
      body: '{"search": "apple juice"}',
    },
    snortTestResult: null,
    snortTestLoading: false,
    customSigForm: {
      name: "",
      tag: "Fruits",
      description: "",
      rule: 'content:"apple"; nocase;',
      signatureType: "request", // 'request' | 'response'
      attackType: "Buffer Overflow",
      systems: ["Unix/Linux"],
      risk: "medium", // 'low' | 'medium' | 'high'
      accuracy: "medium", // 'low' | 'medium' | 'high'
      isEditing: false,
      editIndex: null,
    },
    selectedCustomSigs: [],
    showDeleteCustomSigModal: false,
    customSigToDelete: null,
    customSigToDeleteIndex: null,
    showMassDeleteCustomSigModal: false,

    // URLs multi-select and delete state
    selectedUrls: [],
    showDeleteUrlModal: false,
    urlToDelete: null,
    urlToDeleteIndex: null,
    showMassDeleteUrlModal: false,

    // Parameters multi-select and delete state
    selectedParams: [],
    showDeleteParamModal: false,
    paramToDelete: null,
    paramToDeleteIndex: null,
    showMassDeleteParamModal: false,

    // IP Address Lists state
    selectedIpLists: [],
    showDeleteIpListModal: false,
    ipListToDelete: null,
    ipListToDeleteIndex: null,
    showMassDeleteIpListModal: false,
    showAddIpListModal: false,
    ipListSearch: "",
    ipListForm: {
      name: "",
      description: "",
      blockRequests: "policy-default",
      setGeolocation: "",
      ipAddressesText: "",
      isEditing: false,
      editIndex: null,
    },

    // Response inspection helper state
    newAllowedResponseCodeInput: "",


    sigReqForm: {
      tag: "",
      minRevisionDatetime: "",
      maxRevisionDatetime: "",
      isEditing: false,
      editIndex: null,
    },
    sigReqSearch: "",

    // OpenAPI External References state
    openApiLinkType: "url", // 'url' | 'file'
    openApiSampleSelect: "",
    openApiShowBasicAuth: false,
    openApiAuthUser: "",
    openApiPlainPassword: "",
    openApiAllowSelfSigned: false,
    openApiAuthType: "none", // 'none' | 'basic' | 'bearer' | 'mtls'
    openApiBearerToken: "",
    openApiClientCert: "",
    openApiClientKey: "",
    openApiSyncBasicAuthToPolicy: true,
    openApiTestLoading: false,
    openApiTestResult: null,
    openApiSyntaxMode: "array", // 'array' (open-api-files) | 'direct' (openApiFileReference)

    // gRPC Protection State
    grpcActiveProfileIndex: 0,
    grpcTestLoading: false,
    grpcTestResult: null,
    grpcSampleSelect: "",
    grpcUploadLoading: false,
    grpcUploadedFileName: "",

    // Temporary inputs for WAF lists in visual editor
    tempUrl: { path: "", type: "explicit" },
    tempParam: { name: "", type: "query", sensitive: false, dataType: "string" },
    tempIp: { ip: "", type: "deny", comment: "" },
    tempMethod: "",
    tempRegex: "",

    // URL Edit & Parameters State
    showEditUrlModal: false,
    editingUrlIndex: null,
    urlEditForm: {
      name: "",
      type: "explicit",
      method: "*",
      protocol: "http",
      wildcardOrder: 1,
      isAllowed: true,
      metacharsOnUrlCheck: false,
      metacharOverrides: [],
      attackSignaturesCheck: false,
      signatureOverrides: [],
      disallowFileUploadOfExecutables: false,
      mandatoryBody: false,
      clickjackingProtection: false,
      allowRenderingInFrames: "only-same",
      urlContentProfiles: [],
    },
    // URL configured parameters tracking state
    urlConfiguredParams: [],
    urlParamMode: "existing", // 'existing' | 'new'
    urlParamSelectedExisting: "",
    urlParamNewForm: {
      name: "",
      type: "explicit",
      dataType: "alpha-numeric",
      parameterLocation: "any",
      valueType: "user-input",
      sensitiveParameter: false,
      mandatory: false,
    },
    tempUrlMetachar: { metachar: "0x3c", isAllowed: true },
    tempUrlSig: { signatureId: "", enabled: false },
    tempUrlSigOverride: { signatureId: "", enabled: false },

    // Content Profiles (urlContentProfiles) State
    tempUrlContentProfile: {
      type: "json", // 'json' | 'xml' | 'graphql' | 'grpc' | 'form-data' | 'gwt' | 'do-nothing'
      headerName: "Content-Type",
      headerValue: "*json*",
      headerOrder: "default",
      profileName: "Default",
      isEditing: false,
      editIndex: null,
    },

    // Parameter Edit & Advanced Definition State
    showEditParamModal: false,
    editingParamIndex: null,
    paramEditForm: {
      name: "",
      originalName: "",
      type: "explicit",
      level: "global",
      isGlobal: false,
      urls: [],
      parameterLocation: "any",
      valueType: "user-input",
      dataType: "alpha-numeric",
      mandatory: false,
      allowEmptyValue: false,
      allowRepeatedParameterName: false,
      sensitiveParameter: false,
      decodeValueAsBase64: "disabled",
      disallowFileUploadOfExecutables: false,
      checkMinValueLength: false,
      minimumLength: 0,
      checkMaxValueLength: false,
      maximumLength: 100,
      checkMinValue: false,
      minimumValue: 0,
      exclusiveMin: false,
      checkMaxValue: false,
      maximumValue: 100,
      exclusiveMax: false,
      checkMultipleOfValue: false,
      multipleOf: 1,
      enableRegularExpression: false,
      regularExpression: "",
      attackSignaturesCheck: false,
      signatureOverrides: [],
      checkMetachars: false,
      nameMetacharOverrides: [],
      metacharsOnParameterValueCheck: false,
      valueMetacharOverrides: [],
      arraySerializationFormat: "csv",
      arrayUniqueItemsCheck: false,
      checkMinItemsInArray: false,
      minItemsInArray: 0,
      checkMaxItemsInArray: false,
      maxItemsInArray: 10,
      wildcardOrder: 1,
      staticValuesInput: "",
      enumValuesInput: "",
    },
    tempParamSig: { signatureId: "", enabled: false },
    tempParamNameMetachar: { metachar: "0x3c", isAllowed: true },
    tempParamValMetachar: { metachar: "0x28", isAllowed: false },
    tempParamUrlAssociation: {
      selectedExistingUrl: "",
      name: "",
      method: "*",
      protocol: "http",
      type: "wildcard",
    },

    // URLs and Parameters Search & Filter State
    urlSearchQuery: "",
    urlTypeFilter: "all", // 'all' | 'explicit' | 'wildcard'
    paramSearchQuery: "",
    paramTypeFilter: "all", // 'all' | 'query' | 'body' | 'header' | 'cookie'
    paramDataTypeFilter: "all", // 'all' | 'string' | 'integer' | 'boolean' | 'alpha-numeric'
    paramSensitivityFilter: "all", // 'all' | 'sensitive' | 'normal'
    cookieSearchQuery: "",
    cookieTypeFilter: "all", // 'all' | 'explicit' | 'wildcard'
    cookieEnforcementFilter: "all", // 'all' | 'enforce' | 'allow'
    cookiePage: 1,
    cookiePageSize: 50,
    newCookie: {
      name: "",
      type: "explicit",
      enforcementType: "enforce",
      attackSignaturesCheck: true,
      maskValueInLogs: false,
      accessibleOnlyThroughTheHttpProtocol: false,
    },

    // Server Technologies Search & Filter State
    serverTechSearchQuery: "",
    serverTechCategoryFilter: "all",
    serverTechStatusFilter: "all", // 'all' | 'selected' | 'unselected'

    // Pagination & Virtualization State for Large Policies
    urlPage: 1,
    urlPageSize: 50,
    paramPage: 1,
    paramPageSize: 50,
    sigPage: 1,
    sigPageSize: 50,
    sigSearchQuery: "",
    customSigPage: 1,
    customSigPageSize: 50,
    customSigSearchQuery: "",
    ipListPage: 1,
    ipListPageSize: 50,

    // -------------------------------------------------------------
    // LOGGING PROFILES STATE
    // -------------------------------------------------------------
    logProfiles: [],
    logSearchQuery: "",
    logFilterReqType: "all",
    logFilterFormat: "all",
    logLoading: false,

    logView: "dashboard", // 'dashboard' | 'editor'
    logEditorMode: "visual", // 'visual' | 'json'
    activeLogTab: "filter", // 'filter' | 'format' | 'sizing' | 'escaping' | 'all'
    currentLogName: null,
    currentLogOriginal: null,
    isLogDirty: false,
    rawLogJsonString: "",
    logJsonErrors: [],
    logJsonWarnings: [],

    // Logging Catalogs & Templates
    logCatalog: window.LOG_CATALOG || {
      requestTypes: ["all", "illegal", "blocked"],
      formats: ["default", "arcsight", "bigiq", "grpc", "splunk", "user-defined"],
      attributes: DEFAULT_LOG_ATTRIBUTES,
    },
    logTemplates: [],
    attributeSearchQuery: "",

    // Logging Profile Visual Builder Form
    logForm: {
      name: "",
      filter: {
        request_type: "illegal",
      },
      content: {
        format: "default",
        format_string: "",
        max_request_size: "2k",
        max_message_size: "32k",
        list_prefix: "",
        list_delimiter: ",",
        list_suffix: "",
        escaping_characters: [],
      },
    },
    tempEscaping: { from: "", to: "" },

    // Logging Modals
    showCreateLogModal: false,
    showCloneLogModal: false,
    showDeleteLogModal: false,
    showImportLogModal: false,
    showLogDiffModal: false,
    computedLogDiff: [],

    newLogForm: {
      name: "",
      template_id: "log_default",
    },
    cloneLogTargetName: "",
    logToDelete: null,

    // -------------------------------------------------------------
    // CLICKHOUSE VIOLATION LOGS & POLICY FINE-TUNING STATE
    // -------------------------------------------------------------
    showClickHouseModal: false,
    chLoading: false,
    chTesting: false,
    chSaving: false,
    chTuningInProgress: false,
    chError: null,
    chTestResult: null,
    chStatus: {
      connected: false,
      configured: false,
      persisted_in_redis: false,
      database: "nms",
      config: {
        host: "",
        port: 8123,
        username: "default",
        database: "nms",
        ssl: false,
        verify_ssl: true,
        has_password: false,
        persisted_in_redis: false,
      },
    },
    chConfigForm: {
      host: "",
      port: 8123,
      username: "default",
      password: "",
      database: "nms",
      ssl: false,
      verify_ssl: true,
    },
    chSchemaEventsColumns: [],
    chSchemaViolationColumns: [],
    chSchemaSignaturesColumns: [],
    chFilterOperators: [
      { id: "contains", label: "Contains (case-insensitive)" },
      { id: "equals", label: "Equals (=)" },
      { id: "not_equals", label: "Does not equal (!=)" },
      { id: "not_contains", label: "Does not contain" },
      { id: "starts_with", label: "Starts with" },
      { id: "ends_with", label: "Ends with" },
      { id: "in", label: "In comma-separated list" },
      { id: "gt", label: "Greater than (>)" },
      { id: "gte", label: "Greater than or equal (>=)" },
      { id: "lt", label: "Less than (<)" },
      { id: "lte", label: "Less than or equal (<=)" },
      { id: "is_empty", label: "Is empty or N/A" },
      { id: "is_not_empty", label: "Is not empty and not N/A" },
    ],
    chGlobalSearch: "",
    chQuickFilters: {
      support_id: "",
      policy_name: "",
      request_status: "",
      severity: "",
      http__request_method: "",
      http__uri: "",
      http__remote_addr: "",
      signature_ids: "",
      violations: "",
    },
    chFieldFilters: [],
    chShowColumnPicker: false,
    chVisibleColumns: [
      "timestamp",
      "support_id",
      "request_status",
      "severity",
      "policy_name",
      "http__request_method",
      "http__uri",
      "http__remote_addr",
      "violation_rating",
      "signature_ids",
      "signature_names",
      "violations",
      "bot_signature_name",
    ],
    chSortBy: "timestamp",
    chSortOrder: "DESC",
    chLimit: 50,
    chOffset: 0,
    chTotalEvents: 0,
    chEvents: [],
    chSelectedSupportId: null,
    chCorrelatedData: null,
    chCorrelationTab: "signatures",
    chTargetPolicy: "",
    chInspectorLogPolicyName: "",
    chUnsavedTuningCount: 0,
    chSavingPolicyToRedis: false,
    chPolicySavedToRedis: false,
    chLastSavedPolicyName: "",
    configActiveTab: "all",

    // -------------------------------------------------------------
    // LIFECYCLE
    // -------------------------------------------------------------
    async init() {
      // 1. Initialize Theme from storage or system preference
      const savedTheme = localStorage.getItem("f5_waf_theme");
      if (savedTheme) {
        this.theme = savedTheme;
      } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
        this.theme = "light";
      } else {
        this.theme = "dark";
      }
      this.applyTheme(this.theme);

      // Watch tab changes to scroll the active configuration panel to top
      this.$watch('activeTab', () => {
        this.$nextTick(() => {
          const panel = document.getElementById('waf-main-editor-panel');
          if (panel) panel.scrollTop = 0;
        });
      });
      this.$watch('activeLogTab', () => {
        this.$nextTick(() => {
          const panel = document.getElementById('log-main-editor-panel');
          if (panel) panel.scrollTop = 0;
        });
      });

      // 2. Load health & catalogs
      await this.checkRedisHealth();
      await this.loadTemplates();
      await this.loadCatalog();
      await this.loadLogCatalog();
      await this.loadPolicies();
      await this.loadLogTemplates();
      await this.loadLogProfiles();
      await this.loadCustomSignaturesCatalog();
      await this.loadCustomSignatureFiles();
      await this.loadClickHouseSchema();
      await this.loadClickHouseStatus(false);

      // Poll Redis health periodically
      setInterval(() => this.checkRedisHealth(false), 15000);
    },

    // --- Theme Switcher ---
    applyTheme(theme) {
      this.theme = theme;
      if (theme === "dark") {
        document.documentElement.classList.add("dark");
        document.documentElement.classList.remove("light");
      } else {
        document.documentElement.classList.remove("dark");
        document.documentElement.classList.add("light");
      }
      localStorage.setItem("f5_waf_theme", theme);

      // Update CodeMirror themes
      const cmTheme = theme === "dark" ? "material-darker" : "default";
      if (window.WAF_EDITOR) window.WAF_EDITOR.setTheme(cmTheme);
      if (window.LOG_EDITOR) window.LOG_EDITOR.setTheme(cmTheme);
    },

    toggleTheme() {
      const next = this.theme === "dark" ? "light" : "dark";
      this.applyTheme(next);
      this.notify(`Switched to ${next} theme`, "info");
    },

    // --- Navigation Switcher ---
    async switchSection(section, subTarget = null) {
      this.activeSection = section;
      if (section === "waf") {
        this.loadPolicies();
      } else if (section === "logging") {
        this.loadLogProfiles();
      } else if (section === "violations") {
        await this.loadPolicies();
        if (!this.chTargetPolicy && this.policies.length > 0) {
          this.chTargetPolicy = this.policies[0].name;
        }
        await this.loadClickHouseStatus(true);
        if (this.chStatus.configured && this.chStatus.connected && this.chEvents.length === 0) {
          await this.searchClickHouseEvents(true);
        }
      } else if (section === "configuration") {
        if (subTarget && ["github", "redis", "memory"].includes(subTarget)) {
          this.storageBackendTab = subTarget;
        }
        await this.checkStorageHealth(true);
        await this.loadClickHouseStatus(true);
        const cfg = this.chConfig || this.chStatus.config || {};
        this.chConfigForm = {
          host: cfg.host || this.chConfigForm.host || "",
          port: cfg.port || this.chConfigForm.port || 8123,
          username: cfg.username || this.chConfigForm.username || "default",
          password: this.chConfigForm.password || "",
          database: cfg.database || this.chConfigForm.database || "nms",
          ssl: cfg.ssl !== undefined ? !!cfg.ssl : !!this.chConfigForm.ssl,
          verify_ssl: cfg.verify_ssl !== undefined ? !!cfg.verify_ssl : !!this.chConfigForm.verify_ssl,
        };
        if (subTarget) {
          this.$nextTick(() => {
            const cardId =
              subTarget === "clickhouse"
                ? "config-card-clickhouse"
                : subTarget === "github"
                ? "config-card-github"
                : subTarget === "redis" || subTarget === "memory"
                ? "config-card-redis"
                : null;
            if (cardId) {
              const el = document.getElementById(cardId);
              if (el && typeof el.scrollIntoView === "function") {
                el.scrollIntoView({ behavior: "smooth", block: "start" });
              }
            }
          });
        }
      }
    },

    // --- Toast Notifications ---
    notify(message, type = "success") {
      this.toast = { show: true, message, type };
      setTimeout(() => {
        this.toast.show = false;
      }, 4000);
    },

    openStorageModal(tab = null) {
      if (tab) {
        this.storageBackendTab = tab;
      } else {
        if (this.storageHealth.backend === "github") {
          this.storageBackendTab = "github";
        } else if (this.storageHealth.backend === "redis") {
          this.storageBackendTab = "redis";
        } else if (this.storageHealth.backend === "in_memory") {
          this.storageBackendTab = "memory";
        }
      }
      this.showStorageModal = false;
      this.showRedisModal = false;
      this.switchSection("configuration", tab || this.storageBackendTab);
    },

    closeStorageModal() {
      this.showStorageModal = false;
      this.showRedisModal = false;
    },

    // --- Unified Storage Status & Config (GitHub, Redis, In-Memory) ---
    async checkStorageHealth(showFeedback = true) {
      try {
        const res = await fetch("/api/storage/status");
        if (!res.ok) throw new Error("Health check returned status " + res.status);
        const data = await res.json();
        this.storageHealth = data;
        this.redisHealth = data; // Mirror for backwards compatibility

        // Synchronize active tab ONLY on initial app boot, never while user is interacting or during periodic background polling
        if (!this.storageBackendTabInitialized) {
          if (data.backend === "github") {
            this.storageBackendTab = "github";
          } else if (data.backend === "redis") {
            this.storageBackendTab = "redis";
          } else if (data.backend === "in_memory") {
            this.storageBackendTab = "memory";
          }
          this.storageBackendTabInitialized = true;
        }

        // Only synchronize form inputs if explicitly requested (e.g. on load or after save),
        // and NEVER while the user is actively viewing/editing the settings modal!
        const modalOpen = Boolean(this.showStorageModal || this.showRedisModal);
        if (showFeedback && !modalOpen) {
          const gh = data.github || (data.backend === "github" ? data : null);
          if (gh && (gh.configured || data.backend === "github")) {
            if (gh.owner) this.githubForm.owner = gh.owner;
            if (gh.repo) this.githubForm.repo = gh.repo;
            if (gh.branch) this.githubForm.branch = gh.branch;
            if (gh.api_url) this.githubForm.api_url = gh.api_url;
            if (gh.policies_path) this.githubForm.policies_path = gh.policies_path;
            if (gh.log_profiles_path) this.githubForm.log_profiles_path = gh.log_profiles_path;
            if (gh.custom_sigs_path) this.githubForm.custom_sigs_path = gh.custom_sigs_path;
            if (gh.disable_ssl_verify !== undefined) {
              this.githubForm.disable_ssl_verify = Boolean(gh.disable_ssl_verify);
            } else if (gh.verify_ssl !== undefined) {
              this.githubForm.disable_ssl_verify = !gh.verify_ssl;
            }
          }

          if (data.backend === "redis" && data.connected) {
            this.redisForm.host = data.host || "localhost";
            this.redisForm.port = data.port || 6379;
          }
        }
      } catch (err) {
        this.storageHealth.status = "error";
        this.storageHealth.connected = false;
        this.storageHealth.error = err.message;
        this.redisHealth.status = "error";
        this.redisHealth.connected = false;
        this.redisHealth.error = err.message;
      }
    },

    async checkRedisHealth(showFeedback = true) {
      return this.checkStorageHealth(showFeedback);
    },

    async applyGitHubConfig() {
      const owner = (this.githubForm.owner || "").trim();
      const repo = (this.githubForm.repo || "").trim();
      const token = (this.githubForm.token || "").trim();

      if (!owner || !repo || !token) {
        this.notify("GitHub Organization/Owner, Repository Name, and Personal Access Token (PAT) are required", "error");
        return;
      }

      try {
        this.loading = true;
        const res = await fetch("/api/github/connect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            owner: owner,
            repo: repo,
            token: token,
            branch: (this.githubForm.branch || "main").trim(),
            api_url: (this.githubForm.api_url || "https://api.github.com").trim(),
            disable_ssl_verify: Boolean(this.githubForm.disable_ssl_verify),
            verify_ssl: !this.githubForm.disable_ssl_verify,
            policies_path: (this.githubForm.policies_path || "policies").trim(),
            log_profiles_path: (this.githubForm.log_profiles_path || "log-profiles").trim(),
            custom_sigs_path: (this.githubForm.custom_sigs_path || "custom-signatures").trim(),
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Connection to GitHub failed");
        this.notify(data.message, "success");
        this.storageBackendTab = "github";
        this.closeStorageModal();
        await this.checkStorageHealth(true);
        await this.loadPolicies();
        await this.loadLogProfiles();
        await this.loadCustomSignatureFiles();
      } catch (err) {
        this.notify("GitHub Connection Error: " + err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    async applyRedisConfig() {
      try {
        this.loading = true;
        const res = await fetch("/api/redis/connect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(this.redisForm),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Connection failed");
        this.notify(data.message, "success");
        this.storageBackendTab = "redis";
        this.closeStorageModal();
        await this.checkStorageHealth(true);
        await this.loadPolicies();
        await this.loadLogProfiles();
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    async switchToMemoryBackend() {
      try {
        this.loading = true;
        const res = await fetch("/api/storage/switch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ backend: "memory" }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Switch failed");
        this.notify(data.message, "success");
        this.storageBackendTab = "memory";
        this.closeStorageModal();
        await this.checkStorageHealth(true);
        await this.loadPolicies();
        await this.loadLogProfiles();
      } catch (err) {
        this.notify("Storage Switch Error: " + err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    // --- GitOps GitHub Push / Pull Operations ---
    openGitHubCommitModal(type, name) {
      if (!name) {
        if (type === "policy") {
          name = this.currentPolicyName || this.originalPolicyName || this.currentPolicy?.policy?.name;
        } else if (type === "logging") {
          name = this.currentLogName;
        }
      }
      if (!name) {
        this.notify("Please select an item to commit", "error");
        return;
      }
      const isConfigured = Boolean(this.storageHealth?.github?.configured || this.storageHealth?.github_configured || (this.storageHealth?.backend === "github"));
      if (!isConfigured) {
        this.notify("GitHub integration is not configured. Please configure GitHub credentials in Storage Settings first.", "error");
        this.openStorageModal("github");
        return;
      }

      if (this.storageHealth?.backend === "github") {
        if (type === "policy") {
          const isEditing = this.view === "editor" && (name === this.currentPolicyName || name === this.originalPolicyName || name === this.currentPolicy?.policy?.name);
          if (isEditing && !this.canCommitCurrentPolicy()) {
            this.notify("No modifications to commit (in sync with GitHub)", "info");
            return;
          }
          const p = this.policies?.find((x) => x.name === name);
          if (p && !this.canCommitPolicyRow(p) && (!isEditing || !this.isDirty)) {
            this.notify("No modifications to commit (in sync with GitHub)", "info");
            return;
          }
        } else if (type === "logging") {
          const isEditing = this.logView === "editor" && name === this.currentLogName;
          if (isEditing && !this.canCommitCurrentLog()) {
            this.notify("No modifications to commit (in sync with GitHub)", "info");
            return;
          }
          const p = this.logProfiles?.find((x) => x.name === name);
          if (p && !this.canCommitLogRow(p) && (!isEditing || !this.isLogDirty)) {
            this.notify("No modifications to commit (in sync with GitHub)", "info");
            return;
          }
        }
      }

      const category = type === "policy" ? "waf" : (type === "logging" ? "logging" : "signatures");
      this.githubCommitTarget = {
        type: type,
        name: name,
        message: `feat(${category}): update ${name}`,
        isLoadingPreview: true,
        isSubmitting: false,
      };
      this.showGitHubCommitModal = true;
      this.fetchCommitPreview(type, name);
    },

    async fetchCommitPreview(type, name) {
      try {
        let content = null;
        if (type === "policy" && this.view === "editor" && (name === this.currentPolicyName || name === this.originalPolicyName || name === this.currentPolicy?.policy?.name)) {
          content = this.editorMode === "json" && window.WAF_EDITOR ? window.WAF_EDITOR.getValue() : this.currentPolicy;
        } else if (type === "logging" && this.logView === "editor" && name === this.currentLogName) {
          content = this.logEditorMode === "json" && window.LOG_EDITOR ? window.LOG_EDITOR.getValue() : this.buildLogObjectFromForm();
        }

        const res = await fetch("/api/github/commit-preview", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type, name, content }),
        });
        if (res.ok) {
          const data = await res.json();
          if (data.commit_message && this.showGitHubCommitModal && this.githubCommitTarget.name === name) {
            this.githubCommitTarget.message = data.commit_message;
          }
        }
      } catch (err) {
        console.warn("Could not fetch commit description preview:", err);
      } finally {
        if (this.githubCommitTarget.name === name) {
          this.githubCommitTarget.isLoadingPreview = false;
        }
      }
    },

    async executeGitHubCommit() {
      if (!this.githubCommitTarget.name || !this.githubCommitTarget.message) {
        this.notify("Commit message is required", "error");
        return;
      }

      this.githubCommitTarget.isSubmitting = true;
      try {
        // If editing this item with unsaved changes, save to Redis first
        const isEditingPolicy = this.githubCommitTarget.type === "policy" && this.view === "editor" &&
          (this.currentPolicyName === this.githubCommitTarget.name || this.originalPolicyName === this.githubCommitTarget.name || this.currentPolicy?.policy?.name === this.githubCommitTarget.name);
        const isEditingLog = this.githubCommitTarget.type === "logging" && this.logView === "editor" &&
          this.currentLogName === this.githubCommitTarget.name;

        if (isEditingPolicy && this.isDirty) {
          await this.saveCurrentPolicy();
        } else if (isEditingLog && this.isLogDirty) {
          await this.saveCurrentLogProfile();
        }

        let endpoint = "";
        const encodedName = encodeURIComponent(this.githubCommitTarget.name);
        if (this.githubCommitTarget.type === "policy") {
          endpoint = `/api/policies/${encodedName}/github-push`;
        } else if (this.githubCommitTarget.type === "logging") {
          endpoint = `/api/log-profiles/${encodedName}/github-push`;
        } else if (this.githubCommitTarget.type === "custom_signatures") {
          endpoint = `/api/custom-signatures/${encodedName}/github-push`;
        }

        const res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: this.githubCommitTarget.message }),
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || "Failed to commit and push to GitHub");
        }

        this.notify(data.message || `Successfully committed and pushed ${this.githubCommitTarget.name} to GitHub!`, "success");
        this.showGitHubCommitModal = false;
        if (isEditingPolicy) {
          this.isDirty = false;
          this.currentPolicyOriginal = JSON.parse(JSON.stringify(this.currentPolicy || {}));
          this._originalPolicyJsonString = JSON.stringify(this.currentPolicy || {}, null, 2);
        } else if (isEditingLog) {
          this.isLogDirty = false;
          this.currentLogOriginal = JSON.parse(JSON.stringify(this.logForm || {}));
        }
        await this.loadPolicies();
        await this.loadLogProfiles();
        await this.loadCustomSignatureFiles();
        await this.checkStorageHealth(false);
      } catch (err) {
        this.notify("GitHub Push Error: " + err.message, "error");
      } finally {
        this.githubCommitTarget.isSubmitting = false;
      }
    },

    canRevertCurrentPolicy() {
      if (this.storageHealth?.backend !== "github") return false;
      const name = this.currentPolicyName || this.originalPolicyName || this.currentPolicy?.policy?.name;
      if (!name) return false;
      const p = this.policies?.find((x) => x.name === name);
      if (p && p.status === "new_uncommitted") return false;
      if (this.isDirty) return true;
      return Boolean(p && (p.uncommitted_changes || p.status === "modified"));
    },

    canRevertCurrentLog() {
      if (this.storageHealth?.backend !== "github") return false;
      const name = this.currentLogName;
      if (!name) return false;
      const p = this.logProfiles?.find((x) => x.name === name);
      if (p && p.status === "new_uncommitted") return false;
      if (this.isLogDirty) return true;
      return Boolean(p && (p.uncommitted_changes || p.status === "modified"));
    },

    canCommitPolicyRow(p) {
      if (!p) return false;
      if (this.storageHealth?.backend === "github") {
        return Boolean(p.uncommitted_changes || p.status === "modified" || p.status === "new_uncommitted");
      }
      if (p.uncommitted_changes || p.status === "modified" || p.status === "new_uncommitted" || p.saved_to === "redis") {
        return true;
      }
      if (this.storageHealth?.github_configured || this.storageHealth?.github?.configured) {
        return true;
      }
      return false;
    },

    canCommitLogRow(p) {
      if (!p) return false;
      if (this.storageHealth?.backend === "github") {
        return Boolean(p.uncommitted_changes || p.status === "modified" || p.status === "new_uncommitted");
      }
      if (p.uncommitted_changes || p.status === "modified" || p.status === "new_uncommitted") {
        return true;
      }
      return false;
    },

    canCommitCurrentPolicy() {
      const name = this.currentPolicyName || this.originalPolicyName || this.currentPolicy?.policy?.name;
      if (!name) return false;
      const p = this.policies?.find((x) => x.name === name);
      if (this.storageHealth?.backend === "github") {
        if (this.isDirty) return true;
        return Boolean(p && (p.uncommitted_changes || p.status === "modified" || p.status === "new_uncommitted"));
      }
      if (this.isDirty) return true;
      if (p && (p.uncommitted_changes || p.status === "modified" || p.status === "new_uncommitted" || p.saved_to === "redis")) {
        return true;
      }
      if (this.storageHealth?.github_configured || this.storageHealth?.github?.configured) {
        return true;
      }
      return false;
    },

    canCommitCurrentLog() {
      if (this.storageHealth?.backend !== "github") return false;
      if (this.isLogDirty) return true;
      const name = this.currentLogName;
      if (!name) return false;
      const p = this.logProfiles?.find((x) => x.name === name);
      return Boolean(p && (p.uncommitted_changes || p.status === "modified" || p.status === "new_uncommitted"));
    },

    async revertPolicy(name) {
      if (!name) {
        name = this.currentPolicyName || this.originalPolicyName || this.currentPolicy?.policy?.name;
      }
      if (!name) {
        this.notify("Please select a policy to revert", "error");
        return;
      }
      if (!confirm(`Discard local Redis changes and revert policy '${name}' to the version in the GitHub repository?`)) {
        return;
      }
      try {
        this.loading = true;
        const res = await fetch(`/api/policies/${encodeURIComponent(name)}/github-revert`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || "Failed to revert policy");
        }
        this.notify(data.message || `Policy '${name}' reverted to GitHub version`, "success");
        if (this.view === "editor" && (this.currentPolicyName === name || this.originalPolicyName === name || this.currentPolicy?.policy?.name === name)) {
          await this.openEditor(name, this.editorMode);
        } else {
          await this.loadPolicies();
        }
      } catch (err) {
        this.notify("Error reverting policy: " + err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    async revertLogProfile(name) {
      if (!name) {
        name = this.currentLogName;
      }
      if (!name) {
        this.notify("Please select a logging profile to revert", "error");
        return;
      }
      if (!confirm(`Discard local Redis changes and revert logging profile '${name}' to the version in the GitHub repository?`)) {
        return;
      }
      try {
        this.logLoading = true;
        const res = await fetch(`/api/log-profiles/${encodeURIComponent(name)}/github-revert`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || "Failed to revert logging profile");
        }
        this.notify(data.message || `Logging profile '${name}' reverted to GitHub version`, "success");
        if (this.logView === "editor" && this.currentLogName === name) {
          await this.openLogEditor(name, this.logEditorMode);
        } else {
          await this.loadLogProfiles();
        }
      } catch (err) {
        this.notify("Error reverting logging profile: " + err.message, "error");
      } finally {
        this.logLoading = false;
      }
    },

    async pullFromGitHub() {
      this.githubPulling = true;
      try {
        // First check for conflicts with local Redis drafts
        const conflictRes = await fetch("/api/github/pull/conflicts");
        if (conflictRes.ok) {
          const conflictData = await conflictRes.json();
          if (conflictData.has_conflicts && conflictData.conflicts && conflictData.conflicts.length > 0) {
            this.pullConflicts = conflictData.conflicts;
            this.pullResolutions = {};
            // Default each conflict resolution to 'keep_github'
            this.pullConflicts.forEach((c) => {
              const key = `${c.type}:${c.name}`;
              this.pullResolutions[key] = "keep_github";
            });
            this.showPullConflictModal = true;
            this.githubPulling = false;
            return;
          }
        }

        // No conflicts detected: proceed directly with pull
        await this.executePull();
      } catch (err) {
        this.notify("GitHub Sync Error: " + err.message, "error");
      } finally {
        this.githubPulling = false;
      }
    },

    setAllPullResolutions(choice) {
      if (!this.pullConflicts) return;
      this.pullConflicts.forEach((c) => {
        const key = `${c.type}:${c.name}`;
        this.pullResolutions[key] = choice;
      });
    },

    async confirmPullWithResolutions() {
      this.pullConflictSubmitting = true;
      try {
        // Format resolutions object
        const resolutions = {
          policies: {},
          log_profiles: {},
        };
        for (const [key, choice] of Object.entries(this.pullResolutions)) {
          const [type, name] = key.split(":");
          if (type === "policy") {
            resolutions.policies[name] = choice;
          } else if (type === "logging") {
            resolutions.log_profiles[name] = choice;
          }
        }

        await this.executePull(resolutions);
        this.showPullConflictModal = false;
      } catch (err) {
        this.notify("GitHub Sync Error: " + err.message, "error");
      } finally {
        this.pullConflictSubmitting = false;
      }
    },

    async executePull(resolutions = null) {
      const payload = resolutions ? { resolutions } : {};
      const res = await fetch("/api/github/pull", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to pull from GitHub");
      }

      let msg = data.message || "Successfully pulled latest assets from GitHub into Redis!";
      const preservedCount = (data.policies_preserved?.length || 0) + (data.log_profiles_preserved?.length || 0);
      if (preservedCount > 0) {
        msg += ` (${preservedCount} local draft${preservedCount > 1 ? "s" : ""} preserved in Redis)`;
      }
      this.notify(msg, "success");

      await this.loadPolicies();
      await this.loadLogProfiles();
      await this.loadCustomSignatureFiles();

      // If active editor policy was updated from GitHub, refresh editor baseline
      if (this.view === "editor") {
        const activeName = this.currentPolicyName || this.originalPolicyName || this.currentPolicy?.policy?.name;
        if (activeName && data.policies_pulled && data.policies_pulled.includes(activeName)) {
          await this.loadPolicy(activeName);
        }
      }
      if (this.logView === "editor" && this.currentLogName) {
        if (data.log_profiles_pulled && data.log_profiles_pulled.includes(this.currentLogName)) {
          await this.loadLogProfile(this.currentLogName);
        }
      }
    },

    // =============================================================
    // WAF POLICY MANAGEMENT METHODS
    // =============================================================
    async loadTemplates() {
      try {
        const res = await fetch("/api/templates");
        if (res.ok) {
          this.templates = await res.json();
        }
      } catch (e) {
        console.error("Failed to load templates", e);
      }
    },

    async loadCatalog() {
      try {
        const res = await fetch("/api/catalog");
        if (res.ok) {
          const data = await res.json();
          if (data.categories && data.categories.length) {
            this.catalog.categories = data.categories;
          }
          if (data.signatureSets && data.signatureSets.length) {
            this.catalog.signatureSets = data.signatureSets;
          }
          if (data.serverTechnologies && data.serverTechnologies.length) {
            this.catalog.serverTechnologies = data.serverTechnologies;
          }
          if (data.violations && data.violations.length) {
            this.catalog.violations = data.violations;
          }
          if (data.openApiRecommendedViolations && data.openApiRecommendedViolations.length) {
            this.catalog.openApiRecommendedViolations = data.openApiRecommendedViolations;
          }
          if (data.attackSignatures && data.attackSignatures.length) {
            this.catalog.attackSignatures = data.attackSignatures;
          }
        }
      } catch (e) {
        console.error("Failed to load catalog from API, using static fallback", e);
      }
    },

    async loadPolicies() {
      try {
        this.loading = true;
        const res = await fetch("/api/policies");
        if (!res.ok) throw new Error("Failed to fetch policies");
        const all = await res.json();
        this.policies = all.filter((p) => p.name && !p.name.startsWith("log:"));
      } catch (err) {
        this.notify("Error loading policies: " + err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    get filteredPolicies() {
      return this.policies.filter((p) => {
        if (p.name && p.name.startsWith("log:")) return false;
        const matchesQuery =
          !this.searchQuery ||
          p.name.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
          (p.description && p.description.toLowerCase().includes(this.searchQuery.toLowerCase()));
        const matchesMode =
          this.modeFilter === "all" || p.enforcementMode === this.modeFilter;
        return matchesQuery && matchesMode;
      });
    },

    async loadPolicy(policyName, options = {}) {
      if (!policyName) return;
      const resolved =
        typeof this.resolvePolicyNameFromLog === "function"
          ? this.resolvePolicyNameFromLog(policyName) || policyName
          : policyName;
      const prevSection = this.activeSection;
      const prevView = this.view;
      const prevTab = this.activeTab;
      await this.openEditor(resolved, options.mode || this.editorMode || "visual");
      if (options.preserveView) {
        this.activeSection = prevSection;
        this.view = prevView;
        this.activeTab = prevTab;
      }
    },

    async loadLogProfile(logName, options = {}) {
      if (!logName) return;
      await this.openLogEditor(logName, options.mode || this.logEditorMode || "visual");
    },

    async refreshLoadedPolicyIfMatching(policyName) {
      if (!policyName) return;
      const resolved =
        typeof this.resolvePolicyNameFromLog === "function"
          ? this.resolvePolicyNameFromLog(policyName) || policyName
          : policyName;
      if (
        this.currentPolicyName &&
        (this.currentPolicyName === policyName || this.currentPolicyName === resolved)
      ) {
        try {
          await this.loadPolicy(resolved, { preserveView: true });
        } catch (err) {
          console.warn("Could not refresh loaded policy:", err);
        }
      }
    },

    async openEditor(policyName, mode = "visual") {
      try {
        this.loading = true;
        const res = await fetch(`/api/policies/${encodeURIComponent(policyName)}`);
        if (!res.ok) throw new Error("Could not retrieve policy details");
        let policyObj = await res.json();
        while (policyObj && policyObj.policy && policyObj.policy.policy) {
          policyObj.policy = policyObj.policy.policy;
        }

        // Sanitize any unsupported basicAuth in OpenAPI references
        if (Array.isArray(policyObj?.policy?.["open-api-files"])) {
          policyObj.policy["open-api-files"].forEach((f) => {
            if (f && typeof f === "object") delete f.basicAuth;
          });
        }
        if (policyObj?.policy?.openApiFileReference && typeof policyObj.policy.openApiFileReference === "object") {
          delete policyObj.policy.openApiFileReference.basicAuth;
        }

        // Sanitize data-guard fields to official F5 WAF for NGINX specification
        if (policyObj?.policy?.["data-guard"] && typeof policyObj.policy["data-guard"] === "object") {
          const dg = policyObj.policy["data-guard"];
          if ("maskCreditCardNumbersInResponse" in dg) {
            if (dg.creditCardNumbers === undefined) dg.creditCardNumbers = Boolean(dg.maskCreditCardNumbersInResponse);
            delete dg.maskCreditCardNumbersInResponse;
          }
          if ("maskUssnInResponse" in dg) {
            if (dg.usSocialSecurityNumbers === undefined) dg.usSocialSecurityNumbers = Boolean(dg.maskUssnInResponse);
            delete dg.maskUssnInResponse;
          }
          if (Array.isArray(dg.customPatterns)) {
            if (!Array.isArray(dg.customPatternsList)) dg.customPatternsList = dg.customPatterns;
            dg.customPatterns = dg.customPatternsList.length > 0;
          }
          if (dg.maskData === undefined && dg.enabled) dg.maskData = true;
          if (dg.enforcementMode === undefined && dg.enabled) dg.enforcementMode = "ignore-urls-in-list";
          if (dg.enforcementUrls === undefined && dg.enabled) dg.enforcementUrls = [];
        }

        // Normalize signature-sets (migrate Threat Campaigns to VIOL_THREAT_CAMPAIGN, normalize aliases)
        if (Array.isArray(policyObj?.policy?.["signature-sets"])) {
          const rawSets = policyObj.policy["signature-sets"];
          const cleanedSets = [];
          rawSets.forEach((s) => {
            if (!s || typeof s !== "object") return;
            const sName = (s.name || "").trim();
            if (sName.toLowerCase() === "threat campaigns" || sName.toLowerCase() === "threat-campaigns") {
              if (!policyObj.policy["blocking-settings"]) policyObj.policy["blocking-settings"] = {};
              if (!Array.isArray(policyObj.policy["blocking-settings"].violations)) {
                policyObj.policy["blocking-settings"].violations = [];
              }
              const viols = policyObj.policy["blocking-settings"].violations;
              let tc = viols.find((v) => v.name === "VIOL_THREAT_CAMPAIGN");
              if (!tc) {
                viols.push({ name: "VIOL_THREAT_CAMPAIGN", alarm: s.alarm !== false, block: s.block !== false });
              } else {
                tc.alarm = s.alarm !== false;
                tc.block = s.block !== false;
              }
            } else if (sName.toLowerCase() === "directory traversal signatures") {
              s.name = "Path Traversal Signatures";
              cleanedSets.push(s);
            } else if (sName.toLowerCase() === "xml external entity (xxe) signatures") {
              s.name = "XML External Entities (XXE) Signatures";
              cleanedSets.push(s);
            } else if (sName.toLowerCase() === "authentication / authorization attacks") {
              s.name = "Authentication/Authorization Attack Signatures";
              cleanedSets.push(s);
            } else if (sName.toLowerCase() === "http parser attack signatures") {
              s.name = "Generic Detection Signatures";
              cleanedSets.push(s);
            } else {
              cleanedSets.push(s);
            }
          });
          policyObj.policy["signature-sets"] = cleanedSets;
        }

        this.originalPolicyName = policyName;
        this.currentPolicyName = policyName;
        this.currentPolicy = policyObj;
        // Store original policy JSON string non-reactively to avoid deep proxying 50k+ items
        this._originalPolicyJsonString = JSON.stringify(policyObj, null, 2);
        this.currentPolicyOriginal = null;
        if (this.currentPolicy?.policy && this.currentPolicy.policy.description === undefined) {
          this.currentPolicy.policy.description = "";
        }

        this.resetEditorPagination();

        this.isDirty = false;
        this.editorMode = mode;
        this.activeTab = "general";
        this.view = "editor";
        this.jsonErrors = [];
        this.jsonWarnings = [];
        this.initOpenApiFormState();
        this.initGrpcFormState();

        if (mode === "json") {
          this.rawJsonString = JSON.stringify(policyObj, null, 2);
          this.$nextTick(() => {
            this.initWafCodeMirror();
          });
        } else {
          // Lazy loading: do not stringify 15MB of JSON or initialize CodeMirror until JSON tab is opened
          this.rawJsonString = "";
        }
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    initWafCodeMirror() {
      const container = document.getElementById("json-editor-textarea");
      if (!container) return;
      const cmTheme = this.theme === "dark" ? "material-darker" : "default";

      window.WAF_EDITOR.init(
        "json-editor-textarea",
        this.rawJsonString,
        (val) => {
          this.rawJsonString = val;
          this.markDirty();
          this.validatePolicyJsonDebounced(val);
        },
        cmTheme
      );
      setTimeout(() => {
        if (window.WAF_EDITOR) window.WAF_EDITOR.refresh();
      }, 50);
    },

    validatePolicyJsonDebounced(jsonStr) {
      clearTimeout(this._valTimer);
      const isLarge = (jsonStr || "").length > 400000;
      const delay = isLarge ? 2500 : 400;

      this._valTimer = setTimeout(async () => {
        try {
          const parsed = JSON.parse(jsonStr);
          this.jsonErrors = [];

          // For very large JSON (>1.5MB), avoid continuous heavy network validation during editing
          if ((jsonStr || "").length > 1500000) {
            this.jsonWarnings = [];
            return;
          }

          const res = await fetch("/api/policies/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: parsed }),
          });
          if (res.ok) {
            const data = await res.json();
            this.jsonErrors = data.errors || [];
            this.jsonWarnings = data.warnings || [];
          }
        } catch (e) {
          this.jsonErrors = ["JSON Syntax Error: " + e.message];
        }
      }, delay);
    },

    setEditorMode(mode) {
      if (mode === this.editorMode) return;

      if (mode === "json") {
        this.rawJsonString = JSON.stringify(this.currentPolicy, null, 2);
        this.editorMode = "json";
        this.$nextTick(() => {
          if (!window.WAF_EDITOR || !window.WAF_EDITOR.cmInstance) {
            this.initWafCodeMirror();
          } else {
            window.WAF_EDITOR.setValue(this.rawJsonString);
          }
          setTimeout(() => {
            if (window.WAF_EDITOR) window.WAF_EDITOR.refresh();
          }, 30);
          setTimeout(() => {
            if (window.WAF_EDITOR) window.WAF_EDITOR.refresh();
          }, 150);
        });
      } else {
        if (window.WAF_EDITOR && window.WAF_EDITOR.cmInstance) {
          const val = window.WAF_EDITOR.getValue();
          try {
            const parsed = JSON.parse(val);
            this.currentPolicy = parsed;
            this.editorMode = "visual";
            this.resetEditorPagination();
          } catch (e) {
            this.notify("Cannot switch to Visual Form: JSON contains syntax errors", "error");
            return;
          }
        } else {
          this.editorMode = "visual";
          this.resetEditorPagination();
        }
        this.initOpenApiFormState();
        this.initGrpcFormState();
      }
    },

    closeEditor() {
      if (this.isDirty) {
        if (!confirm("You have unsaved changes. Discard and return to dashboard?")) {
          return;
        }
      }
      this.currentPolicy = null;
      this.currentPolicyOriginal = null;
      this._originalPolicyJsonString = null;
      this.originalPolicyName = null;
      this.currentPolicyName = null;
      this.isDirty = false;
      this.view = "dashboard";
      this.loadPolicies();
    },

    markDirty() {
      this.isDirty = true;
    },

    async saveCurrentPolicy() {
      let payload = this.currentPolicy;
      if (this.editorMode === "json" && window.WAF_EDITOR) {
        try {
          payload = JSON.parse(window.WAF_EDITOR.getValue());
        } catch (e) {
          this.notify("Cannot save: Invalid JSON syntax", "error");
          return;
        }
      }

      const originalName = this.currentPolicyName || this.originalPolicyName || this.currentPolicyOriginal?.policy?.name;
      const targetName = (payload?.policy?.name || originalName || "").trim();

      if (!targetName) {
        this.notify("Policy name cannot be empty", "error");
        return;
      }

      // Ensure OpenAPI basicAuth is stripped if present in payload
      if (Array.isArray(payload?.policy?.["open-api-files"])) {
        payload.policy["open-api-files"].forEach((f) => {
          if (f && typeof f === "object") delete f.basicAuth;
        });
      }
      if (payload?.policy?.openApiFileReference && typeof payload.policy.openApiFileReference === "object") {
        delete payload.policy.openApiFileReference.basicAuth;
      }

      try {
        this.loading = true;
        const routeName = originalName || targetName;
        const res = await fetch(`/api/policies/${encodeURIComponent(routeName)}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            content: payload,
            original_name: originalName || undefined,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          const errMsg = data.detail?.errors
            ? data.detail.errors.join("; ")
            : data.detail || "Save failed";
          throw new Error(errMsg);
        }

        const actualName = data.new_name || targetName;
        this.originalPolicyName = actualName;
        this.currentPolicyName = actualName;
        if (payload?.policy) payload.policy.name = actualName;

        let successMsg = data.message || `Policy '${actualName}' saved successfully!`;
        if (data.metadata?.uncommitted_changes) {
          successMsg = `Policy '${actualName}' saved to local Redis (uncommitted draft). Ready to commit to GitHub.`;
        } else if (data.metadata?.commit_sha) {
          const shortSha = data.metadata.commit_sha.substring(0, 7);
          successMsg += ` (Git commit ${shortSha} created)`;
        }
        this.notify(successMsg, "success");
        this.currentPolicy = payload;
        this._originalPolicyJsonString = JSON.stringify(payload, null, 2);
        this.currentPolicyOriginal = null;
        if (this.editorMode === "json") {
          this.rawJsonString = this._originalPolicyJsonString;
          if (window.WAF_EDITOR) {
            window.WAF_EDITOR.setValue(this.rawJsonString);
          }
        }
        this.isDirty = false;
        await this.loadPolicies();
      } catch (err) {
        this.notify("Error saving policy: " + err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    // WAF CRUD Modals
    openCreateModal(templateId = "default") {
      this.newPolicyForm = {
        name: "",
        template_id: templateId,
        description: "",
        enforcementMode: "blocking",
      };
      this.showCreateModal = true;
    },

    async createPolicy() {
      const name = this.newPolicyForm.name.trim();
      if (!name) {
        this.notify("Policy name is required", "error");
        return;
      }
      if (name.startsWith("log:")) {
        this.notify("Policy name cannot start with 'log:' (reserved for logging profiles)", "error");
        return;
      }

      try {
        this.loading = true;
        const res = await fetch("/api/policies", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: name,
            template_id: this.newPolicyForm.template_id,
            description: this.newPolicyForm.description ? this.newPolicyForm.description.trim() : undefined,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          const err = data.detail?.errors ? data.detail.errors.join("; ") : data.detail || "Creation failed";
          throw new Error(err);
        }

        this.notify(`Policy '${name}' created successfully`, "success");
        this.showCreateModal = false;
        await this.loadPolicies();
        this.openEditor(name, "visual");
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    openCloneModal(policyName) {
      this.cloneTargetName = `${policyName}_copy`;
      this.currentPolicyToClone = policyName;
      this.showCloneModal = true;
    },

    async clonePolicy() {
      const target = this.cloneTargetName.trim();
      if (!target) return;
      if (target.startsWith("log:")) {
        this.notify("Target policy name cannot start with 'log:'", "error");
        return;
      }

      try {
        this.loading = true;
        const res = await fetch(
          `/api/policies/${encodeURIComponent(this.currentPolicyToClone)}/clone`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ new_name: target }),
          }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Clone failed");

        this.notify(`Policy cloned as '${target}'`, "success");
        this.showCloneModal = false;
        await this.loadPolicies();
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    confirmDelete(policyName) {
      this.policyToDelete = policyName;
      this.showDeleteModal = true;
    },

    async deletePolicy() {
      if (!this.policyToDelete) return;

      try {
        this.loading = true;
        const res = await fetch(`/api/policies/${encodeURIComponent(this.policyToDelete)}`, {
          method: "DELETE",
        });
        if (!res.ok) throw new Error("Delete failed");

        this.notify(`Policy '${this.policyToDelete}' deleted`, "info");
        this.showDeleteModal = false;
        this.policyToDelete = null;
        await this.loadPolicies();
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.loading = false;
      }
    },

    exportPolicy(policyName) {
      window.location.href = `/api/policies/${encodeURIComponent(policyName)}/export`;
    },

    async importPolicyFile(event) {
      const file = event.target.files[0];
      if (!file) return;

      const formData = new FormData();
      formData.append("file", file);

      try {
        this.loading = true;
        const res = await fetch("/api/policies/import", {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        if (!res.ok) {
          const err = data.detail?.errors ? data.detail.errors.join("; ") : data.detail || "Import failed";
          throw new Error(err);
        }

        this.notify(data.message, "success");
        this.showImportModal = false;
        if (data.metadata) {
          const importedName = data.metadata.name;
          this.policies = this.policies.filter((p) => p.name !== importedName);
          this.policies.unshift(data.metadata);
        } else {
          await this.loadPolicies();
        }
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.loading = false;
        event.target.value = "";
      }
    },

    // --- BIG-IP WAF Policy Converter Methods ---

    openBigIpModal() {
      this.bigIpFile = null;
      this.bigIpFileName = "";
      this.bigIpFileSize = 0;
      this.bigIpForm = {
        targetName: "",
        fullExport: true,
        keepFullConfiguration: false,
        includeAllSignatures: false,
        saveToStorage: true,
      };
      this.bigIpResult = null;
      this.showBigIpModal = true;
    },

    onBigIpFileSelected(event) {
      const file = event.target.files[0];
      if (!file) return;
      this.bigIpFile = file;
      this.bigIpFileName = file.name;
      this.bigIpFileSize = file.size;

      // Suggest clean target name from file
      let base = file.name.replace(/\.(json|xml|gz|tar|tgz|txt)$/gi, "").replace(/[^a-zA-Z0-9_\-.:]/g, "_");
      if (!this.bigIpForm.targetName) {
        this.bigIpForm.targetName = base;
      }
    },

    async convertBigIpPolicy() {
      if (!this.bigIpFile) {
        this.notify("Please select a BIG-IP JSON policy file first", "error");
        return;
      }

      const formData = new FormData();
      formData.append("file", this.bigIpFile);
      if (this.bigIpForm.targetName) {
        formData.append("target_name", this.bigIpForm.targetName.trim());
      }
      formData.append("full_export", this.bigIpForm.fullExport);
      formData.append("keep_full_configuration", this.bigIpForm.keepFullConfiguration);
      formData.append("include_all_signatures", this.bigIpForm.includeAllSignatures);
      formData.append("save_to_storage", this.bigIpForm.saveToStorage);

      try {
        this.bigIpLoading = true;
        this.bigIpResult = null;
        const res = await fetch("/api/policies/convert-bigip", {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        if (!res.ok) {
          const err = data.detail || "BIG-IP conversion failed";
          throw new Error(err);
        }

        if (data.policy) {
          delete data.policy; // Keep Alpine reactive tree lightweight for large converted policies
        }
        this.bigIpResult = data;
        this.notify(data.message, "success");
        if (this.bigIpForm.saveToStorage) {
          if (data.metadata) {
            const convertedName = data.metadata.name;
            this.policies = this.policies.filter((p) => p.name !== convertedName);
            this.policies.unshift(data.metadata);
          } else {
            await this.loadPolicies();
          }
        }
      } catch (err) {
        this.notify(err.message, "error");
        this.bigIpResult = {
          success: false,
          error: err.message,
        };
      } finally {
        this.bigIpLoading = false;
      }
    },

    async openConvertedInEditor(policyName) {
      this.showBigIpModal = false;
      await this.openEditor(policyName);
    },

    // --- F5 WAF Compiler Tester Methods ---

    async loadCompilerStatus() {
      try {
        const res = await fetch("/api/compiler/status");
        if (res.ok) {
          this.compilerStatus = await res.json();
        }
      } catch (e) {
        console.warn("Could not load compiler status", e);
      }
    },

    escapeHtml(str) {
      if (str === null || str === undefined) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    },

    setCompilerTargetType(targetType) {
      this.compilerForm.targetType = targetType;
      this.compilerResult = null;
      this.showCompilerRawOutput = false;

      if (targetType === "policy") {
        const opts = this.getPolicyTargetOptions();
        if (opts.length > 0) {
          this.compilerForm.selectedName = opts[0].value;
          this.compilerForm.targetSource = opts[0].isEditor ? "editor" : "storage";
        } else {
          this.compilerForm.selectedName = "";
          this.compilerForm.targetSource = "storage";
        }
      } else {
        const opts = this.getLogTargetOptions();
        if (opts.length > 0) {
          this.compilerForm.selectedName = opts[0].value;
          this.compilerForm.targetSource = opts[0].isEditor ? "editor" : "storage";
        } else {
          this.compilerForm.selectedName = "";
          this.compilerForm.targetSource = "storage";
        }
      }
    },

    getPolicyTargetOptions() {
      const options = [];
      if (this.view === "editor" && this.currentPolicy?.policy?.name) {
        options.push({
          value: this.currentPolicy.policy.name,
          label: `[Active Editor Draft] ${this.currentPolicy.policy.name}`,
          isEditor: true,
        });
      }
      (this.policies || []).forEach((p) => {
        if (!options.some((o) => o.value === p.name)) {
          options.push({
            value: p.name,
            label: p.name,
            isEditor: false,
          });
        }
      });
      return options;
    },

    getLogTargetOptions() {
      const options = [];
      if (this.logView === "editor" && this.currentLogName) {
        options.push({
          value: this.currentLogName,
          label: `[Active Editor Draft] ${this.currentLogName}`,
          isEditor: true,
        });
      }
      (this.logProfiles || []).forEach((lp) => {
        if (!options.some((o) => o.value === lp.name)) {
          options.push({
            value: lp.name,
            label: lp.name,
            isEditor: false,
          });
        }
      });
      return options;
    },

    onCompilerTargetChange() {
      const selected = this.compilerForm.selectedName;
      const isPolicy = this.compilerForm.targetType === "policy";
      const options = isPolicy ? this.getPolicyTargetOptions() : this.getLogTargetOptions();
      const match = options.find((o) => o.value === selected);
      if (match) {
        this.compilerForm.targetSource = match.isEditor ? "editor" : "storage";
      }
    },

    getCompilerExecutionJson() {
      if (!this.compilerResult) return null;

      // 1. Try to extract JSON from compilerResult.stdout or stderr
      let raw = this.compilerResult.stdout;
      if (!raw && this.compilerResult.stderr) {
        raw = this.compilerResult.stderr;
      }

      if (raw && typeof raw === "string") {
        try {
          return JSON.parse(raw.trim());
        } catch (e) {
          const start = raw.indexOf("{");
          const end = raw.lastIndexOf("}");
          if (start !== -1 && end !== -1 && end > start) {
            try {
              return JSON.parse(raw.substring(start, end + 1));
            } catch (e2) {}
          }
        }
      } else if (raw && typeof raw === "object") {
        return raw;
      }

      // 2. Synthesize structured JSON matching apcompile format if not directly JSON
      const isSuccess = Boolean(this.compilerResult.success);
      const warnings = Array.isArray(this.compilerResult.warnings) ? this.compilerResult.warnings : [];
      const errors = Array.isArray(this.compilerResult.errors)
        ? this.compilerResult.errors.map((e) => (typeof e === "string" ? e : e.message || e.title || JSON.stringify(e)))
        : [];

      const payload = {
        completed_successfully: isSuccess,
      };

      if (this.compilerResult.bundle_name) {
        payload.bundle_name = this.compilerResult.bundle_name;
      }
      if (this.compilerResult.bundle_size) {
        payload.bundle_size = this.compilerResult.bundle_size;
      }
      if (this.compilerResult.bundle_sha256) {
        payload.bundle_sha256 = this.compilerResult.bundle_sha256;
      }
      if (this.compilerResult.diagnostics?.compile_time_ms) {
        payload.compile_time_ms = this.compilerResult.diagnostics.compile_time_ms;
      }
      if (warnings.length > 0) {
        payload.warnings = warnings;
      }
      if (!isSuccess && errors.length > 0) {
        payload.errors = errors;
      }

      return payload;
    },

    hasCompilerWarnings() {
      const json = this.getCompilerExecutionJson();
      if (json && Array.isArray(json.warnings) && json.warnings.length > 0) {
        return true;
      }
      if (this.compilerResult && Array.isArray(this.compilerResult.warnings) && this.compilerResult.warnings.length > 0) {
        return true;
      }
      return false;
    },

    getCompilerWarnings() {
      const json = this.getCompilerExecutionJson();
      if (json && Array.isArray(json.warnings)) {
        return json.warnings;
      }
      if (this.compilerResult && Array.isArray(this.compilerResult.warnings)) {
        return this.compilerResult.warnings;
      }
      return [];
    },

    getCompilerWarningsCount() {
      return this.getCompilerWarnings().length;
    },

    syntaxHighlightCompilerJson(raw) {
      if (!raw) return "";

      let obj = null;
      if (typeof raw === "object") {
        obj = raw;
      } else if (typeof raw === "string") {
        try {
          obj = JSON.parse(raw.trim());
        } catch (e) {
          const start = raw.indexOf("{");
          const end = raw.lastIndexOf("}");
          if (start !== -1 && end !== -1 && end > start) {
            try {
              obj = JSON.parse(raw.substring(start, end + 1));
            } catch (e2) {}
          }
        }
      }

      if (!obj) {
        return this.escapeHtml(String(raw || ""));
      }

      const warningsList = Array.isArray(obj.warnings) ? obj.warnings : [];
      const hasWarnings = warningsList.length > 0;
      const errorsList = Array.isArray(obj.errors) ? obj.errors : [];
      const hasErrors = errorsList.length > 0;

      const rawJson = JSON.stringify(obj, null, 2);

      const pattern = /("completed_successfully":\s*(?:true|false))|("warnings":)|("errors":)|("(?:\\.|[^"\\])*":)|("(?:\\.|[^"\\])*")|(\b(?:true|false|null)\b)|(-?\d+(?:\.\d+)?)/g;

      return rawJson.replace(pattern, (tok) => {
        // Highlight completed_successfully key and boolean value in green (true) or red (false)
        if (tok.startsWith('"completed_successfully":')) {
          if (tok.includes("true")) {
            return '<span class="text-emerald-400 font-bold bg-emerald-500/20 px-1.5 py-0.5 rounded border border-emerald-500/40 shadow-sm shadow-emerald-500/10">"completed_successfully": true</span>';
          } else {
            return '<span class="text-rose-400 font-bold bg-rose-500/20 px-1.5 py-0.5 rounded border border-rose-500/40 shadow-sm shadow-rose-500/10">"completed_successfully": false</span>';
          }
        }

        // Highlight "warnings" key when there are warnings
        if (tok === '"warnings":') {
          if (hasWarnings) {
            return '<span class="text-amber-300 font-bold bg-amber-500/25 px-1.5 py-0.5 rounded border border-amber-500/40 shadow-sm shadow-amber-500/10">"warnings"</span>:';
          }
          return '<span class="text-indigo-300 font-medium">"warnings"</span>:';
        }

        // Highlight "errors" key when there are errors
        if (tok === '"errors":') {
          return '<span class="text-rose-300 font-bold bg-rose-500/25 px-1.5 py-0.5 rounded border border-rose-500/40 shadow-sm shadow-rose-500/10">"errors"</span>:';
        }

        // Object Key
        if (tok.endsWith(":")) {
          const k = tok.slice(0, -1);
          return `<span class="text-indigo-300 font-medium">${this.escapeHtml(k)}</span>:`;
        }

        // Boolean
        if (tok === "true" || tok === "false") {
          return `<span class="text-cyan-400 font-semibold">${tok}</span>`;
        }

        // Null
        if (tok === "null") {
          return `<span class="text-slate-400 italic">${tok}</span>`;
        }

        // Number
        if (/^-?\d+(?:\.\d+)?$/.test(tok)) {
          return `<span class="text-amber-300 font-semibold">${tok}</span>`;
        }

        // String values
        if (tok.startsWith('"')) {
          try {
            const innerStr = JSON.parse(tok);
            if (hasWarnings && warningsList.includes(innerStr)) {
              return `<span class="text-amber-200 bg-amber-500/15 px-1 rounded">${this.escapeHtml(tok)}</span>`;
            }
            if (hasErrors && (errorsList.includes(innerStr) || errorsList.some((e) => e && (e === innerStr || e.message === innerStr)))) {
              return `<span class="text-rose-200 bg-rose-500/15 px-1 rounded">${this.escapeHtml(tok)}</span>`;
            }
          } catch (e) {}
          return `<span class="text-emerald-300">${this.escapeHtml(tok)}</span>`;
        }

        return this.escapeHtml(tok);
      });
    },

    getFormattedCompilerLog() {
      const jsonObj = this.getCompilerExecutionJson();
      if (jsonObj) {
        return this.syntaxHighlightCompilerJson(jsonObj);
      }
      const raw = this.compilerResult?.stdout || this.compilerResult?.stderr || "No log output recorded";
      return this.syntaxHighlightCompilerJson(raw);
    },

    copyCompilerExecutionLog() {
      const json = this.getCompilerExecutionJson();
      const text = json ? JSON.stringify(json, null, 2) : (this.compilerResult?.stdout || this.compilerResult?.stderr || "");
      if (!text) {
        this.notify("No compiler log output available to copy.", "info");
        return;
      }
      navigator.clipboard.writeText(text);
      this.notify("Compiler execution log copied to clipboard!", "success");
    },

    async openCompilerTesterModal(targetType = null, targetName = null) {
      await this.loadCompilerStatus();
      this.compilerResult = null;
      this.showCompilerRawOutput = false;

      const chosenType = targetType || (this.activeSection === "logging" ? "log_profile" : "policy");
      this.setCompilerTargetType(chosenType);

      if (targetName) {
        this.compilerForm.selectedName = targetName;
        this.onCompilerTargetChange();
      }

      this.showCompilerModal = true;
    },

    testCurrentPolicyCompilation() {
      const name = this.currentPolicy?.policy?.name || "current_policy";
      this.openCompilerTesterModal("policy", name);
    },

    testCurrentLogProfileCompilation() {
      const name = this.currentLogName || "current_log_profile";
      this.openCompilerTesterModal("log_profile", name);
    },

    async runCompilerTest() {
      try {
        this.compilerLoading = true;
        this.compilerResult = null;

        let content = null;
        const targetType = this.compilerForm.targetType;
        const isEditor = this.compilerForm.targetSource === "editor";

        if (isEditor) {
          if (targetType === "policy") {
            this.clientSanitizeSignatureSets();
            if (this.editorMode === "json" && window.CODE_EDITOR) {
              try {
                content = JSON.parse(window.CODE_EDITOR.getValue());
                while (content && content.policy && content.policy.policy) {
                  content.policy = content.policy.policy;
                }
              } catch (e) {
                this.compilerResult = {
                  success: false,
                  target_type: "policy",
                  target_name: this.compilerForm.selectedName || "editor_policy",
                  compiler_engine: "json_validator",
                  stdout: "",
                  stderr: "JSON Syntax Error: " + e.message,
                  errors: [{
                    code: "ERR_INVALID_JSON_SYNTAX",
                    title: "Invalid JSON Syntax in Editor",
                    path: "/",
                    message: e.message,
                    solution: "Fix the JSON syntax errors in the CodeMirror editor before compiling.",
                  }],
                  warnings: [],
                  diagnostics: { compile_time_ms: 0, schema_valid: false },
                };
                this.compilerLoading = false;
                return;
              }
            } else {
              while (this.currentPolicy && this.currentPolicy.policy && this.currentPolicy.policy.policy) {
                this.currentPolicy.policy = this.currentPolicy.policy.policy;
              }
              content = this.currentPolicy;
            }
          } else {
            if (this.logEditorMode === "json" && window.LOG_EDITOR) {
              try {
                content = JSON.parse(window.LOG_EDITOR.getValue());
              } catch (e) {
                this.compilerResult = {
                  success: false,
                  target_type: "log_profile",
                  target_name: this.compilerForm.selectedName || "editor_log_profile",
                  compiler_engine: "json_validator",
                  stdout: "",
                  stderr: "JSON Syntax Error: " + e.message,
                  errors: [{
                    code: "ERR_INVALID_JSON_SYNTAX",
                    title: "Invalid JSON Syntax in Log Profile Editor",
                    path: "/",
                    message: e.message,
                    solution: "Fix the JSON syntax errors in the CodeMirror editor before compiling.",
                  }],
                  warnings: [],
                  diagnostics: { compile_time_ms: 0, schema_valid: false },
                };
                this.compilerLoading = false;
                return;
              }
            } else {
              content = this.buildLogObjectFromForm();
            }
          }
        }

        let globalSettings = null;
        if (this.compilerForm.globalSettingsJson && this.compilerForm.globalSettingsJson.trim()) {
          try {
            globalSettings = JSON.parse(this.compilerForm.globalSettingsJson);
          } catch (e) {
            this.notify("Invalid Global Settings JSON: " + e.message, "error");
            this.compilerLoading = false;
            return;
          }
        }

        const payload = {
          target_type: targetType,
          target_name: this.compilerForm.selectedName || (targetType === "policy" ? "policy" : "log_profile"),
          content: isEditor ? content : null,
          include_source: this.compilerForm.includeSource,
          full_export: this.compilerForm.fullExport,
          global_settings: globalSettings,
        };

        const res = await fetch("/api/compiler/test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || "Compiler execution failed");
        }

        this.compilerResult = data;
        if (data.success) {
          this.notify(`Compilation successful! Bundle: ${data.bundle_name}`, "success");
        } else {
          this.notify(`Compilation failed with ${data.errors?.length || 1} error(s)`, "error");
        }
      } catch (err) {
        this.notify(err.message, "error");
        this.compilerResult = {
          success: false,
          target_type: this.compilerForm.targetType,
          target_name: this.compilerForm.selectedName,
          compiler_engine: "error_handler",
          stdout: "",
          stderr: err.message,
          errors: [{
            code: "ERR_COMPILER_REQUEST",
            title: "Compilation Request Failed",
            path: "/",
            message: err.message,
            solution: "Verify network connectivity and storage backend status.",
          }],
          warnings: [],
          diagnostics: { compile_time_ms: 0, schema_valid: false },
        };
      } finally {
        this.compilerLoading = false;
      }
    },

    async autoFixAndRecompile() {
      try {
        this.compilerLoading = true;
        this.notify("Sanitizing policy and signature sets...", "info");

        // 1. Client-side sanitization
        this.clientSanitizeSignatureSets();

        // 2. Server-side sanitization if policy has a name
        const polName = this.currentPolicy?.policy?.name || this.compilerForm.selectedName;
        if (polName) {
          try {
            const res = await fetch(`/api/policies/${encodeURIComponent(polName)}/sanitize`, { method: "POST" });
            if (res.ok) {
              const data = await res.json();
              if (data.policy) {
                let unwrapped = data.policy;
                while (unwrapped && unwrapped.policy && typeof unwrapped.policy === "object" && unwrapped.policy.policy) {
                  unwrapped = unwrapped.policy;
                }
                const policyBody = unwrapped.policy || unwrapped;
                this.currentPolicy = { policy: policyBody };
                this.invalidateParamCache();
              }
            }
          } catch (e) {
            console.warn("Server sanitize call failed, proceeding with client-sanitized policy:", e);
          }
        }

        // 3. Re-run client sanitization to ensure complete consistency
        this.clientSanitizeSignatureSets();

        // 4. Update CodeMirror if active
        if (this.editorMode === "json" && window.CODE_EDITOR && this.currentPolicy) {
          window.CODE_EDITOR.setValue(JSON.stringify(this.currentPolicy, null, 2));
        }

        this.notify("Signature sets normalized. Recompiling...", "success");
      } catch (err) {
        console.error("Auto-fix error:", err);
      } finally {
        this.compilerLoading = false;
      }

      await this.runCompilerTest();
    },

    clientSanitizeSignatureSets() {
      if (!this.currentPolicy) return;
      while (this.currentPolicy.policy && this.currentPolicy.policy.policy) {
        this.currentPolicy.policy = this.currentPolicy.policy.policy;
      }
      const pol = this.currentPolicy.policy;
      if (!pol || typeof pol !== "object") return;

      const OFFICIAL_PREDEFINED_SETS = new Set([
        "High Accuracy Signatures",
        "Command Execution Signatures",
        "Cross Site Scripting Signatures",
        "Directory Indexing Signatures",
        "Information Leakage Signatures",
        "OS Command Injection Signatures",
        "Path Traversal Signatures",
        "Predictable Resource Location Signatures",
        "Remote File Include Signatures",
        "SQL Injection Signatures",
        "Authentication/Authorization Attack Signatures",
        "XML External Entities (XXE) Signatures",
        "XPath Injection Signatures",
        "Buffer Overflow Signatures",
        "Denial of Service Signatures",
        "Vulnerability Scan Signatures",
        "Server Side Code Injection Signatures",
        "CVE Signatures",
        "All Signatures",
        "Generic Detection Signatures",
        "Generic Detection Signatures (High/Medium Accuracy)",
        "Generic Detection Signatures (High Accuracy)",
        "Low Accuracy Signatures",
        "Medium Accuracy Signatures",
        "OWA Signatures",
        "WebSphere signatures",
        "HTTP Response Splitting Signatures",
        "Other Application Attacks Signatures",
        "High Accuracy Detection Evasion Signatures",
        "All Response Signatures"
      ]);
      const OFFICIAL_LOOKUP = {};
      OFFICIAL_PREDEFINED_SETS.forEach((name) => {
        OFFICIAL_LOOKUP[name.toLowerCase()] = name;
      });

      const ALIASES = {
        "directory traversal signatures": "Path Traversal Signatures",
        "directory traversal": "Path Traversal Signatures",
        "path traversal": "Path Traversal Signatures",
        "cross-site scripting signatures": "Cross Site Scripting Signatures",
        "cross-site scripting": "Cross Site Scripting Signatures",
        "cross site scripting": "Cross Site Scripting Signatures",
        "cross site scripting (xss) signatures": "Cross Site Scripting Signatures",
        "cross-site scripting (xss) signatures": "Cross Site Scripting Signatures",
        "xss signatures": "Cross Site Scripting Signatures",
        "xss": "Cross Site Scripting Signatures",
        "sql-injection signatures": "SQL Injection Signatures",
        "sql-injection": "SQL Injection Signatures",
        "sql injection": "SQL Injection Signatures",
        "sqli signatures": "SQL Injection Signatures",
        "sqli": "SQL Injection Signatures",
        "sql-injection attacks": "SQL Injection Signatures",
        "sql injection attacks": "SQL Injection Signatures",
        "server-side code injection signatures": "Server Side Code Injection Signatures",
        "server-side code injection": "Server Side Code Injection Signatures",
        "server side code injection": "Server Side Code Injection Signatures",
        "ssrf": "Server Side Code Injection Signatures",
        "server side request forgery": "Server Side Code Injection Signatures",
        "server-side request forgery": "Server Side Code Injection Signatures",
        "operating system command injection signatures": "OS Command Injection Signatures",
        "operating system command injection": "OS Command Injection Signatures",
        "os command injection": "OS Command Injection Signatures",
        "command execution": "Command Execution Signatures",
        "xml external entity (xxe) signatures": "XML External Entities (XXE) Signatures",
        "xml external entity signatures": "XML External Entities (XXE) Signatures",
        "xml external entities signatures": "XML External Entities (XXE) Signatures",
        "xxe signatures": "XML External Entities (XXE) Signatures",
        "xxe": "XML External Entities (XXE) Signatures",
        "authentication / authorization attacks": "Authentication/Authorization Attack Signatures",
        "authentication/authorization attacks": "Authentication/Authorization Attack Signatures",
        "authentication and authorization attacks": "Authentication/Authorization Attack Signatures",
        "authentication/authorization attack": "Authentication/Authorization Attack Signatures",
        "websphere signatures": "WebSphere signatures",
        "websphere": "WebSphere signatures",
        "owa": "OWA Signatures",
        "high accuracy evasion signatures": "High Accuracy Detection Evasion Signatures",
        "http parser attack signatures": "Generic Detection Signatures",
        "http parser attacks": "Generic Detection Signatures",
        "http parser attack": "Generic Detection Signatures",
        "http response splitting": "HTTP Response Splitting Signatures",
        "other application attacks": "Other Application Attacks Signatures",
        "ldap injection": "Other Application Attacks Signatures",
        "ldap injection signatures": "Other Application Attacks Signatures",
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
        "all response signatures": "All Response Signatures"
      };

      if (Array.isArray(pol["signature-sets"])) {
        const sanitized = [];
        for (const sset of pol["signature-sets"]) {
          if (!sset || typeof sset !== "object" || !sset.name) continue;
          let sName = sset.name.trim();
          const sNameNorm = sName.toLowerCase().replace(/[-_]/g, " ");
          if (["threat campaigns", "threat campaign"].includes(sNameNorm)) {
            if (!pol["blocking-settings"]) pol["blocking-settings"] = {};
            if (!Array.isArray(pol["blocking-settings"].violations)) pol["blocking-settings"].violations = [];
            const viols = pol["blocking-settings"].violations;
            const tc = viols.find((v) => v && v.name === "VIOL_THREAT_CAMPAIGN");
            if (tc) {
              tc.alarm = sset.alarm !== undefined ? !!sset.alarm : true;
              tc.block = sset.block !== undefined ? !!sset.block : true;
            } else {
              viols.push({
                name: "VIOL_THREAT_CAMPAIGN",
                alarm: sset.alarm !== undefined ? !!sset.alarm : true,
                block: sset.block !== undefined ? !!sset.block : true,
              });
            }
            continue;
          }

          const sLower = sName.toLowerCase();
          if (ALIASES[sLower]) {
            sName = ALIASES[sLower];
          } else if (OFFICIAL_LOOKUP[sLower]) {
            sName = OFFICIAL_LOOKUP[sLower];
          }
          sset.name = sName;

          // If signatures or filter was placed directly at root of sset, move into signatureSet
          if (!sset.signatureSet && (sset.filter || sset.signatures)) {
            sset.signatureSet = {};
            if (sset.filter) { sset.signatureSet.filter = sset.filter; delete sset.filter; }
            if (sset.signatures) { sset.signatureSet.signatures = sset.signatures; delete sset.signatures; }
          }

          if (sset.signatureSet && typeof sset.signatureSet === "object") {
            const cs = sset.signatureSet;
            if (!cs.type) {
              if (cs.filter) cs.type = "filter-based";
              else if (cs.signatures) cs.type = "manual";
            }
            if (cs.filter && typeof cs.filter === "object" && typeof cs.filter.attackType === "string") {
              cs.filter.attackType = { name: cs.filter.attackType };
            }
            if (Array.isArray(cs.signatures)) {
              cs.signatures = cs.signatures.map((sig) => {
                if (sig && typeof sig === "object" && sig.signatureId) {
                  return { signatureId: parseInt(sig.signatureId, 10) };
                }
                if (typeof sig === "number" || typeof sig === "string") {
                  return { signatureId: parseInt(sig, 10) };
                }
                return null;
              }).filter((s) => s && !isNaN(s.signatureId));
            }
            if (!cs.filter && (!cs.signatures || cs.signatures.length === 0)) continue;
          } else if (!OFFICIAL_PREDEFINED_SETS.has(sName)) {
            // Omit unknown predefined sets that cause SQLite foreign key violation
            continue;
          }

          sanitized.push(sset);
        }
        pol["signature-sets"] = sanitized;

        // Strip non-configurable violations (VIOL_ATTACK_SIGNATURE, VIOL_BOT_CLIENT)
        if (pol["blocking-settings"] && Array.isArray(pol["blocking-settings"].violations)) {
          const nonConfigurable = new Set(["VIOL_ATTACK_SIGNATURE", "VIOL_BOT_CLIENT"]);
          pol["blocking-settings"].violations = pol["blocking-settings"].violations.filter(
            (v) => v && typeof v === "object" && !nonConfigurable.has(v.name)
          );
        }

        // Canonicalize server technologies and drop invalid ones
        if (Array.isArray(pol["server-technologies"])) {
          const OFFICIAL_TECHS = new Set([
            "ASP", "ASP.NET", "AngularJS", "Apache Struts", "Apache Tomcat",
            "Apache/NCSA HTTP Server", "BEA Systems WebLogic Server", "Backbone.js",
            "CGI", "Cisco", "Citrix", "CodeIgniter", "CouchDB", "Django", "Elasticsearch",
            "Ember.js", "Express.js", "Front Page Server Extensions (FPSE)", "Google Web Toolkit",
            "GraphQL", "Handlebars", "IBM DB2", "IIS", "JBoss", "Java Servlets/JSP",
            "JavaScript", "JavaServer Faces (JSF)", "Jenkins", "Jetty", "Joomla", "Laravel",
            "Lotus Domino", "Macromedia ColdFusion", "Macromedia JRun", "Microsoft SQL Server",
            "Microsoft Windows", "MongoDB", "MooTools", "Mustache", "MySQL", "Nginx",
            "Node.js", "Novell", "Oracle", "Oracle Application Server", "Oracle Identity Manager",
            "Outlook Web Access", "PHP", "PostgreSQL", "Prototype", "Proxy Servers", "Python",
            "React", "Redis", "RequireJS", "Ruby", "SQLite", "SSI (Server Side Includes)",
            "SharePoint", "Spring Boot", "Sybase/ASE", "TYPO3 CMS", "UIKit", "Underscore.js",
            "Unix/Linux", "Vue.js", "WebDAV", "WordPress", "XML", "ZURB Foundation",
            "Zend", "ef.js", "jQuery"
          ]);
          const TECH_LOOKUP = {};
          OFFICIAL_TECHS.forEach((t) => { TECH_LOOKUP[t.toLowerCase()] = t; });

          const TECH_ALIASES = {
            "apache": "Apache/NCSA HTTP Server",
            "apache http server": "Apache/NCSA HTTP Server",
            "apache web server": "Apache/NCSA HTTP Server",
            "apache/ncsa": "Apache/NCSA HTTP Server",
            "apache ncsa": "Apache/NCSA HTTP Server",
            "httpd": "Apache/NCSA HTTP Server",
            "ncsa": "Apache/NCSA HTTP Server",
            "microsoft iis": "IIS",
            "ms iis": "IIS",
            "windows": "Microsoft Windows",
            "linux": "Unix/Linux",
            "unix": "Unix/Linux",
            "postgres": "PostgreSQL",
            "postgresql": "PostgreSQL",
            "mssql": "Microsoft SQL Server",
            "sql server": "Microsoft SQL Server",
            "node": "Node.js",
            "nodejs": "Node.js",
            "reactjs": "React",
            "vue": "Vue.js",
            "vuejs": "Vue.js",
            "angular": "AngularJS",
            "angular.js": "AngularJS",
            "tomcat": "Apache Tomcat",
            "spring": "Spring Boot",
            "springboot": "Spring Boot",
            "java": "Java Servlets/JSP",
            "jsp": "Java Servlets/JSP",
            "sharepoint": "SharePoint"
          };

          const sanitizedTechs = [];
          const seenTechs = new Set();
          pol["server-technologies"].forEach((item) => {
            let tName = "";
            if (typeof item === "string") tName = item.trim();
            else if (item && typeof item === "object") tName = (item.serverTechnologyName || item.name || "").trim();
            if (!tName) return;
            const tLower = tName.toLowerCase();
            if (TECH_ALIASES[tLower]) tName = TECH_ALIASES[tLower];
            else if (TECH_LOOKUP[tLower]) tName = TECH_LOOKUP[tLower];

            if (OFFICIAL_TECHS.has(tName) && !seenTechs.has(tName)) {
              seenTechs.add(tName);
              sanitizedTechs.push({ serverTechnologyName: tName });
            }
          });
          pol["server-technologies"] = sanitizedTechs;
        }

        this.markDirty();
      }
    },

    downloadCompiledBundle(bundleId) {
      if (!bundleId) return;
      window.location.href = `/api/compiler/download/${encodeURIComponent(bundleId)}`;
    },

    copyCompilerDiagnostics() {
      if (!this.compilerResult) return;
      let text = `F5 WAF Compiler Test Report\n`;
      text += `Status: ${this.compilerResult.success ? "SUCCESS" : "FAILED"}\n`;
      text += `Target: ${this.compilerResult.target_name} (${this.compilerResult.target_type})\n`;
      text += `Engine: ${this.compilerResult.compiler_engine}\n`;
      if (this.compilerResult.bundle_name) {
        text += `Bundle: ${this.compilerResult.bundle_name} (${this.compilerResult.bundle_size} bytes)\n`;
        text += `SHA256: ${this.compilerResult.bundle_sha256}\n`;
      }
      if (this.compilerResult.errors && this.compilerResult.errors.length) {
        text += `\nErrors (${this.compilerResult.errors.length}):\n`;
        this.compilerResult.errors.forEach((e, idx) => {
          text += `${idx + 1}. [${e.code}] ${e.title} (${e.path}):\n   ${e.message}\n   Solution: ${e.solution}\n`;
        });
      }
      if (this.compilerResult.warnings && this.compilerResult.warnings.length) {
        text += `\nWarnings:\n- ` + this.compilerResult.warnings.join("\n- ") + "\n";
      }
      if (this.compilerResult.stdout) {
        text += `\nStdout:\n${this.compilerResult.stdout}\n`;
      }
      navigator.clipboard.writeText(text);
      this.notify("Compiler report copied to clipboard!", "info");
    },


    // Visual Form helpers for WAF
    ensurePolicySection(sectionName, defaultValue = {}) {
      if (!this.currentPolicy) return;
      if (!this.currentPolicy.policy) this.currentPolicy.policy = {};
      if (!this.currentPolicy.policy[sectionName]) {
        this.currentPolicy.policy[sectionName] = defaultValue;
      }
    },

    getViolationSetting(violationName) {
      const violations = this.currentPolicy?.policy?.["blocking-settings"]?.violations || [];
      return violations.find((v) => v.name === violationName) || null;
    },

    setViolationAlarm(violationName, enabled) {
      const vDef = this.catalog?.violations?.find((v) => v.name === violationName);
      if (vDef && vDef.configurable === false) return;
      this.markDirty();
      this.ensurePolicySection("blocking-settings", { violations: [] });
      const violations = this.currentPolicy.policy["blocking-settings"].violations;
      let existing = violations.find((v) => v.name === violationName);
      if (!existing) {
        existing = { name: violationName, alarm: enabled, block: false };
        violations.push(existing);
      } else {
        existing.alarm = enabled;
        if (!enabled) existing.block = false;
      }
    },

    setViolationBlock(violationName, enabled) {
      const vDef = this.catalog?.violations?.find((v) => v.name === violationName);
      if (vDef && vDef.configurable === false) return;
      this.markDirty();
      this.ensurePolicySection("blocking-settings", { violations: [] });
      const violations = this.currentPolicy.policy["blocking-settings"].violations;
      let existing = violations.find((v) => v.name === violationName);
      if (!existing) {
        existing = { name: violationName, alarm: enabled, block: enabled };
        violations.push(existing);
      } else {
        existing.block = enabled;
        if (enabled) existing.alarm = true;
      }
    },

    applyViolationsPreset(preset) {
      this.markDirty();
      this.ensurePolicySection("blocking-settings", { violations: [] });
      const currentList = this.currentPolicy.policy["blocking-settings"].violations;

      this.catalog.violations.forEach((vDef) => {
        if (vDef.configurable === false) return;
        let entry = currentList.find((v) => v.name === vDef.name);
        if (!entry) {
          entry = { name: vDef.name, alarm: false, block: false };
          currentList.push(entry);
        }

        if (preset === "factory") {
          entry.alarm = vDef.defaultAlarm;
          entry.block = vDef.defaultBlock;
        } else if (preset === "block_all") {
          entry.alarm = true;
          entry.block = true;
        } else if (preset === "alarm_only") {
          entry.alarm = true;
          entry.block = false;
        } else if (preset === "disable_all") {
          entry.alarm = false;
          entry.block = false;
        }
      });
      this.notify(`Applied '${preset}' preset to violations`, "info");
    },

    get filteredViolations() {
      const violations = this.catalog?.violations || [];
      const search = (this.violationsSearch || "").trim().toLowerCase();
      const cat = this.violationsCategory || "All Categories";

      return violations.filter((item) => {
        if (!item) return false;
        const matchesCategory =
          !cat || cat === "All Categories" || item.category === cat;
        if (!matchesCategory) return false;

        if (!search) return true;
        const nameMatch = item.name && item.name.toLowerCase().includes(search);
        const titleMatch = item.title && item.title.toLowerCase().includes(search);
        const descMatch = item.description && item.description.toLowerCase().includes(search);
        return Boolean(nameMatch || titleMatch || descMatch);
      });
    },

    get violationsByCategory() {
      let cats = (this.catalog?.categories || []).filter((c) => c !== "All Categories");
      if (!cats.length) {
        cats = [
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
        ];
      }
      const activeCat = this.violationsCategory || "All Categories";
      const search = (this.violationsSearch || "").trim().toLowerCase();
      const allViols = this.catalog?.violations || [];

      const cacheKey = `${allViols.length}:${activeCat}:${search}`;
      if (this._violationsCacheKey === cacheKey && this._cachedViolationsByCategory) {
        return this._cachedViolationsByCategory;
      }

      const targetCats = (activeCat === "All Categories")
        ? cats
        : [activeCat];

      const result = [];
      for (const catName of targetCats) {
        let viols = allViols.filter((v) => v.category === catName);
        if (search) {
          viols = viols.filter(
            (v) =>
              (v.name && v.name.toLowerCase().includes(search)) ||
              (v.title && v.title.toLowerCase().includes(search)) ||
              (v.description && v.description.toLowerCase().includes(search))
          );
        }
        if (viols.length > 0) {
          result.push({
            category: catName,
            count: viols.length,
            violations: viols,
          });
        }
      }
      this._violationsCacheKey = cacheKey;
      this._cachedViolationsByCategory = result;
      return result;
    },

    getCategoryViolationCount(cat) {
      const allViols = this.catalog?.violations || [];
      if (!cat || cat === "All Categories") return allViols.length;
      return allViols.filter((v) => v.category === cat).length;
    },

    getUrlsAndParamsCount() {
      const urlsCount = Array.isArray(this.currentPolicy?.policy?.urls)
        ? this.currentPolicy.policy.urls.length
        : 0;
      const paramsCount = Array.isArray(this.currentPolicy?.policy?.parameters)
        ? this.currentPolicy.policy.parameters.length
        : 0;
      return urlsCount + paramsCount;
    },

    getUrlsCount() {
      return Array.isArray(this.currentPolicy?.policy?.urls)
        ? this.currentPolicy.policy.urls.length
        : 0;
    },

    getParametersCount() {
      return Array.isArray(this.currentPolicy?.policy?.parameters)
        ? this.currentPolicy.policy.parameters.length
        : 0;
    },

    get filteredUrls() {
      const urls = this.currentPolicy?.policy?.urls;
      if (!Array.isArray(urls)) return [];
      const q = (this.urlSearchQuery || "").trim().toLowerCase();
      const typeFilter = (this.urlTypeFilter || "all").toLowerCase();

      // Fast-path: no filter applied, return original array directly in O(1)
      if (!q && typeFilter === "all") {
        return urls;
      }

      const key = `${urls.length}:${q}:${typeFilter}`;
      if (this._urlCacheKey === key && this._cachedFilteredUrls) {
        return this._cachedFilteredUrls;
      }

      this._urlCacheKey = key;
      this._cachedFilteredUrls = urls.filter((u) => {
        if (!u || typeof u !== "object") return false;
        const name = (u.name || "").toLowerCase();
        if (q && !name.includes(q)) return false;
        if (typeFilter !== "all" && (u.type || "explicit").toLowerCase() !== typeFilter) return false;
        return true;
      });
      return this._cachedFilteredUrls;
    },

    get groupedParameters() {
      const params = this.currentPolicy?.policy?.parameters;
      if (!Array.isArray(params)) return [];

      const cacheKey = `${params.length}:${this._paramMutatedSeq || 0}`;
      if (this._cachedGroupedParamKey === cacheKey && this._cachedGroupedParams) {
        return this._cachedGroupedParams;
      }

      const map = new Map();
      params.forEach((p, idx) => {
        if (!p || typeof p !== "object") return;
        const name = (p.name || "").trim();
        if (!name) return;

        let group = map.get(name);
        if (!group) {
          group = {
            name: name,
            type: p.type || "explicit",
            dataType: p.dataType || "alpha-numeric",
            parameterLocation: p.parameterLocation || (["query", "body", "form-data", "header", "cookie", "path"].includes(p.type) ? p.type : "any"),
            valueType: p.valueType || "user-input",
            sensitiveParameter: p.sensitiveParameter !== undefined ? !!p.sensitiveParameter : !!p.sensitive,
            mandatory: !!p.mandatory,
            allowEmptyValue: p.allowEmptyValue !== undefined ? !!p.allowEmptyValue : false,
            allowRepeatedParameterName: !!p.allowRepeatedParameterName,
            decodeValueAsBase64: p.decodeValueAsBase64 || "disabled",
            enableRegularExpression: !!p.enableRegularExpression,
            regularExpression: p.regularExpression || "",
            attackSignaturesCheck: p.attackSignaturesCheck !== undefined ? !!p.attackSignaturesCheck : true,
            disallowFileUploadOfExecutables: !!p.disallowFileUploadOfExecutables,
            checkMinValueLength: !!p.checkMinValueLength,
            minimumLength: p.minimumLength,
            checkMaxValueLength: !!p.checkMaxValueLength,
            maximumLength: p.maximumLength,
            checkMinValue: !!p.checkMinValue,
            minimumValue: p.minimumValue,
            exclusiveMin: !!p.exclusiveMin,
            checkMaxValue: !!p.checkMaxValue,
            maximumValue: p.maximumValue,
            exclusiveMax: !!p.exclusiveMax,
            checkMultipleOfValue: !!p.checkMultipleOfValue,
            multipleOf: p.multipleOf,
            signatureOverrides: Array.isArray(p.signatureOverrides) ? p.signatureOverrides : [],
            checkMetachars: !!p.checkMetachars,
            nameMetacharOverrides: Array.isArray(p.nameMetacharOverrides) ? p.nameMetacharOverrides : [],
            metacharsOnParameterValueCheck: !!p.metacharsOnParameterValueCheck,
            valueMetacharOverrides: Array.isArray(p.valueMetacharOverrides) ? p.valueMetacharOverrides : [],
            wildcardOrder: p.wildcardOrder,
            staticValues: p.staticValues,
            parameterEnumValues: p.parameterEnumValues,
            arraySerializationFormat: p.arraySerializationFormat,
            arrayUniqueItemsCheck: !!p.arrayUniqueItemsCheck,
            checkMinItemsInArray: !!p.checkMinItemsInArray,
            minItemsInArray: p.minItemsInArray,
            checkMaxItemsInArray: !!p.checkMaxItemsInArray,
            maxItemsInArray: p.maxItemsInArray,
            isGlobal: false,
            urls: [],
            rawIndices: [],
          };
          map.set(name, group);
        }

        group.rawIndices.push(idx);

        const lvl = (p.level || "global").toLowerCase();
        if (lvl === "url" && p.url && typeof p.url === "object") {
          group.urls.push({
            name: p.url.name || "",
            method: p.url.method || "*",
            protocol: p.url.protocol || "http",
            type: p.url.type || "explicit",
            rawIndex: idx,
            paramItem: p,
          });
        } else {
          group.isGlobal = true;
        }
      });

      this._cachedGroupedParamKey = cacheKey;
      this._cachedGroupedParams = Array.from(map.values());
      return this._cachedGroupedParams;
    },

    get filteredParameters() {
      const grouped = this.groupedParameters;
      if (!Array.isArray(grouped)) return [];
      const q = (this.paramSearchQuery || "").trim().toLowerCase();
      const typeFilter = (this.paramTypeFilter || "all").toLowerCase();
      const dtFilter = (this.paramDataTypeFilter || "all").toLowerCase();
      const sensFilter = this.paramSensitivityFilter || "all";

      const key = `${grouped.length}:${q}:${typeFilter}:${dtFilter}:${sensFilter}:${this._paramMutatedSeq || 0}`;
      if (this._paramCacheKey === key && this._cachedFilteredParams) {
        return this._cachedFilteredParams;
      }

      this._paramCacheKey = key;
      this._cachedFilteredParams = grouped.filter((p) => {
        if (!p || typeof p !== "object") return false;
        const name = (p.name || "").toLowerCase();
        if (q && !name.includes(q)) return false;
        if (typeFilter !== "all") {
          const loc = (p.parameterLocation || p.type || "any").toLowerCase();
          if (loc !== typeFilter && (typeFilter !== "body" || loc !== "form-data")) return false;
        }
        if (dtFilter !== "all" && (p.dataType || "string").toLowerCase() !== dtFilter) return false;
        if (sensFilter !== "all") {
          const isSens = p.sensitiveParameter !== undefined ? !!p.sensitiveParameter : !!p.sensitive;
          if (sensFilter === "sensitive" && !isSens) return false;
          if (sensFilter === "normal" && isSens) return false;
        }
        return true;
      });
      return this._cachedFilteredParams;
    },

    getPageNumbers(currentPage, totalPages) {
      if (totalPages <= 1) return [1];
      if (totalPages <= 7) {
        const pages = [];
        for (let i = 1; i <= totalPages; i++) pages.push(i);
        return pages;
      }
      const pages = [1];
      let start = Math.max(2, currentPage - 1);
      let end = Math.min(totalPages - 1, currentPage + 1);

      if (currentPage <= 3) {
        start = 2;
        end = Math.min(totalPages - 1, 4);
      } else if (currentPage >= totalPages - 2) {
        start = Math.max(2, totalPages - 3);
        end = totalPages - 1;
      }

      if (start > 2) {
        pages.push("...");
      }
      for (let i = start; i <= end; i++) {
        pages.push(i);
      }
      if (end < totalPages - 1) {
        pages.push("...");
      }
      pages.push(totalPages);
      return pages;
    },

    get paginatedUrls() {
      const list = this.filteredUrls;
      if (!Array.isArray(list)) return [];
      if (!this.urlPageSize || this.urlPageSize <= 0) return list;
      const totalPages = this.totalUrlPages;
      const page = Math.max(1, Math.min(this.urlPage || 1, totalPages));
      const start = (page - 1) * this.urlPageSize;
      return list.slice(start, start + this.urlPageSize);
    },

    get totalUrlPages() {
      if (!this.urlPageSize || this.urlPageSize <= 0) return 1;
      const count = (this.filteredUrls || []).length;
      return Math.max(1, Math.ceil(count / this.urlPageSize));
    },

    get urlPageNumbers() {
      return this.getPageNumbers(this.urlPage || 1, this.totalUrlPages);
    },

    get paginatedParameters() {
      const list = this.filteredParameters;
      if (!Array.isArray(list)) return [];
      if (!this.paramPageSize || this.paramPageSize <= 0) return list;
      const totalPages = this.totalParamPages;
      const page = Math.max(1, Math.min(this.paramPage || 1, totalPages));
      const start = (page - 1) * this.paramPageSize;
      return list.slice(start, start + this.paramPageSize);
    },

    get totalParamPages() {
      if (!this.paramPageSize || this.paramPageSize <= 0) return 1;
      const count = (this.filteredParameters || []).length;
      return Math.max(1, Math.ceil(count / this.paramPageSize));
    },

    get paramPageNumbers() {
      return this.getPageNumbers(this.paramPage || 1, this.totalParamPages);
    },

    get filteredSignatures() {
      const sigs = this.getSignatures();
      const q = (this.sigSearchQuery || "").trim().toLowerCase();
      if (!q) return sigs;
      const key = `${sigs.length}:${q}`;
      if (this._sigCacheKey === key && this._cachedFilteredSigs) {
        return this._cachedFilteredSigs;
      }
      this._sigCacheKey = key;
      this._cachedFilteredSigs = sigs.filter((s) => {
        const id = String(s.signatureId || "");
        const name = (s.name || "").toLowerCase();
        const tag = (s.tag || "").toLowerCase();
        return id.includes(q) || name.includes(q) || tag.includes(q);
      });
      return this._cachedFilteredSigs;
    },

    get paginatedSignatures() {
      const list = this.filteredSignatures;
      const start = (this.sigPage - 1) * this.sigPageSize;
      return list.slice(start, start + this.sigPageSize);
    },

    get totalSigPages() {
      return Math.max(1, Math.ceil(this.filteredSignatures.length / this.sigPageSize));
    },

    get filteredCustomSignatures() {
      const sigs = this.getCustomSignatures();
      const q = (this.customSigSearchQuery || "").trim().toLowerCase();
      if (!q) return sigs;
      return sigs.filter((s) => {
        const name = (s.name || "").toLowerCase();
        const tag = (s.tag || "").toLowerCase();
        const rule = (s.rule || "").toLowerCase();
        return name.includes(q) || tag.includes(q) || rule.includes(q);
      });
    },

    get paginatedCustomSignatures() {
      const list = this.filteredCustomSignatures;
      const start = (this.customSigPage - 1) * this.customSigPageSize;
      return list.slice(start, start + this.customSigPageSize);
    },

    get totalCustomSigPages() {
      return Math.max(1, Math.ceil(this.filteredCustomSignatures.length / this.customSigPageSize));
    },

    get paginatedIpAddressLists() {
      const list = this.getFilteredIpAddressLists();
      const start = (this.ipListPage - 1) * this.ipListPageSize;
      return list.slice(start, start + this.ipListPageSize);
    },

    get totalIpListPages() {
      return Math.max(1, Math.ceil(this.getFilteredIpAddressLists().length / this.ipListPageSize));
    },

    resetEditorPagination() {
      this.urlPage = 1;
      this.paramPage = 1;
      this.sigPage = 1;
      this.customSigPage = 1;
      this.ipListPage = 1;
      this.invalidateFilterCaches();
    },

    invalidateFilterCaches() {
      this._urlCacheKey = null;
      this._cachedFilteredUrls = null;
      this._paramCacheKey = null;
      this._cachedFilteredParams = null;
      this._sigCacheKey = null;
      this._cachedFilteredSigs = null;
      this._wildcardUrlsCountCache = undefined;
      this._wildcardUrlsLen = undefined;
      this._sensitiveParamsCountCache = undefined;
      this._sensitiveParamsLen = undefined;
      this._violationsCacheKey = null;
      this._cachedViolationsByCategory = null;
    },

    invalidateUrlCache() {
      this._urlCacheKey = null;
      this._cachedFilteredUrls = null;
      this._wildcardUrlsCountCache = undefined;
      this._wildcardUrlsLen = undefined;
    },

    invalidateParamCache() {
      this._paramCacheKey = null;
      this._cachedFilteredParams = null;
      this._cachedGroupedParamKey = null;
      this._cachedGroupedParams = null;
      this._paramMutatedSeq = (this._paramMutatedSeq || 0) + 1;
      this._sensitiveParamsCountCache = undefined;
      this._sensitiveParamsLen = undefined;
    },

    jumpToUrlPage(page) {
      const p = parseInt(page);
      if (!isNaN(p)) {
        this.urlPage = Math.max(1, Math.min(p, this.totalUrlPages));
      }
    },

    jumpToParamPage(page) {
      const p = parseInt(page);
      if (!isNaN(p)) {
        this.paramPage = Math.max(1, Math.min(p, this.totalParamPages));
      }
    },

    getWildcardUrlsCount() {
      const urls = this.currentPolicy?.policy?.urls;
      if (!Array.isArray(urls) || !urls.length) return 0;
      if (this._wildcardUrlsCountCache !== undefined && this._wildcardUrlsLen === urls.length) {
        return this._wildcardUrlsCountCache;
      }
      let count = 0;
      for (let i = 0; i < urls.length; i++) {
        if ((urls[i]?.type || "").toLowerCase() === "wildcard") count++;
      }
      this._wildcardUrlsLen = urls.length;
      this._wildcardUrlsCountCache = count;
      return count;
    },

    getExplicitUrlsCount() {
      const urls = this.currentPolicy?.policy?.urls;
      if (!Array.isArray(urls)) return 0;
      return Math.max(0, urls.length - this.getWildcardUrlsCount());
    },

    getSensitiveParamsCount() {
      const params = this.currentPolicy?.policy?.parameters;
      if (!Array.isArray(params) || !params.length) return 0;
      if (this._sensitiveParamsCountCache !== undefined && this._sensitiveParamsLen === params.length) {
        return this._sensitiveParamsCountCache;
      }
      let count = 0;
      for (let i = 0; i < params.length; i++) {
        const p = params[i];
        if (p && (p.sensitiveParameter !== undefined ? !!p.sensitiveParameter : !!p.sensitive)) count++;
      }
      this._sensitiveParamsLen = params.length;
      this._sensitiveParamsCountCache = count;
      return count;
    },

    isDataGuardEnabled() {
      return !!this.currentPolicy?.policy?.["data-guard"]?.enabled;
    },

    isBotDefenseEnabled() {
      const bd = this.currentPolicy?.policy?.["bot-defense"] || this.currentPolicy?.policy?.botDefense;
      if (!bd) return false;
      if (typeof bd === "boolean") return bd;
      if (bd.settings && typeof bd.settings === "object") {
        return Boolean(bd.settings.isEnabled ?? bd.settings.enabled);
      }
      return Boolean(bd.isEnabled ?? bd.enabled);
    },

    toggleBotDefense(enabled) {
      this.markDirty();
      this.ensurePolicySection("bot-defense", {});
      if (!this.currentPolicy.policy["bot-defense"] || typeof this.currentPolicy.policy["bot-defense"] !== "object") {
        this.currentPolicy.policy["bot-defense"] = {};
      }
      if (!this.currentPolicy.policy["bot-defense"].settings || typeof this.currentPolicy.policy["bot-defense"].settings !== "object") {
        this.currentPolicy.policy["bot-defense"].settings = {};
      }
      this.currentPolicy.policy["bot-defense"].settings.isEnabled = Boolean(enabled);
    },

    hasServerTech(techName) {
      if (!this.currentPolicy?.policy) return false;
      const techs = this.currentPolicy.policy["server-technologies"];
      if (!Array.isArray(techs)) return false;
      const target = (techName || "").trim().toLowerCase();
      return techs.some((t) => {
        if (!t) return false;
        if (typeof t === "string") return t.trim().toLowerCase() === target;
        const n = t.serverTechnologyName || t.name;
        return typeof n === "string" && n.trim().toLowerCase() === target;
      });
    },

    toggleServerTech(techName) {
      if (!this.currentPolicy) return;
      this.markDirty();
      this.ensurePolicySection("server-technologies", []);
      if (!Array.isArray(this.currentPolicy.policy["server-technologies"])) {
        this.currentPolicy.policy["server-technologies"] = [];
      }
      const list = this.currentPolicy.policy["server-technologies"];
      const target = (techName || "").trim().toLowerCase();
      const idx = list.findIndex((t) => {
        if (!t) return false;
        if (typeof t === "string") return t.trim().toLowerCase() === target;
        const n = t.serverTechnologyName || t.name;
        return typeof n === "string" && n.trim().toLowerCase() === target;
      });

      if (idx >= 0) {
        list.splice(idx, 1);
      } else {
        list.push({ serverTechnologyName: techName });
      }
    },

    clearAllServerTech() {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      this.currentPolicy.policy["server-technologies"] = [];
    },

    selectAllServerTech() {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      this.ensurePolicySection("server-technologies", []);
      if (!Array.isArray(this.currentPolicy.policy["server-technologies"])) {
        this.currentPolicy.policy["server-technologies"] = [];
      }
      const list = this.currentPolicy.policy["server-technologies"];
      const techCatalog = this.catalog.serverTechnologies || [];
      techCatalog.forEach((tech) => {
        if (!this.hasServerTech(tech.name)) {
          list.push({ serverTechnologyName: tech.name });
        }
      });
    },

    getServerTechIcon(techName) {
      if (!techName) return window.SERVER_TECH_ICONS?.defaultIcon || "";
      const key = String(techName).trim();
      if (window.SERVER_TECH_ICONS && window.SERVER_TECH_ICONS[key]) {
        return window.SERVER_TECH_ICONS[key];
      }
      // Case-insensitive lookup fallback
      const lower = key.toLowerCase();
      if (window.SERVER_TECH_ICONS) {
        for (const [k, svg] of Object.entries(window.SERVER_TECH_ICONS)) {
          if (k.toLowerCase() === lower) return svg;
        }
      }
      return window.SERVER_TECH_ICONS?.defaultIcon || `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" stroke-width="1.8"/><path d="M8 21h8M12 17v4" stroke-width="1.8" stroke-linecap="round"/></svg>`;
    },

    getServerTechSelectedCount() {
      if (!this.currentPolicy?.policy) return 0;
      const list = this.currentPolicy.policy["server-technologies"];
      return Array.isArray(list) ? list.length : 0;
    },

    get serverTechCategories() {
      const techs = this.catalog.serverTechnologies || [];
      const cats = new Set();
      techs.forEach((t) => {
        if (t.category) cats.add(t.category);
      });
      return ["all", ...Array.from(cats).sort()];
    },

    get filteredServerTechnologies() {
      const techs = this.catalog.serverTechnologies || [];
      const q = (this.serverTechSearchQuery || "").trim().toLowerCase();
      const cat = this.serverTechCategoryFilter || "all";
      const status = this.serverTechStatusFilter || "all";

      return techs.filter((tech) => {
        // Query match
        if (q) {
          const matchName = (tech.name || "").toLowerCase().includes(q);
          const matchCat = (tech.category || "").toLowerCase().includes(q);
          if (!matchName && !matchCat) return false;
        }

        // Category filter
        if (cat !== "all" && tech.category !== cat) {
          return false;
        }

        // Status filter
        if (status === "selected" && !this.hasServerTech(tech.name)) {
          return false;
        }
        if (status === "unselected" && this.hasServerTech(tech.name)) {
          return false;
        }

        return true;
      });
    },

    selectFilteredServerTech() {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      this.ensurePolicySection("server-technologies", []);
      if (!Array.isArray(this.currentPolicy.policy["server-technologies"])) {
        this.currentPolicy.policy["server-technologies"] = [];
      }
      const list = this.currentPolicy.policy["server-technologies"];
      const items = this.filteredServerTechnologies;
      items.forEach((tech) => {
        if (!this.hasServerTech(tech.name)) {
          list.push({ serverTechnologyName: tech.name });
        }
      });
    },

    clearFilteredServerTech() {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      const list = this.currentPolicy.policy["server-technologies"];
      if (!Array.isArray(list)) return;
      const toRemoveNames = new Set(this.filteredServerTechnologies.map((t) => t.name.toLowerCase()));
      this.currentPolicy.policy["server-technologies"] = list.filter((t) => {
        const n = (typeof t === "string" ? t : (t.serverTechnologyName || t.name || "")).trim().toLowerCase();
        return !toRemoveNames.has(n);
      });
    },

    applyServerTechStack(stackId) {
      if (!this.currentPolicy?.policy) return;
      const stacks = {
        lamp: ["Apache/NCSA HTTP Server", "PHP", "MySQL", "Unix/Linux"],
        mean: ["Node.js", "Express.js", "MongoDB", "AngularJS"],
        mern: ["Node.js", "Express.js", "MongoDB", "React"],
        django: ["Python", "Django", "Nginx", "PostgreSQL"],
        spring: ["Java Servlets/JSP", "Spring Boot", "Apache Tomcat", "MySQL"],
        dotnet: ["IIS", "ASP.NET", "Microsoft SQL Server", "Microsoft Windows"],
        wordpress: ["WordPress", "PHP", "MySQL", "Apache/NCSA HTTP Server", "Nginx"],
      };

      const targetStack = stacks[stackId];
      if (!targetStack) return;

      this.markDirty();
      this.ensurePolicySection("server-technologies", []);
      if (!Array.isArray(this.currentPolicy.policy["server-technologies"])) {
        this.currentPolicy.policy["server-technologies"] = [];
      }
      const list = this.currentPolicy.policy["server-technologies"];
      targetStack.forEach((name) => {
        if (!this.hasServerTech(name)) {
          list.push({ serverTechnologyName: name });
        }
      });
    },

    // -------------------------------------------------------------
    // Attack Signature Sets Methods
    // -------------------------------------------------------------
    getSignatureSets() {
      if (!this.currentPolicy?.policy) return [];
      const sets = this.currentPolicy.policy["signature-sets"];
      return Array.isArray(sets) ? sets : [];
    },

    get filteredSignatureSets() {
      const sets = this.getSignatureSets();
      const q = (this.sigSetSearch || "").trim().toLowerCase();
      if (!q) return sets;
      return sets.filter((s) => {
        const name = (s.name || "").toLowerCase();
        const tag = (s.signatureSet?.filter?.tagValue || "").toLowerCase();
        const atk = (s.signatureSet?.filter?.attackType?.name || "").toLowerCase();
        const catItem = (this.catalog.signatureSets || []).find(
          (c) => c.name.toLowerCase() === name
        );
        const cat = (catItem?.category || "").toLowerCase();
        const desc = (catItem?.description || "").toLowerCase();
        return name.includes(q) || tag.includes(q) || atk.includes(q) || cat.includes(q) || desc.includes(q);
      });
    },

    get availableCatalogSigSets() {
      const catalogSets = this.catalog.signatureSets || [];
      const currentSets = this.getSignatureSets();
      return catalogSets.filter((c) => {
        return !currentSets.some((s) => (s.name || "").trim().toLowerCase() === c.name.trim().toLowerCase());
      });
    },

    hasSignatureSet(setName) {
      const currentSets = this.getSignatureSets();
      const target = (setName || "").trim().toLowerCase();
      return currentSets.some((s) => (s.name || "").trim().toLowerCase() === target);
    },

    addSignatureSetFromCatalog(itemOrName) {
      if (!this.currentPolicy) return;
      this.markDirty();
      this.ensurePolicySection("signature-sets", []);
      if (!Array.isArray(this.currentPolicy.policy["signature-sets"])) {
        this.currentPolicy.policy["signature-sets"] = [];
      }
      const list = this.currentPolicy.policy["signature-sets"];

      let item = null;
      if (typeof itemOrName === "string") {
        item = (this.catalog.signatureSets || []).find(
          (c) => c.name.trim().toLowerCase() === itemOrName.trim().toLowerCase()
        ) || { name: itemOrName, defaultAlarm: true, defaultBlock: true };
      } else {
        item = itemOrName;
      }

      if (!item || !item.name) return;
      if (this.hasSignatureSet(item.name)) {
        this.notify(`Signature set '${item.name}' is already added.`, "info");
        return;
      }

      list.push({
        name: item.name,
        alarm: item.defaultAlarm !== false,
        block: item.defaultBlock !== false,
      });
      this.notify(`Added '${item.name}' signature set.`, "success");
    },

    isUserDefinedSigSet(set) {
      if (!set) return false;
      return !!(set.signatureSet || set.signatures || set.filter);
    },

    confirmDeleteSignatureSet(index) {
      const list = this.getSignatureSets();
      if (index >= 0 && index < list.length) {
        this.sigSetToDelete = list[index];
        this.sigSetToDeleteIndex = index;
        this.showDeleteSigSetModal = true;
      }
    },

    executeDeleteSignatureSet() {
      if (this.sigSetToDeleteIndex === null || !this.currentPolicy?.policy) {
        this.showDeleteSigSetModal = false;
        return;
      }
      const list = this.getSignatureSets();
      if (this.sigSetToDeleteIndex >= 0 && this.sigSetToDeleteIndex < list.length) {
        const removed = list.splice(this.sigSetToDeleteIndex, 1)[0];
        this.markDirty();
        this.notify(`Removed signature set '${removed.name || "signature set"}'.`, "info");
      }
      this.showDeleteSigSetModal = false;
      this.sigSetToDelete = null;
      this.sigSetToDeleteIndex = null;
    },

    toggleSelectAllSigSets() {
      const list = this.filteredSignatureSets || [];
      if (this.selectedSigSets.length === list.length && list.length > 0) {
        this.selectedSigSets = [];
      } else {
        this.selectedSigSets = list.map((s) => s.name);
      }
    },

    confirmMassDeleteSigSets() {
      if (!this.selectedSigSets || this.selectedSigSets.length === 0) {
        this.notify("No signature sets selected.", "warning");
        return;
      }
      this.showMassDeleteSigSetModal = true;
    },

    executeMassDeleteSigSets() {
      if (!this.currentPolicy?.policy || !this.selectedSigSets.length) {
        this.showMassDeleteSigSetModal = false;
        return;
      }
      const sets = this.getSignatureSets();
      const toRemove = new Set(this.selectedSigSets);
      const count = toRemove.size;
      this.currentPolicy.policy["signature-sets"] = sets.filter((s) => !toRemove.has(s.name));
      this.markDirty();
      this.selectedSigSets = [];
      this.showMassDeleteSigSetModal = false;
      this.notify(`Successfully removed ${count} signature set(s).`, "info");
    },


    openAddCustomSigSetModal() {
      this.editingSigSetIndex = null;
      this.customSigSetForm = {
        name: "",
        alarm: true,
        block: true,
        type: "filter-based",
        tagFilter: "eq",
        tagValue: "",
        riskFilter: "all",
        riskValue: "all",
        accuracyFilter: "all",
        accuracyValue: "all",
        signatureType: "all",
        hasCve: "all",
        attackType: "",
        manualSignaturesInput: "",
      };
      this.showAddCustomSigSetModal = true;
    },

    openEditCustomSigSetModal(index) {
      const list = this.getSignatureSets();
      if (index < 0 || index >= list.length) return;
      const set = list[index];
      this.editingSigSetIndex = index;

      const sigSetObj = set.signatureSet || {};
      const isManual = sigSetObj.type === "manual" || Array.isArray(sigSetObj.signatures) || Array.isArray(set.signatures);
      const setType = isManual ? "manual" : "filter-based";

      let manualIds = "";
      if (isManual) {
        const sigList = sigSetObj.signatures || set.signatures || [];
        manualIds = sigList
          .map((s) => (typeof s === "object" ? s.signatureId : s))
          .filter(Boolean)
          .join(", ");
      }

      const flt = sigSetObj.filter || set.filter || {};
      const atkType = (flt.attackType && flt.attackType.name)
        ? flt.attackType.name
        : (typeof flt.attackType === "string" ? flt.attackType : "");

      this.customSigSetForm = {
        name: set.name || "",
        alarm: set.alarm !== undefined ? !!set.alarm : true,
        block: set.block !== undefined ? !!set.block : false,
        type: setType,
        tagFilter: flt.tagFilter || "eq",
        tagValue: flt.tagValue || "",
        riskFilter: flt.riskFilter || "all",
        riskValue: flt.riskValue || "all",
        accuracyFilter: flt.accuracyFilter || "all",
        accuracyValue: flt.accuracyValue || "all",
        signatureType: flt.signatureType || "all",
        hasCve: flt.hasCve || "all",
        attackType: atkType,
        manualSignaturesInput: manualIds,
      };
      this.showAddCustomSigSetModal = true;
    },

    saveCustomSignatureSet() {
      if (!this.currentPolicy) return;
      const name = (this.customSigSetForm.name || "").trim();
      if (!name) {
        this.notify("Please enter a name for the signature set.", "error");
        return;
      }

      this.markDirty();
      this.ensurePolicySection("signature-sets", []);
      if (!Array.isArray(this.currentPolicy.policy["signature-sets"])) {
        this.currentPolicy.policy["signature-sets"] = [];
      }
      const list = this.currentPolicy.policy["signature-sets"];

      const existingIdx = list.findIndex((s) => (s.name || "").toLowerCase() === name.toLowerCase());
      if (existingIdx !== -1 && existingIdx !== this.editingSigSetIndex) {
        this.notify(`Signature set '${name}' already exists in this policy.`, "error");
        return;
      }

      const newSet = {
        name: name,
        alarm: !!this.customSigSetForm.alarm,
        block: !!this.customSigSetForm.block,
      };

      if (this.customSigSetForm.type === "manual") {
        const ids = (this.customSigSetForm.manualSignaturesInput || "")
          .split(/[\n,\s]+/)
          .map((id) => parseInt(id.trim(), 10))
          .filter((id) => !isNaN(id) && id > 0);

        newSet.signatureSet = {
          type: "manual",
          signatures: ids.map((id) => ({ signatureId: id })),
        };
      } else {
        const filter = {};
        if (this.customSigSetForm.tagValue && this.customSigSetForm.tagValue.trim()) {
          filter.tagFilter = this.customSigSetForm.tagFilter || "eq";
          filter.tagValue = this.customSigSetForm.tagValue.trim();
        }
        if (this.customSigSetForm.attackType && this.customSigSetForm.attackType.trim()) {
          filter.attackType = { name: this.customSigSetForm.attackType.trim() };
        }
        if (this.customSigSetForm.riskFilter && this.customSigSetForm.riskFilter !== "all") {
          filter.riskFilter = this.customSigSetForm.riskFilter;
          filter.riskValue = this.customSigSetForm.riskValue || "medium";
        }
        if (this.customSigSetForm.accuracyFilter && this.customSigSetForm.accuracyFilter !== "all") {
          filter.accuracyFilter = this.customSigSetForm.accuracyFilter;
          filter.accuracyValue = this.customSigSetForm.accuracyValue || "medium";
        }
        if (this.customSigSetForm.signatureType && this.customSigSetForm.signatureType !== "all") {
          filter.signatureType = this.customSigSetForm.signatureType;
        }
        if (this.customSigSetForm.hasCve && this.customSigSetForm.hasCve !== "all") {
          filter.hasCve = this.customSigSetForm.hasCve;
        }

        newSet.signatureSet = {
          type: "filter-based",
          filter: filter,
        };
      }

      if (this.editingSigSetIndex !== null && this.editingSigSetIndex >= 0 && this.editingSigSetIndex < list.length) {
        list[this.editingSigSetIndex] = newSet;
        this.notify(`Custom signature set '${name}' updated.`, "success");
      } else {
        list.push(newSet);
        this.notify(`Custom signature set '${name}' added.`, "success");
      }

      this.showAddCustomSigSetModal = false;
      this.editingSigSetIndex = null;
    },

    removeSignatureSet(index) {
      this.confirmDeleteSignatureSet(index);
    },

    toggleSignatureSetAlarm(index) {
      if (!this.currentPolicy?.policy) return;
      const list = this.getSignatureSets();
      if (index >= 0 && index < list.length) {
        this.markDirty();
        const set = list[index];
        set.alarm = !set.alarm;
        if (!set.alarm) {
          set.block = false;
        }
      }
    },

    toggleSignatureSetBlock(index) {
      if (!this.currentPolicy?.policy) return;
      const list = this.getSignatureSets();
      if (index >= 0 && index < list.length) {
        this.markDirty();
        const set = list[index];
        set.block = !set.block;
        if (set.block) {
          set.alarm = true;
        }
      }
    },

    applySignatureSetsPreset(preset) {
      if (!this.currentPolicy) return;
      this.markDirty();
      this.ensurePolicySection("signature-sets", []);
      if (!Array.isArray(this.currentPolicy.policy["signature-sets"])) {
        this.currentPolicy.policy["signature-sets"] = [];
      }
      const list = this.currentPolicy.policy["signature-sets"];

      if (preset === "clear_all") {
        this.currentPolicy.policy["signature-sets"] = [];
        this.notify("Cleared all signature sets", "info");
        return;
      }

      if (preset === "block_all") {
        list.forEach((s) => {
          s.alarm = true;
          s.block = true;
        });
        this.notify("Set Alarm & Block for all active signature sets", "success");
        return;
      }

      if (preset === "alarm_only") {
        list.forEach((s) => {
          s.alarm = true;
          s.block = false;
        });
        this.notify("Set Alarm Only for all active signature sets", "info");
        return;
      }

      if (preset === "recommended") {
        const recommendedNames = [
          "High Accuracy Signatures",
          "SQL Injection Signatures",
          "Cross Site Scripting Signatures",
          "Command Execution Signatures",
          "Path Traversal Signatures",
          "Server Side Code Injection Signatures",
          "Remote File Include Signatures",
          "XML External Entities (XXE) Signatures",
        ];
        recommendedNames.forEach((recName) => {
          if (!this.hasSignatureSet(recName)) {
            const catItem = (this.catalog.signatureSets || []).find((c) => c.name === recName);
            list.push({
              name: recName,
              alarm: true,
              block: catItem ? catItem.defaultBlock : true,
            });
          }
        });

        // In F5 WAF for NGINX, Threat Campaigns is configured via VIOL_THREAT_CAMPAIGN violation
        if (this.currentPolicy?.policy) {
          if (!this.currentPolicy.policy["blocking-settings"]) {
            this.currentPolicy.policy["blocking-settings"] = {};
          }
          if (!Array.isArray(this.currentPolicy.policy["blocking-settings"].violations)) {
            this.currentPolicy.policy["blocking-settings"].violations = [];
          }
          const viols = this.currentPolicy.policy["blocking-settings"].violations;
          let tc = viols.find((v) => v.name === "VIOL_THREAT_CAMPAIGN");
          if (!tc) {
            viols.push({ name: "VIOL_THREAT_CAMPAIGN", alarm: true, block: true });
          } else {
            tc.alarm = true;
            tc.block = true;
          }
        }

        this.notify("Applied recommended signature sets (and enabled VIOL_THREAT_CAMPAIGN)", "success");
      }
    },

    // -------------------------------------------------------------
    // Individual Signature Exceptions (policy.signatures)
    // -------------------------------------------------------------
    getSignatures() {
      if (!this.currentPolicy?.policy) return [];
      const sigs = this.currentPolicy.policy.signatures;
      return Array.isArray(sigs) ? sigs : [];
    },

    onCustomSigExceptionSelected() {
      if (!this.tempSigException.selectedCustomSig) return;
      try {
        const parsed = JSON.parse(this.tempSigException.selectedCustomSig);
        this.tempSigException.customName = parsed.name || "";
        this.tempSigException.customTag = parsed.tag || "";
      } catch (e) {
        const sigs = this.getCustomSignatures();
        const found = sigs.find((s) => s.name === this.tempSigException.selectedCustomSig);
        if (found) {
          this.tempSigException.customName = found.name;
          this.tempSigException.customTag = found.tag;
        }
      }
    },

    addSignatureException() {
      if (!this.currentPolicy) return;
      this.markDirty();
      this.ensurePolicySection("signatures", []);
      if (!Array.isArray(this.currentPolicy.policy.signatures)) {
        this.currentPolicy.policy.signatures = [];
      }
      const list = this.currentPolicy.policy.signatures;

      if (this.tempSigException.mode === "custom") {
        const name = (this.tempSigException.customName || "").trim();
        const tag = (this.tempSigException.customTag || "").trim();
        if (!name || !tag) {
          this.notify("Both Name and Tag are required for custom signature exceptions.", "error");
          return;
        }
        const existing = list.find((s) => s.name === name && s.tag === tag);
        if (existing) {
          this.notify(`Exception for custom signature '${name}' (tag: ${tag}) already exists.`, "info");
          return;
        }
        const entry = {
          name: name,
          tag: tag,
          enabled: !!this.tempSigException.enabled,
        };
        list.push(entry);
        this.tempSigException.customName = "";
        this.tempSigException.customTag = "";
        this.tempSigException.selectedCustomSig = "";
        this.notify(`Added exception override for custom signature '${name}'`, "success");
      } else {
        const idRaw = (this.tempSigException.signatureId + "").trim();
        const sigId = parseInt(idRaw, 10);
        if (isNaN(sigId) || sigId <= 0) {
          this.notify("Please enter a valid numeric Signature ID (e.g. 200001475)", "error");
          return;
        }

        const existing = list.find((s) => s.signatureId === sigId);
        if (existing) {
          this.notify(`Exception for Signature ID ${sigId} already exists.`, "info");
          return;
        }

        const entry = {
          signatureId: sigId,
          enabled: !!this.tempSigException.enabled,
        };
        if (this.tempSigException.tag && this.tempSigException.tag.trim()) {
          entry.tag = this.tempSigException.tag.trim();
        }

        list.push(entry);
        this.tempSigException.signatureId = "";
        this.tempSigException.tag = "";
        this.notify(`Added exception override for Signature ${sigId}`, "success");
      }
    },

    removeSignatureException(sigOrIndex) {
      if (!this.currentPolicy?.policy) return;
      const list = this.getSignatures();
      const index = typeof sigOrIndex === "number" ? sigOrIndex : list.indexOf(sigOrIndex);
      if (index >= 0 && index < list.length) {
        const removed = list.splice(index, 1)[0];
        this.markDirty();
        const ident = removed.name ? `${removed.name} (tag: ${removed.tag})` : `Signature ${removed.signatureId}`;
        this.notify(`Removed exception for ${ident}`, "info");
      }
    },

    toggleSignatureExceptionEnabled(sigOrIndex) {
      if (!this.currentPolicy?.policy) return;
      const list = this.getSignatures();
      const index = typeof sigOrIndex === "number" ? sigOrIndex : list.indexOf(sigOrIndex);
      if (index >= 0 && index < list.length) {
        this.markDirty();
        list[index].enabled = !list[index].enabled;
      }
    },

    // -------------------------------------------------------------
    // User-Defined Signatures (Custom Signatures) Methods
    // -------------------------------------------------------------
    getCustomSignatures() {
      if (!this.currentPolicy?.policy) return [];
      const sigs =
        this.currentPolicy.policy["custom-signatures"] ||
        this.currentPolicy.policy["user-defined-signatures"];
      return Array.isArray(sigs) ? sigs : [];
    },

    async loadCustomSignaturesCatalog() {
      try {
        const res = await fetch("/api/custom-signatures-catalog");
        if (res.ok) {
          this.customSigCatalog = await res.json();
        }
      } catch (err) {
        console.warn("Could not load custom signatures catalog:", err);
      }
    },

    async loadCustomSignatureFiles() {
      try {
        const res = await fetch("/api/custom-signatures");
        if (res.ok) {
          this.customSigFiles = await res.json();
        }
      } catch (err) {
        console.warn("Could not load custom signature files:", err);
      }
    },

    openAddCustomSigModal() {
      this.customSigTab = "rule";
      this.snortTestResult = null;
      this.customSigForm = {
        name: "",
        tag: "Fruits",
        description: "",
        rule: 'content:"apple"; nocase;',
        signatureType: "request",
        attackType: "Buffer Overflow",
        systems: ["Unix/Linux"],
        risk: "medium",
        accuracy: "medium",
        isEditing: false,
        editIndex: null,
      };
      this.showCustomSigModal = true;
      this.$nextTick(() => {
        this.validateCurrentSnortRule();
      });
    },

    openEditCustomSigModal(sig, index) {
      this.customSigTab = "rule";
      this.snortTestResult = null;
      this.customSigForm = {
        name: sig.name || "",
        tag: sig.tag || "Fruits",
        description: sig.description || "",
        rule: sig.rule || "",
        signatureType: sig.signatureType || "request",
        attackType:
          typeof sig.attackType === "object"
            ? sig.attackType?.name || ""
            : sig.attackType || "",
        systems: Array.isArray(sig.systems)
          ? sig.systems.map((s) => (typeof s === "object" ? s.name : s))
          : [],
        risk: sig.risk || "medium",
        accuracy: sig.accuracy || "medium",
        isEditing: true,
        editIndex: index,
      };
      this.showCustomSigModal = true;
      this.$nextTick(() => {
        this.validateCurrentSnortRule();
      });
    },


    toggleSystemInCustomSig(sysName) {
      if (!Array.isArray(this.customSigForm.systems)) {
        this.customSigForm.systems = [];
      }
      const idx = this.customSigForm.systems.indexOf(sysName);
      if (idx >= 0) {
        this.customSigForm.systems.splice(idx, 1);
      } else {
        this.customSigForm.systems.push(sysName);
      }
    },

    saveCustomSig() {
      if (!this.currentPolicy) return;
      const name = (this.customSigForm.name || "").trim();
      const tag = (this.customSigForm.tag || "").trim();
      const rule = (this.customSigForm.rule || "").trim();

      if (!name) {
        this.notify("Signature Name is required.", "error");
        return;
      }
      if (!tag) {
        this.notify("Tag is required.", "error");
        return;
      }
      if (!rule) {
        this.notify("Snort rule string is required.", "error");
        return;
      }

      this.markDirty();
      this.ensurePolicySection("custom-signatures", []);
      if (!Array.isArray(this.currentPolicy.policy["custom-signatures"])) {
        this.currentPolicy.policy["custom-signatures"] = [];
      }
      const list = this.currentPolicy.policy["custom-signatures"];

      const sigObj = {
        name: name,
        tag: tag,
        rule: rule,
        signatureType: this.customSigForm.signatureType || "request",
        risk: this.customSigForm.risk || "medium",
        accuracy: this.customSigForm.accuracy || "medium",
      };

      if (this.customSigForm.description?.trim()) {
        sigObj.description = this.customSigForm.description.trim();
      }
      if (this.customSigForm.attackType?.trim()) {
        sigObj.attackType = { name: this.customSigForm.attackType.trim() };
      }
      if (Array.isArray(this.customSigForm.systems) && this.customSigForm.systems.length > 0) {
        sigObj.systems = this.customSigForm.systems.map((sys) => ({
          name: typeof sys === "string" ? sys : sys.name,
        }));
      }

      if (this.customSigForm.isEditing && this.customSigForm.editIndex !== null) {
        list[this.customSigForm.editIndex] = sigObj;
        this.notify(`Custom signature '${name}' updated.`, "success");
      } else {
        list.push(sigObj);
        this.notify(`Custom signature '${name}' added.`, "success");
      }

      // Auto ensure requirement tag is present
      this.ensureSignatureRequirement(tag);
      this.showCustomSigModal = false;
    },

    testCustomSigDirect(sig) {
      if (!sig) return;
      const list = this.getCustomSignatures();
      const idx = list.indexOf(sig);
      this.openEditCustomSigModal(sig, idx >= 0 ? idx : null);
      this.customSigTab = "tester";
      this.$nextTick(() => {
        this.validateCurrentSnortRule();
      });
    },

    cloneCustomSig(sig) {
      if (!this.currentPolicy?.policy || !sig) return;
      this.ensurePolicySection("custom-signatures", []);
      if (!Array.isArray(this.currentPolicy.policy["custom-signatures"])) {
        this.currentPolicy.policy["custom-signatures"] = [];
      }
      const list = this.currentPolicy.policy["custom-signatures"];
      const cloned = JSON.parse(JSON.stringify(sig));

      let baseName = cloned.name || "Custom_Sig";
      let newName = `${baseName}_copy`;
      let counter = 1;
      while (list.some((s) => s.name === newName)) {
        counter++;
        newName = `${baseName}_copy_${counter}`;
      }
      cloned.name = newName;
      if (cloned.signatureId) {
        const existingIds = list.map((s) => Number(s.signatureId)).filter((n) => !isNaN(n));
        cloned.signatureId = Math.max(300000000, ...(existingIds.length ? existingIds : [300000000])) + 1;
      }
      list.push(cloned);
      this.markDirty();
      this.notify(`Cloned custom signature to '${newName}'.`, "success");
    },

    confirmDeleteCustomSig(index) {
      const list = this.getCustomSignatures();
      if (index >= 0 && index < list.length) {
        this.customSigToDelete = list[index];
        this.customSigToDeleteIndex = index;
        this.showDeleteCustomSigModal = true;
      }
    },

    executeDeleteCustomSig() {
      if (this.customSigToDeleteIndex === null || !this.currentPolicy?.policy) {
        this.showDeleteCustomSigModal = false;
        return;
      }
      const list = this.getCustomSignatures();
      if (this.customSigToDeleteIndex >= 0 && this.customSigToDeleteIndex < list.length) {
        const removed = list.splice(this.customSigToDeleteIndex, 1)[0];
        this.markDirty();
        this.notify(`Removed custom signature '${removed.name}'.`, "info");
      }
      this.showDeleteCustomSigModal = false;
      this.customSigToDelete = null;
      this.customSigToDeleteIndex = null;
    },

    deleteCustomSig(index) {
      this.confirmDeleteCustomSig(index);
    },

    toggleSelectAllCustomSigs() {
      const list = this.getCustomSignatures() || [];
      if (this.selectedCustomSigs.length === list.length && list.length > 0) {
        this.selectedCustomSigs = [];
      } else {
        this.selectedCustomSigs = list.map((s) => s.name);
      }
    },

    confirmMassDeleteCustomSigs() {
      if (!this.selectedCustomSigs || this.selectedCustomSigs.length === 0) {
        this.notify("No custom signatures selected.", "warning");
        return;
      }
      this.showMassDeleteCustomSigModal = true;
    },

    executeMassDeleteCustomSigs() {
      if (!this.currentPolicy?.policy || !this.selectedCustomSigs.length) {
        this.showMassDeleteCustomSigModal = false;
        return;
      }
      const list = this.getCustomSignatures();
      const toRemove = new Set(this.selectedCustomSigs);
      const count = toRemove.size;
      this.currentPolicy.policy["custom-signatures"] = list.filter((s) => !toRemove.has(s.name));
      this.markDirty();
      this.selectedCustomSigs = [];
      this.showMassDeleteCustomSigModal = false;
      this.notify(`Successfully removed ${count} custom signature(s).`, "info");
    },

    createSigSetForCustomSig(sig) {
      if (!this.currentPolicy || !sig?.tag) return;
      const tag = sig.tag;
      const setName = `${tag}_Signatures`;
      if (this.hasSignatureSet(setName)) {
        this.notify(`Signature set '${setName}' already exists.`, "info");
        return;
      }
      this.markDirty();
      this.ensurePolicySection("signature-sets", []);
      this.currentPolicy.policy["signature-sets"].push({
        name: setName,
        alarm: true,
        block: true,
        signatureSet: {
          type: "filter-based",
          filter: {
            tagFilter: "eq",
            tagValue: tag,
          },
        },
      });
      this.notify(`Created signature set '${setName}' filtering by tag '${tag}'.`, "success");
    },

    addExceptionForCustomSig(sig) {
      if (!this.currentPolicy || !sig?.name || !sig?.tag) return;
      this.markDirty();
      this.ensurePolicySection("signatures", []);
      const sigs = this.currentPolicy.policy.signatures;
      const existing = sigs.find((s) => s.name === sig.name && s.tag === sig.tag);
      if (existing) {
        this.notify(`Exception override for '${sig.name}' already exists.`, "info");
        return;
      }
      sigs.push({
        name: sig.name,
        tag: sig.tag,
        enabled: false,
      });
      this.notify(`Added exception override suppressing custom signature '${sig.name}'.`, "success");
    },

    exportCustomSignaturesFile(tagFilter = null) {
      const allSigs = this.getCustomSignatures();
      const filtered = tagFilter ? allSigs.filter((s) => s.tag === tagFilter) : allSigs;
      if (filtered.length === 0) {
        this.notify("No custom signatures available in policy to export.", "error");
        return;
      }
      const exportTag = tagFilter || filtered[0].tag || "CustomSignatures";
      const doc = {
        softwareVersion: "15.1.0",
        tag: exportTag,
        revisionDatetime: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        signatures: filtered,
      };
      const jsonStr = JSON.stringify(doc, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `signatures_${exportTag}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      this.notify(`Exported ${filtered.length} signature(s) to signatures_${exportTag}.json`, "success");
    },

    async importCustomSignaturesFile(event) {
      const file = event.target?.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (!data.tag || !Array.isArray(data.signatures)) {
          throw new Error("Invalid format: JSON file must contain 'tag' and 'signatures' array.");
        }
        this.markDirty();
        this.ensurePolicySection("custom-signatures", []);
        const list = this.currentPolicy.policy["custom-signatures"];
        let count = 0;
        data.signatures.forEach((sig) => {
          if (!sig.name || !sig.rule) return;
          const normalized = {
            ...sig,
            tag: sig.tag || data.tag,
          };
          const existingIdx = list.findIndex(
            (s) => s.name === normalized.name && s.tag === normalized.tag
          );
          if (existingIdx >= 0) {
            list[existingIdx] = normalized;
          } else {
            list.push(normalized);
          }
          count++;
        });
        this.ensureSignatureRequirement(data.tag);
        this.notify(`Successfully imported ${count} custom signature(s) with tag '${data.tag}'.`, "success");
      } catch (err) {
        this.notify(`Failed to import custom signatures: ${err.message}`, "error");
      } finally {
        event.target.value = "";
      }
    },

    // -------------------------------------------------------------
    // Signature Requirements (policy['signature-requirements'])
    // -------------------------------------------------------------
    getSignatureRequirements() {
      if (!this.currentPolicy?.policy) return [];
      const reqs = this.currentPolicy.policy["signature-requirements"];
      return Array.isArray(reqs) ? reqs : [];
    },

    ensureSignatureRequirement(tag) {
      if (!tag || !this.currentPolicy?.policy) return;
      this.ensurePolicySection("signature-requirements", []);
      if (!Array.isArray(this.currentPolicy.policy["signature-requirements"])) {
        this.currentPolicy.policy["signature-requirements"] = [];
      }
      const reqs = this.currentPolicy.policy["signature-requirements"];
      if (!reqs.some((r) => r.tag === tag)) {
        reqs.push({ tag: tag });
      }
    },

    autoSyncSignatureRequirements() {
      if (!this.currentPolicy?.policy) return;
      const customSigs = this.getCustomSignatures();
      const tags = [...new Set(customSigs.map((s) => s.tag).filter(Boolean))];
      if (tags.length === 0) {
        this.notify("No custom signatures defined to sync requirements from.", "info");
        return;
      }
      this.markDirty();
      this.ensurePolicySection("signature-requirements", []);
      const reqs = this.currentPolicy.policy["signature-requirements"];
      let added = 0;
      tags.forEach((t) => {
        if (!reqs.some((r) => r.tag === t)) {
          reqs.push({ tag: t });
          added++;
        }
      });
      this.notify(`Synced signature requirements (${added} tag(s) added).`, "success");
    },

    openAddSigReqModal() {
      this.sigReqForm = {
        tag: "",
        minRevisionDatetime: "",
        maxRevisionDatetime: "",
        isEditing: false,
        editIndex: null,
      };
      this.showSigReqModal = true;
    },

    openEditSigReqModal(req, index) {
      this.sigReqForm = {
        tag: req.tag || "",
        minRevisionDatetime: req.minRevisionDatetime || "",
        maxRevisionDatetime: req.maxRevisionDatetime || "",
        isEditing: true,
        editIndex: index,
      };
      this.showSigReqModal = true;
    },

    saveSigReq() {
      if (!this.currentPolicy) return;
      const tag = (this.sigReqForm.tag || "").trim();
      if (!tag) {
        this.notify("Requirement Tag is required.", "error");
        return;
      }
      this.markDirty();
      this.ensurePolicySection("signature-requirements", []);
      const reqs = this.currentPolicy.policy["signature-requirements"];
      const reqObj = { tag: tag };
      if (this.sigReqForm.minRevisionDatetime?.trim()) {
        reqObj.minRevisionDatetime = this.sigReqForm.minRevisionDatetime.trim();
      }
      if (this.sigReqForm.maxRevisionDatetime?.trim()) {
        reqObj.maxRevisionDatetime = this.sigReqForm.maxRevisionDatetime.trim();
      }

      if (this.sigReqForm.isEditing && this.sigReqForm.editIndex !== null) {
        reqs[this.sigReqForm.editIndex] = reqObj;
        this.notify(`Signature requirement '${tag}' updated.`, "success");
      } else {
        reqs.push(reqObj);
        this.notify(`Signature requirement '${tag}' added.`, "success");
      }
      this.showSigReqModal = false;
    },

    deleteSigReq(index) {
      if (!this.currentPolicy?.policy) return;
      const reqs = this.getSignatureRequirements();
      if (index >= 0 && index < reqs.length) {
        const removed = reqs.splice(index, 1)[0];
        this.markDirty();
        this.notify(`Removed signature requirement for tag '${removed.tag}'`, "info");
      }
    },

    // -------------------------------------------------------------
    // Snort Rule Helper, Validation & Live Testing Methods
    // -------------------------------------------------------------
    openSnortHelperModal() {
      this.showSnortHelperModal = true;
    },

    insertSnortTemplate(snippet) {
      if (!snippet) return;
      this.customSigForm.rule = snippet;
      this.showSnortHelperModal = false;
      this.notify("Applied Snort rule template.", "success");
      this.validateCurrentSnortRule();
    },

    appendSnortToken(token) {
      if (!token) return;
      const current = (this.customSigForm.rule || "").trim();
      this.customSigForm.rule = current ? `${current} ${token}` : token;
      this.notify(`Appended '${token}' to Snort rule.`, "info");
      this.validateCurrentSnortRule();
    },

    onSnortRuleInput() {
      if (this.snortRuleDebounceTimer) {
        clearTimeout(this.snortRuleDebounceTimer);
      }
      this.snortRuleDebounceTimer = setTimeout(() => {
        this.validateCurrentSnortRule();
      }, 250);
    },

    async validateCurrentSnortRule() {
      const rule = (this.customSigForm.rule || "").trim();
      if (!rule) {
        this.snortValidationStatus = {
          checked: true,
          valid: false,
          errors: ["Rule cannot be empty"],
          warnings: [],
          parsed: null,
        };
        return;
      }
      try {
        const res = await fetch("/api/custom-signatures/validate-snort-rule", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rule: rule }),
        });
        if (res.ok) {
          const data = await res.json();
          this.snortValidationStatus = {
            checked: true,
            valid: data.valid,
            errors: data.errors || [],
            warnings: data.warnings || [],
            parsed: data.parsed || null,
          };
        }
      } catch (err) {
        console.warn("Snort validation check error:", err);
      }
    },

    applySnortHexEscape() {
      const rule = this.customSigForm.rule || "";
      // Converts spaces -> |20|, semicolons -> |3B|, colons -> |3A|, quotes -> |22| in content strings
      const replaced = rule.replace(/(content|uricontent|headercontent|valuecontent):"([^"]*)";/gi, (match, kw, val) => {
        let hexed = val
          .replace(/ /g, "|20|")
          .replace(/;/g, "|3B|")
          .replace(/:/g, "|3A|")
          .replace(/"/g, "|22|");
        // Clean up adjacent pipes e.g. |20||3B| -> |20 3B|
        hexed = hexed.replace(/\|([0-9a-fA-F]{2})\|\|([0-9a-fA-F]{2})\|/g, "|$1 $2|");
        return `${kw}:"${hexed}";`;
      });
      if (replaced !== rule) {
        this.customSigForm.rule = replaced;
        this.notify("Converted special characters to Snort hex escapes (|20|, |3B|, etc.).", "success");
        this.validateCurrentSnortRule();
      } else {
        this.notify("No unescaped characters (spaces, colons, etc.) found inside content strings.", "info");
      }
    },

    async runSnortTest() {
      const rule = (this.customSigForm.rule || "").trim();
      if (!rule) {
        this.notify("Please enter a Snort rule before testing.", "error");
        return;
      }
      this.snortTestLoading = true;
      this.snortTestResult = null;

      // Parse headers from string format: "Header: value\nHeader2: value2"
      const headersMap = {};
      const lines = (this.snortTestForm.headers || "").split("\n");
      for (const line of lines) {
        const idx = line.indexOf(":");
        if (idx > 0) {
          const k = line.slice(0, idx).trim();
          const v = line.slice(idx + 1).trim();
          headersMap[k] = v;
        }
      }

      const context = {
        method: this.snortTestForm.method || "GET",
        uri: this.snortTestForm.uri || "/",
        headers: headersMap,
        body: this.snortTestForm.body || "",
      };

      try {
        const res = await fetch("/api/custom-signatures/test-snort-rule", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rule: rule, context: context }),
        });
        if (res.ok) {
          this.snortTestResult = await res.json();
          if (this.snortTestResult.matched) {
            this.notify("Snort rule MATCHED simulated payload!", "success");
          } else {
            this.notify("Snort rule did NOT match simulated payload.", "info");
          }
        } else {
          const err = await res.json();
          this.notify(`Testing failed: ${err.detail || "Server error"}`, "error");
        }
      } catch (err) {
        this.notify(`Test failed: ${err.message}`, "error");
      } finally {
        this.snortTestLoading = false;
      }
    },

    resetSnortTest() {
      this.snortTestResult = null;
      this.snortTestForm = {
        method: "GET",
        uri: "/store/basket?fruit=apple",
        headers: "User-Agent: Mozilla/5.0\nAccept: application/json",
        body: '{"search": "apple juice"}',
      };
    },


    // -------------------------------------------------------------
    // Signature Set Inspector Modal Methods
    // -------------------------------------------------------------
    inspectSignatureSet(set) {
      if (!set) return;
      this.inspectedSigSet = typeof set === "string" ? { name: set } : set;
      this.sigInspectorSearch = "";
      this.sigInspectorAccuracyFilter = "all";
      this.sigInspectorRiskFilter = "all";
      this.showSigSetInspectorModal = true;
    },

    closeSignatureSetInspector() {
      this.showSigSetInspectorModal = false;
      this.inspectedSigSet = null;
    },

    getSignaturesInInspectedSet() {
      if (!this.inspectedSigSet) return [];
      const setName = (this.inspectedSigSet.name || "").trim();
      const filterCriteria = this.inspectedSigSet.signatureSet?.filter || null;
      return this.getSignaturesInSet(setName, filterCriteria);
    },

    getSignaturesInSet(setName, filterCriteria) {
      const allSigs = this.catalog.attackSignatures || window.WAF_CATALOG?.attackSignatures || [];
      const nameClean = (setName || "").trim();
      const nameLower = nameClean.toLowerCase();

      // 1. Custom filter criteria
      if (filterCriteria && typeof filterCriteria === "object") {
        const tagVal = (filterCriteria.tagValue || "").trim().toLowerCase();
        let atkTypeVal = "";
        if (filterCriteria.attackType) {
          atkTypeVal = typeof filterCriteria.attackType === "object"
            ? (filterCriteria.attackType.name || "").trim().toLowerCase()
            : (filterCriteria.attackType + "").trim().toLowerCase();
        }

        const filtered = allSigs.filter((sig) => {
          let match = true;
          if (tagVal) {
            const cve = (sig.cve || "").toLowerCase();
            const name = (sig.name || "").toLowerCase();
            const desc = (sig.description || "").toLowerCase();
            if (!cve.includes(tagVal) && !name.includes(tagVal) && !desc.includes(tagVal)) {
              match = false;
            }
          }
          if (match && atkTypeVal) {
            const sType = (sig.attackType || "").toLowerCase();
            if (!sType.includes(atkTypeVal)) match = false;
          }
          return match;
        });
        if (filtered.length > 0) return filtered;
      }

      // 2. Accuracy based standard sets
      if (nameLower === "high accuracy signatures") {
        return allSigs.filter((s) => s.accuracy === "High");
      }
      if (nameLower === "medium accuracy signatures") {
        return allSigs.filter((s) => s.accuracy === "High" || s.accuracy === "Medium");
      }
      if (nameLower === "low accuracy signatures") {
        return allSigs.filter((s) => s.accuracy === "Low");
      }

      // 3. Exact signatureSets membership
      const matched = allSigs.filter((s) => {
        const sets = (s.signatureSets || []).map((x) => x.toLowerCase());
        return sets.includes(nameLower);
      });
      if (matched.length > 0) return matched;

      // 4. Relaxed stem matching
      const stem = nameLower.replace("signatures", "").trim();
      if (stem) {
        return allSigs.filter((s) => {
          const at = (s.attackType || "").toLowerCase();
          const nm = (s.name || "").toLowerCase();
          return at.includes(stem) || nm.includes(stem);
        });
      }

      return [];
    },

    get filteredInspectedSignatures() {
      const sigs = this.getSignaturesInInspectedSet();
      const q = (this.sigInspectorSearch || "").trim().toLowerCase();
      const acc = (this.sigInspectorAccuracyFilter || "all").toLowerCase();
      const risk = (this.sigInspectorRiskFilter || "all").toLowerCase();

      return sigs.filter((sig) => {
        if (acc !== "all" && (sig.accuracy || "").toLowerCase() !== acc) return false;
        if (risk !== "all" && (sig.risk || "").toLowerCase() !== risk) return false;
        if (!q) return true;

        const id = (sig.signatureId + "").toLowerCase();
        const name = (sig.name || "").toLowerCase();
        const desc = (sig.description || "").toLowerCase();
        const cve = (sig.cve || "").toLowerCase();
        const atk = (sig.attackType || "").toLowerCase();
        const sys = (sig.systems || []).join(" ").toLowerCase();

        return id.includes(q) || name.includes(q) || desc.includes(q) || cve.includes(q) || atk.includes(q) || sys.includes(q);
      });
    },

    isSignatureExceptionConfigured(sigId) {
      const list = this.getSignatures();
      return list.some((s) => s.signatureId === sigId);
    },

    getSignatureException(sigId) {
      const list = this.getSignatures();
      return list.find((s) => s.signatureId === sigId) || null;
    },

    addExceptionForSignature(sig) {
      if (!this.currentPolicy || !sig) return;
      const sigId = sig.signatureId;
      if (this.isSignatureExceptionConfigured(sigId)) {
        this.notify(`Exception for Signature ${sigId} already exists.`, "info");
        return;
      }

      this.markDirty();
      this.ensurePolicySection("signatures", []);
      if (!Array.isArray(this.currentPolicy.policy.signatures)) {
        this.currentPolicy.policy.signatures = [];
      }
      this.currentPolicy.policy.signatures.push({
        signatureId: sigId,
        enabled: false,
        tag: `Suppressed: ${sig.name}`,
      });
      this.notify(`Added exception override suppressing Signature ${sigId}`, "success");
    },

    // -------------------------------------------------------------
    // OpenAPI / REST Protection Methods
    // -------------------------------------------------------------
    initOpenApiFormState() {
      // Clean up any legacy or unsupported basicAuth from the policy JSON
      if (Array.isArray(this.currentPolicy?.policy?.["open-api-files"])) {
        this.currentPolicy.policy["open-api-files"].forEach((f) => {
          if (f && typeof f === "object" && "basicAuth" in f) {
            delete f.basicAuth;
          }
        });
      }
      if (this.currentPolicy?.policy?.openApiFileReference && typeof this.currentPolicy.policy.openApiFileReference === "object") {
        delete this.currentPolicy.policy.openApiFileReference.basicAuth;
      }

      const cfg = this.getOpenApiConfig();
      this.openApiTestResult = null;
      this.openApiSampleSelect = "";
      if (cfg.link) {
        this.openApiLinkType = cfg.link.startsWith("file://") ? "file" : "url";
        this.openApiSyntaxMode = cfg.mode === "direct" ? "direct" : "array";
      } else {
        this.openApiLinkType = "url";
        this.openApiSyntaxMode = "array";
      }
      this.openApiAuthType = "none";
      this.openApiAuthUser = "";
      this.openApiPlainPassword = "";
      this.openApiBearerToken = "";
      this.openApiClientCert = "";
      this.openApiClientKey = "";
      this.openApiShowBasicAuth = false;
    },

    getOpenApiConfig() {
      if (!this.currentPolicy?.policy) {
        return { link: "", mode: "none" };
      }
      const files = this.currentPolicy.policy["open-api-files"];
      if (Array.isArray(files) && files.length > 0 && files[0]?.link) {
        return {
          link: files[0].link,
          mode: "array",
          index: 0,
        };
      }
      const ref = this.currentPolicy.policy.openApiFileReference;
      if (ref && typeof ref === "object" && ref.link) {
        return {
          link: ref.link,
          mode: "direct",
        };
      }
      return { link: "", mode: "none" };
    },

    hasOpenApiReference() {
      const cfg = this.getOpenApiConfig();
      return !!(cfg.link && cfg.link.trim());
    },

    getOpenApiLink() {
      return this.getOpenApiConfig().link || "";
    },

    setOpenApiLink(newLink) {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      const trimmed = (newLink || "").trim();
      if (!trimmed) {
        this.removeOpenApiReference();
        return;
      }

      if (this.openApiSyntaxMode === "direct") {
        delete this.currentPolicy.policy["open-api-files"];
        if (!this.currentPolicy.policy.openApiFileReference) {
          this.currentPolicy.policy.openApiFileReference = {};
        }
        this.currentPolicy.policy.openApiFileReference.link = trimmed;
      } else {
        delete this.currentPolicy.policy.openApiFileReference;
        if (!Array.isArray(this.currentPolicy.policy["open-api-files"])) {
          this.currentPolicy.policy["open-api-files"] = [];
        }
        if (this.currentPolicy.policy["open-api-files"].length === 0) {
          this.currentPolicy.policy["open-api-files"].push({ link: trimmed });
        } else {
          this.currentPolicy.policy["open-api-files"][0] = { link: trimmed };
        }
      }
    },

    setOpenApiSyntaxMode(mode) {
      if (!this.currentPolicy?.policy) return;
      this.openApiSyntaxMode = mode;
      const cfg = this.getOpenApiConfig();
      if (!cfg.link) return;
      this.markDirty();
      const link = cfg.link;
      if (mode === "direct") {
        delete this.currentPolicy.policy["open-api-files"];
        this.currentPolicy.policy.openApiFileReference = { link };
      } else {
        delete this.currentPolicy.policy.openApiFileReference;
        this.currentPolicy.policy["open-api-files"] = [{ link }];
      }
    },

    removeOpenApiReference() {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      delete this.currentPolicy.policy["open-api-files"];
      delete this.currentPolicy.policy.openApiFileReference;
      this.openApiTestResult = null;
      this.openApiSampleSelect = "";
      this.notify("Removed OpenAPI reference from policy", "info");
    },

    updateOpenApiAuthUser(username) {
      this.openApiAuthUser = username;
    },

    updateOpenApiPlainPassword(plainPwd) {
      this.openApiPlainPassword = plainPwd;
    },

    applyOpenApiSample(sampleUrl) {
      if (!sampleUrl) return;
      this.setOpenApiLink(sampleUrl);
      if (sampleUrl.startsWith("file://")) {
        this.openApiLinkType = "file";
      } else {
        this.openApiLinkType = "url";
      }
      this.notify(`Configured OpenAPI spec: ${sampleUrl}`, "info");
      this.testOpenApiReference();
    },

    async testOpenApiReference() {
      const cfg = this.getOpenApiConfig();
      const link = (cfg.link || "").trim();
      if (!link) {
        this.notify("Please enter an OpenAPI URL or file path to test", "warning");
        return;
      }

      this.openApiTestLoading = true;
      this.openApiTestResult = null;

      try {
        const payload = {
          link,
          allowSelfSigned: !!this.openApiAllowSelfSigned,
          authType: this.openApiAuthType || "none",
        };

        if (this.openApiAuthType === "bearer" && this.openApiBearerToken) {
          payload.bearerToken = this.openApiBearerToken.trim();
        } else if (this.openApiAuthType === "basic" || this.openApiAuthUser || this.openApiPlainPassword) {
          const user = (this.openApiAuthUser || "").trim();
          const pwd = this.openApiPlainPassword || "";
          let pwd_b64 = "";
          if (pwd) {
            try {
              pwd_b64 = btoa(unescape(encodeURIComponent(pwd)));
            } catch (e) {
              pwd_b64 = "";
            }
          }
          payload.basicAuth = {
            user: user,
            password: pwd,
            passwordBase64: pwd_b64,
          };
        } else if (this.openApiAuthType === "mtls") {
          payload.clientCert = this.openApiClientCert || "";
          payload.clientKey = this.openApiClientKey || "";
        }

        const res = await fetch("/api/policies/test-openapi-link", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        this.openApiTestResult = data;
        if (data.success && data.validSpec) {
          this.notify(`Spec verified! Found ${data.pathsCount} API paths and ${data.schemasCount} schemas.`, "success");
        } else if (data.success) {
          this.notify(`Document retrieved, but does not appear to have 'openapi' or 'swagger' definition.`, "warning");
        } else {
          this.notify(`OpenAPI inspection error: ${data.error}`, "error");
        }
      } catch (err) {
        this.openApiTestResult = {
          success: false,
          error: `Network error reaching backend: ${err.message}`,
        };
        this.notify(`Failed to test OpenAPI spec: ${err.message}`, "error");
      } finally {
        this.openApiTestLoading = false;
      }
    },

    applyOpenApiRecommendedViolations() {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      this.ensurePolicySection("blocking-settings", {});
      if (!this.currentPolicy.policy["blocking-settings"].violations) {
        this.currentPolicy.policy["blocking-settings"].violations = [];
      }
      const viols = this.currentPolicy.policy["blocking-settings"].violations;

      const recList = this.catalog.openApiRecommendedViolations || [
        { name: "VIOL_URL", alarm: true, block: true },
        { name: "VIOL_METHOD", alarm: true, block: true },
        { name: "VIOL_PARAMETER", alarm: true, block: true },
        { name: "VIOL_PARAMETER_LOCATION", alarm: true, block: true },
        { name: "VIOL_MANDATORY_PARAMETER", alarm: true, block: true },
        { name: "VIOL_MANDATORY_REQUEST_BODY", alarm: true, block: true },
        { name: "VIOL_JSON_SCHEMA", alarm: true, block: true },
        { name: "VIOL_PARAMETER_DATA_TYPE", alarm: true, block: true },
        { name: "VIOL_PARAMETER_NUMERIC_VALUE", alarm: true, block: true },
        { name: "VIOL_PARAMETER_VALUE_LENGTH", alarm: true, block: true },
        { name: "VIOL_PARAMETER_STATIC_VALUE", alarm: true, block: true },
        { name: "VIOL_PARAMETER_VALUE_REGEXP", alarm: true, block: true },
        { name: "VIOL_PARAMETER_EMPTY_VALUE", alarm: true, block: true },
        { name: "VIOL_PARAMETER_REPEATED", alarm: true, block: true },
        { name: "VIOL_PARAMETER_ARRAY_VALUE", alarm: true, block: true },
        { name: "VIOL_PARAMETER_VALUE_BASE64", alarm: true, block: true },
        { name: "VIOL_URL_CONTENT_TYPE", alarm: true, block: true },
        { name: "VIOL_FILE_UPLOAD", alarm: true, block: true },
        { name: "VIOL_FILE_UPLOAD_IN_BODY", alarm: true, block: true },
      ];

      recList.forEach((rec) => {
        const existing = viols.find((v) => v.name === rec.name);
        if (existing) {
          existing.alarm = true;
          existing.block = true;
        } else {
          viols.push({
            name: rec.name,
            alarm: true,
            block: true,
          });
        }
      });

      this.notify(`Applied recommended OpenAPI violations (${recList.length} enabled & enforced)`, "success");
    },

    // -------------------------------------------------------------
    // gRPC Protection Methods (policy["grpc-profiles"])
    // -------------------------------------------------------------
    initGrpcFormState() {
      this.grpcActiveProfileIndex = 0;
      this.grpcTestResult = null;
      this.grpcSampleSelect = "";
    },

    getGrpcProfiles() {
      if (!this.currentPolicy?.policy) return [];
      const profiles = this.currentPolicy.policy["grpc-profiles"];
      return Array.isArray(profiles) ? profiles : [];
    },

    hasGrpcProfiles() {
      return this.getGrpcProfiles().length > 0;
    },

    getActiveGrpcProfile() {
      const list = this.getGrpcProfiles();
      if (list.length === 0) return null;
      if (this.grpcActiveProfileIndex < 0 || this.grpcActiveProfileIndex >= list.length) {
        this.grpcActiveProfileIndex = 0;
      }
      return list[this.grpcActiveProfileIndex];
    },

    addGrpcProfile(name = "grpc_service_profile") {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      this.ensurePolicySection("grpc-profiles", []);
      if (!Array.isArray(this.currentPolicy.policy["grpc-profiles"])) {
        this.currentPolicy.policy["grpc-profiles"] = [];
      }
      const list = this.currentPolicy.policy["grpc-profiles"];
      const newProf = {
        name: name || `grpc_profile_${list.length + 1}`,
        description: "gRPC protection profile with protobuf validation",
        associateUrls: true,
        attackSignaturesCheck: true,
        metacharCheck: true,
        decodeStringValuesAsBase64: "disabled",
        defenseAttributes: {
          maximumDataLength: 100000,
          allowUnknownFields: false,
        },
        idlFiles: [
          {
            idlFile: {
              "$ref": "file:///etc/app_protect/conf/grpc/example_grpc_service.proto"
            },
            isPrimary: true
          }
        ]
      };
      list.push(newProf);
      this.grpcActiveProfileIndex = list.length - 1;
      this.notify(`Added gRPC profile '${newProf.name}'`, "success");
    },

    removeGrpcProfile(index) {
      if (!this.currentPolicy?.policy) return;
      const list = this.getGrpcProfiles();
      if (index >= 0 && index < list.length) {
        const removed = list.splice(index, 1)[0];
        this.markDirty();
        if (this.grpcActiveProfileIndex >= list.length) {
          this.grpcActiveProfileIndex = Math.max(0, list.length - 1);
        }
        this.notify(`Removed gRPC profile '${removed.name}'`, "info");
      }
    },

    addIdlFileToProfile(profileIndex) {
      if (!this.currentPolicy?.policy) return;
      const list = this.getGrpcProfiles();
      const prof = list[profileIndex];
      if (!prof) return;
      this.markDirty();
      if (!Array.isArray(prof.idlFiles)) {
        prof.idlFiles = [];
      }
      const isFirst = prof.idlFiles.length === 0;
      prof.idlFiles.push({
        idlFile: {
          "$ref": "file:///etc/app_protect/conf/grpc/example_grpc_service.proto"
        },
        isPrimary: isFirst
      });
      this.notify("Added IDL file reference", "success");
    },

    removeIdlFileFromProfile(profileIndex, fileIndex) {
      if (!this.currentPolicy?.policy) return;
      const list = this.getGrpcProfiles();
      const prof = list[profileIndex];
      if (!prof || !Array.isArray(prof.idlFiles)) return;
      if (fileIndex >= 0 && fileIndex < prof.idlFiles.length) {
        prof.idlFiles.splice(fileIndex, 1);
        this.markDirty();
        this.notify("Removed IDL file reference", "info");
      }
    },

    applyGrpcSample(sample) {
      if (!sample || !this.currentPolicy?.policy) return;
      this.markDirty();
      this.ensurePolicySection("grpc-profiles", []);
      if (!Array.isArray(this.currentPolicy.policy["grpc-profiles"])) {
        this.currentPolicy.policy["grpc-profiles"] = [];
      }
      const list = this.currentPolicy.policy["grpc-profiles"];
      if (list.length === 0) {
        this.addGrpcProfile("example_grpc_service_profile");
      }
      const prof = this.getActiveGrpcProfile();
      if (!prof) return;

      prof.idlFiles = [];
      if (sample.fileType === "archive") {
        prof.idlFiles.push({
          idlFile: {
            "$ref": sample.link
          },
          primaryIdlFileName: sample.primaryIdlFileName || "example_grpc_service.proto"
        });
      } else {
        prof.idlFiles.push({
          idlFile: {
            "$ref": sample.link
          },
          isPrimary: true
        });
      }
      this.notify(`Applied gRPC sample: ${sample.name}`, "info");
      this.testGrpcIdl(sample.link, sample.primaryIdlFileName);
    },

    async testGrpcIdl(link, primaryIdlFileName) {
      const targetLink = (link || "").trim();
      if (!targetLink) {
        this.notify("Please enter an IDL URL or file path (.proto, .tar, .tgz)", "warning");
        return;
      }

      this.grpcTestLoading = true;
      this.grpcTestResult = null;

      try {
        const payload = {
          link: targetLink,
          primaryIdlFileName: (primaryIdlFileName || "").trim() || undefined
        };

        const res = await fetch("/api/policies/test-grpc-idl", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        this.grpcTestResult = data;
        if (data.success) {
          const detail = data.isArchive
            ? `Archive bundle verified! Contains ${data.protoFiles?.length || 0} proto files. Primary: ${data.primaryIdlFileName || 'none'}`
            : `Protobuf verified! Found ${data.servicesCount} service(s) and ${data.messagesCount} message(s).`;
          this.notify(detail, "success");
        } else {
          this.notify(`gRPC IDL verification error: ${data.error}`, "error");
        }
      } catch (err) {
        this.grpcTestResult = {
          success: false,
          error: `Network error reaching backend: ${err.message}`,
        };
        this.notify(`Failed to inspect gRPC IDL: ${err.message}`, "error");
      } finally {
        this.grpcTestLoading = false;
      }
    },

    async uploadAndInspectGrpcIdl(event, profileIndex = null) {
      const file = event.target.files && event.target.files[0];
      if (!file) return;

      this.grpcUploadLoading = true;
      this.grpcUploadedFileName = file.name;
      this.grpcTestResult = null;

      try {
        const formData = new FormData();
        formData.append("file", file);

        const targetIndex = (profileIndex !== null) ? profileIndex : this.grpcActiveProfileIndex;
        const list = this.getGrpcProfiles();
        const prof = list[targetIndex];
        const primaryName = prof?.idlFiles?.[0]?.primaryIdlFileName;
        if (primaryName) {
          formData.append("primaryIdlFileName", primaryName);
        }

        const res = await fetch("/api/policies/inspect-grpc-upload", {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        this.grpcTestResult = data;
        if (data.success) {
          const detail = data.isArchive
            ? `Uploaded bundle '${file.name}' verified! Contains ${data.protoFiles?.length || 0} proto files.`
            : `Uploaded proto '${file.name}' verified! Found ${data.servicesCount} service(s) and ${data.messagesCount} message(s).`;
          this.notify(detail, "success");
        } else {
          this.notify(`Uploaded IDL inspection error: ${data.error}`, "error");
        }
      } catch (err) {
        this.grpcTestResult = {
          success: false,
          error: `Upload inspection failed: ${err.message}`,
        };
        this.notify(`Failed to inspect uploaded file: ${err.message}`, "error");
      } finally {
        this.grpcUploadLoading = false;
        event.target.value = "";
      }
    },

    applyUploadedGrpcToProfile(profileIndex = null, defaultDir = "/etc/nginx/protos") {
      if (!this.grpcUploadedFileName) return;
      const targetIndex = (profileIndex !== null) ? profileIndex : this.grpcActiveProfileIndex;
      const list = this.getGrpcProfiles();
      const prof = list[targetIndex];
      if (!prof) return;

      this.markDirty();
      if (!Array.isArray(prof.idlFiles) || prof.idlFiles.length === 0) {
        prof.idlFiles = [{
          idlFile: { "$ref": "" },
          isPrimary: true
        }];
      }

      const cleanDir = defaultDir.replace(/\/+$/, "");
      const newRef = `file://${cleanDir}/${this.grpcUploadedFileName}`;
      prof.idlFiles[0].idlFile["$ref"] = newRef;

      const lower = this.grpcUploadedFileName.toLowerCase();
      const isArch = lower.endsWith(".tar") || lower.endsWith(".tgz") || lower.endsWith(".tar.gz");
      if (isArch && !prof.idlFiles[0].primaryIdlFileName) {
        if (this.grpcTestResult?.primaryIdlFileName) {
          prof.idlFiles[0].primaryIdlFileName = this.grpcTestResult.primaryIdlFileName;
        } else if (this.grpcTestResult?.protoFiles?.length) {
          prof.idlFiles[0].primaryIdlFileName = this.grpcTestResult.protoFiles[0];
        }
      }

      this.notify(`Set policy IDL reference to ${newRef}`, "success");
    },

    applyGrpcRecommendedViolations() {
      if (!this.currentPolicy?.policy) return;
      this.markDirty();
      this.ensurePolicySection("blocking-settings", {});
      if (!this.currentPolicy.policy["blocking-settings"].violations) {
        this.currentPolicy.policy["blocking-settings"].violations = [];
      }
      const viols = this.currentPolicy.policy["blocking-settings"].violations;

      const recList = this.catalog.grpcRecommendedViolations || [
        { name: "VIOL_GRPC_MALFORMED", alarm: true, block: true },
        { name: "VIOL_GRPC_FORMAT", alarm: true, block: true },
        { name: "VIOL_GRPC_METHOD", alarm: true, block: true },
        { name: "VIOL_METHOD", alarm: true, block: true },
        { name: "VIOL_ATTACK_SIGNATURE", alarm: true, block: true },
      ];

      recList.forEach((rec) => {
        const existing = viols.find((v) => v.name === rec.name);
        if (existing) {
          existing.alarm = true;
          existing.block = true;
        } else {
          viols.push({
            name: rec.name,
            alarm: true,
            block: true,
          });
        }
      });

      this.notify(`Applied recommended gRPC violations (${recList.length} enabled & enforced)`, "success");
    },

    hasMethod(methodName) {
      if (!this.currentPolicy?.policy?.methods) return false;
      const methods = this.currentPolicy.policy.methods;
      if (!Array.isArray(methods)) return false;
      const target = (methodName || "").trim().toUpperCase();
      return methods.some((m) => {
        if (!m) return false;
        if (typeof m === "string") return m.trim().toUpperCase() === target;
        return m.name && m.name.trim().toUpperCase() === target;
      });
    },

    toggleMethod(methodName) {
      if (!this.currentPolicy) return;
      this.markDirty();
      this.ensurePolicySection("methods", []);
      if (!Array.isArray(this.currentPolicy.policy.methods)) {
        this.currentPolicy.policy.methods = [];
      }
      const list = this.currentPolicy.policy.methods;
      const target = (methodName || "").trim().toUpperCase();
      const idx = list.findIndex((m) => {
        if (!m) return false;
        if (typeof m === "string") return m.trim().toUpperCase() === target;
        return m.name && m.name.trim().toUpperCase() === target;
      });
      if (idx >= 0) {
        list.splice(idx, 1);
      } else {
        list.push({ name: methodName });
      }
    },

    addCustomMethod() {
      const m = this.tempMethod.trim().toUpperCase();
      if (!m) return;
      this.toggleMethod(m);
      this.tempMethod = "";
    },

    addUrl() {
      let path = this.tempUrl.path.trim();
      if (!path) return;
      if (!path.startsWith("/")) path = "/" + path;
      this.markDirty();
      this.ensurePolicySection("urls", []);

      // Prevent duplicate URLs with same name and type
      const exists = this.currentPolicy.policy.urls.some(
        (u) => (u.name || "").toLowerCase() === path.toLowerCase() && (u.type || "explicit") === this.tempUrl.type
      );
      if (exists) {
        this.notify(`URL '${path}' already exists in the policy`, "warning");
        return;
      }

      this.currentPolicy.policy.urls.push({
        name: path,
        type: this.tempUrl.type || "explicit",
      });
      this.invalidateUrlCache();
      this.notify(`Added URL '${path}'`, "success");
      this.tempUrl = { path: "", type: "explicit" };
    },

    confirmDeleteUrl(target) {
      const urls = this.currentPolicy?.policy?.urls;
      if (!Array.isArray(urls)) return;
      let urlObj = null;
      let idx = -1;
      if (typeof target === "number") {
        idx = target;
        urlObj = urls[idx];
      } else {
        idx = urls.indexOf(target);
        urlObj = target;
      }
      if (idx !== -1 && urlObj) {
        this.urlToDelete = urlObj;
        this.urlToDeleteIndex = idx;
        this.showDeleteUrlModal = true;
      }
    },

    executeDeleteUrl() {
      if (this.urlToDeleteIndex === null || !this.currentPolicy?.policy) {
        this.showDeleteUrlModal = false;
        return;
      }
      const urls = this.currentPolicy.policy.urls;
      if (Array.isArray(urls) && this.urlToDeleteIndex >= 0 && this.urlToDeleteIndex < urls.length) {
        const removed = urls.splice(this.urlToDeleteIndex, 1)[0];
        this.invalidateUrlCache();
        this.markDirty();
        this.notify(`Removed URL '${removed.name || "URL"}'.`, "info");
      }
      this.showDeleteUrlModal = false;
      this.urlToDelete = null;
      this.urlToDeleteIndex = null;
    },

    removeUrl(target) {
      this.confirmDeleteUrl(target);
    },

    toggleSelectAllUrls() {
      const list = this.filteredUrls || [];
      if (this.selectedUrls.length === list.length && list.length > 0) {
        this.selectedUrls = [];
      } else {
        this.selectedUrls = list.map((u) => u.name);
      }
    },

    confirmMassDeleteUrls() {
      if (!this.selectedUrls || this.selectedUrls.length === 0) {
        this.notify("No URLs selected.", "warning");
        return;
      }
      this.showMassDeleteUrlModal = true;
    },

    executeMassDeleteUrls() {
      if (!this.currentPolicy?.policy || !this.selectedUrls.length) {
        this.showMassDeleteUrlModal = false;
        return;
      }
      const urls = this.currentPolicy.policy.urls;
      if (!Array.isArray(urls)) return;
      const toRemove = new Set(this.selectedUrls);
      const count = toRemove.size;
      this.currentPolicy.policy.urls = urls.filter((u) => !toRemove.has(u.name));
      this.invalidateUrlCache();
      this.markDirty();
      this.selectedUrls = [];
      this.showMassDeleteUrlModal = false;
      this.notify(`Successfully removed ${count} URL(s).`, "info");
    },

    copyUrlPath(path) {
      if (!path) return;
      if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(path);
        this.notify(`Copied URL '${path}' to clipboard`, "info");
      }
    },

    // -------------------------------------------------------------
    // URL Endpoint Parameters & Overrides Modal Handlers
    // -------------------------------------------------------------
    openEditUrlModal(u) {
      if (!u || !this.currentPolicy?.policy?.urls) return;
      const urls = this.currentPolicy.policy.urls;
      const idx = typeof u === "number" ? u : urls.indexOf(u);
      if (idx === -1) return;
      const item = urls[idx];
      this.editingUrlIndex = idx;
      this.urlEditForm = {
        name: item.name || "",
        type: item.type || "explicit",
        method: item.method || "*",
        protocol: item.protocol || "http",
        wildcardOrder: item.wildcardOrder !== undefined ? item.wildcardOrder : 1,
        isAllowed: item.isAllowed !== undefined ? !!item.isAllowed : true,
        metacharsOnUrlCheck: !!item.metacharsOnUrlCheck,
        metacharOverrides: Array.isArray(item.metacharOverrides)
          ? JSON.parse(JSON.stringify(item.metacharOverrides))
          : [],
        attackSignaturesCheck: item.attackSignaturesCheck !== undefined ? !!item.attackSignaturesCheck : false,
        signatureOverrides: Array.isArray(item.signatureOverrides)
          ? JSON.parse(JSON.stringify(item.signatureOverrides))
          : [],
        disallowFileUploadOfExecutables: !!item.disallowFileUploadOfExecutables,
        mandatoryBody: !!item.mandatoryBody,
        clickjackingProtection: !!item.clickjackingProtection,
        allowRenderingInFrames: item.allowRenderingInFrames || "only-same",
        urlContentProfiles: Array.isArray(item.urlContentProfiles)
          ? JSON.parse(JSON.stringify(item.urlContentProfiles))
          : [],
      };
      this.tempUrlMetachar = { metachar: "0x3c", isAllowed: true };
      this.tempUrlSig = { signatureId: "", enabled: false };
      this.tempUrlContentProfile = {
        type: "json",
        headerName: "Content-Type",
        headerValue: "*json*",
        headerOrder: "default",
        profileName: "Default",
        isEditing: false,
        editIndex: null,
      };
      this.refreshUrlConfiguredParams();
      this.showEditUrlModal = true;
    },

    saveEditUrl() {
      if (this.editingUrlIndex === null || !this.currentPolicy?.policy?.urls) return;
      const urls = this.currentPolicy.policy.urls;
      if (this.editingUrlIndex < 0 || this.editingUrlIndex >= urls.length) return;

      const oldItem = urls[this.editingUrlIndex];
      const oldName = oldItem ? oldItem.name : "";
      const oldMethod = oldItem ? (oldItem.method || "*") : "*";
      const oldProto = oldItem ? (oldItem.protocol || "http") : "http";

      const path = (this.urlEditForm.name || "").trim();
      if (!path) {
        this.notify("URL path cannot be empty", "error");
        return;
      }

      this.markDirty();
      const updated = {
        name: path.startsWith("/") ? path : "/" + path,
        type: this.urlEditForm.type || "explicit",
        method: this.urlEditForm.method || "*",
        protocol: this.urlEditForm.protocol || "http",
        isAllowed: !!this.urlEditForm.isAllowed,
      };

      if (updated.type === "wildcard" && this.urlEditForm.wildcardOrder) {
        updated.wildcardOrder = parseInt(this.urlEditForm.wildcardOrder, 10) || 1;
      }
      if (this.urlEditForm.metacharsOnUrlCheck) {
        updated.metacharsOnUrlCheck = true;
      }
      if (this.urlEditForm.metacharOverrides && this.urlEditForm.metacharOverrides.length > 0) {
        updated.metacharOverrides = this.urlEditForm.metacharOverrides.map((o) => ({
          metachar: o.metachar,
          isAllowed: !!o.isAllowed,
        }));
      }
      if (this.urlEditForm.attackSignaturesCheck) {
        updated.attackSignaturesCheck = true;
      }
      if (this.urlEditForm.signatureOverrides && this.urlEditForm.signatureOverrides.length > 0) {
        updated.signatureOverrides = this.urlEditForm.signatureOverrides.map((s) => ({
          signatureId: parseInt(s.signatureId, 10),
          enabled: !!s.enabled,
        }));
      }
      if (this.urlEditForm.disallowFileUploadOfExecutables) {
        updated.disallowFileUploadOfExecutables = true;
      }
      if (this.urlEditForm.mandatoryBody) {
        updated.mandatoryBody = true;
      }
      if (this.urlEditForm.clickjackingProtection) {
        updated.clickjackingProtection = true;
        updated.allowRenderingInFrames = this.urlEditForm.allowRenderingInFrames || "only-same";
      }
      if (this.urlEditForm.urlContentProfiles && this.urlEditForm.urlContentProfiles.length > 0) {
        updated.urlContentProfiles = this.urlEditForm.urlContentProfiles.map((cp) => {
          const entry = {
            type: (cp.type || "json").trim().toLowerCase(),
            headerName: (cp.headerName || "Content-Type").trim(),
            headerValue: (cp.headerValue || "*").trim(),
            headerOrder: (cp.headerOrder !== undefined && cp.headerOrder !== null ? cp.headerOrder : "default").toString().trim(),
          };
          const profName = (cp.profileName || cp.contentProfile?.name || "").trim();
          if (entry.type !== "form-data" && entry.type !== "do-nothing" && profName) {
            entry.contentProfile = { name: profName };
          } else if (cp.contentProfile && cp.contentProfile.name) {
            entry.contentProfile = { name: cp.contentProfile.name.trim() };
          }
          return entry;
        });
      }

      // If URL coordinate changed, update parameter references
      if (oldName && (oldName !== updated.name || oldMethod !== updated.method || oldProto !== updated.protocol)) {
        (this.currentPolicy.policy.parameters || []).forEach((p) => {
          if (p && p.level === "url" && p.url && p.url.name === oldName) {
            p.url.name = updated.name;
            p.url.method = updated.method;
            p.url.protocol = updated.protocol;
            p.url.type = updated.type;
          }
        });
        this.invalidateParamCache();
      }

      urls[this.editingUrlIndex] = updated;
      this.invalidateUrlCache();
      this.showEditUrlModal = false;
      this.editingUrlIndex = null;
      this.notify(`URL '${updated.name}' updated successfully`, "success");
    },

    refreshUrlConfiguredParams() {
      if (!this.currentPolicy?.policy) {
        this.urlConfiguredParams = [];
        return;
      }
      const uName = (this.urlEditForm.name || "").trim();
      const uMethod = (this.urlEditForm.method || "*").trim().toUpperCase();
      const uProto = (this.urlEditForm.protocol || "http").trim().toLowerCase();
      const params = this.currentPolicy.policy.parameters || [];

      this.urlConfiguredParams = params.filter((p) => {
        if (!p || typeof p !== "object" || p.level !== "url" || !p.url) return false;
        const pUrl = p.url;
        const pName = (pUrl.name || "").trim();
        if (pName !== uName) return false;
        const pMethod = (pUrl.method || "*").trim().toUpperCase();
        const pProto = (pUrl.protocol || "http").trim().toLowerCase();
        const methodMatch = pMethod === "*" || uMethod === "*" || pMethod === uMethod;
        const protoMatch = pProto === "any" || pProto === "all" || uProto === "any" || uProto === "all" || pProto === uProto;
        return methodMatch && protoMatch;
      });
    },

    removeParamFromUrl(param) {
      if (!param || !this.currentPolicy?.policy?.parameters) return;
      const params = this.currentPolicy.policy.parameters;
      const idx = params.indexOf(param);
      if (idx !== -1) {
        params.splice(idx, 1);
        this.invalidateParamCache();
        this.markDirty();
        this.refreshUrlConfiguredParams();
        this.notify(`Removed parameter '${param.name}' from this URL.`, "info");
      }
    },

    addParamToUrl() {
      if (!this.currentPolicy?.policy) return;
      if (!Array.isArray(this.currentPolicy.policy.parameters)) {
        this.currentPolicy.policy.parameters = [];
      }
      const params = this.currentPolicy.policy.parameters;
      const uName = (this.urlEditForm.name || "").trim();
      if (!uName) {
        this.notify("URL Path cannot be empty.", "warning");
        return;
      }
      const uMethod = this.urlEditForm.method || "*";
      const uProto = this.urlEditForm.protocol || "http";
      const uType = this.urlEditForm.type || "explicit";

      if (this.urlParamMode === "existing") {
        const paramName = (this.urlParamSelectedExisting || "").trim();
        if (!paramName) {
          this.notify("Please select an existing parameter to associate.", "warning");
          return;
        }
        const existing = params.find((p) => (p.name || "").trim() === paramName);
        const base = existing ? JSON.parse(JSON.stringify(existing)) : { name: paramName };
        delete base._rawIndex;
        delete base.rawIndices;
        delete base.urls;
        delete base.isGlobal;
        base.level = "url";
        base.url = {
          name: uName,
          method: uMethod,
          protocol: uProto,
          type: uType,
        };
        const exists = params.some(
          (p) =>
            p.level === "url" &&
            (p.name || "").trim() === paramName &&
            p.url &&
            p.url.name === uName &&
            (p.url.method || "*") === uMethod &&
            (p.url.protocol || "http") === uProto
        );
        if (exists) {
          this.notify(`Parameter '${paramName}' is already configured on this URL.`, "warning");
          return;
        }
        params.push(base);
        this.urlParamSelectedExisting = "";
        this.invalidateParamCache();
        this.markDirty();
        this.refreshUrlConfiguredParams();
        this.notify(`Associated parameter '${paramName}' to this URL.`, "info");
      } else {
        const pName = (this.urlParamNewForm.name || "").trim();
        if (!pName) {
          this.notify("Parameter name cannot be empty.", "warning");
          return;
        }
        const exists = params.some(
          (p) =>
            p.level === "url" &&
            (p.name || "").trim() === pName &&
            p.url &&
            p.url.name === uName &&
            (p.url.method || "*") === uMethod &&
            (p.url.protocol || "http") === uProto
        );
        if (exists) {
          this.notify(`Parameter '${pName}' is already configured on this URL.`, "warning");
          return;
        }
        const newParam = {
          name: pName,
          type: this.urlParamNewForm.type || "explicit",
          level: "url",
          parameterLocation: this.urlParamNewForm.parameterLocation || "any",
          dataType: this.urlParamNewForm.dataType || "alpha-numeric",
          valueType: this.urlParamNewForm.valueType || "user-input",
          sensitiveParameter: !!this.urlParamNewForm.sensitiveParameter,
          mandatory: !!this.urlParamNewForm.mandatory,
          allowEmptyValue: true,
          allowRepeatedParameterName: true,
          attackSignaturesCheck: true,
          enableRegularExpression: false,
          regularExpression: "",
          url: {
            name: uName,
            method: uMethod,
            protocol: uProto,
            type: uType,
          },
        };
        params.push(newParam);
        this.urlParamNewForm.name = "";
        this.invalidateParamCache();
        this.markDirty();
        this.refreshUrlConfiguredParams();
        this.notify(`Created parameter '${pName}' on this URL.`, "info");
      }
    },

    addUrlMetacharOverride() {
      const hex = (this.tempUrlMetachar.metachar || "").trim();
      if (!hex) return;
      if (!this.urlEditForm.metacharOverrides) this.urlEditForm.metacharOverrides = [];
      const exists = this.urlEditForm.metacharOverrides.find((m) => m.metachar.toLowerCase() === hex.toLowerCase());
      if (exists) {
        exists.isAllowed = !!this.tempUrlMetachar.isAllowed;
      } else {
        this.urlEditForm.metacharOverrides.push({
          metachar: hex,
          isAllowed: !!this.tempUrlMetachar.isAllowed,
        });
      }
      this.tempUrlMetachar = { metachar: "0x28", isAllowed: false };
    },

    removeUrlMetacharOverride(index) {
      if (this.urlEditForm.metacharOverrides) {
        this.urlEditForm.metacharOverrides.splice(index, 1);
      }
    },

    addUrlSigOverride() {
      const idRaw = this.tempUrlSig.signatureId || this.tempUrlSigOverride.signatureId;
      const id = parseInt(idRaw, 10);
      if (!id || isNaN(id)) {
        this.notify("Please enter a valid numeric Signature ID", "error");
        return;
      }
      const enabled = this.tempUrlSig.signatureId !== "" ? !!this.tempUrlSig.enabled : !!this.tempUrlSigOverride.enabled;
      if (!this.urlEditForm.signatureOverrides) this.urlEditForm.signatureOverrides = [];
      const exists = this.urlEditForm.signatureOverrides.find((s) => s.signatureId === id);
      if (exists) {
        exists.enabled = enabled;
      } else {
        this.urlEditForm.signatureOverrides.push({
          signatureId: id,
          enabled: enabled,
        });
      }
      this.tempUrlSig = { signatureId: "", enabled: false };
      this.tempUrlSigOverride = { signatureId: "", enabled: false };
    },

    removeUrlSigOverride(index) {
      if (this.urlEditForm.signatureOverrides) {
        this.urlEditForm.signatureOverrides.splice(index, 1);
      }
    },

    // -------------------------------------------------------------
    // URL Content Profiles (urlContentProfiles) Handlers
    // -------------------------------------------------------------
    applyUrlContentProfilePreset(presetKey) {
      const presets = {
        json: { type: "json", headerName: "Content-Type", headerValue: "*json*", headerOrder: "default", profileName: "Default" },
        xml: { type: "xml", headerName: "Content-Type", headerValue: "*xml*", headerOrder: "default", profileName: "Default" },
        graphql: { type: "graphql", headerName: "Content-Type", headerValue: "*graphql*", headerOrder: "default", profileName: "Default" },
        grpc: { type: "grpc", headerName: "Content-Type", headerValue: "*application/grpc*", headerOrder: "default", profileName: "Default" },
        form_data: { type: "form-data", headerName: "*", headerValue: "*", headerOrder: "default", profileName: "" },
        do_nothing: { type: "do-nothing", headerName: "Content-Type", headerValue: "*", headerOrder: "default", profileName: "" },
      };
      const p = presets[presetKey];
      if (p) {
        this.tempUrlContentProfile.type = p.type;
        this.tempUrlContentProfile.headerName = p.headerName;
        this.tempUrlContentProfile.headerValue = p.headerValue;
        this.tempUrlContentProfile.headerOrder = p.headerOrder;
        this.tempUrlContentProfile.profileName = p.profileName;
        this.notify(`Applied '${presetKey}' preset`, "info");
      }
    },

    addUrlContentProfile() {
      const type = (this.tempUrlContentProfile.type || "json").trim().toLowerCase();
      const headerName = (this.tempUrlContentProfile.headerName || "Content-Type").trim();
      const headerValue = (this.tempUrlContentProfile.headerValue || "*").trim();
      const headerOrder = (this.tempUrlContentProfile.headerOrder || "default").toString().trim();
      const profileName = (this.tempUrlContentProfile.profileName || "").trim();

      if (!type) {
        this.notify("Content profile type is required", "error");
        return;
      }

      const item = {
        type: type,
        headerName: headerName || "Content-Type",
        headerValue: headerValue || "*",
        headerOrder: headerOrder || "default",
      };

      if (type !== "form-data" && type !== "do-nothing" && profileName) {
        item.contentProfile = { name: profileName };
        item.profileName = profileName;
      }

      if (!Array.isArray(this.urlEditForm.urlContentProfiles)) {
        this.urlEditForm.urlContentProfiles = [];
      }

      if (this.tempUrlContentProfile.isEditing && this.tempUrlContentProfile.editIndex !== null) {
        this.urlEditForm.urlContentProfiles[this.tempUrlContentProfile.editIndex] = item;
        this.notify(`Updated content profile (${type})`, "success");
      } else {
        this.urlEditForm.urlContentProfiles.push(item);
        this.notify(`Added content profile (${type})`, "success");
      }

      this.cancelEditUrlContentProfile();
    },

    editUrlContentProfile(index) {
      if (!this.urlEditForm.urlContentProfiles || !this.urlEditForm.urlContentProfiles[index]) return;
      const cp = this.urlEditForm.urlContentProfiles[index];
      this.tempUrlContentProfile = {
        type: cp.type || "json",
        headerName: cp.headerName || "Content-Type",
        headerValue: cp.headerValue || "*",
        headerOrder: (cp.headerOrder !== undefined && cp.headerOrder !== null ? cp.headerOrder : "default").toString(),
        profileName: cp.profileName || cp.contentProfile?.name || (cp.type === "do-nothing" || cp.type === "form-data" ? "" : "Default"),
        isEditing: true,
        editIndex: index,
      };
    },

    cancelEditUrlContentProfile() {
      this.tempUrlContentProfile = {
        type: "json",
        headerName: "Content-Type",
        headerValue: "*json*",
        headerOrder: "default",
        profileName: "Default",
        isEditing: false,
        editIndex: null,
      };
    },

    removeUrlContentProfile(index) {
      if (this.urlEditForm.urlContentProfiles) {
        this.urlEditForm.urlContentProfiles.splice(index, 1);
        if (this.tempUrlContentProfile.isEditing && this.tempUrlContentProfile.editIndex === index) {
          this.cancelEditUrlContentProfile();
        }
        this.notify("Removed content profile", "info");
      }
    },

    getAvailableContentProfiles() {
      const list = ["Default"];
      if (this.currentPolicy?.policy?.['json-profiles']) {
        for (const p of this.currentPolicy.policy['json-profiles']) {
          if (p.name && !list.includes(p.name)) list.push(p.name);
        }
      }
      if (this.currentPolicy?.policy?.['xml-profiles']) {
        for (const p of this.currentPolicy.policy['xml-profiles']) {
          if (p.name && !list.includes(p.name)) list.push(p.name);
        }
      }
      if (this.currentPolicy?.policy?.['graphql-profiles']) {
        for (const p of this.currentPolicy.policy['graphql-profiles']) {
          if (p.name && !list.includes(p.name)) list.push(p.name);
        }
      }
      if (this.currentPolicy?.policy?.['grpc-profiles']) {
        for (const p of this.currentPolicy.policy['grpc-profiles']) {
          if (p.name && !list.includes(p.name)) list.push(p.name);
        }
      }
      return list;
    },

    // -------------------------------------------------------------
    // Parameter Definition & Options Modal Handlers
    // -------------------------------------------------------------
    openAddParamModal() {
      this.editingParamIndex = null;
      this.paramEditForm = {
        name: "",
        originalName: "",
        type: "explicit",
        level: "global",
        isGlobal: true,
        urls: [],
        parameterLocation: "any",
        valueType: "user-input",
        dataType: "alpha-numeric",
        mandatory: false,
        allowEmptyValue: false,
        allowRepeatedParameterName: false,
        sensitiveParameter: false,
        decodeValueAsBase64: "disabled",
        disallowFileUploadOfExecutables: false,
        checkMinValueLength: false,
        minimumLength: 0,
        checkMaxValueLength: false,
        maximumLength: 100,
        checkMinValue: false,
        minimumValue: 0,
        exclusiveMin: false,
        checkMaxValue: false,
        maximumValue: 100,
        exclusiveMax: false,
        checkMultipleOfValue: false,
        multipleOf: 1,
        enableRegularExpression: false,
        regularExpression: "",
        attackSignaturesCheck: false,
        signatureOverrides: [],
        checkMetachars: false,
        nameMetacharOverrides: [],
        metacharsOnParameterValueCheck: false,
        valueMetacharOverrides: [],
        arraySerializationFormat: "csv",
        arrayUniqueItemsCheck: false,
        checkMinItemsInArray: false,
        minItemsInArray: 0,
        checkMaxItemsInArray: false,
        maxItemsInArray: 10,
        wildcardOrder: 1,
        staticValuesInput: "",
        enumValuesInput: "",
      };
      this.tempParamUrlAssociation = {
        selectedExistingUrl: "",
        name: "",
        method: "*",
        protocol: "http",
        type: "wildcard",
      };
      this.tempParamSig = { signatureId: "", enabled: false };
      this.tempParamNameMetachar = { metachar: "0x3c", isAllowed: true };
      this.tempParamValMetachar = { metachar: "0x28", isAllowed: false };
      this.showEditParamModal = true;
    },

    openEditParamModal(p) {
      if (!p || !this.currentPolicy?.policy?.parameters) return;
      const params = this.currentPolicy.policy.parameters;

      let targetName = "";
      if (typeof p === "string") {
        targetName = p;
      } else if (typeof p === "number") {
        targetName = params[p]?.name || "";
      } else if (p.name) {
        targetName = p.name;
      }

      let group = null;
      if (targetName) {
        group = this.groupedParameters.find((g) => g.name === targetName);
      }

      if (!group) {
        const item = typeof p === "object" ? p : {};
        group = {
          name: targetName || item.name || "",
          type: item.type === "wildcard" ? "wildcard" : "explicit",
          level: item.level || "global",
          isGlobal: item.level !== "url",
          urls: item.level === "url" && item.url ? [JSON.parse(JSON.stringify(item.url))] : [],
          parameterLocation: item.parameterLocation || "any",
          valueType: item.valueType || "user-input",
          dataType: item.dataType || "alpha-numeric",
          mandatory: !!item.mandatory,
          allowEmptyValue: !!item.allowEmptyValue,
          allowRepeatedParameterName: !!item.allowRepeatedParameterName,
          sensitiveParameter: item.sensitiveParameter !== undefined ? !!item.sensitiveParameter : !!item.sensitive,
          decodeValueAsBase64: item.decodeValueAsBase64 || "disabled",
          enableRegularExpression: !!item.enableRegularExpression,
          regularExpression: item.regularExpression || "",
          attackSignaturesCheck: item.attackSignaturesCheck !== undefined ? !!item.attackSignaturesCheck : true,
          signatureOverrides: Array.isArray(item.signatureOverrides) ? JSON.parse(JSON.stringify(item.signatureOverrides)) : [],
          checkMetachars: !!item.checkMetachars,
          nameMetacharOverrides: Array.isArray(item.nameMetacharOverrides) ? JSON.parse(JSON.stringify(item.nameMetacharOverrides)) : [],
          metacharsOnParameterValueCheck: !!item.metacharsOnParameterValueCheck,
          valueMetacharOverrides: Array.isArray(item.valueMetacharOverrides) ? JSON.parse(JSON.stringify(item.valueMetacharOverrides)) : [],
        };
      }

      const staticStr = Array.isArray(group.staticValues) ? group.staticValues.join(", ") : "";
      const enumStr = Array.isArray(group.parameterEnumValues) ? group.parameterEnumValues.join(", ") : "";

      let loc = group.parameterLocation;
      if (!loc) {
        if (["query", "body", "form-data", "header", "cookie", "path", "any"].includes(group.type)) {
          loc = group.type === "body" ? "form-data" : group.type;
        } else {
          loc = "any";
        }
      }

      this.paramEditForm = {
        name: group.name || "",
        originalName: group.name || "",
        type: group.type === "wildcard" ? "wildcard" : "explicit",
        level: group.urls && group.urls.length > 0 && !group.isGlobal ? "url" : (group.level || "global"),
        isGlobal: group.isGlobal !== undefined ? group.isGlobal : group.level !== "url",
        urls: Array.isArray(group.urls) ? JSON.parse(JSON.stringify(group.urls)) : [],
        parameterLocation: loc,
        valueType: group.valueType || "user-input",
        dataType: group.dataType || "alpha-numeric",
        mandatory: !!group.mandatory,
        allowEmptyValue: group.allowEmptyValue !== undefined ? !!group.allowEmptyValue : false,
        allowRepeatedParameterName: !!group.allowRepeatedParameterName,
        sensitiveParameter: group.sensitiveParameter !== undefined ? !!group.sensitiveParameter : !!group.sensitive,
        decodeValueAsBase64: group.decodeValueAsBase64 || "disabled",
        disallowFileUploadOfExecutables: !!group.disallowFileUploadOfExecutables,
        checkMinValueLength: !!group.checkMinValueLength,
        minimumLength: group.minimumLength !== undefined ? group.minimumLength : 0,
        checkMaxValueLength: !!group.checkMaxValueLength,
        maximumLength: group.maximumLength !== undefined ? group.maximumLength : 100,
        checkMinValue: !!group.checkMinValue,
        minimumValue: group.minimumValue !== undefined ? group.minimumValue : 0,
        exclusiveMin: !!group.exclusiveMin,
        checkMaxValue: !!group.checkMaxValue,
        maximumValue: group.maximumValue !== undefined ? group.maximumValue : 100,
        exclusiveMax: !!group.exclusiveMax,
        checkMultipleOfValue: !!group.checkMultipleOfValue,
        multipleOf: group.multipleOf !== undefined ? group.multipleOf : 1,
        enableRegularExpression: !!group.enableRegularExpression,
        regularExpression: group.regularExpression || "",
        attackSignaturesCheck: group.attackSignaturesCheck !== undefined ? !!group.attackSignaturesCheck : true,
        signatureOverrides: Array.isArray(group.signatureOverrides)
          ? JSON.parse(JSON.stringify(group.signatureOverrides))
          : [],
        checkMetachars: !!group.checkMetachars,
        nameMetacharOverrides: Array.isArray(group.nameMetacharOverrides)
          ? JSON.parse(JSON.stringify(group.nameMetacharOverrides))
          : [],
        metacharsOnParameterValueCheck: !!group.metacharsOnParameterValueCheck,
        valueMetacharOverrides: Array.isArray(group.valueMetacharOverrides)
          ? JSON.parse(JSON.stringify(group.valueMetacharOverrides))
          : [],
        arraySerializationFormat: group.arraySerializationFormat || "csv",
        arrayUniqueItemsCheck: !!group.arrayUniqueItemsCheck,
        checkMinItemsInArray: !!group.checkMinItemsInArray,
        minItemsInArray: group.minItemsInArray !== undefined ? group.minItemsInArray : 0,
        checkMaxItemsInArray: !!group.checkMaxItemsInArray,
        maxItemsInArray: group.maxItemsInArray !== undefined ? group.maxItemsInArray : 10,
        wildcardOrder: group.wildcardOrder !== undefined ? group.wildcardOrder : 1,
        staticValuesInput: staticStr,
        enumValuesInput: enumStr,
      };
      this.tempParamUrlAssociation = {
        selectedExistingUrl: "",
        name: "",
        method: "*",
        protocol: "http",
        type: "wildcard",
      };
      this.tempParamSig = { signatureId: "", enabled: false };
      this.tempParamNameMetachar = { metachar: "0x3c", isAllowed: true };
      this.tempParamValMetachar = { metachar: "0x28", isAllowed: false };
      this.showEditParamModal = true;
    },

    onSelectExistingParamUrl() {
      const sel = this.tempParamUrlAssociation.selectedExistingUrl;
      if (!sel) return;
      const urls = this.currentPolicy?.policy?.urls || [];
      const found = urls.find((u) => u.name === sel);
      if (found) {
        this.tempParamUrlAssociation.name = found.name;
        this.tempParamUrlAssociation.method = found.method || "*";
        this.tempParamUrlAssociation.protocol = found.protocol || "http";
        this.tempParamUrlAssociation.type = found.type || "wildcard";
      }
    },

    addParamUrlAssociation() {
      const uPath = (this.tempParamUrlAssociation.name || "").trim();
      if (!uPath) {
        this.notify("URL path is required to associate.", "warning");
        return;
      }
      if (!Array.isArray(this.paramEditForm.urls)) {
        this.paramEditForm.urls = [];
      }
      const uMethod = this.tempParamUrlAssociation.method || "*";
      const uProto = this.tempParamUrlAssociation.protocol || "http";
      const uType = this.tempParamUrlAssociation.type || "wildcard";

      const exists = this.paramEditForm.urls.some(
        (u) =>
          u.name.trim() === uPath &&
          (u.method || "*") === uMethod &&
          (u.protocol || "http") === uProto
      );
      if (exists) {
        this.notify("This URL association already exists.", "warning");
        return;
      }

      this.paramEditForm.urls.push({
        name: uPath,
        method: uMethod,
        protocol: uProto,
        type: uType,
      });

      this.tempParamUrlAssociation.name = "";
      this.tempParamUrlAssociation.selectedExistingUrl = "";
      this.notify(`Added association to '${uPath}'.`, "info");
    },

    removeParamUrlAssociation(idx) {
      if (Array.isArray(this.paramEditForm.urls) && idx >= 0 && idx < this.paramEditForm.urls.length) {
        const removed = this.paramEditForm.urls.splice(idx, 1)[0];
        this.notify(`Removed association to '${removed.name}'.`, "info");
      }
    },

    saveEditParam() {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("parameters", []);
      const params = this.currentPolicy.policy.parameters;
      const name = (this.paramEditForm.name || "").trim();
      if (!name) {
        this.notify("Parameter name cannot be empty", "error");
        return;
      }

      this.markDirty();
      const baseProps = {
        name: name,
        type: this.paramEditForm.type || "explicit",
        parameterLocation: this.paramEditForm.parameterLocation || "any",
        valueType: this.paramEditForm.valueType || "user-input",
        dataType: this.paramEditForm.dataType || "alpha-numeric",
        mandatory: !!this.paramEditForm.mandatory,
        allowEmptyValue: !!this.paramEditForm.allowEmptyValue,
        allowRepeatedParameterName: !!this.paramEditForm.allowRepeatedParameterName,
        sensitiveParameter: !!this.paramEditForm.sensitiveParameter,
        decodeValueAsBase64: this.paramEditForm.decodeValueAsBase64 || "disabled",
      };

      if (this.paramEditForm.type === "wildcard" && this.paramEditForm.wildcardOrder) {
        baseProps.wildcardOrder = parseInt(this.paramEditForm.wildcardOrder, 10) || 1;
      }
      if (this.paramEditForm.disallowFileUploadOfExecutables) {
        baseProps.disallowFileUploadOfExecutables = true;
      }
      if (this.paramEditForm.checkMinValueLength) {
        baseProps.checkMinValueLength = true;
        baseProps.minimumLength = parseInt(this.paramEditForm.minimumLength, 10) || 0;
      }
      if (this.paramEditForm.checkMaxValueLength) {
        baseProps.checkMaxValueLength = true;
        baseProps.maximumLength = parseInt(this.paramEditForm.maximumLength, 10) || 0;
      }
      if (this.paramEditForm.checkMinValue) {
        baseProps.checkMinValue = true;
        baseProps.minimumValue = Number(this.paramEditForm.minimumValue) || 0;
        if (this.paramEditForm.exclusiveMin) baseProps.exclusiveMin = true;
      }
      if (this.paramEditForm.checkMaxValue) {
        baseProps.checkMaxValue = true;
        baseProps.maximumValue = Number(this.paramEditForm.maximumValue) || 0;
        if (this.paramEditForm.exclusiveMax) baseProps.exclusiveMax = true;
      }
      if (this.paramEditForm.checkMultipleOfValue) {
        baseProps.checkMultipleOfValue = true;
        baseProps.multipleOf = Number(this.paramEditForm.multipleOf) || 1;
      }
      if (this.paramEditForm.enableRegularExpression && this.paramEditForm.regularExpression) {
        baseProps.enableRegularExpression = true;
        baseProps.regularExpression = this.paramEditForm.regularExpression.trim();
      }
      if (this.paramEditForm.attackSignaturesCheck) {
        baseProps.attackSignaturesCheck = true;
      }
      if (this.paramEditForm.signatureOverrides && this.paramEditForm.signatureOverrides.length > 0) {
        baseProps.signatureOverrides = this.paramEditForm.signatureOverrides.map((s) => ({
          signatureId: parseInt(s.signatureId, 10),
          enabled: !!s.enabled,
        }));
      }
      if (this.paramEditForm.checkMetachars) {
        baseProps.checkMetachars = true;
      }
      if (this.paramEditForm.nameMetacharOverrides && this.paramEditForm.nameMetacharOverrides.length > 0) {
        baseProps.nameMetacharOverrides = this.paramEditForm.nameMetacharOverrides.map((m) => ({
          metachar: m.metachar,
          isAllowed: !!m.isAllowed,
        }));
      }
      if (this.paramEditForm.metacharsOnParameterValueCheck) {
        baseProps.metacharsOnParameterValueCheck = true;
      }
      if (this.paramEditForm.valueMetacharOverrides && this.paramEditForm.valueMetacharOverrides.length > 0) {
        baseProps.valueMetacharOverrides = this.paramEditForm.valueMetacharOverrides.map((m) => ({
          metachar: m.metachar,
          isAllowed: !!m.isAllowed,
        }));
      }

      if (this.paramEditForm.staticValuesInput && this.paramEditForm.staticValuesInput.trim()) {
        baseProps.staticValues = this.paramEditForm.staticValuesInput
          .split(/[\n,]+/)
          .map((v) => v.trim())
          .filter(Boolean);
      }
      if (this.paramEditForm.enumValuesInput && this.paramEditForm.enumValuesInput.trim()) {
        baseProps.parameterEnumValues = this.paramEditForm.enumValuesInput
          .split(/[\n,]+/)
          .map((v) => v.trim())
          .filter(Boolean);
      }

      if (this.paramEditForm.valueType === "array" || this.paramEditForm.valueType === "openapi-array") {
        if (this.paramEditForm.arraySerializationFormat) {
          baseProps.arraySerializationFormat = this.paramEditForm.arraySerializationFormat;
        }
        if (this.paramEditForm.arrayUniqueItemsCheck) {
          baseProps.arrayUniqueItemsCheck = true;
        }
        if (this.paramEditForm.checkMinItemsInArray) {
          baseProps.checkMinItemsInArray = true;
          baseProps.minItemsInArray = parseInt(this.paramEditForm.minItemsInArray, 10) || 0;
        }
        if (this.paramEditForm.checkMaxItemsInArray) {
          baseProps.checkMaxItemsInArray = true;
          baseProps.maxItemsInArray = parseInt(this.paramEditForm.maxItemsInArray, 10) || 0;
        }
      }

      const newEntries = [];
      const isGlobal = !!this.paramEditForm.isGlobal;
      const urls = Array.isArray(this.paramEditForm.urls) ? this.paramEditForm.urls : [];

      if (isGlobal || urls.length === 0) {
        newEntries.push({
          ...JSON.parse(JSON.stringify(baseProps)),
          level: "global",
        });
      }

      for (const u of urls) {
        if (!u || !u.name) continue;
        newEntries.push({
          ...JSON.parse(JSON.stringify(baseProps)),
          level: "url",
          url: {
            name: (u.name || "").trim(),
            method: u.method || "*",
            protocol: u.protocol || "http",
            type: u.type || "wildcard",
          },
        });
      }

      const origName = (this.paramEditForm.originalName || name).trim();
      this.currentPolicy.policy.parameters = params.filter(
        (p) => (p.name || "").trim() !== origName && (p.name || "").trim() !== name
      );

      for (const entry of newEntries) {
        this.currentPolicy.policy.parameters.push(entry);
      }

      this.invalidateParamCache();
      this.showEditParamModal = false;
      this.editingParamIndex = null;
      if (this.showEditUrlModal) {
        this.refreshUrlConfiguredParams();
      }
      this.notify(`Parameter '${name}' saved successfully (${newEntries.length} scope/URL instance(s)).`, "success");
    },

    addParamSigOverride() {
      const id = parseInt(this.tempParamSig.signatureId, 10);
      if (!id || isNaN(id)) {
        this.notify("Please enter a numeric Signature ID", "error");
        return;
      }
      if (!this.paramEditForm.signatureOverrides) this.paramEditForm.signatureOverrides = [];
      const exists = this.paramEditForm.signatureOverrides.find((s) => s.signatureId === id);
      if (exists) {
        exists.enabled = !!this.tempParamSig.enabled;
      } else {
        this.paramEditForm.signatureOverrides.push({ signatureId: id, enabled: !!this.tempParamSig.enabled });
      }
      this.tempParamSig = { signatureId: "", enabled: false };
    },

    removeParamSigOverride(idx) {
      if (this.paramEditForm.signatureOverrides) {
        this.paramEditForm.signatureOverrides.splice(idx, 1);
      }
    },

    addParamNameMetacharOverride() {
      const hex = (this.tempParamNameMetachar.metachar || "").trim();
      if (!hex) return;
      if (!this.paramEditForm.nameMetacharOverrides) this.paramEditForm.nameMetacharOverrides = [];
      const exists = this.paramEditForm.nameMetacharOverrides.find((m) => m.metachar.toLowerCase() === hex.toLowerCase());
      if (exists) {
        exists.isAllowed = !!this.tempParamNameMetachar.isAllowed;
      } else {
        this.paramEditForm.nameMetacharOverrides.push({ metachar: hex, isAllowed: !!this.tempParamNameMetachar.isAllowed });
      }
      this.tempParamNameMetachar = { metachar: "0x28", isAllowed: false };
    },

    removeParamNameMetacharOverride(idx) {
      if (this.paramEditForm.nameMetacharOverrides) {
        this.paramEditForm.nameMetacharOverrides.splice(idx, 1);
      }
    },

    addParamValMetacharOverride() {
      const hex = (this.tempParamValMetachar.metachar || "").trim();
      if (!hex) return;
      if (!this.paramEditForm.valueMetacharOverrides) this.paramEditForm.valueMetacharOverrides = [];
      const exists = this.paramEditForm.valueMetacharOverrides.find((m) => m.metachar.toLowerCase() === hex.toLowerCase());
      if (exists) {
        exists.isAllowed = !!this.tempParamValMetachar.isAllowed;
      } else {
        this.paramEditForm.valueMetacharOverrides.push({ metachar: hex, isAllowed: !!this.tempParamValMetachar.isAllowed });
      }
      this.tempParamValMetachar = { metachar: "0x3c", isAllowed: true };
    },

    removeParamValMetacharOverride(idx) {
      if (this.paramEditForm.valueMetacharOverrides) {
        this.paramEditForm.valueMetacharOverrides.splice(idx, 1);
      }
    },

    addParameter() {
      const name = this.tempParam.name.trim();
      if (!name) return;
      this.markDirty();
      this.ensurePolicySection("parameters", []);

      // Prevent duplicate parameter with same name and type
      const exists = this.currentPolicy.policy.parameters.some(
        (p) => (p.name || "").toLowerCase() === name.toLowerCase() && (p.type || "query") === this.tempParam.type
      );
      if (exists) {
        this.notify(`Parameter '${name}' (${this.tempParam.type}) already exists`, "warning");
        return;
      }

      this.currentPolicy.policy.parameters.push({
        name: name,
        type: this.tempParam.type || "query",
        dataType: this.tempParam.dataType || "string",
        sensitive: !!this.tempParam.sensitive,
      });
      this.invalidateParamCache();
      this.notify(`Added parameter '${name}'`, "success");
      this.tempParam = { name: "", type: "query", sensitive: false, dataType: "string" };
    },

    confirmDeleteParam(target) {
      if (!this.currentPolicy?.policy?.parameters) return;
      let name = "";
      if (typeof target === "string") {
        name = target;
      } else if (typeof target === "number") {
        name = this.currentPolicy.policy.parameters[target]?.name || "";
      } else if (target && target.name) {
        name = target.name;
      }
      if (!name) return;
      this.paramToDelete = { name: name };
      this.paramToDeleteIndex = 0;
      this.showDeleteParamModal = true;
    },

    executeDeleteParam() {
      if (!this.paramToDelete?.name || !this.currentPolicy?.policy?.parameters) {
        this.showDeleteParamModal = false;
        return;
      }
      const name = (this.paramToDelete.name || "").trim();
      const params = this.currentPolicy.policy.parameters;
      const initialCount = params.length;
      this.currentPolicy.policy.parameters = params.filter((p) => (p.name || "").trim() !== name);
      const removed = initialCount - this.currentPolicy.policy.parameters.length;
      this.invalidateParamCache();
      this.markDirty();
      if (this.showEditUrlModal) {
        this.refreshUrlConfiguredParams();
      }
      this.notify(`Removed parameter '${name}' (${removed} instance(s)).`, "info");
      this.showDeleteParamModal = false;
      this.paramToDelete = null;
      this.paramToDeleteIndex = null;
    },

    removeParameter(target) {
      this.confirmDeleteParam(target);
    },

    toggleSelectAllParams() {
      const list = this.filteredParameters || [];
      if (this.selectedParams.length === list.length && list.length > 0) {
        this.selectedParams = [];
      } else {
        this.selectedParams = list.map((p) => p.name);
      }
    },

    confirmMassDeleteParams() {
      if (!this.selectedParams || this.selectedParams.length === 0) {
        this.notify("No parameters selected.", "warning");
        return;
      }
      this.showMassDeleteParamModal = true;
    },

    executeMassDeleteParams() {
      if (!this.currentPolicy?.policy || !this.selectedParams.length) {
        this.showMassDeleteParamModal = false;
        return;
      }
      const params = this.currentPolicy.policy.parameters;
      if (!Array.isArray(params)) return;
      const toRemove = new Set(this.selectedParams);
      const count = toRemove.size;
      this.currentPolicy.policy.parameters = params.filter((p) => !toRemove.has(p.name));
      this.invalidateParamCache();
      this.markDirty();
      this.selectedParams = [];
      this.showMassDeleteParamModal = false;
      this.notify(`Successfully removed ${count} parameter(s).`, "info");
    },

    toggleParamSensitivity(param) {
      if (!param || !this.currentPolicy?.policy?.parameters) return;
      this.markDirty();
      const current = param.sensitiveParameter !== undefined ? !!param.sensitiveParameter : !!param.sensitive;
      const nextVal = !current;
      const pName = (param.name || "").trim();
      this.currentPolicy.policy.parameters.forEach((p) => {
        if ((p.name || "").trim() === pName) {
          p.sensitiveParameter = nextVal;
          p.sensitive = nextVal;
        }
      });
      param.sensitiveParameter = nextVal;
      param.sensitive = nextVal;
      this.invalidateParamCache();
    },

    toggleDataGuard() {
      this.markDirty();
      this.ensurePolicySection("data-guard", {
        enabled: false,
        maskData: true,
        creditCardNumbers: true,
        usSocialSecurityNumbers: true,
        enforcementMode: "ignore-urls-in-list",
        enforcementUrls: [],
      });
      const dg = this.currentPolicy.policy["data-guard"];
      dg.enabled = !dg.enabled;
      if (dg.enabled) {
        if (dg.maskData === undefined) dg.maskData = true;
        if (dg.creditCardNumbers === undefined) dg.creditCardNumbers = true;
        if (dg.usSocialSecurityNumbers === undefined) dg.usSocialSecurityNumbers = true;
        if (dg.enforcementMode === undefined) dg.enforcementMode = "ignore-urls-in-list";
        if (!Array.isArray(dg.enforcementUrls)) dg.enforcementUrls = [];
      }
    },

    getDataGuardPatterns() {
      const dg = this.currentPolicy?.policy?.["data-guard"];
      if (!dg) return [];
      if (Array.isArray(dg.customPatternsList)) return dg.customPatternsList;
      if (Array.isArray(dg.customPatterns)) return dg.customPatterns;
      return [];
    },

    addCustomPattern() {
      const pattern = this.tempRegex.trim();
      if (!pattern) return;
      this.markDirty();
      this.ensurePolicySection("data-guard", {
        enabled: true,
        maskData: true,
        creditCardNumbers: true,
        usSocialSecurityNumbers: true,
        enforcementMode: "ignore-urls-in-list",
        enforcementUrls: [],
        customPatterns: true,
        customPatternsList: [],
      });
      const dg = this.currentPolicy.policy["data-guard"];
      if (!Array.isArray(dg.customPatternsList)) {
        dg.customPatternsList = Array.isArray(dg.customPatterns) ? [...dg.customPatterns] : [];
      }
      dg.customPatterns = true;
      dg.customPatternsList.push(pattern);
      this.tempRegex = "";
    },

    removeCustomPattern(index) {
      this.markDirty();
      const dg = this.currentPolicy?.policy?.["data-guard"];
      if (!dg) return;
      if (Array.isArray(dg.customPatternsList)) {
        dg.customPatternsList.splice(index, 1);
        if (dg.customPatternsList.length === 0) {
          dg.customPatterns = false;
        }
      } else if (Array.isArray(dg.customPatterns)) {
        dg.customPatterns.splice(index, 1);
      }
    },

    addDataGuardEnforcementUrl(urlStr) {
      const u = (urlStr || "").trim();
      if (!u) return;
      this.markDirty();
      this.ensurePolicySection("data-guard", {
        enabled: true,
        maskData: true,
        creditCardNumbers: true,
        usSocialSecurityNumbers: true,
        enforcementMode: "ignore-urls-in-list",
        enforcementUrls: [],
      });
      const dg = this.currentPolicy.policy["data-guard"];
      if (!Array.isArray(dg.enforcementUrls)) dg.enforcementUrls = [];
      if (!dg.enforcementUrls.includes(u)) {
        dg.enforcementUrls.push(u);
      }
    },

    removeDataGuardEnforcementUrl(index) {
      this.markDirty();
      const dg = this.currentPolicy?.policy?.["data-guard"];
      if (Array.isArray(dg?.enforcementUrls)) {
        dg.enforcementUrls.splice(index, 1);
      }
    },

    openDiffModal() {
      const orig = this._originalPolicyJsonString || (this.currentPolicyOriginal ? JSON.stringify(this.currentPolicyOriginal, null, 2) : "{}");
      const mod =
        this.editorMode === "json" && window.WAF_EDITOR
          ? window.WAF_EDITOR.getValue()
          : JSON.stringify(this.currentPolicy, null, 2);

      this.computedDiff = window.WAF_EDITOR.computeSimpleDiff(orig, mod);
      this.showDiffModal = true;
    },

    formatJson() {
      if (window.WAF_EDITOR) {
        const ok = window.WAF_EDITOR.format();
        if (ok) {
          this.notify("JSON formatted successfully", "info");
        } else {
          this.notify("Unable to format: Syntax error", "error");
        }
      }
    },

    // =============================================================
    // LOGGING PROFILES MANAGEMENT METHODS
    // =============================================================
    async loadLogCatalog() {
      try {
        const res = await fetch("/api/log-catalog");
        if (res.ok) {
          const data = await res.json();
          if (data && typeof data === "object") {
            this.logCatalog = {
              requestTypes: data.request_types || data.requestTypes || ["all", "illegal", "blocked"],
              formats: data.formats || ["default", "arcsight", "bigiq", "grpc", "splunk", "user-defined"],
              attributes: (Array.isArray(data.attributes) && data.attributes.length > 0) ? data.attributes : DEFAULT_LOG_ATTRIBUTES,
            };
          }
        }
      } catch (e) {
        console.warn("Failed to load log catalog from API, using defaults:", e);
      }
    },

    async loadLogTemplates() {
      try {
        const res = await fetch("/api/log-templates");
        if (res.ok) {
          this.logTemplates = await res.json();
        }
      } catch (e) {
        console.error("Failed to load logging templates", e);
      }
    },

    async loadLogProfiles() {
      try {
        this.logLoading = true;
        const res = await fetch("/api/log-profiles");
        if (!res.ok) throw new Error("Failed to fetch logging profiles");
        this.logProfiles = await res.json();
      } catch (err) {
        this.notify("Error loading logging profiles: " + err.message, "error");
      } finally {
        this.logLoading = false;
      }
    },

    get filteredLogProfiles() {
      return this.logProfiles.filter((p) => {
        const matchesQuery =
          !this.logSearchQuery ||
          p.name.toLowerCase().includes(this.logSearchQuery.toLowerCase()) ||
          p.format.toLowerCase().includes(this.logSearchQuery.toLowerCase());
        const matchesType =
          this.logFilterReqType === "all" || p.request_type === this.logFilterReqType;
        const matchesFormat =
          this.logFilterFormat === "all" || p.format === this.logFilterFormat;
        return matchesQuery && matchesType && matchesFormat;
      });
    },

    get filteredLogAttributes() {
      const q = this.attributeSearchQuery.trim().toLowerCase();
      const list = (this.logCatalog && Array.isArray(this.logCatalog.attributes) && this.logCatalog.attributes.length > 0)
        ? this.logCatalog.attributes
        : DEFAULT_LOG_ATTRIBUTES;
      if (!q) return list;
      return list.filter(
        (a) =>
          (a.name && a.name.toLowerCase().includes(q)) ||
          (a.token && a.token.toLowerCase().includes(q)) ||
          (a.description && a.description.toLowerCase().includes(q))
      );
    },

    async openLogEditor(profileName, mode = "visual") {
      try {
        this.logLoading = true;
        const res = await fetch(`/api/log-profiles/${encodeURIComponent(profileName)}`);
        if (!res.ok) throw new Error("Could not retrieve logging profile details");
        const logObj = await res.json();

        this.currentLogName = profileName;
        this.currentLogOriginal = JSON.parse(JSON.stringify(logObj));
        this.rawLogJsonString = JSON.stringify(logObj, null, 2);
        this.isLogDirty = false;
        this.logEditorMode = mode;
        this.activeLogTab = "filter";
        this.logView = "editor";
        this.logJsonErrors = [];
        this.logJsonWarnings = [];

        // Populate visual form
        this.populateLogForm(profileName, logObj);

        this.$nextTick(() => {
          this.initLogCodeMirror();
          setTimeout(() => {
            if (window.LOG_EDITOR) window.LOG_EDITOR.refresh();
          }, 50);
        });
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.logLoading = false;
      }
    },

    populateLogForm(name, obj) {
      const flt = obj.filter || {};
      const cnt = obj.content || {};

      this.logForm = {
        name: name,
        filter: {
          request_type: flt.request_type || "illegal",
        },
        content: {
          format: cnt.format || "default",
          format_string: cnt.format_string || "",
          max_request_size: cnt.max_request_size !== undefined ? String(cnt.max_request_size) : "2k",
          max_message_size: cnt.max_message_size !== undefined ? String(cnt.max_message_size) : "32k",
          list_prefix: cnt.list_prefix || "",
          list_delimiter: cnt.list_delimiter || ",",
          list_suffix: cnt.list_suffix || "",
          escaping_characters: Array.isArray(cnt.escaping_characters)
            ? JSON.parse(JSON.stringify(cnt.escaping_characters))
            : [],
        },
      };
    },

    buildLogObjectFromForm() {
      const f = this.logForm;
      const result = {
        filter: {
          request_type: f.filter.request_type || "illegal",
        },
        content: {
          format: f.content.format || "default",
          max_request_size: f.content.max_request_size || "2k",
          max_message_size: f.content.max_message_size || "32k",
        },
      };

      if (f.content.format === "user-defined") {
        result.content.format_string = f.content.format_string || "";
      }

      if (f.content.list_prefix) result.content.list_prefix = f.content.list_prefix;
      if (f.content.list_delimiter && f.content.list_delimiter !== ",") {
        result.content.list_delimiter = f.content.list_delimiter;
      }
      if (f.content.list_suffix) result.content.list_suffix = f.content.list_suffix;

      if (f.content.escaping_characters && f.content.escaping_characters.length > 0) {
        result.content.escaping_characters = f.content.escaping_characters;
      }

      return result;
    },

    initLogCodeMirror() {
      const container = document.getElementById("log-editor-textarea");
      if (!container) return;
      const cmTheme = this.theme === "dark" ? "material-darker" : "default";

      window.LOG_EDITOR.init(
        "log-editor-textarea",
        this.rawLogJsonString,
        (val) => {
          this.rawLogJsonString = val;
          this.isLogDirty = true;
          this.validateLogJsonDebounced(val);
        },
        cmTheme
      );
      setTimeout(() => {
        if (window.LOG_EDITOR) window.LOG_EDITOR.refresh();
      }, 50);
    },

    validateLogJsonDebounced(jsonStr) {
      clearTimeout(this._logValTimer);
      this._logValTimer = setTimeout(async () => {
        try {
          const parsed = JSON.parse(jsonStr);
          const res = await fetch("/api/log-profiles/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: parsed }),
          });
          if (res.ok) {
            const data = await res.json();
            this.logJsonErrors = data.errors || [];
            this.logJsonWarnings = data.warnings || [];
            if (data.valid && this.logEditorMode === "json") {
              this.populateLogForm(this.currentLogName, parsed);
            }
          }
        } catch (e) {
          this.logJsonErrors = ["JSON Syntax Error: " + e.message];
        }
      }, 400);
    },

    setLogEditorMode(mode) {
      if (mode === this.logEditorMode) return;

      if (mode === "json") {
        const obj = this.buildLogObjectFromForm();
        this.rawLogJsonString = JSON.stringify(obj, null, 2);
        this.logEditorMode = "json";
        this.$nextTick(() => {
          if (!window.LOG_EDITOR || !window.LOG_EDITOR.cmInstance) {
            this.initLogCodeMirror();
          } else {
            window.LOG_EDITOR.setValue(this.rawLogJsonString);
          }
          setTimeout(() => {
            if (window.LOG_EDITOR) window.LOG_EDITOR.refresh();
          }, 30);
          setTimeout(() => {
            if (window.LOG_EDITOR) window.LOG_EDITOR.refresh();
          }, 150);
        });
      } else {
        if (window.LOG_EDITOR && window.LOG_EDITOR.cmInstance) {
          const val = window.LOG_EDITOR.getValue();
          try {
            const parsed = JSON.parse(val);
            this.populateLogForm(this.currentLogName, parsed);
            this.logEditorMode = "visual";
          } catch (e) {
            this.notify("Cannot switch to Visual Form: JSON contains syntax errors", "error");
            return;
          }
        } else {
          this.logEditorMode = "visual";
        }
      }
    },

    closeLogEditor() {
      if (this.isLogDirty) {
        if (!confirm("You have unsaved changes. Discard and return to dashboard?")) {
          return;
        }
      }
      this.currentLogName = null;
      this.currentLogOriginal = null;
      this.isLogDirty = false;
      this.logView = "dashboard";
      this.loadLogProfiles();
    },

    insertLogToken(token) {
      this.isLogDirty = true;
      if (this.logForm.content.format !== "user-defined") {
        this.logForm.content.format = "user-defined";
      }
      const cur = this.logForm.content.format_string || "";
      this.logForm.content.format_string = cur ? `${cur},${token}` : token;
      this.notify(`Inserted token ${token}`, "info");
    },

    addEscapingChar() {
      const from = this.tempEscaping.from;
      const to = this.tempEscaping.to;
      if (!from) return;
      this.isLogDirty = true;
      if (!this.logForm.content.escaping_characters) {
        this.logForm.content.escaping_characters = [];
      }
      this.logForm.content.escaping_characters.push({ from, to });
      this.tempEscaping = { from: "", to: "" };
    },

    removeEscapingChar(index) {
      this.isLogDirty = true;
      this.logForm.content.escaping_characters.splice(index, 1);
    },

    async saveCurrentLogProfile() {
      if (!this.currentLogName) return;

      let payload;
      if (this.logEditorMode === "json" && window.LOG_EDITOR) {
        try {
          payload = JSON.parse(window.LOG_EDITOR.getValue());
        } catch (e) {
          this.notify("Cannot save: Invalid JSON syntax", "error");
          return;
        }
      } else {
        payload = this.buildLogObjectFromForm();
      }

      if (payload && payload.content) {
        const msgSize = String(payload.content.max_message_size || "").trim();
        const reqSize = String(payload.content.max_request_size || "").trim();
        if (msgSize) {
          const m = msgSize.match(/^(\d+)[kK]?$/);
          const val = m ? parseInt(m[1], 10) : 0;
          if (val <= 0) {
            this.notify("Invalid Max Message Size: must be greater than zero (e.g. '32k' between 1k and 64k)", "error");
            return;
          }
        }
        if (reqSize && reqSize.toLowerCase() !== "any") {
          const m = reqSize.match(/^(\d+)[kK]?$/);
          const val = m ? parseInt(m[1], 10) : 0;
          if (val <= 0) {
            this.notify("Invalid Max Request Size: must be greater than zero (e.g. '2k' between 1k and 10k or 'any')", "error");
            return;
          }
        }
      }

      try {
        this.logLoading = true;
        const res = await fetch(`/api/log-profiles/${encodeURIComponent(this.currentLogName)}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: payload }),
        });
        const data = await res.json();
        if (!res.ok) {
          const errMsg = data.detail?.errors
            ? data.detail.errors.join("; ")
            : data.detail || "Save failed";
          throw new Error(errMsg);
        }

        let successMsg = `Logging profile '${this.currentLogName}' saved successfully!`;
        if (data.metadata?.uncommitted_changes) {
          successMsg = `Logging profile '${this.currentLogName}' saved to local Redis (uncommitted draft). Ready to commit to GitHub.`;
        } else if (data.metadata?.commit_sha) {
          const shortSha = data.metadata.commit_sha.substring(0, 7);
          successMsg += ` (Git commit ${shortSha} created)`;
        }
        this.notify(successMsg, "success");
        this.currentLogOriginal = JSON.parse(JSON.stringify(payload));
        this.isLogDirty = false;
        await this.loadLogProfiles();
      } catch (err) {
        this.notify("Error saving logging profile: " + err.message, "error");
      } finally {
        this.logLoading = false;
      }
    },

    // Logging Modals & Actions
    openCreateLogModal(templateId = "log_default") {
      this.newLogForm = {
        name: "",
        template_id: templateId,
      };
      this.showCreateLogModal = true;
    },

    async createLogProfile() {
      const name = this.newLogForm.name.trim();
      if (!name) {
        this.notify("Profile name is required", "error");
        return;
      }

      try {
        this.logLoading = true;
        const res = await fetch("/api/log-profiles", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: name,
            template_id: this.newLogForm.template_id,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          const err = data.detail?.errors ? data.detail.errors.join("; ") : data.detail || "Creation failed";
          throw new Error(err);
        }

        this.notify(`Logging profile '${name}' created`, "success");
        this.showCreateLogModal = false;
        await this.loadLogProfiles();
        this.openLogEditor(name, "visual");
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.logLoading = false;
      }
    },

    openCloneLogModal(profileName) {
      this.cloneLogTargetName = `${profileName}_copy`;
      this.currentLogToClone = profileName;
      this.showCloneLogModal = true;
    },

    async cloneLogProfile() {
      const target = this.cloneLogTargetName.trim();
      if (!target) return;

      try {
        this.logLoading = true;
        const res = await fetch(
          `/api/log-profiles/${encodeURIComponent(this.currentLogToClone)}/clone`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ new_name: target }),
          }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Clone failed");

        this.notify(`Logging profile cloned as '${target}'`, "success");
        this.showCloneLogModal = false;
        await this.loadLogProfiles();
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.logLoading = false;
      }
    },

    confirmDeleteLog(profileName) {
      this.logToDelete = profileName;
      this.showDeleteLogModal = true;
    },

    async deleteLogProfile() {
      if (!this.logToDelete) return;

      try {
        this.logLoading = true;
        const res = await fetch(`/api/log-profiles/${encodeURIComponent(this.logToDelete)}`, {
          method: "DELETE",
        });
        if (!res.ok) throw new Error("Delete failed");

        this.notify(`Logging profile '${this.logToDelete}' deleted`, "info");
        this.showDeleteLogModal = false;
        this.logToDelete = null;
        await this.loadLogProfiles();
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.logLoading = false;
      }
    },

    exportLogProfile(profileName) {
      window.location.href = `/api/log-profiles/${encodeURIComponent(profileName)}/export`;
    },

    async importLogFile(event) {
      const file = event.target.files[0];
      if (!file) return;

      const formData = new FormData();
      formData.append("file", file);

      try {
        this.logLoading = true;
        const res = await fetch("/api/log-profiles/import", {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        if (!res.ok) {
          const err = data.detail?.errors ? data.detail.errors.join("; ") : data.detail || "Import failed";
          throw new Error(err);
        }

        this.notify(data.message, "success");
        this.showImportLogModal = false;
        await this.loadLogProfiles();
      } catch (err) {
        this.notify(err.message, "error");
      } finally {
        this.logLoading = false;
        event.target.value = "";
      }
    },

    openLogDiffModal() {
      const orig = JSON.stringify(this.currentLogOriginal, null, 2);
      const mod =
        this.logEditorMode === "json" && window.LOG_EDITOR
          ? window.LOG_EDITOR.getValue()
          : JSON.stringify(this.buildLogObjectFromForm(), null, 2);

      this.computedLogDiff = window.LOG_EDITOR.computeSimpleDiff(orig, mod);
      this.showLogDiffModal = true;
    },

    // -----------------------------------------------------------------
    // Cookie Protection (policy.cookies & policy['cookie-settings'])
    // -----------------------------------------------------------------
    getCookies() {
      if (!this.currentPolicy?.policy) return [];
      if (!Array.isArray(this.currentPolicy.policy.cookies)) {
        return [];
      }
      return this.currentPolicy.policy.cookies;
    },

    getCookiesCount() {
      return this.getCookies().length;
    },

    get filteredCookies() {
      const list = this.getCookies();
      const q = (this.cookieSearchQuery || "").trim().toLowerCase();
      const typeFilter = (this.cookieTypeFilter || "all").toLowerCase();
      const enfFilter = (this.cookieEnforcementFilter || "all").toLowerCase();

      if (!q && typeFilter === "all" && enfFilter === "all") {
        return list;
      }

      return list.filter((c) => {
        if (!c || typeof c !== "object") return false;
        const name = (c.name || "").toLowerCase();
        if (q && !name.includes(q)) return false;
        if (typeFilter !== "all" && (c.type || "explicit").toLowerCase() !== typeFilter) return false;
        if (enfFilter !== "all" && (c.enforcementType || "allow").toLowerCase() !== enfFilter) return false;
        return true;
      });
    },

    addCookie(cookieData = null) {
      this.ensurePolicySection("cookies", []);
      if (!Array.isArray(this.currentPolicy.policy.cookies)) {
        this.currentPolicy.policy.cookies = [];
      }

      const data = cookieData || this.newCookie;
      const name = (data.name || "").trim();
      if (!name) {
        this.notify("Please specify a cookie name.", "warning");
        return;
      }

      // Infer wildcard type if '*' is in the name
      let type = data.type || "explicit";
      if (name.includes("*")) {
        type = "wildcard";
      }

      const newEntry = {
        name: name,
        type: type,
        enforcementType: data.enforcementType || "enforce",
        attackSignaturesCheck: data.attackSignaturesCheck !== undefined ? Boolean(data.attackSignaturesCheck) : true,
        maskValueInLogs: Boolean(data.maskValueInLogs),
        accessibleOnlyThroughTheHttpProtocol: Boolean(data.accessibleOnlyThroughTheHttpProtocol),
      };

      // Check for duplicates
      const existing = this.currentPolicy.policy.cookies.find(
        (c) => (c.name || "").toLowerCase() === name.toLowerCase()
      );
      if (existing) {
        this.notify(`Cookie '${name}' already exists in the policy.`, "warning");
        return;
      }

      this.currentPolicy.policy.cookies.push(newEntry);
      this.markDirty();
      this.syncRawJson();

      // Reset form
      this.newCookie = {
        name: "",
        type: "explicit",
        enforcementType: "enforce",
        attackSignaturesCheck: true,
        maskValueInLogs: false,
        accessibleOnlyThroughTheHttpProtocol: false,
      };

      this.notify(`Cookie '${name}' added to policy.`, "success");
    },

    removeCookie(index) {
      if (!Array.isArray(this.currentPolicy?.policy?.cookies)) return;
      const removed = this.currentPolicy.policy.cookies.splice(index, 1);
      this.markDirty();
      this.syncRawJson();
      if (removed.length > 0) {
        this.notify(`Cookie '${removed[0].name}' removed.`, "info");
      }
    },

    applyCookiePreset(presetName) {
      const presets = {
        session_id: {
          name: "session_id",
          type: "explicit",
          enforcementType: "enforce",
          attackSignaturesCheck: true,
          maskValueInLogs: true,
          accessibleOnlyThroughTheHttpProtocol: true,
        },
        jwt_token: {
          name: "access_token",
          type: "explicit",
          enforcementType: "enforce",
          attackSignaturesCheck: true,
          maskValueInLogs: true,
          accessibleOnlyThroughTheHttpProtocol: true,
        },
        wildcard_tracking: {
          name: "track_*",
          type: "wildcard",
          enforcementType: "allow",
          attackSignaturesCheck: false,
          maskValueInLogs: false,
          accessibleOnlyThroughTheHttpProtocol: false,
        },
        catch_all: {
          name: "*",
          type: "wildcard",
          enforcementType: "allow",
          attackSignaturesCheck: true,
          maskValueInLogs: false,
          accessibleOnlyThroughTheHttpProtocol: false,
        },
      };

      const preset = presets[presetName];
      if (preset) {
        this.addCookie(preset);
      }
    },

    getCookieSettings() {
      if (!this.currentPolicy?.policy) return {};
      return this.currentPolicy.policy["cookie-settings"] || {};
    },

    updateCookieHeaderLength(val) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("cookie-settings", {});
      const parsed = parseInt(val, 10);
      if (isNaN(parsed) || parsed < 0) {
        delete this.currentPolicy.policy["cookie-settings"].maximumCookieHeaderLength;
        if (Object.keys(this.currentPolicy.policy["cookie-settings"]).length === 0) {
          delete this.currentPolicy.policy["cookie-settings"];
        }
      } else {
        this.currentPolicy.policy["cookie-settings"].maximumCookieHeaderLength = parsed;
      }
      this.markDirty();
      this.syncRawJson();
    },

    getEnforcerStateCookies() {
      if (!this.currentPolicy?.policy) return {};
      const enf = this.currentPolicy.policy["enforcer-settings"];
      if (!enf || typeof enf !== "object") return {};
      return enf.enforcerStateCookies || {};
    },

    updateEnforcerStateCookie(key, value) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("enforcer-settings", {});
      if (!this.currentPolicy.policy["enforcer-settings"].enforcerStateCookies) {
        this.currentPolicy.policy["enforcer-settings"].enforcerStateCookies = {};
      }
      this.currentPolicy.policy["enforcer-settings"].enforcerStateCookies[key] = value;
      this.markDirty();
      this.syncRawJson();
    },

    enforceAllCookieViolations() {
      const cookieViolations = [
        "VIOL_COOKIE_MALFORMED",
        "VIOL_COOKIE_MODIFIED",
        "VIOL_ASM_COOKIE_MODIFIED",
        "VIOL_COOKIE_EXPIRED",
      ];
      cookieViolations.forEach((violName) => {
        this.setViolationAlarm(violName, true);
        this.setViolationBlock(violName, true);
      });
      this.notify("Enforced all cookie violations (Alarm & Block active).", "success");
    },

    // -----------------------------------------------------------------
    // IP Address Lists (policy['ip-address-lists'])
    // -----------------------------------------------------------------
    getIpAddressLists() {
      if (!this.currentPolicy?.policy) return [];
      if (!Array.isArray(this.currentPolicy.policy["ip-address-lists"])) {
        return [];
      }
      return this.currentPolicy.policy["ip-address-lists"];
    },

    getFilteredIpAddressLists() {
      const list = this.getIpAddressLists();
      const q = (this.ipListSearch || "").trim().toLowerCase();
      if (!q) return list;
      return list.filter((item) => {
        const nameMatch = (item.name || "").toLowerCase().includes(q);
        const descMatch = (item.description || "").toLowerCase().includes(q);
        const blockMatch = (item.blockRequests || "").toLowerCase().includes(q);
        const geoMatch = (item.setGeolocation || "").toLowerCase().includes(q);
        const ipMatch = Array.isArray(item.ipAddresses) && item.ipAddresses.some((ipObj) => (ipObj.ipAddress || "").toLowerCase().includes(q));
        return nameMatch || descMatch || blockMatch || geoMatch || ipMatch;
      });
    },

    openAddIpListModal() {
      this.ipListForm = {
        name: "",
        description: "",
        blockRequests: "policy-default",
        setGeolocation: "",
        ipAddressesText: "",
        isEditing: false,
        editIndex: null,
      };
      this.showAddIpListModal = true;
    },

    openEditIpListModal(item, index) {
      if (!item) return;
      const ips = Array.isArray(item.ipAddresses) ? item.ipAddresses.map((x) => x.ipAddress || x).join("\n") : "";
      this.ipListForm = {
        name: item.name || "",
        description: item.description || "",
        blockRequests: item.blockRequests || "policy-default",
        setGeolocation: item.setGeolocation || "",
        ipAddressesText: ips,
        isEditing: true,
        editIndex: index,
      };
      this.showAddIpListModal = true;
    },

    saveIpList() {
      if (!this.currentPolicy?.policy) return;
      const name = (this.ipListForm.name || "").trim();
      if (!name) {
        this.notify("IP Address List Name is required.", "error");
        return;
      }
      this.ensurePolicySection("ip-address-lists", []);
      const lists = this.currentPolicy.policy["ip-address-lists"];

      const rawIps = (this.ipListForm.ipAddressesText || "")
        .split(/[\r\n,]+/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const ipAddressObjs = rawIps.map((ip) => ({ ipAddress: ip }));

      const obj = {
        name: name,
        blockRequests: this.ipListForm.blockRequests || "policy-default",
      };
      if (this.ipListForm.description?.trim()) {
        obj.description = this.ipListForm.description.trim();
      }
      if (this.ipListForm.setGeolocation?.trim()) {
        obj.setGeolocation = this.ipListForm.setGeolocation.trim().toUpperCase();
      }
      if (ipAddressObjs.length > 0) {
        obj.ipAddresses = ipAddressObjs;
      }

      this.markDirty();
      if (this.ipListForm.isEditing && this.ipListForm.editIndex !== null) {
        lists[this.ipListForm.editIndex] = obj;
        this.notify(`Updated IP address list '${name}'.`, "success");
      } else {
        lists.push(obj);
        this.notify(`Added IP address list '${name}' with ${ipAddressObjs.length} address(es).`, "success");
      }
      this.showAddIpListModal = false;
    },

    confirmDeleteIpList(index) {
      const lists = this.getIpAddressLists();
      if (index >= 0 && index < lists.length) {
        this.ipListToDelete = lists[index];
        this.ipListToDeleteIndex = index;
        this.showDeleteIpListModal = true;
      }
    },

    executeDeleteIpList() {
      if (this.ipListToDeleteIndex === null || !this.currentPolicy?.policy) {
        this.showDeleteIpListModal = false;
        return;
      }
      const lists = this.getIpAddressLists();
      if (this.ipListToDeleteIndex >= 0 && this.ipListToDeleteIndex < lists.length) {
        const removed = lists.splice(this.ipListToDeleteIndex, 1)[0];
        this.markDirty();
        this.notify(`Removed IP address list '${removed.name || "list"}'.`, "info");
      }
      this.showDeleteIpListModal = false;
      this.ipListToDelete = null;
      this.ipListToDeleteIndex = null;
    },

    toggleSelectAllIpLists() {
      const list = this.getFilteredIpAddressLists() || [];
      if (this.selectedIpLists.length === list.length && list.length > 0) {
        this.selectedIpLists = [];
      } else {
        this.selectedIpLists = list.map((l) => l.name);
      }
    },

    confirmMassDeleteIpLists() {
      if (!this.selectedIpLists || this.selectedIpLists.length === 0) {
        this.notify("No IP address lists selected.", "warning");
        return;
      }
      this.showMassDeleteIpListModal = true;
    },

    executeMassDeleteIpLists() {
      if (!this.currentPolicy?.policy || !this.selectedIpLists.length) {
        this.showMassDeleteIpListModal = false;
        return;
      }
      const lists = this.getIpAddressLists();
      const toRemove = new Set(this.selectedIpLists);
      const count = toRemove.size;
      this.currentPolicy.policy["ip-address-lists"] = lists.filter((l) => !toRemove.has(l.name));
      this.markDirty();
      this.selectedIpLists = [];
      this.showMassDeleteIpListModal = false;
      this.notify(`Successfully removed ${count} IP address list(s).`, "info");
    },

    applyIpListPreset(presetKey) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("ip-address-lists", []);
      const lists = this.currentPolicy.policy["ip-address-lists"];
      this.markDirty();

      if (presetKey === "whitelist") {
        lists.push({
          name: "trusted_corporate_network",
          description: "Internal corporate networks and VPN ranges exempt from policy default blocking",
          blockRequests: "never",
          ipAddresses: [
            { ipAddress: "10.0.0.0/8" },
            { ipAddress: "172.16.0.0/12" },
            { ipAddress: "192.168.0.0/16" },
          ],
        });
        this.notify("Added Trusted Corporate Network whitelist preset.", "success");
      } else if (presetKey === "blocklist") {
        lists.push({
          name: "known_malicious_actors",
          description: "Strict IP blocklist always blocked regardless of signature evaluation",
          blockRequests: "always",
          ipAddresses: [
            { ipAddress: "198.51.100.1" },
            { ipAddress: "203.0.113.50" },
          ],
        });
        this.notify("Added Known Malicious Actors blocklist preset.", "success");
      }
    },

    // -----------------------------------------------------------------
    // Response Signatures & HTTP Response Inspection Settings
    // -----------------------------------------------------------------
    getResponseCheck() {
      return this.currentPolicy?.policy?.general?.responseCheck ?? false;
    },

    toggleResponseCheck() {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("general", {});
      if (typeof this.currentPolicy.policy.general !== "object") {
        this.currentPolicy.policy.general = {};
      }
      this.markDirty();
      const current = !!this.currentPolicy.policy.general.responseCheck;
      this.currentPolicy.policy.general.responseCheck = !current;
      this.notify(`HTTP Response Inspection ${!current ? "Enabled" : "Disabled"}.`, "info");
    },

    getResponseCheckLength() {
      return this.currentPolicy?.policy?.general?.responseCheckLength ?? 20000;
    },

    setResponseCheckLength(val) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("general", {});
      this.markDirty();
      this.currentPolicy.policy.general.responseCheckLength = parseInt(val, 10) || 20000;
    },

    getAllowedResponseCodes() {
      const g = this.currentPolicy?.policy?.general;
      if (Array.isArray(g?.allowedResponseCodes)) {
        return g.allowedResponseCodes;
      }
      return [200, 201, 202, 204, 206, 301, 302, 304, 307, 308];
    },

    addAllowedResponseCode(code) {
      if (!this.currentPolicy?.policy) return;
      const num = parseInt(code, 10);
      if (isNaN(num) || num < 100 || num > 599) {
        this.notify("Invalid HTTP status code (must be 100-599).", "error");
        return;
      }
      this.ensurePolicySection("general", {});
      if (!Array.isArray(this.currentPolicy.policy.general.allowedResponseCodes)) {
        this.currentPolicy.policy.general.allowedResponseCodes = [...this.getAllowedResponseCodes()];
      }
      const codes = this.currentPolicy.policy.general.allowedResponseCodes;
      if (codes.includes(num)) {
        this.notify(`Status code ${num} is already allowed.`, "warning");
        return;
      }
      this.markDirty();
      codes.push(num);
      codes.sort((a, b) => a - b);
      this.notify(`Added HTTP status code ${num} to allowed responses.`, "success");
      this.newAllowedResponseCodeInput = "";
    },

    removeAllowedResponseCode(code) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("general", {});
      if (!Array.isArray(this.currentPolicy.policy.general.allowedResponseCodes)) {
        this.currentPolicy.policy.general.allowedResponseCodes = [...this.getAllowedResponseCodes()];
      }
      const codes = this.currentPolicy.policy.general.allowedResponseCodes;
      const idx = codes.indexOf(code);
      if (idx !== -1) {
        this.markDirty();
        codes.splice(idx, 1);
        this.notify(`Removed HTTP status code ${code} from allowed responses.`, "info");
      }
    },

    // -----------------------------------------------------------------
    // Evasion Techniques (policy['blocking-settings']['evasions'])
    // -----------------------------------------------------------------
    getStandardEvasionsList() {
      return [
        { description: "Bad unescape", maxDecodingPasses: null },
        { description: "Directory traversals", maxDecodingPasses: null },
        { description: "Bare byte decoding", maxDecodingPasses: null },
        { description: "Apache whitespace", maxDecodingPasses: null },
        { description: "Multiple decoding", maxDecodingPasses: 2 },
        { description: "IIS Unicode codepoints", maxDecodingPasses: null },
        { description: "IIS backslashes", maxDecodingPasses: null },
        { description: "%u decoding", maxDecodingPasses: null },
      ];
    },

    getEvasions() {
      const bs = this.currentPolicy?.policy?.["blocking-settings"];
      if (Array.isArray(bs?.evasions)) {
        return bs.evasions;
      }
      return [];
    },

    getEvasionsCount() {
      const evasions = this.getEvasions();
      return evasions.filter((e) => e.enabled !== false).length;
    },

    isEvasionEnabled(description) {
      const evs = this.getEvasions();
      const match = evs.find((e) => (e.description || "").toLowerCase() === description.toLowerCase());
      return match ? match.enabled !== false : false;
    },

    isEvasionLearn(description) {
      const evs = this.getEvasions();
      const match = evs.find((e) => (e.description || "").toLowerCase() === description.toLowerCase());
      return match ? !!match.learn : false;
    },

    getMultipleDecodingPasses() {
      const evs = this.getEvasions();
      const md = evs.find((e) => (e.description || "").toLowerCase() === "multiple decoding");
      return md?.maxDecodingPasses ?? 2;
    },

    setMultipleDecodingPasses(passes) {
      if (!this.currentPolicy?.policy) return;
      const num = parseInt(passes, 10) || 2;
      this.ensurePolicySection("blocking-settings", {});
      if (!Array.isArray(this.currentPolicy.policy["blocking-settings"].evasions)) {
        this.currentPolicy.policy["blocking-settings"].evasions = [];
      }
      const evs = this.currentPolicy.policy["blocking-settings"].evasions;
      let md = evs.find((e) => (e.description || "").toLowerCase() === "multiple decoding");
      this.markDirty();
      if (md) {
        md.maxDecodingPasses = num;
      } else {
        evs.push({ description: "Multiple decoding", enabled: true, learn: false, maxDecodingPasses: num });
      }
    },

    toggleEvasionEnabled(description) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("blocking-settings", {});
      if (!Array.isArray(this.currentPolicy.policy["blocking-settings"].evasions)) {
        this.currentPolicy.policy["blocking-settings"].evasions = [];
      }
      const evs = this.currentPolicy.policy["blocking-settings"].evasions;
      let match = evs.find((e) => (e.description || "").toLowerCase() === description.toLowerCase());
      this.markDirty();
      if (match) {
        match.enabled = !match.enabled;
      } else {
        const standard = this.getStandardEvasionsList().find((s) => s.description.toLowerCase() === description.toLowerCase());
        const newObj = {
          description: description,
          enabled: true,
          learn: false,
        };
        if (standard?.maxDecodingPasses !== null && standard?.maxDecodingPasses !== undefined) {
          newObj.maxDecodingPasses = standard.maxDecodingPasses;
        }
        evs.push(newObj);
      }
    },

    toggleEvasionLearn(description) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("blocking-settings", {});
      if (!Array.isArray(this.currentPolicy.policy["blocking-settings"].evasions)) {
        this.currentPolicy.policy["blocking-settings"].evasions = [];
      }
      const evs = this.currentPolicy.policy["blocking-settings"].evasions;
      let match = evs.find((e) => (e.description || "").toLowerCase() === description.toLowerCase());
      this.markDirty();
      if (match) {
        match.learn = !match.learn;
      } else {
        const standard = this.getStandardEvasionsList().find((s) => s.description.toLowerCase() === description.toLowerCase());
        const newObj = {
          description: description,
          enabled: true,
          learn: true,
        };
        if (standard?.maxDecodingPasses !== null && standard?.maxDecodingPasses !== undefined) {
          newObj.maxDecodingPasses = standard.maxDecodingPasses;
        }
        evs.push(newObj);
      }
    },

    applyEvasionsPreset(preset) {
      if (!this.currentPolicy?.policy) return;
      this.ensurePolicySection("blocking-settings", {});
      this.markDirty();
      const standardList = this.getStandardEvasionsList();

      if (preset === "all_enabled") {
        this.currentPolicy.policy["blocking-settings"].evasions = standardList.map((s) => {
          const item = { description: s.description, enabled: true, learn: false };
          if (s.maxDecodingPasses !== null) item.maxDecodingPasses = s.maxDecodingPasses;
          return item;
        });
        this.notify("Applied standard preset: all 8 evasion techniques enabled.", "success");
      } else if (preset === "strict") {
        this.currentPolicy.policy["blocking-settings"].evasions = standardList.map((s) => {
          const item = { description: s.description, enabled: true, learn: false };
          if (s.maxDecodingPasses !== null) item.maxDecodingPasses = 3;
          return item;
        });
        this.notify("Applied strict evasion preset: 3 decoding passes and all evasions active.", "success");
      } else if (preset === "all_disabled") {
        this.currentPolicy.policy["blocking-settings"].evasions = standardList.map((s) => {
          const item = { description: s.description, enabled: false, learn: false };
          if (s.maxDecodingPasses !== null) item.maxDecodingPasses = s.maxDecodingPasses;
          return item;
        });
        this.notify("Disabled all evasion technique checks.", "info");
      }
    },

    formatLogJson() {
      if (window.LOG_EDITOR) {
        const ok = window.LOG_EDITOR.format();
        if (ok) {
          this.notify("JSON formatted successfully", "info");
        } else {
          this.notify("Unable to format: Syntax error", "error");
        }
      }
    },

    // =========================================================================
    // CLICKHOUSE VIOLATION LOGS & WAF POLICY FINE-TUNING
    // =========================================================================

    async loadClickHouseSchema() {
      try {
        const res = await fetch("/api/clickhouse/schema");
        if (!res.ok) return;
        const data = await res.json();
        const tables = data.tables || {};
        this.chSchema = {
          tables,
          operators: data.operators || [],
          correlation_key: data.correlation_key || "support_id",
        };
        if (tables.v4_security_events && Array.isArray(tables.v4_security_events.columns)) {
          this.chSchemaEventsColumns = tables.v4_security_events.columns;
        }
        if (
          tables.v4_security_events_violation_data &&
          Array.isArray(tables.v4_security_events_violation_data.columns)
        ) {
          this.chSchemaViolationColumns = tables.v4_security_events_violation_data.columns.map(
            (c) => (typeof c === "string" ? c : c.name)
          );
        }
        if (
          tables.v4_security_events_signatures_data &&
          Array.isArray(tables.v4_security_events_signatures_data.columns)
        ) {
          this.chSchemaSignaturesColumns = tables.v4_security_events_signatures_data.columns.map(
            (c) => (typeof c === "string" ? c : c.name)
          );
        }
        if (Array.isArray(data.operators) && data.operators.length > 0) {
          this.chFilterOperators = data.operators.map((op) => ({
            id: op.id || op.op,
            label: op.label,
          }));
        }
      } catch (e) {
        console.warn("Failed to load ClickHouse schema:", e);
      }
    },

    async loadClickHouseStatus(ping = true) {
      try {
        const res = await fetch(`/api/clickhouse/status?ping=${ping ? "true" : "false"}`);
        if (!res.ok) return;
        const data = await res.json();
        const cfg = data.config || {};
        this.chStatus = {
          configured: !!data.configured,
          connected: !!data.connected,
          version: data.version || "",
          database: data.database || cfg.database || "nms",
          error: data.error || null,
          persisted_in_redis: !!(data.persisted_in_redis || cfg.persisted_in_redis),
          tables: data.tables || {},
          config: {
            host: cfg.host || "",
            port: cfg.port || 8123,
            username: cfg.username || "default",
            database: data.database || cfg.database || "nms",
            ssl: !!cfg.ssl,
            verify_ssl: cfg.verify_ssl !== undefined ? !!cfg.verify_ssl : false,
            has_password: !!cfg.has_password,
            persisted_in_redis: !!(data.persisted_in_redis || cfg.persisted_in_redis),
          },
        };
        this.chConfig = {
          host: cfg.host || "",
          port: cfg.port || 8123,
          username: cfg.username || "default",
          password: "",
          has_password: !!cfg.has_password,
          database: data.database || cfg.database || "nms",
          ssl: !!cfg.ssl,
          verify_ssl: cfg.verify_ssl !== undefined ? !!cfg.verify_ssl : false,
        };
        if (!this.chConfigForm.host && cfg.host) {
          this.chConfigForm = {
            host: cfg.host || "",
            port: cfg.port || 8123,
            username: cfg.username || "default",
            password: "",
            database: data.database || cfg.database || "nms",
            ssl: !!cfg.ssl,
            verify_ssl: cfg.verify_ssl !== undefined ? !!cfg.verify_ssl : false,
          };
        }
      } catch (e) {
        console.warn("Failed to load ClickHouse status:", e);
      }
    },

    async openClickHouseModal() {
      this.chModalError = "";
      this.chModalSuccess = "";
      this.chTestResult = null;
      this.showClickHouseModal = false;
      await this.switchSection("configuration", "clickhouse");
    },

    async testClickHouseConnection() {
      this.chTesting = true;
      this.chModalError = "";
      this.chModalSuccess = "";
      this.chTestResult = null;
      try {
        const payload = {
          host: (this.chConfigForm.host || "").trim(),
          port: parseInt(this.chConfigForm.port, 10) || 8123,
          username: (this.chConfigForm.username || "default").trim(),
          password: this.chConfigForm.password || "",
          database: (this.chConfigForm.database || "nms").trim(),
          ssl: !!this.chConfigForm.ssl,
          verify_ssl: !!this.chConfigForm.verify_ssl,
        };
        const res = await fetch("/api/clickhouse/test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          const errMsg = data.detail || "Connection test failed.";
          this.chModalError = errMsg;
          this.chTestResult = { connected: false, error: errMsg };
          return;
        }
        this.chTestResult = data;
        this.chStatus = {
          ...this.chStatus,
          configured: !!data.configured,
          connected: !!data.connected,
          version: data.version || "",
          database: data.database || payload.database,
          error: data.error || null,
          tables: data.tables || {},
        };
        if (data.connected) {
          const resolvedDb = data.database || payload.database;
          if (data.database) {
            this.chConfigForm.database = data.database;
          }
          const tableCount = Object.values(data.tables || {}).filter((t) => t && t.exists).length;
          this.chModalSuccess = `Connected to ClickHouse ${data.version || ""} (${tableCount}/3 WAF tables found in '${resolvedDb}').`;
        } else {
          this.chModalError = data.error || "Could not connect to ClickHouse.";
        }
      } catch (e) {
        this.chModalError = `Connection error: ${e.message}`;
        this.chTestResult = { connected: false, error: e.message };
      } finally {
        this.chTesting = false;
      }
    },

    async saveClickHouseConfig() {
      this.chSaving = true;
      this.chModalError = "";
      this.chModalSuccess = "";
      this.chTestResult = null;
      try {
        const payload = {
          host: (this.chConfigForm.host || "").trim(),
          port: parseInt(this.chConfigForm.port, 10) || 8123,
          username: (this.chConfigForm.username || "default").trim(),
          password: this.chConfigForm.password || "",
          database: (this.chConfigForm.database || "nms").trim(),
          ssl: !!this.chConfigForm.ssl,
          verify_ssl: !!this.chConfigForm.verify_ssl,
        };
        const res = await fetch("/api/clickhouse/config", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          const errMsg = data.detail || "Failed to save ClickHouse configuration.";
          this.chModalError = errMsg;
          this.chTestResult = { connected: false, error: errMsg };
          return;
        }
        const connInfo = data.connection || data;
        this.chTestResult = connInfo;
        const cfg = data.config || {};
        const resolvedDb = connInfo.database || cfg.database || payload.database || "nms";
        this.chStatus = {
          configured: !!data.configured,
          connected: !!data.connected,
          version: data.version || connInfo.version || "",
          database: resolvedDb,
          error: data.error || null,
          persisted_in_redis: !!data.persisted_in_redis,
          tables: data.tables || connInfo.tables || {},
          config: {
            host: cfg.host || payload.host,
            port: cfg.port || payload.port,
            username: cfg.username || payload.username,
            database: resolvedDb,
            ssl: !!cfg.ssl,
            verify_ssl: !!cfg.verify_ssl,
            has_password: !!cfg.has_password,
            persisted_in_redis: !!data.persisted_in_redis,
          },
        };
        this.chConfig = {
          host: cfg.host || payload.host,
          port: cfg.port || payload.port,
          username: cfg.username || payload.username,
          password: "",
          has_password: !!cfg.has_password,
          database: resolvedDb,
          ssl: !!cfg.ssl,
          verify_ssl: !!cfg.verify_ssl,
        };
        this.chConfigForm.database = resolvedDb;

        const persistNote = data.persisted_in_redis
          ? "Saved & persisted in Redis across reboots."
          : "Saved in memory (connect Redis to persist across reboots).";
        if (data.connected) {
          this.chModalSuccess = `Connected to ClickHouse ${data.version || ""}. ${persistNote}`;
          this.chError = null;
          this.notify(`ClickHouse connected (${this.chConfig.host}:${this.chConfig.port})`, "success");
          if (this.activeSection === "violations") {
            await this.searchClickHouseEvents(true);
          }
        } else {
          this.chModalError = `Configuration saved (${persistNote}), but connection failed: ${data.error || "Unknown error"}`;
        }
      } catch (e) {
        this.chModalError = `Failed to save config: ${e.message}`;
        this.chTestResult = { connected: false, error: e.message };
      } finally {
        this.chSaving = false;
      }
    },

    addChFieldFilter(defaultField = "", defaultOp = "contains", defaultVal = "") {
      const col =
        (defaultField || "").trim() ||
        (this.chNewFilter && this.chNewFilter.column ? this.chNewFilter.column.trim() : "") ||
        (this.chSchemaEventsColumns.length > 0 ? this.chSchemaEventsColumns[0].name : "support_id");
      const op =
        defaultOp ||
        (this.chNewFilter && this.chNewFilter.operator ? this.chNewFilter.operator : "contains");
      const val =
        defaultVal ||
        (this.chNewFilter && this.chNewFilter.value ? this.chNewFilter.value.trim() : "");
      this.chFieldFilters.push({
        field: col,
        column: col,
        operator: op,
        value: op === "is_empty" || op === "is_not_empty" ? "" : val,
      });
      if (val || op === "is_empty" || op === "is_not_empty") {
        this.searchClickHouseEvents(true);
      }
    },

    removeChFieldFilter(idx) {
      this.chFieldFilters.splice(idx, 1);
      this.searchClickHouseEvents(true);
    },

    addQuickFieldFilterFromCell(column, value) {
      if (!column || value === undefined || value === null) return;
      const strVal = String(value);
      const exists = this.chFieldFilters.some(
        (f) => (f.field === column || f.column === column) && f.operator === "equals" && f.value === strVal
      );
      if (!exists) {
        this.chFieldFilters.push({
          field: column,
          column: column,
          operator: "equals",
          value: strVal,
        });
        this.notify(`Added filter: ${column} = ${strVal}`, "info");
        this.searchClickHouseEvents(true);
      }
    },

    resetChFilters() {
      this.chGlobalSearch = "";
      this.chQuickFilters = {
        support_id: "",
        policy_name: "",
        request_status: "",
        severity: "",
        http__request_method: "",
        http__uri: "",
        http__remote_addr: "",
        violations: "",
        signature_ids: "",
      };
      this.chFieldFilters = [];
      this.chOffset = 0;
      if (this.chStatus.configured) {
        this.searchClickHouseEvents(true);
      }
    },

    resetChVisibleColumns() {
      this.chVisibleColumns = [
        "timestamp",
        "support_id",
        "policy_name",
        "request_status",
        "severity",
        "http__request_method",
        "http__uri",
        "http__remote_addr",
        "violation_rating",
        "violations",
        "signature_ids",
        "signature_names",
      ];
    },

    toggleChSort(col) {
      if (this.chSortBy === col) {
        const nextDir = (this.chSortOrder || this.chSortDir) === "DESC" ? "ASC" : "DESC";
        this.chSortOrder = nextDir;
        this.chSortDir = nextDir;
      } else {
        this.chSortBy = col;
        this.chSortOrder = "DESC";
        this.chSortDir = "DESC";
      }
      this.searchClickHouseEvents(false);
    },

    chPrevPage() {
      const step = parseInt(this.chLimit, 10) || 50;
      this.chOffset = Math.max(0, this.chOffset - step);
      this.searchClickHouseEvents(false);
    },

    chNextPage() {
      const step = parseInt(this.chLimit, 10) || 50;
      if (this.chOffset + step < this.chTotalEvents) {
        this.chOffset += step;
        this.searchClickHouseEvents(false);
      }
    },

    async searchClickHouseEvents(resetOffset = true) {
      if (resetOffset) {
        this.chOffset = 0;
      }
      this.chLoading = true;
      this.chError = "";

      try {
        // Combine custom 53-column filters + quick filters
        const combinedFilters = (this.chFieldFilters || [])
          .map((f) => {
            const colName = (f.field || f.column || "").trim();
            const opName = (f.operator || "contains").trim();
            const valStr = f.value !== undefined && f.value !== null ? String(f.value).trim() : "";
            return { field: colName, column: colName, operator: opName, value: valStr };
          })
          .filter(
            (f) =>
              f.column &&
              (f.operator === "is_empty" || f.operator === "is_not_empty" || f.value !== "")
          );

        const qf = this.chQuickFilters || {};
        if ((qf.support_id || "").trim()) {
          combinedFilters.push({ field: "support_id", column: "support_id", operator: "contains", value: qf.support_id.trim() });
        }
        if ((qf.policy_name || "").trim()) {
          combinedFilters.push({ field: "policy_name", column: "policy_name", operator: "contains", value: qf.policy_name.trim() });
        }
        if ((qf.request_status || "").trim()) {
          combinedFilters.push({ field: "request_status", column: "request_status", operator: "equals", value: qf.request_status.trim() });
        }
        if ((qf.severity || "").trim()) {
          combinedFilters.push({ field: "severity", column: "severity", operator: "equals", value: qf.severity.trim() });
        }
        if ((qf.http__request_method || "").trim()) {
          combinedFilters.push({ field: "http__request_method", column: "http__request_method", operator: "equals", value: qf.http__request_method.trim() });
        }
        if ((qf.http__uri || "").trim()) {
          combinedFilters.push({ field: "http__uri", column: "http__uri", operator: "contains", value: qf.http__uri.trim() });
        }
        if ((qf.http__remote_addr || "").trim()) {
          combinedFilters.push({ field: "http__remote_addr", column: "http__remote_addr", operator: "contains", value: qf.http__remote_addr.trim() });
        }
        if ((qf.violations || "").trim()) {
          combinedFilters.push({ field: "violations", column: "violations", operator: "contains", value: qf.violations.trim() });
        }
        if ((qf.signature_ids || "").trim()) {
          combinedFilters.push({ field: "signature_ids", column: "signature_ids", operator: "contains", value: qf.signature_ids.trim() });
        }

        const sortDirection = this.chSortOrder || this.chSortDir || "DESC";
        const payload = {
          global_search: (this.chGlobalSearch || "").trim(),
          filters: combinedFilters,
          field_filters: combinedFilters,
          limit: parseInt(this.chLimit, 10) || 50,
          offset: this.chOffset || 0,
          sort_by: this.chSortBy || "timestamp",
          sort_order: sortDirection,
          sort_dir: sortDirection,
        };

        const res = await fetch("/api/clickhouse/events/search", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          this.chError = data.detail || "Failed to query ClickHouse security events.";
          this.chEvents = [];
          this.chTotalEvents = 0;
          return;
        }
        this.chEvents = data.rows || data.events || [];
        this.chTotalEvents = data.total || 0;
        this.chExecutedQuery = data.query || "";
        this.chStatus.connected = true;

        // If previously correlated support_id is no longer in the filtered results, clear or correlate first row
        if (this.chEvents.length === 0) {
          this.chSelectedSupportId = null;
          this.chCorrelated = null;
          this.chCorrelatedData = null;
        } else if (this.chSelectedSupportId) {
          const stillPresent = this.chEvents.some(
            (r) => String(r.support_id) === String(this.chSelectedSupportId)
          );
          if (!stillPresent) {
            this.chSelectedSupportId = null;
            this.chCorrelated = null;
            this.chCorrelatedData = null;
          }
        }
      } catch (e) {
        this.chError = `Error querying ClickHouse: ${e.message}`;
      } finally {
        this.chLoading = false;
      }
    },

    resolvePolicyNameFromLog(rawPolicyName) {
      if (!rawPolicyName) return "";
      const clean = String(rawPolicyName).trim();
      if (!clean || clean.toUpperCase() === "N/A") return "";
      const list = Array.isArray(this.policies) ? this.policies : [];
      // 1. Exact match
      const exact = list.find((p) => p && p.name === clean);
      if (exact) return exact.name;
      // 2. Case-insensitive match
      const lower = clean.toLowerCase();
      const ci = list.find((p) => p && String(p.name || "").toLowerCase() === lower);
      if (ci) return ci.name;
      // 3. Normalized basename without path or .json suffix
      const norm = (s) =>
        String(s || "")
          .trim()
          .replace(/^.*[/\\]/, "")
          .replace(/\.json$/i, "")
          .toLowerCase();
      const cleanNorm = norm(clean);
      const normMatch = list.find((p) => p && norm(p.name) === cleanNorm);
      if (normMatch) return normMatch.name;
      return "";
    },

    async correlateClickHouseEvent(supportId, ev = null, userInitiated = true) {
      if (!supportId) return;
      const cleanId = String(supportId).trim();
      this.chSelectedSupportId = cleanId;
      this.chCorrelating = true;

      try {
        if (!Array.isArray(this.policies) || this.policies.length === 0) {
          await this.loadPolicies();
        }

        // Automatically select the policy matching the violation's policy_name field
        const selectedRow =
          ev ||
          (Array.isArray(this.chEvents)
            ? this.chEvents.find((r) => String(r.support_id) === cleanId)
            : null);
        const rowPolicyRaw =
          selectedRow &&
          selectedRow.policy_name &&
          String(selectedRow.policy_name).trim() !== "" &&
          String(selectedRow.policy_name).trim().toUpperCase() !== "N/A"
            ? String(selectedRow.policy_name).trim()
            : "";

        if (rowPolicyRaw) {
          this.chInspectorLogPolicyName = rowPolicyRaw;
          const matchedFromRow = this.resolvePolicyNameFromLog(rowPolicyRaw);
          this.chTargetPolicy = matchedFromRow || rowPolicyRaw;
        } else {
          this.chInspectorLogPolicyName = "";
        }

        const qs = this.chTargetPolicy
          ? `?policy_name=${encodeURIComponent(this.chTargetPolicy)}`
          : "";
        const res = await fetch(
          `/api/clickhouse/events/${encodeURIComponent(cleanId)}/correlate${qs}`
        );
        const data = await res.json();
        if (!res.ok) {
          this.notify(data.detail || `Failed to correlate support_id ${cleanId}`, "error");
          return;
        }
        this.chCorrelated = data;
        this.chCorrelatedData = data;
        this.chSignatureStates = data.policy_signature_states || {};

        // Ensure policy_name from the correlated violation log is always auto-selected
        const logPolicyFromData =
          (data.log_policy_name && String(data.log_policy_name).trim()) ||
          (data.event_summary &&
            data.event_summary.policy_name &&
            String(data.event_summary.policy_name).trim()) ||
          rowPolicyRaw ||
          "";
        const cleanLogPolicy =
          logPolicyFromData && logPolicyFromData.toUpperCase() !== "N/A"
            ? logPolicyFromData
            : "";

        if (cleanLogPolicy) {
          this.chInspectorLogPolicyName = cleanLogPolicy;
          const resolvedPolicy =
            data.matched_log_policy_name ||
            this.resolvePolicyNameFromLog(cleanLogPolicy) ||
            data.matched_policy_name ||
            cleanLogPolicy;
          if (resolvedPolicy && resolvedPolicy !== this.chTargetPolicy) {
            this.chTargetPolicy = resolvedPolicy;
            await this.onChTargetPolicyChange();
          } else if (resolvedPolicy) {
            this.chTargetPolicy = resolvedPolicy;
          }
        } else if (data.matched_policy_name) {
          this.chTargetPolicy = data.matched_policy_name;
        } else if (!this.chTargetPolicy && this.policies.length > 0) {
          this.chTargetPolicy = this.policies[0].name;
        }

        if (userInitiated) {
          this.$nextTick(() => {
            const el = document.getElementById("ch-correlation-panel");
            if (el && typeof el.scrollIntoView === "function") {
              el.scrollIntoView({ behavior: "smooth", block: "nearest" });
            }
          });
        }
      } catch (e) {
        this.notify(`Correlation error: ${e.message}`, "error");
      } finally {
        this.chCorrelating = false;
      }
    },

    _applySignatureStatesToCorrelated(statesMap) {
      const corr = this.chCorrelatedData || this.chCorrelated;
      if (!corr) return;
      const defaultStateFor = (sigId) => ({
        signatureId: /^\d+$/.test(String(sigId)) ? parseInt(String(sigId), 10) : sigId,
        in_policy: false,
        status: "default",
        enabled: null,
        tag: null,
      });
      if (Array.isArray(corr.signatures_data)) {
        corr.signatures_data = corr.signatures_data.map((row) => {
          const sid = String(row.signature_id || "").trim();
          return {
            ...row,
            policy_override: statesMap[sid] || defaultStateFor(sid),
          };
        });
      }
      if (Array.isArray(corr.unique_signatures)) {
        corr.unique_signatures = corr.unique_signatures.map((row) => {
          const sid = String(row.signature_id || "").trim();
          return {
            ...row,
            policy_override: statesMap[sid] || defaultStateFor(sid),
          };
        });
      }
      this.chCorrelatedData = { ...corr };
      this.chCorrelated = this.chCorrelatedData;
    },

    async onChTargetPolicyChange() {
      this.chPolicySavedToRedis = false;
      this.chUnsavedTuningCount = 0;
      const corr = this.chCorrelatedData || this.chCorrelated;
      if (!this.chTargetPolicy || !corr) {
        this.chSignatureStates = {};
        if (corr) this._applySignatureStatesToCorrelated({});
        return;
      }
      const sigIds = (corr.unique_signatures || [])
        .map((s) => s.signature_id)
        .filter((id) => id !== undefined && id !== null && String(id).trim() !== "");
      if (sigIds.length === 0) {
        this.chSignatureStates = {};
        return;
      }
      try {
        const res = await fetch(
          `/api/clickhouse/policy/${encodeURIComponent(this.chTargetPolicy)}/signature-states?signature_ids=${encodeURIComponent(sigIds.join(","))}`
        );
        if (!res.ok) {
          this.chSignatureStates = {};
          return;
        }
        const data = await res.json();
        this.chSignatureStates = data.states || {};
        this._applySignatureStatesToCorrelated(this.chSignatureStates);
      } catch (e) {
        console.warn("Failed to load policy signature states:", e);
      }
    },

    async tuneSignatureInPolicy(sigOrId, enabled, actionOrName = "") {
      if (!this.chTargetPolicy) {
        this.notify("Please select a Target WAF Policy first.", "warn");
        return;
      }
      let rawId = sigOrId;
      let sigName = "";
      let action = "set";
      if (sigOrId && typeof sigOrId === "object") {
        rawId = sigOrId.signature_id ?? sigOrId.signatureId;
        sigName = sigOrId.signature_name || "";
        if (actionOrName === "remove" || enabled === null) {
          action = "remove";
        }
      } else {
        if (actionOrName === "remove" || enabled === null) {
          action = "remove";
        } else {
          sigName = actionOrName || "";
        }
      }

      const sigInt = parseInt(String(rawId).trim(), 10);
      if (isNaN(sigInt)) {
        this.notify(`Invalid signature_id: ${rawId}`, "error");
        return;
      }
      this.chTuningInProgress = true;
      this.chTuningBusy = true;
      try {
        const payload = {
          policy_name: this.chTargetPolicy,
          signature_id: sigInt,
          enabled: action === "remove" ? null : enabled,
          action: action,
          signature_name: sigName || null,
          support_id: this.chSelectedSupportId || null,
        };
        const res = await fetch("/api/clickhouse/policy/tune-signature", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          this.notify(data.detail || "Failed to update signature in policy.", "error");
          return;
        }

        // Update local signature state map and correlated rows immediately
        this.chSignatureStates = {
          ...this.chSignatureStates,
          [String(sigInt)]: data.signature_state,
        };
        this._applySignatureStatesToCorrelated(this.chSignatureStates);
        this.chUnsavedTuningCount = (this.chUnsavedTuningCount || 0) + 1;
        this.chPolicySavedToRedis = false;

        // If this policy is also currently loaded in the Policy Builder, refresh it safely
        await this.refreshLoadedPolicyIfMatching(data.policy_name || this.chTargetPolicy);
        await this.loadPolicies();

        const actionLabel =
          enabled === false
            ? "DISABLED (relaxed)"
            : enabled === true
            ? "ENABLED (enforced)"
            : "RESET to policy default";
        this.notify(`Signature ${sigInt} ${actionLabel} in policy '${data.policy_name || this.chTargetPolicy}'`, "success");
      } catch (e) {
        this.notify(`Failed to tune signature: ${e.message}`, "error");
      } finally {
        this.chTuningInProgress = false;
        this.chTuningBusy = false;
      }
    },

    async bulkTuneCorrelatedSignatures(enabled) {
      if (!this.chTargetPolicy) {
        this.notify("Please select a Target WAF Policy first.", "warn");
        return;
      }
      const corr = this.chCorrelatedData || this.chCorrelated;
      const uniqueSigs = (corr && corr.unique_signatures) || [];
      if (uniqueSigs.length === 0) {
        this.notify("No correlated signatures to update.", "warn");
        return;
      }
      this.chTuningInProgress = true;
      this.chTuningBusy = true;
      try {
        const payload = {
          policy_name: this.chTargetPolicy,
          support_id: this.chSelectedSupportId || null,
          signatures: uniqueSigs.map((s) => ({
            signature_id: parseInt(String(s.signature_id).trim(), 10),
            enabled: enabled,
            signature_name: s.signature_name || null,
          })),
        };
        const res = await fetch("/api/clickhouse/policy/tune-signatures-bulk", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          this.notify(data.detail || "Bulk signature update failed.", "error");
          return;
        }
        const updatedStates = { ...this.chSignatureStates };
        if (data.signature_states) {
          Object.assign(updatedStates, data.signature_states);
        }
        for (const item of data.updated || []) {
          const itemState = item.state || {
            signatureId: item.signature_id,
            in_policy: item.status !== "default",
            status: item.status,
            enabled: item.enabled,
            tag: item.tag || null,
          };
          updatedStates[String(item.signature_id)] = itemState;
        }
        this.chSignatureStates = updatedStates;
        this._applySignatureStatesToCorrelated(this.chSignatureStates);
        this.chUnsavedTuningCount = (this.chUnsavedTuningCount || 0) + uniqueSigs.length;
        this.chPolicySavedToRedis = false;

        await this.refreshLoadedPolicyIfMatching(data.policy_name || this.chTargetPolicy);
        await this.loadPolicies();

        const actionWord = enabled === false ? "Disabled" : enabled === true ? "Enabled" : "Reset";
        this.notify(
          `${actionWord} ${uniqueSigs.length} correlated signature(s) in policy '${data.policy_name || this.chTargetPolicy}'`,
          "success"
        );
      } catch (e) {
        this.notify(`Bulk tune error: ${e.message}`, "error");
      } finally {
        this.chTuningInProgress = false;
        this.chTuningBusy = false;
      }
    },

    async saveInspectorFineTuning() {
      return await this.saveTunedPolicyToRedis(this.chTargetPolicy, true);
    },

    async saveTunedPolicyToRedis(policyName = null, fromInspector = false) {
      const target = policyName || this.chTargetPolicy || this.chInspectorLogPolicyName;
      if (!target) {
        this.notify("Please select a WAF policy to save.", "warn");
        return;
      }
      const resolved =
        typeof this.resolvePolicyNameFromLog === "function"
          ? this.resolvePolicyNameFromLog(target) || target
          : target;

      this.chSavingPolicyToRedis = true;
      this.chTuningInProgress = true;
      try {
        // Collect any active correlated signature overrides from the inspector if open
        const corr = this.chCorrelatedData || this.chCorrelated;
        const signaturesPayload = [];
        if (corr && Array.isArray(corr.unique_signatures)) {
          for (const sig of corr.unique_signatures) {
            const sidStr = String(sig.signature_id || "").trim();
            const sigInt = parseInt(sidStr, 10);
            if (isNaN(sigInt)) continue;
            const st =
              (this.chSignatureStates && this.chSignatureStates[sidStr]) ||
              sig.policy_override ||
              null;
            if (st && st.in_policy && (st.enabled === true || st.enabled === false)) {
              signaturesPayload.push({
                signature_id: sigInt,
                enabled: st.enabled,
                action: "set",
                signature_name: sig.signature_name || null,
                tag: st.tag || null,
              });
            }
          }
        }

        const payload = {
          policy_name: resolved,
          support_id: this.chSelectedSupportId || null,
          signatures: signaturesPayload.length > 0 ? signaturesPayload : null,
        };

        const res = await fetch("/api/clickhouse/policy/save-to-redis", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          this.notify(data.detail || "Failed to save fine-tuned policy to Redis.", "error");
          return;
        }

        const savedName = data.policy_name || resolved;
        this.chTargetPolicy = savedName;
        this.chUnsavedTuningCount = 0;
        this.chPolicySavedToRedis = true;
        this.chLastSavedPolicyName = savedName;

        await this.refreshLoadedPolicyIfMatching(savedName);
        await this.loadPolicies();
        await this.checkStorageHealth(false);

        const msg = fromInspector
          ? `Fine-tuning changes saved for '${savedName}' to Redis (${data.total_signature_overrides ?? 0} signature overrides). Ready to commit to GitHub on the WAF Policies page.`
          : data.message || `Policy '${savedName}' saved to Redis and marked ready to commit to GitHub from the WAF Policies page.`;
        this.notify(msg, "success");
      } catch (e) {
        this.notify(`Failed to save policy to Redis: ${e.message}`, "error");
      } finally {
        this.chSavingPolicyToRedis = false;
        this.chTuningInProgress = false;
      }
    },

    async openPolicyFromTuning(policyName) {
      const target = policyName || this.chTargetPolicy || this.chInspectorLogPolicyName;
      if (!target) {
        this.notify("Please select a WAF policy to open.", "warn");
        return;
      }
      const resolved =
        typeof this.resolvePolicyNameFromLog === "function"
          ? this.resolvePolicyNameFromLog(target) || target
          : target;
      try {
        if (!Array.isArray(this.policies) || this.policies.length === 0) {
          await this.loadPolicies();
        }
        await this.openEditor(resolved, "visual");
        this.activeSection = "waf";
        this.view = "editor";
        this.activeTab = "signatures";
        await this.loadPolicies();
      } catch (e) {
        this.notify(`Failed to open policy '${resolved}': ${e.message}`, "error");
      }
    },

    formatRawHttpRequest(str) {
      if (!str) return "N/A";
      return String(str)
        .replace(/\\r\\n/g, "\n")
        .replace(/\\n/g, "\n")
        .replace(/\\t/g, "\t");
    },
  }));
});

