"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  AATP_VERSION: () => AATP_VERSION,
  AmorceAPIError: () => AmorceAPIError,
  AmorceClient: () => AmorceClient,
  AmorceConfigError: () => AmorceConfigError,
  AmorceEnvelope: () => AmorceEnvelope,
  AmorceError: () => AmorceError,
  AmorceNetworkError: () => AmorceNetworkError,
  AmorceResponseImpl: () => AmorceResponseImpl,
  AmorceSecurityError: () => AmorceSecurityError,
  AmorceValidationError: () => AmorceValidationError,
  EnvVarProvider: () => EnvVarProvider,
  Envelope: () => Envelope,
  IdentityManager: () => IdentityManager,
  MCPToolClient: () => MCPToolClient,
  PriorityLevel: () => PriorityLevel,
  SDK_VERSION: () => SDK_VERSION,
  createWellKnownHandler: () => createWellKnownHandler,
  fetchManifest: () => fetchManifest,
  generateManifestJson: () => generateManifestJson,
  serveWellKnown: () => serveWellKnown,
  verifyRequest: () => verifyRequest
});
module.exports = __toCommonJS(index_exports);

// src/exceptions.ts
var AmorceError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "AmorceError";
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
};
var AmorceConfigError = class extends AmorceError {
  constructor(message) {
    super(message);
    this.name = "AmorceConfigError";
  }
};
var AmorceNetworkError = class extends AmorceError {
  constructor(message) {
    super(message);
    this.name = "AmorceNetworkError";
  }
};
var AmorceAPIError = class extends AmorceError {
  constructor(message, statusCode, responseBody) {
    super(message);
    this.name = "AmorceAPIError";
    this.statusCode = statusCode;
    this.responseBody = responseBody;
  }
};
var AmorceSecurityError = class extends AmorceError {
  constructor(message) {
    super(message);
    this.name = "AmorceSecurityError";
  }
};
var AmorceValidationError = class extends AmorceError {
  constructor(message) {
    super(message);
    this.name = "AmorceValidationError";
  }
};

// src/identity.ts
var import_libsodium_wrappers = __toESM(require("libsodium-wrappers"));
var EnvVarProvider = class {
  constructor(envVarName = "AGENT_PRIVATE_KEY") {
    this.envVarName = envVarName;
  }
  async getPrivateKey() {
    await import_libsodium_wrappers.default.ready;
    let pemData;
    if (typeof process !== "undefined" && process.env) {
      pemData = process.env[this.envVarName];
    }
    if (!pemData) {
      throw new AmorceSecurityError(`Environment variable ${this.envVarName} is not set.`);
    }
    pemData = pemData.replace(/\\n/g, "\n");
    try {
      return this.pemToPrivateKey(pemData);
    } catch (e) {
      throw new AmorceSecurityError(`Failed to load key from environment variable: ${e}`);
    }
  }
  pemToPrivateKey(pem) {
    const b64 = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace(/\s/g, "");
    const fullBytes = import_libsodium_wrappers.default.from_base64(b64, import_libsodium_wrappers.default.base64_variants.ORIGINAL);
    if (fullBytes.length >= 48) {
      return fullBytes.slice(16, 48);
    }
    throw new AmorceSecurityError("Invalid private key format");
  }
};
var IdentityManager = class _IdentityManager {
  constructor(privateKey, publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }
  /**
   * Initializes from a provider (flexible key source).
   */
  static async fromProvider(provider) {
    await import_libsodium_wrappers.default.ready;
    const privateKey = await provider.getPrivateKey();
    const keypair = import_libsodium_wrappers.default.crypto_sign_seed_keypair(privateKey);
    return new _IdentityManager(keypair.privateKey, keypair.publicKey);
  }
  /**
   * Factory method: Generates a new ephemeral Ed25519 identity in memory.
   * Matches Python's IdentityManager.generate_ephemeral()
   */
  static async generate() {
    await import_libsodium_wrappers.default.ready;
    const keypair = import_libsodium_wrappers.default.crypto_sign_keypair();
    return new _IdentityManager(keypair.privateKey, keypair.publicKey);
  }
  /**
   * Legacy method: Loads an identity from a raw private key (Uint8Array).
   * Kept for backward compatibility.
   */
  static async fromPrivateKey(privateKey) {
    await import_libsodium_wrappers.default.ready;
    const publicKey = import_libsodium_wrappers.default.crypto_sign_ed25519_sk_to_pk(privateKey);
    return new _IdentityManager(privateKey, publicKey);
  }
  /**
   * Signs a message (string or bytes) and returns the signature in Base64.
   */
  async sign(message) {
    await import_libsodium_wrappers.default.ready;
    const signature = import_libsodium_wrappers.default.crypto_sign_detached(message, this.privateKey);
    return import_libsodium_wrappers.default.to_base64(signature, import_libsodium_wrappers.default.base64_variants.ORIGINAL);
  }
  /**
   * Verifies a signature against a public key.
   * Static utility for validation.
   */
  static async verify(message, signatureBase64, publicKey) {
    await import_libsodium_wrappers.default.ready;
    try {
      const signature = import_libsodium_wrappers.default.from_base64(signatureBase64, import_libsodium_wrappers.default.base64_variants.ORIGINAL);
      return import_libsodium_wrappers.default.crypto_sign_verify_detached(signature, message, publicKey);
    } catch (e) {
      return false;
    }
  }
  /**
   * Exports the Public Key to PEM format (PKIX).
   * Matches Python's serialization.PublicFormat.SubjectPublicKeyInfo
   */
  getPublicKeyPem() {
    const prefix = new Uint8Array([
      48,
      42,
      // Sequence, length 42
      48,
      5,
      // Sequence, length 5
      6,
      3,
      43,
      101,
      112,
      // OID: 1.3.101.112 (Ed25519)
      3,
      33,
      0
      // Bit String, length 33, 0 padding
    ]);
    const combined = new Uint8Array(prefix.length + this.publicKey.length);
    combined.set(prefix);
    combined.set(this.publicKey, prefix.length);
    const b64 = import_libsodium_wrappers.default.to_base64(combined, import_libsodium_wrappers.default.base64_variants.ORIGINAL);
    return `-----BEGIN PUBLIC KEY-----
${b64}
-----END PUBLIC KEY-----
`;
  }
  /**
   * MCP 1.0: Deterministic Agent ID derivation.
   * Returns the SHA-256 hash of the public key PEM.
   * This ensures the ID is cryptographically bound to the key.
   * Matches Python SDK behavior.
   */
  getAgentId() {
    const cleanPem = this.getPublicKeyPem().trim();
    if (typeof require !== "undefined") {
      try {
        const crypto = require("crypto");
        return crypto.createHash("sha256").update(cleanPem, "utf-8").digest("hex");
      } catch (e) {
      }
    }
    throw new Error("Agent ID derivation requires Node.js crypto module");
  }
  /**
   * Returns the canonical JSON byte representation for signing.
   * Strict: sort_keys=True, no whitespace.
   * Matches Python's get_canonical_json_bytes()
   */
  static getCanonicalJsonBytes(payload) {
    const stringify2 = require("fast-json-stable-stringify");
    const jsonStr = stringify2(payload);
    return new TextEncoder().encode(jsonStr);
  }
  /**
   * Generate agent manifest JSON for registration.
   * This creates a signed manifest that can be submitted to the Trust Directory.
   * 
   * @param options - Manifest options
   * @returns JSON string of the manifest
   * 
   * @example
   * ```typescript
   * const identity = await IdentityManager.generate();
   * const manifest = identity.toManifestJson({
   *   name: 'My Restaurant Bot',
   *   endpoint: 'https://api.example.com/webhook',
   *   capabilities: ['book_table', 'check_availability'],
   *   description: 'Fine dining reservations'
   * });
   * 
   * // Save or submit to Trust Directory
   * fs.writeFileSync('manifest.json', manifest);
   * ```
   */
  toManifestJson(options) {
    const manifest = {
      agent_id: this.getAgentId(),
      name: options.name,
      public_key: this.getPublicKeyPem(),
      endpoint: options.endpoint,
      capabilities: options.capabilities,
      description: options.description || "",
      version: "1.0",
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    };
    return JSON.stringify(manifest, null, 2);
  }
};

// src/envelope.ts
var import_fast_json_stable_stringify = __toESM(require("fast-json-stable-stringify"));
var import_uuid = require("uuid");
var import_libsodium_wrappers2 = __toESM(require("libsodium-wrappers"));
var AmorceEnvelope = class _AmorceEnvelope {
  constructor(sender, payload, priority = "normal") {
    this.natp_version = "0.1.0";
    if (!["normal", "high", "critical"].includes(priority)) {
      throw new AmorceValidationError(
        `Invalid priority: ${priority}. Must be 'normal', 'high', or 'critical'.`
      );
    }
    this.id = (0, import_uuid.v4)();
    this.priority = priority;
    this.timestamp = Date.now() / 1e3;
    this.sender = sender;
    this.payload = payload;
    this.settlement = { amount: 0, currency: "USD", facilitation_fee: 0 };
  }
  /**
   * Returns the canonical JSON bytes of the envelope WITHOUT the signature.
   */
  getCanonicalJson() {
    const { signature, ...dataToSign } = this;
    const jsonStr = (0, import_fast_json_stable_stringify.default)(dataToSign);
    return new TextEncoder().encode(jsonStr);
  }
  /**
   * Signs the envelope using the provided IdentityManager.
   */
  async sign(identity) {
    const bytes = this.getCanonicalJson();
    this.signature = await identity.sign(bytes);
  }
  /**
   * Helper to parse a PEM public key back to Uint8Array for verification.
   * FIX: We must strip the ASN.1 header to get the raw Ed25519 key.
   */
  static pemToBytes(pem) {
    const b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace(/\s/g, "");
    const fullBytes = import_libsodium_wrappers2.default.from_base64(b64, import_libsodium_wrappers2.default.base64_variants.ORIGINAL);
    if (fullBytes.length > 32) {
      return fullBytes.slice(fullBytes.length - 32);
    }
    return fullBytes;
  }
  /**
   * Verifies the envelope's signature against its own sender public key.
   */
  async verify() {
    if (!this.signature) {
      throw new AmorceValidationError("Envelope has no signature");
    }
    await import_libsodium_wrappers2.default.ready;
    try {
      const canonicalBytes = this.getCanonicalJson();
      const publicKeyBytes = _AmorceEnvelope.pemToBytes(this.sender.public_key);
      return IdentityManager.verify(canonicalBytes, this.signature, publicKeyBytes);
    } catch (e) {
      throw new AmorceValidationError(`Verification failed: ${e}`);
    }
  }
};
var Envelope = AmorceEnvelope;

// src/client.ts
var import_undici = require("undici");
var import_p_retry = __toESM(require("p-retry"));
var import_uuid2 = require("uuid");

// src/models.ts
var AmorceResponseImpl = class {
  constructor(transaction_id, status_code, result, error) {
    this.transaction_id = transaction_id;
    this.status_code = status_code;
    this.result = result;
    this.error = error;
  }
  isSuccess() {
    return this.status_code >= 200 && this.status_code < 300;
  }
  isRetryable() {
    return [429, 500, 502, 503, 504].includes(this.status_code);
  }
};

// src/client.ts
var PriorityLevel = class {
};
PriorityLevel.NORMAL = "normal";
PriorityLevel.HIGH = "high";
PriorityLevel.CRITICAL = "critical";
var AmorceClient = class {
  constructor(identity, directoryUrl, orchestratorUrl, agentId, apiKey) {
    this.identity = identity;
    if (!directoryUrl.startsWith("http://") && !directoryUrl.startsWith("https://")) {
      throw new AmorceConfigError(`Invalid directory_url: ${directoryUrl}`);
    }
    if (!orchestratorUrl.startsWith("http://") && !orchestratorUrl.startsWith("https://")) {
      throw new AmorceConfigError(`Invalid orchestrator_url: ${orchestratorUrl}`);
    }
    this.directoryUrl = directoryUrl.replace(/\/$/, "");
    this.orchestratorUrl = orchestratorUrl.replace(/\/$/, "");
    this.agentId = agentId || identity.getAgentId();
    this.apiKey = apiKey;
  }
  /**
   * Discover services from the Trust Directory.
   * Uses p-retry for exponential backoff with jitter.
   */
  async discover(serviceType) {
    const url = `${this.directoryUrl}/api/v1/services/search?service_type=${encodeURIComponent(serviceType)}`;
    try {
      const response = await (0, import_p_retry.default)(
        async () => {
          const res = await (0, import_undici.request)(url, {
            method: "GET",
            headers: {
              "Content-Type": "application/json"
            }
          });
          if ([429, 503, 504].includes(res.statusCode)) {
            throw new Error(`Retryable status: ${res.statusCode}`);
          }
          if (res.statusCode !== 200) {
            const errorText = await res.body.text();
            throw new AmorceAPIError(
              `Discovery API error: ${res.statusCode}`,
              res.statusCode,
              errorText
            );
          }
          return res;
        },
        {
          retries: 3,
          minTimeout: 1e3,
          maxTimeout: 1e4,
          randomize: true,
          // Adds jitter to prevent thundering herd
          onFailedAttempt: (error) => {
            console.warn(`Discovery retry attempt ${error.attemptNumber}: ${error.message}`);
          }
        }
      );
      return await response.body.json();
    } catch (e) {
      if (e instanceof AmorceAPIError) {
        throw e;
      }
      throw new AmorceNetworkError(`Discovery network error: ${e}`);
    }
  }
  /**
   * Execute a transaction via the Orchestrator.
   * 
   * v2.1.0 Enhancements:
   * - HTTP/2 via undici (automatic for https://)
   * - Exponential backoff + jitter via p-retry
   * - Idempotency key auto-generation
   * - Returns AmorceResponse with utility methods
   * 
   * @param serviceContract - Service identifier (must contain service_id)
   * @param payload - Transaction payload
   * @param priority - Priority level (normal|high|critical)
   * @param idempotencyKey - Optional idempotency key (auto-generated if not provided)
   * @returns AmorceResponse with transaction details
   */
  async transact(serviceContract, payload, priority = PriorityLevel.NORMAL, idempotencyKey) {
    if (!serviceContract.service_id) {
      throw new AmorceConfigError("Invalid service contract: missing service_id");
    }
    const key = idempotencyKey || (0, import_uuid2.v4)();
    const requestBody = {
      service_id: serviceContract.service_id,
      consumer_agent_id: this.agentId,
      payload,
      priority
    };
    const canonicalBytes = IdentityManager.getCanonicalJsonBytes(requestBody);
    const signature = await this.identity.sign(canonicalBytes);
    const headers = {
      "X-Agent-Signature": signature,
      "X-Amorce-Idempotency": key,
      // NEW in v2.1.0
      "X-Amorce-Agent-ID": this.agentId,
      // NEW in v2.1.0
      "Content-Type": "application/json"
    };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    const url = `${this.orchestratorUrl}/v1/a2a/transact`;
    try {
      const response = await (0, import_p_retry.default)(
        async () => {
          const res = await (0, import_undici.request)(url, {
            method: "POST",
            headers,
            body: JSON.stringify(requestBody)
            // undici uses HTTP/2 by default for https:// URLs
          });
          if ([429, 503, 504].includes(res.statusCode)) {
            throw new Error(`Retryable status: ${res.statusCode}`);
          }
          if (res.statusCode >= 400 && res.statusCode < 500 && res.statusCode !== 429) {
            const errorText = await res.body.text();
            throw new AmorceAPIError(
              `Transaction failed with status ${res.statusCode}`,
              res.statusCode,
              errorText
            );
          }
          if (res.statusCode >= 500) {
            throw new Error(`Server error: ${res.statusCode}`);
          }
          return res;
        },
        {
          retries: 3,
          minTimeout: 1e3,
          // 1s
          maxTimeout: 1e4,
          // 10s
          randomize: true,
          // Adds 0-2s jitter
          onFailedAttempt: (error) => {
            console.warn(`Transaction retry attempt ${error.attemptNumber}: ${error.message}`);
          }
        }
      );
      const jsonData = await response.body.json();
      return new AmorceResponseImpl(
        jsonData.transaction_id || key,
        response.statusCode,
        {
          status: jsonData.status || "success",
          message: jsonData.message,
          data: jsonData.data
        },
        void 0
        // No error for successful responses
      );
    } catch (e) {
      if (e instanceof AmorceAPIError) {
        throw e;
      }
      throw new AmorceNetworkError(`Transaction network error: ${e}`);
    }
  }
  /**
   * Request human approval for a transaction (HITL - Human-in-the-Loop).
   * 
   * @param options - Approval request options
   * @returns Approval ID for tracking
   * 
   * @example
   * ```typescript
   * const approvalId = await client.requestApproval({
   *   transactionId: 'tx_123',
   *   summary: 'Book table for 4 guests',
   *   details: { restaurant: 'Le Petit Bistro', date: '2025-12-05' },
   *   timeoutSeconds: 300  // 5 minutes
   * });
   * ```
   */
  async requestApproval(options) {
    const requestBody = {
      transaction_id: options.transactionId,
      summary: options.summary,
      details: options.details,
      timeout_seconds: options.timeoutSeconds || 300,
      agent_id: this.agentId,
      requested_at: (/* @__PURE__ */ new Date()).toISOString()
    };
    const canonicalBytes = IdentityManager.getCanonicalJsonBytes(requestBody);
    const signature = await this.identity.sign(canonicalBytes);
    const headers = {
      "X-Agent-Signature": signature,
      "X-Amorce-Agent-ID": this.agentId,
      "Content-Type": "application/json"
    };
    const url = `${this.orchestratorUrl}/api/v1/approvals`;
    try {
      const response = await (0, import_undici.request)(url, {
        method: "POST",
        headers,
        body: JSON.stringify(requestBody)
      });
      if (response.statusCode !== 201 && response.statusCode !== 200) {
        const errorText = await response.body.text();
        throw new AmorceAPIError(
          `Failed to request approval: ${response.statusCode}`,
          response.statusCode,
          errorText
        );
      }
      const data = await response.body.json();
      return data.approval_id;
    } catch (e) {
      if (e instanceof AmorceAPIError) {
        throw e;
      }
      throw new AmorceNetworkError(`Approval request network error: ${e}`);
    }
  }
  /**
   * Check the status of an approval request.
   * 
   * @param approvalId - The approval ID to check
   * @returns Approval status object
   * 
   * @example
   * ```typescript
   * const status = await client.checkApproval(approvalId);
   * if (status.status === 'approved') {
   *   // Proceed with transaction
   * }
   * ```
   */
  async checkApproval(approvalId) {
    const url = `${this.orchestratorUrl}/api/v1/approvals/${approvalId}`;
    const headers = {
      "X-Amorce-Agent-ID": this.agentId,
      "Content-Type": "application/json"
    };
    try {
      const response = await (0, import_undici.request)(url, {
        method: "GET",
        headers
      });
      if (response.statusCode !== 200) {
        const errorText = await response.body.text();
        throw new AmorceAPIError(
          `Failed to check approval: ${response.statusCode}`,
          response.statusCode,
          errorText
        );
      }
      return await response.body.json();
    } catch (e) {
      if (e instanceof AmorceAPIError) {
        throw e;
      }
      throw new AmorceNetworkError(`Approval check network error: ${e}`);
    }
  }
  /**
   * Submit a decision for an approval request.
   * Typically called by the human approval interface.
   * 
   * @param options - Approval decision options
   * 
   * @example
   * ```typescript
   * await client.submitApproval({
   *   approvalId: 'appr_123',
   *   decision: 'approve',
   *   approvedBy: 'user@example.com',
   *   comments: 'Looks good!'
   * });
   * ```
   */
  async submitApproval(options) {
    const requestBody = {
      decision: options.decision,
      approved_by: options.approvedBy,
      comments: options.comments,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    const canonicalBytes = IdentityManager.getCanonicalJsonBytes(requestBody);
    const signature = await this.identity.sign(canonicalBytes);
    const headers = {
      "X-Agent-Signature": signature,
      "X-Amorce-Agent-ID": this.agentId,
      "Content-Type": "application/json"
    };
    const url = `${this.orchestratorUrl}/api/v1/approvals/${options.approvalId}/submit`;
    try {
      const response = await (0, import_undici.request)(url, {
        method: "POST",
        headers,
        body: JSON.stringify(requestBody)
      });
      if (response.statusCode !== 200 && response.statusCode !== 204) {
        const errorText = await response.body.text();
        throw new AmorceAPIError(
          `Failed to submit approval: ${response.statusCode}`,
          response.statusCode,
          errorText
        );
      }
    } catch (e) {
      if (e instanceof AmorceAPIError) {
        throw e;
      }
      throw new AmorceNetworkError(`Approval submission network error: ${e}`);
    }
  }
};

// src/verify.ts
var import_undici2 = require("undici");
async function verifyRequest(options) {
  const {
    headers,
    body,
    allowedIntents,
    publicKey,
    directoryUrl = "https://directory.amorce.io"
  } = options;
  const signature = headers["x-agent-signature"] || headers["X-Agent-Signature"];
  if (!signature) {
    throw new AmorceSecurityError("Missing X-Agent-Signature header");
  }
  const agentId = headers["x-amorce-agent-id"] || headers["X-Amorce-Agent-ID"];
  if (!agentId) {
    throw new AmorceSecurityError("Missing X-Amorce-Agent-ID header");
  }
  const bodyBytes = typeof body === "string" ? Buffer.from(body, "utf-8") : body;
  let payload;
  try {
    const bodyStr = typeof body === "string" ? body : body.toString("utf-8");
    payload = JSON.parse(bodyStr);
  } catch (e) {
    throw new AmorceValidationError(`Invalid JSON payload: ${e}`);
  }
  let agentPublicKey;
  if (publicKey) {
    agentPublicKey = publicKey;
  } else {
    try {
      const url = `${directoryUrl}/api/v1/agents/${agentId}/public-key`;
      const response = await (0, import_undici2.request)(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json"
        }
      });
      if (response.statusCode !== 200) {
        throw new AmorceSecurityError(`Agent ${agentId} not found in Trust Directory`);
      }
      const data = await response.body.json();
      agentPublicKey = data.public_key;
      if (!agentPublicKey) {
        throw new AmorceSecurityError(`No public key found for agent ${agentId}`);
      }
    } catch (e) {
      if (e instanceof AmorceSecurityError) {
        throw e;
      }
      throw new AmorceSecurityError(`Failed to fetch public key from Trust Directory: ${e}`);
    }
  }
  const publicKeyBytes = pemToPublicKey(agentPublicKey);
  const isValid = await IdentityManager.verify(bodyBytes, signature, publicKeyBytes);
  if (!isValid) {
    throw new AmorceSecurityError("Invalid signature - request authentication failed");
  }
  if (allowedIntents && allowedIntents.length > 0) {
    const intent = payload?.payload?.intent;
    if (!intent) {
      throw new AmorceValidationError("No intent found in payload");
    }
    if (!allowedIntents.includes(intent)) {
      throw new AmorceValidationError(
        `Intent '${intent}' not in allowed list: ${allowedIntents.join(", ")}`
      );
    }
  }
  return {
    agentId,
    payload,
    signature
  };
}
function pemToPublicKey(pem) {
  const sodium3 = require("libsodium-wrappers");
  const b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace(/\\s/g, "");
  const fullBytes = sodium3.from_base64(b64, sodium3.base64_variants.ORIGINAL);
  if (fullBytes.length >= 44) {
    return fullBytes.slice(12, 44);
  }
  throw new AmorceSecurityError("Invalid public key PEM format");
}

// src/mcp.ts
var import_undici3 = require("undici");
var MCPToolClient = class {
  constructor(identity, wrapperUrl) {
    this.identity = identity;
    this.wrapperUrl = wrapperUrl.replace(/\/$/, "");
    this.agentId = identity.getAgentId();
  }
  /**
   * List all available MCP tools across all servers.
   * 
   * @returns Array of available tools with metadata
   * 
   * @example
   * ```typescript
   * const tools = await mcp.listTools();
   * for (const tool of tools) {
   *   const hitl = tool.requiresApproval ? '🔒' : '✓';
   *   console.log(`${hitl} ${tool.name}: ${tool.description}`);
   * }
   * ```
   */
  async listTools() {
    const url = `${this.wrapperUrl}/mcp/tools`;
    try {
      const response = await (0, import_undici3.request)(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Amorce-Agent-ID": this.agentId
        },
        body: JSON.stringify({})
      });
      if (response.statusCode !== 200) {
        const errorText = await response.body.text();
        throw new AmorceAPIError(
          `Failed to list MCP tools: ${response.statusCode}`,
          response.statusCode,
          errorText
        );
      }
      const data = await response.body.json();
      return data.tools || [];
    } catch (e) {
      if (e instanceof AmorceAPIError) {
        throw e;
      }
      throw new AmorceNetworkError(`MCP tool listing network error: ${e}`);
    }
  }
  /**
   * Call an MCP tool with signed request.
   * 
   * For tools that require approval (write/delete operations), you must provide
   * an approvalId obtained through the HITL workflow.
   * 
   * @param server - MCP server name (e.g., 'filesystem', 'brave-search')
   * @param tool - Tool name (e.g., 'read_file', 'write_file')
   * @param args - Tool-specific arguments
   * @param approvalId - Optional approval ID for tools requiring HITL
   * @returns Tool execution result
   * 
   * @throws AmorceValidationError if tool requires approval and none provided
   * 
   * @example
   * ```typescript
   * // Read operation (no approval needed)
   * const content = await mcp.callTool('filesystem', 'read_file', {
   *   path: '/tmp/data.txt'
   * });
   * 
   * // Write operation (approval required)
   * const approvalId = await client.requestApproval({...});
   * await mcp.callTool('filesystem', 'write_file', {
   *   path: '/tmp/output.txt',
   *   content: 'Hello!'
   * }, approvalId);
   * ```
   */
  async callTool(server, tool, args, approvalId) {
    const requestBody = {
      server,
      tool,
      arguments: args,
      approval_id: approvalId,
      agent_id: this.agentId,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    const canonicalBytes = IdentityManager.getCanonicalJsonBytes(requestBody);
    const signature = await this.identity.sign(canonicalBytes);
    const url = `${this.wrapperUrl}/mcp/call`;
    try {
      const response = await (0, import_undici3.request)(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Agent-Signature": signature,
          "X-Amorce-Agent-ID": this.agentId
        },
        body: JSON.stringify(requestBody)
      });
      if (response.statusCode === 403) {
        const errorText = await response.body.text();
        throw new AmorceValidationError(
          `Tool ${tool} requires approval. Request approval first using client.requestApproval()`
        );
      }
      if (response.statusCode !== 200) {
        const errorText = await response.body.text();
        throw new AmorceAPIError(
          `MCP tool call failed: ${response.statusCode}`,
          response.statusCode,
          errorText
        );
      }
      const data = await response.body.json();
      return data.result;
    } catch (e) {
      if (e instanceof AmorceAPIError || e instanceof AmorceValidationError) {
        throw e;
      }
      throw new AmorceNetworkError(`MCP tool call network error: ${e}`);
    }
  }
};

// src/wellKnown.ts
var AMORCE_DIRECTORY_URL = "https://amorce-trust-api-425870997313.us-central1.run.app";
async function fetchManifest(agentId, directoryUrl = AMORCE_DIRECTORY_URL) {
  const url = `${directoryUrl}/api/v1/agents/${agentId}/manifest`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch manifest: ${response.status} ${response.statusText}`);
  }
  return response.json();
}
function serveWellKnown(options) {
  const {
    agentId,
    directoryUrl = AMORCE_DIRECTORY_URL,
    cacheTtl = 300
  } = options;
  let cachedManifest = null;
  let cachedAt = 0;
  return async (req, res, next) => {
    if (req.path !== "/.well-known/agent.json") {
      return next();
    }
    const now = Date.now() / 1e3;
    if (cachedManifest && now - cachedAt < cacheTtl) {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", `public, max-age=${cacheTtl}`);
      return res.json(cachedManifest);
    }
    try {
      cachedManifest = await fetchManifest(agentId, directoryUrl);
      cachedAt = now;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", `public, max-age=${cacheTtl}`);
      res.json(cachedManifest);
    } catch (error) {
      console.error("Failed to fetch A2A manifest:", error.message);
      res.status(500).json({ error: "Failed to fetch agent manifest" });
    }
  };
}
function createWellKnownHandler(options) {
  const {
    agentId,
    directoryUrl = AMORCE_DIRECTORY_URL,
    cacheTtl = 300
  } = options;
  let cachedManifest = null;
  let cachedAt = 0;
  return async (req) => {
    const now = Date.now() / 1e3;
    if (cachedManifest && now - cachedAt < cacheTtl) {
      return new Response(JSON.stringify(cachedManifest), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": `public, max-age=${cacheTtl}`
        }
      });
    }
    try {
      cachedManifest = await fetchManifest(agentId, directoryUrl);
      cachedAt = now;
      return new Response(JSON.stringify(cachedManifest), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": `public, max-age=${cacheTtl}`
        }
      });
    } catch (error) {
      console.error("Failed to fetch A2A manifest:", error.message);
      return new Response(JSON.stringify({ error: "Failed to fetch agent manifest" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  };
}
async function generateManifestJson(agentId, directoryUrl = AMORCE_DIRECTORY_URL) {
  const manifest = await fetchManifest(agentId, directoryUrl);
  return JSON.stringify(manifest, null, 2);
}

// src/index.ts
var SDK_VERSION = "3.1.0";
var AATP_VERSION = "0.1.0";
console.log(`Amorce JS SDK v${SDK_VERSION} loaded.`);
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AATP_VERSION,
  AmorceAPIError,
  AmorceClient,
  AmorceConfigError,
  AmorceEnvelope,
  AmorceError,
  AmorceNetworkError,
  AmorceResponseImpl,
  AmorceSecurityError,
  AmorceValidationError,
  EnvVarProvider,
  Envelope,
  IdentityManager,
  MCPToolClient,
  PriorityLevel,
  SDK_VERSION,
  createWellKnownHandler,
  fetchManifest,
  generateManifestJson,
  serveWellKnown,
  verifyRequest
});
//# sourceMappingURL=index.js.map