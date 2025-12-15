/**
 * Amorce Exceptions Module
 * Defines custom exceptions for the Amorce SDK to allow fine-grained error handling.
 * Matches the exception hierarchy from nexus-py-sdk v0.1.7
 */
/**
 * Base class for all Amorce SDK exceptions.
 */
declare class AmorceError extends Error {
    constructor(message: string);
}
/**
 * Raised when there is a configuration issue (e.g. invalid URL, missing key).
 */
declare class AmorceConfigError extends AmorceError {
    constructor(message: string);
}
/**
 * Raised when a network operation fails (e.g. connection timeout, DNS error).
 */
declare class AmorceNetworkError extends AmorceError {
    constructor(message: string);
}
/**
 * Raised when the Amorce API returns an error response (4xx, 5xx).
 */
declare class AmorceAPIError extends AmorceError {
    statusCode?: number;
    responseBody?: string;
    constructor(message: string, statusCode?: number, responseBody?: string);
}
/**
 * Raised when a security-related operation fails (e.g. signing, key loading).
 */
declare class AmorceSecurityError extends AmorceError {
    constructor(message: string);
}
/**
 * Raised when data validation fails (e.g. invalid envelope structure).
 */
declare class AmorceValidationError extends AmorceError {
    constructor(message: string);
}

/**
 * Amorce Identity Module (Task 2.2 - Enhanced for v0.1.7)
 * Handles Ed25519 key management and signing using libsodium.
 * Compatible with both Browser and Node.js environments.
 *
 * v0.1.7 Updates:
 * - Added Provider Pattern for flexible key sources
 * - Added Agent ID derivation (SHA-256 of public key)
 * - Added canonical JSON helper
 * - Improved error handling with custom exceptions
 */
/**
 * Abstract base class for retrieving private keys.
 */
interface IdentityProvider {
    getPrivateKey(): Promise<Uint8Array>;
}
/**
 * Loads a private key from an environment variable string.
 * Works in both Node.js and browser environments (if env vars are available).
 */
declare class EnvVarProvider implements IdentityProvider {
    private envVarName;
    constructor(envVarName?: string);
    getPrivateKey(): Promise<Uint8Array>;
    private pemToPrivateKey;
}
/**
 * Central class to manage the agent's identity.
 */
declare class IdentityManager {
    private privateKey;
    publicKey: Uint8Array;
    private constructor();
    /**
     * Initializes from a provider (flexible key source).
     */
    static fromProvider(provider: IdentityProvider): Promise<IdentityManager>;
    /**
     * Factory method: Generates a new ephemeral Ed25519 identity in memory.
     * Matches Python's IdentityManager.generate_ephemeral()
     */
    static generate(): Promise<IdentityManager>;
    /**
     * Legacy method: Loads an identity from a raw private key (Uint8Array).
     * Kept for backward compatibility.
     */
    static fromPrivateKey(privateKey: Uint8Array): Promise<IdentityManager>;
    /**
     * Signs a message (string or bytes) and returns the signature in Base64.
     */
    sign(message: string | Uint8Array): Promise<string>;
    /**
     * Verifies a signature against a public key.
     * Static utility for validation.
     */
    static verify(message: string | Uint8Array, signatureBase64: string, publicKey: Uint8Array): Promise<boolean>;
    /**
     * Exports the Public Key to PEM format (PKIX).
     * Matches Python's serialization.PublicFormat.SubjectPublicKeyInfo
     */
    getPublicKeyPem(): string;
    /**
     * MCP 1.0: Deterministic Agent ID derivation.
     * Returns the SHA-256 hash of the public key PEM.
     * This ensures the ID is cryptographically bound to the key.
     * Matches Python SDK behavior.
     */
    getAgentId(): string;
    /**
     * Returns the canonical JSON byte representation for signing.
     * Strict: sort_keys=True, no whitespace.
     * Matches Python's get_canonical_json_bytes()
     */
    static getCanonicalJsonBytes(payload: any): Uint8Array;
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
    toManifestJson(options: {
        name: string;
        endpoint: string;
        capabilities: string[];
        description?: string;
    }): string;
}

/**
 * Amorce Envelope (Task 2.3 - Updated for v0.1.7)
 * Defines the strict AATP v0.1 data structure.
 * Handles canonical serialization and signing.
 *
 * v0.1.7 Updates:
 * - Enhanced error handling with custom exceptions
 * - Better validation
 *
 * NOTE: This module is kept for potential future use and backward compatibility.
 * The current transaction protocol (v0.1.7) uses a flat JSON structure instead
 * of wrapping everything in an envelope.
 */

type AmorcePriority = 'normal' | 'high' | 'critical';
interface SenderInfo {
    public_key: string;
    agent_id?: string;
}
interface SettlementInfo {
    amount: number;
    currency: string;
    facilitation_fee: number;
}
declare class AmorceEnvelope {
    natp_version: string;
    id: string;
    priority: AmorcePriority;
    timestamp: number;
    sender: SenderInfo;
    payload: Record<string, any>;
    settlement: SettlementInfo;
    signature?: string;
    constructor(sender: SenderInfo, payload: Record<string, any>, priority?: AmorcePriority);
    /**
     * Returns the canonical JSON bytes of the envelope WITHOUT the signature.
     */
    getCanonicalJson(): Uint8Array;
    /**
     * Signs the envelope using the provided IdentityManager.
     */
    sign(identity: IdentityManager): Promise<void>;
    /**
     * Helper to parse a PEM public key back to Uint8Array for verification.
     * FIX: We must strip the ASN.1 header to get the raw Ed25519 key.
     */
    private static pemToBytes;
    /**
     * Verifies the envelope's signature against its own sender public key.
     */
    verify(): Promise<boolean>;
}
declare const Envelope: typeof AmorceEnvelope;

/**
 * Amorce Response Models Module
 * TypeScript interfaces and classes for structured responses.
 * Matches Python SDK's Pydantic models for consistency.
 */
/**
 * Configuration for Amorce clients.
 */
interface AmorceConfig {
    directoryUrl: string;
    orchestratorUrl: string;
}
/**
 * Nested result data from a successful transaction.
 */
interface TransactionResult {
    status: string;
    message?: string;
    data?: Record<string, any>;
}
/**
 * Standardized response wrapper for transact() operations.
 * Provides consistent interface across sync and async implementations.
 */
interface AmorceResponse {
    transaction_id: string;
    status_code: number;
    result?: TransactionResult;
    error?: string;
    /**
     * Check if transaction was successful (2xx status)
     */
    isSuccess(): boolean;
    /**
     * Check if error is retryable (5xx or 429)
     */
    isRetryable(): boolean;
}
/**
 * Concrete implementation of AmorceResponse.
 */
declare class AmorceResponseImpl implements AmorceResponse {
    transaction_id: string;
    status_code: number;
    result?: TransactionResult | undefined;
    error?: string | undefined;
    constructor(transaction_id: string, status_code: number, result?: TransactionResult | undefined, error?: string | undefined);
    isSuccess(): boolean;
    isRetryable(): boolean;
}

/**
 * Amorce Client Module (v2.1.0 - Enhanced)
 * High-level HTTP client for the Amorce Agent Transaction Protocol (AATP).
 *
 * v2.1.0 Updates (Feature Parity with Python SDK v0.2.0):
 * - HTTP/2 support via undici
 * - Exponential backoff + jitter via p-retry
 * - Idempotency key generation (UUIDv4)
 * - Structured AmorceResponse return type
 * - Additional headers: X-Amorce-Idempotency, X-Amorce-Agent-ID
 */

/**
 * Priority Level constants for easier developer access.
 * Matches Python SDK's PriorityLevel class.
 */
declare class PriorityLevel {
    static readonly NORMAL: AmorcePriority;
    static readonly HIGH: AmorcePriority;
    static readonly CRITICAL: AmorcePriority;
}
interface ServiceContract {
    service_id: string;
    provider_agent_id?: string;
    service_type?: string;
    [key: string]: any;
}
declare class AmorceClient {
    private identity;
    private directoryUrl;
    private orchestratorUrl;
    private agentId;
    private apiKey?;
    constructor(identity: IdentityManager, directoryUrl: string, orchestratorUrl: string, agentId?: string, apiKey?: string);
    /**
     * Discover services from the Trust Directory.
     * Uses p-retry for exponential backoff with jitter.
     */
    discover(serviceType: string): Promise<ServiceContract[]>;
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
    transact(serviceContract: ServiceContract, payload: Record<string, any>, priority?: AmorcePriority, idempotencyKey?: string): Promise<AmorceResponse>;
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
    requestApproval(options: {
        transactionId?: string;
        summary: string;
        details: any;
        timeoutSeconds?: number;
    }): Promise<string>;
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
    checkApproval(approvalId: string): Promise<{
        status: 'pending' | 'approved' | 'rejected' | 'expired';
        approvedBy?: string;
        timestamp?: string;
        comments?: string;
    }>;
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
    submitApproval(options: {
        approvalId: string;
        decision: 'approve' | 'reject';
        approvedBy: string;
        comments?: string;
    }): Promise<void>;
}

/**
 * Amorce Request Verification Module (v3.0.0)
 * For builders to verify incoming signed requests from other agents.
 *
 * Matches Python SDK's verify_request() function.
 */
interface VerifyRequestOptions {
    headers: Record<string, string>;
    body: Buffer | string;
    allowedIntents?: string[];
    publicKey?: string;
    directoryUrl?: string;
}
interface VerifiedRequest {
    agentId: string;
    payload: any;
    signature: string;
}
/**
 * Verify an incoming signed request from another agent.
 *
 * This function:
 * 1. Extracts the signature and agent ID from headers
 * 2. Fetches the agent's public key from the Trust Directory (or uses provided key)
 * 3. Verifies the Ed25519 signature
 * 4. Optionally validates that the intent is in the allowed list
 *
 * @param options - Verification options
 * @returns Verified request with agent ID and parsed payload
 * @throws AmorceSecurityError if verification fails
 * @throws AmorceValidationError if intent not allowed
 *
 * @example
 * ```typescript
 * // Express/Fastify route handler
 * app.post('/api/v1/webhook', async (req, res) => {
 *   try {
 *     const verified = await verifyRequest({
 *       headers: req.headers,
 *       body: req.body,
 *       allowedIntents: ['book_table', 'cancel_reservation']
 *     });
 *
 *     console.log(`Verified request from agent: ${verified.agentId}`);
 *     // Process the verified request...
 *
 *   } catch (error) {
 *     if (error instanceof AmorceSecurityError) {
 *       return res.status(401).json({ error: 'Unauthorized' });
 *     }
 *     throw error;
 *   }
 * });
 * ```
 */
declare function verifyRequest(options: VerifyRequestOptions): Promise<VerifiedRequest>;

/**
 * Amorce MCP Tool Client (v3.0.0)
 * Integration with Model Context Protocol (MCP) servers through Amorce wrapper.
 *
 * Provides cryptographic signing and HITL approvals for MCP tool calls.
 */

interface MCPTool {
    name: string;
    description: string;
    requiresApproval: boolean;
    parameters: any;
    server: string;
}
/**
 * Client for calling MCP tools through the Amorce wrapper.
 * Adds Ed25519 signatures and HITL approvals to MCP tool calls.
 *
 * @example
 * ```typescript
 * const identity = await IdentityManager.generate();
 * const mcp = new MCPToolClient(identity, 'http://localhost:5001');
 *
 * // List available tools
 * const tools = await mcp.listTools();
 *
 * // Call a tool
 * const result = await mcp.callTool('filesystem', 'read_file', {
 *   path: '/tmp/data.txt'
 * });
 * ```
 */
declare class MCPToolClient {
    private identity;
    private wrapperUrl;
    private agentId;
    constructor(identity: IdentityManager, wrapperUrl: string);
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
    listTools(): Promise<MCPTool[]>;
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
    callTool(server: string, tool: string, args: any, approvalId?: string): Promise<any>;
}

/**
 * A2A Well-Known Manifest Helper
 *
 * Provides easy integration for serving /.well-known/agent.json endpoints
 * to make your agent discoverable in the A2A ecosystem.
 */
interface ManifestOptions {
    agentId: string;
    directoryUrl?: string;
    cacheTtl?: number;
}
interface A2AManifest {
    name: string;
    url: string;
    version: string;
    description: string;
    protocol_version: string;
    capabilities: string[];
    authentication: {
        type: string;
        public_key: string;
        algorithm: string;
        directory_url: string;
    };
    amorce: {
        agent_id: string;
        status: string;
        registered_at: string;
        category: string;
    };
}
/**
 * Fetch the A2A manifest for an agent from the Amorce Directory.
 */
declare function fetchManifest(agentId: string, directoryUrl?: string): Promise<A2AManifest>;
/**
 * Express middleware to serve /.well-known/agent.json
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { serveWellKnown } from '@amorce/sdk';
 *
 * const app = express();
 * app.use(serveWellKnown({ agentId: 'my-agent-id' }));
 * ```
 */
declare function serveWellKnown(options: ManifestOptions): (req: any, res: any, next: any) => Promise<any>;
/**
 * Next.js API route handler for /.well-known/agent.json
 *
 * @example
 * ```typescript
 * // pages/api/.well-known/agent.json.ts (Next.js Pages Router)
 * // or app/.well-known/agent.json/route.ts (Next.js App Router)
 *
 * import { createWellKnownHandler } from '@amorce/sdk';
 *
 * export const GET = createWellKnownHandler({ agentId: 'my-agent-id' });
 * ```
 */
declare function createWellKnownHandler(options: ManifestOptions): (req: Request) => Promise<Response>;
/**
 * Generate a static manifest JSON that can be deployed as a file.
 *
 * @example
 * ```typescript
 * import { generateManifestJson } from '@amorce/sdk';
 *
 * const manifest = await generateManifestJson('my-agent-id');
 * // Save to .well-known/agent.json
 * ```
 */
declare function generateManifestJson(agentId: string, directoryUrl?: string): Promise<string>;

/**
 * Amorce SDK for JavaScript/TypeScript
 * Version 3.1.0
 *
 * Aligned with amorce-py-sdk v0.2.2
 *
 * v3.1.0 Updates:
 * - A2A Well-Known manifest helpers for agent discoverability
 *
 * v3.0.0 Updates:
 * - HITL (Human-in-the-Loop) approval workflow
 * - MCP Integration for secure tool calling
 * - verifyRequest() for builders
 * - toManifestJson() for agent registration
 * - Full feature parity with Python SDK
 */
declare const SDK_VERSION = "3.1.0";
declare const AATP_VERSION = "0.1.0";

export { type A2AManifest, AATP_VERSION, AmorceAPIError, AmorceClient, type AmorceConfig, AmorceConfigError, AmorceEnvelope, AmorceError, AmorceNetworkError, type AmorcePriority, type AmorceResponse, AmorceResponseImpl, AmorceSecurityError, AmorceValidationError, EnvVarProvider, Envelope, IdentityManager, type IdentityProvider, type MCPTool, MCPToolClient, type ManifestOptions, PriorityLevel, SDK_VERSION, type SenderInfo, type ServiceContract, type SettlementInfo, type TransactionResult, type VerifiedRequest, type VerifyRequestOptions, createWellKnownHandler, fetchManifest, generateManifestJson, serveWellKnown, verifyRequest };
