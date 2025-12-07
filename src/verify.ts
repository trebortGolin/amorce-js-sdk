/**
 * Amorce Request Verification Module (v3.0.0)
 * For builders to verify incoming signed requests from other agents.
 * 
 * Matches Python SDK's verify_request() function.
 */

import { IdentityManager } from './identity';
import { AmorceSecurityError, AmorceValidationError } from './exceptions';
import { request } from 'undici';

export interface VerifyRequestOptions {
    headers: Record<string, string>;
    body: Buffer | string;
    allowedIntents?: string[];
    publicKey?: string;
    directoryUrl?: string;
}

export interface VerifiedRequest {
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
export async function verifyRequest(options: VerifyRequestOptions): Promise<VerifiedRequest> {
    const {
        headers,
        body,
        allowedIntents,
        publicKey,
        directoryUrl = 'https://directory.amorce.io'
    } = options;

    // 1. Extract signature from headers
    const signature = headers['x-agent-signature'] || headers['X-Agent-Signature'];
    if (!signature) {
        throw new AmorceSecurityError('Missing X-Agent-Signature header');
    }

    // 2. Extract agent ID from headers
    const agentId = headers['x-amorce-agent-id'] || headers['X-Amorce-Agent-ID'];
    if (!agentId) {
        throw new AmorceSecurityError('Missing X-Amorce-Agent-ID header');
    }

    // 3. Get body bytes
    const bodyBytes = typeof body === 'string' ? Buffer.from(body, 'utf-8') : body;

    // 4. Parse payload
    let payload: any;
    try {
        const bodyStr = typeof body === 'string' ? body : body.toString('utf-8');
        payload = JSON.parse(bodyStr);
    } catch (e) {
        throw new AmorceValidationError(`Invalid JSON payload: ${e}`);
    }

    // 5. Get public key (either from parameter or fetch from Trust Directory)
    let agentPublicKey: string;

    if (publicKey) {
        agentPublicKey = publicKey;
    } else {
        // Fetch from Trust Directory
        try {
            const url = `${directoryUrl}/api/v1/agents/${agentId}/public-key`;
            const response = await request(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.statusCode !== 200) {
                throw new AmorceSecurityError(`Agent ${agentId} not found in Trust Directory`);
            }

            const data = await response.body.json() as any;
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

    // 6. Convert PEM public key to Uint8Array
    const publicKeyBytes = pemToPublicKey(agentPublicKey);

    // 7. Verify signature
    const isValid = await IdentityManager.verify(bodyBytes, signature, publicKeyBytes);

    if (!isValid) {
        throw new AmorceSecurityError('Invalid signature - request authentication failed');
    }

    // 8. Validate intent if allowed list provided
    if (allowedIntents && allowedIntents.length > 0) {
        const intent = payload?.payload?.intent;

        if (!intent) {
            throw new AmorceValidationError('No intent found in payload');
        }

        if (!allowedIntents.includes(intent)) {
            throw new AmorceValidationError(
                `Intent '${intent}' not in allowed list: ${allowedIntents.join(', ')}`
            );
        }
    }

    return {
        agentId,
        payload,
        signature
    };
}

/**
 * Helper function to convert PEM public key to Uint8Array.
 * Extracts the Ed25519 public key from PEM format (SubjectPublicKeyInfo).
 */
function pemToPublicKey(pem: string): Uint8Array {
    const sodium = require('libsodium-wrappers');

    // Remove PEM headers and whitespace
    const b64 = pem
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\\s/g, '');

    // Decode base64
    const fullBytes = sodium.from_base64(b64, sodium.base64_variants.ORIGINAL);

    // Ed25519 public key in SubjectPublicKeyInfo has a 12-byte header
    // Sequence (0x30 0x2a) + Algorithm OID + Bit String prefix
    // The actual 32-byte public key starts at byte 12
    if (fullBytes.length >= 44) {
        return fullBytes.slice(12, 44);
    }

    throw new AmorceSecurityError('Invalid public key PEM format');
}
