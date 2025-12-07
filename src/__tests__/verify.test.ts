/**
 * Unit tests for verifyRequest function
 */

import { verifyRequest } from '../verify';
import { IdentityManager } from '../identity';
import { AmorceSecurityError, AmorceValidationError } from '../exceptions';

describe('verifyRequest', () => {
    let identity: IdentityManager;
    let agentId: string;
    let signature: string;
    const testPayload = {
        service_id: 'test_service',
        consumer_agent_id: 'test_consumer',
        payload: { intent: 'book_table', params: { guests: 4 } }
    };

    beforeAll(async () => {
        identity = await IdentityManager.generate();
        agentId = identity.getAgentId();
        const canonicalBytes = IdentityManager.getCanonicalJsonBytes(testPayload);
        signature = await identity.sign(canonicalBytes);
    });

    it('should verify a valid signed request', async () => {
        const headers = {
            'X-Agent-Signature': signature,
            'X-Amorce-Agent-ID': agentId
        };

        const body = JSON.stringify(testPayload);
        const publicKey = identity.getPublicKeyPem();

        const verified = await verifyRequest({
            headers,
            body: Buffer.from(body),
            publicKey
        });

        expect(verified.agentId).toBe(agentId);
        expect(verified.payload).toEqual(testPayload);
        expect(verified.signature).toBe(signature);
    });

    it('should throw error when signature header is missing', async () => {
        const headers = {
            'X-Amorce-Agent-ID': agentId
        };

        await expect(
            verifyRequest({
                headers,
                body: Buffer.from(JSON.stringify(testPayload)),
                publicKey: identity.getPublicKeyPem()
            })
        ).rejects.toThrow(AmorceSecurityError);
    });

    it('should throw error when agent ID header is missing', async () => {
        const headers = {
            'X-Agent-Signature': signature
        };

        await expect(
            verifyRequest({
                headers,
                body: Buffer.from(JSON.stringify(testPayload)),
                publicKey: identity.getPublicKeyPem()
            })
        ).rejects.toThrow(AmorceSecurityError);
    });

    it('should throw error with invalid signature', async () => {
        const headers = {
            'X-Agent-Signature': 'invalid_signature',
            'X-Amorce-Agent-ID': agentId
        };

        await expect(
            verifyRequest({
                headers,
                body: Buffer.from(JSON.stringify(testPayload)),
                publicKey: identity.getPublicKeyPem()
            })
        ).rejects.toThrow(AmorceSecurityError);
    });

    it('should validate allowed intents', async () => {
        const headers = {
            'X-Agent-Signature': signature,
            'X-Amorce-Agent-ID': agentId
        };

        const verified = await verifyRequest({
            headers,
            body: Buffer.from(JSON.stringify(testPayload)),
            publicKey: identity.getPublicKeyPem(),
            allowedIntents: ['book_table', 'cancel_reservation']
        });

        expect(verified).toBeDefined();
    });

    it('should reject disallowed intent', async () => {
        const headers = {
            'X-Agent-Signature': signature,
            'X-Amorce-Agent-ID': agentId
        };

        await expect(
            verifyRequest({
                headers,
                body: Buffer.from(JSON.stringify(testPayload)),
                publicKey: identity.getPublicKeyPem(),
                allowedIntents: ['cancel_reservation']  // book_table not allowed
            })
        ).rejects.toThrow(AmorceValidationError);
    });
});
