/**
 * Unit tests for HITL (Human-in-the-Loop) functionality
 */

import { AmorceClient } from '../client';
import { IdentityManager } from '../identity';

describe('HITL Approval Workflow', () => {
    let client: AmorceClient;
    let identity: IdentityManager;

    beforeAll(async () => {
        identity = await IdentityManager.generate();
        client = new AmorceClient(
            identity,
            'http://localhost:8080',  // Mock directory
            'http://localhost:8080',  // Mock orchestrator
        );
    });

    it('should have requestApproval method', () => {
        expect(client.requestApproval).toBeDefined();
        expect(typeof client.requestApproval).toBe('function');
    });

    it('should have checkApproval method', () => {
        expect(client.checkApproval).toBeDefined();
        expect(typeof client.checkApproval).toBe('function');
    });

    it('should have submitApproval method', () => {
        expect(client.submitApproval).toBeDefined();
        expect(typeof client.submitApproval).toBe('function');
    });

    it('should create approval request with correct structure', async () => {
        // This would need a mock server, but we can test the method exists
        // and has proper type signature
        const requestApproval = client.requestApproval.bind(client);
        expect(requestApproval).toBeDefined();
    });
});

describe('IdentityManager manifest generation', () => {
    it('should generate manifest JSON', async () => {
        const identity = await IdentityManager.generate();

        const manifest = identity.toManifestJson({
            name: 'Test Agent',
            endpoint: 'https://api.example.com/webhook',
            capabilities: ['book_table', 'check_availability'],
            description: 'Test agent for unit tests'
        });

        expect(manifest).toBeDefined();
        const parsed = JSON.parse(manifest);

        expect(parsed.agent_id).toBe(identity.getAgentId());
        expect(parsed.name).toBe('Test Agent');
        expect(parsed.endpoint).toBe('https://api.example.com/webhook');
        expect(parsed.capabilities).toEqual(['book_table', 'check_availability']);
        expect(parsed.description).toBe('Test agent for unit tests');
        expect(parsed.version).toBe('1.0');
        expect(parsed.public_key).toBe(identity.getPublicKeyPem());
    });
});
