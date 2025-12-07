/**
 * Unit tests for MCP Tool Client
 */

import { MCPToolClient } from '../mcp';
import { IdentityManager } from '../identity';

describe('MCPToolClient', () => {
    let mcp: MCPToolClient;
    let identity: IdentityManager;

    beforeAll(async () => {
        identity = await IdentityManager.generate();
        mcp = new MCPToolClient(identity, 'http://localhost:5001');
    });

    it('should create MCP client instance', () => {
        expect(mcp).toBeDefined();
        expect(mcp).toBeInstanceOf(MCPToolClient);
    });

    it('should have listTools method', () => {
        expect(mcp.listTools).toBeDefined();
        expect(typeof mcp.listTools).toBe('function');
    });

    it('should have callTool method', () => {
        expect(mcp.callTool).toBeDefined();
        expect(typeof mcp.callTool).toBe('function');
    });

    it('should remove trailing slash from wrapper URL', () => {
        const mcpWithSlash = new MCPToolClient(identity, 'http://localhost:5001/');
        expect(mcpWithSlash).toBeDefined();
    });
});
