/**
 * Amorce MCP Tool Client (v3.0.0)
 * Integration with Model Context Protocol (MCP) servers through Amorce wrapper.
 * 
 * Provides cryptographic signing and HITL approvals for MCP tool calls.
 */

import { IdentityManager } from './identity';
import { AmorceNetworkError, AmorceAPIError, AmorceValidationError } from './exceptions';
import { request } from 'undici';

export interface MCPTool {
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
export class MCPToolClient {
    private identity: IdentityManager;
    private wrapperUrl: string;
    private agentId: string;

    constructor(identity: IdentityManager, wrapperUrl: string) {
        this.identity = identity;
        this.wrapperUrl = wrapperUrl.replace(/\/$/, '');  // Remove trailing slash
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
    async listTools(): Promise<MCPTool[]> {
        const url = `${this.wrapperUrl}/mcp/tools`;

        try {
            const response = await request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Amorce-Agent-ID': this.agentId
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

            const data = await response.body.json() as any;
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
    async callTool(
        server: string,
        tool: string,
        args: any,
        approvalId?: string
    ): Promise<any> {
        const requestBody = {
            server,
            tool,
            arguments: args,
            approval_id: approvalId,
            agent_id: this.agentId,
            timestamp: new Date().toISOString()
        };

        // Sign the request
        const canonicalBytes = IdentityManager.getCanonicalJsonBytes(requestBody);
        const signature = await this.identity.sign(canonicalBytes);

        const url = `${this.wrapperUrl}/mcp/call`;

        try {
            const response = await request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Agent-Signature': signature,
                    'X-Amorce-Agent-ID': this.agentId
                },
                body: JSON.stringify(requestBody)
            });

            // Tool requires approval but none provided
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

            const data = await response.body.json() as any;
            return data.result;
        } catch (e) {
            if (e instanceof AmorceAPIError || e instanceof AmorceValidationError) {
                throw e;
            }
            throw new AmorceNetworkError(`MCP tool call network error: ${e}`);
        }
    }
}
