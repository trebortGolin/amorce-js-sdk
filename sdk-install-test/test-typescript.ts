/**
 * TypeScript Installation Test
 * Tests that the SDK works with TypeScript and has proper type definitions
 */

import {
    IdentityManager,
    NexusClient,
    PriorityLevel,
    NexusAPIError,
    EnvVarProvider,
    NexusPriority
} from '@nexus/sdk';

async function testTypeScriptInstallation(): Promise<boolean> {
    console.log('=== TypeScript SDK Installation Test ===\n');

    try {
        // Test 1: Type-safe identity generation
        console.log('Test 1: Type-safe identity generation...');
        const identity: IdentityManager = await IdentityManager.generate();
        const agentId: string = identity.getAgentId();
        const publicKey: string = identity.getPublicKeyPem();

        console.log('✅ Identity generated with type safety');
        console.log(`   Agent ID type: ${typeof agentId}`);
        console.log(`   Public Key type: ${typeof publicKey}\n`);

        // Test 2: Type-safe client creation
        console.log('Test 2: Type-safe client creation...');
        const client: NexusClient = new NexusClient(
            identity,
            'https://directory.example.com',
            'https://orchestrator.example.com'
        );
        console.log('✅ Client created with type safety\n');

        // Test 3: Priority levels with types
        console.log('Test 3: Testing typed PriorityLevel...');
        const priorities: NexusPriority[] = [
            PriorityLevel.NORMAL,
            PriorityLevel.HIGH,
            PriorityLevel.CRITICAL
        ];
        console.log('✅ Priority types work correctly');
        console.log(`   Priorities: ${priorities.join(', ')}\n`);

        // Test 4: Exception type safety
        console.log('Test 4: Testing typed exceptions...');
        try {
            const error = new NexusAPIError('Test', 404, 'Not Found');
            if (error.statusCode) {
                console.log(`✅ Exception types are correct`);
                console.log(`   statusCode is: ${typeof error.statusCode}\n`);
            }
        } catch (e) {
            console.error('Unexpected error in exception test');
        }

        // Test 5: Static methods
        console.log('Test 5: Testing static typed methods...');
        const testPayload = {
            test: 'data',
            number: 123
        };
        const canonical: Uint8Array = IdentityManager.getCanonicalJsonBytes(testPayload);
        console.log('✅ Static methods work with types');
        console.log(`   Canonical bytes type: ${canonical.constructor.name}\n`);

        console.log('='.repeat(60));
        console.log('✅ ALL TYPESCRIPT TESTS PASSED');
        console.log('='.repeat(60));
        console.log('\nTypeScript features verified:');
        console.log('  • All type definitions are present');
        console.log('  • Types are correctly exported');
        console.log('  • Type safety works as expected');
        console.log('  • No type errors during compilation\n');

        return true;
    } catch (error) {
        console.error('❌ TYPESCRIPT TEST FAILED:', error);
        return false;
    }
}

// Run the test
testTypeScriptInstallation()
    .then(success => {
        process.exit(success ? 0 : 1);
    })
    .catch(error => {
        console.error('Unexpected error:', error);
        process.exit(1);
    });
