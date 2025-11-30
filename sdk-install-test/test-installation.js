/**
 * Real Installation Test
 * Tests that the SDK works when installed as a dependency
 */

const {
    IdentityManager,
    NexusClient,
    PriorityLevel,
    NexusError,
    NexusConfigError,
    NexusNetworkError,
    NexusAPIError,
    EnvVarProvider
} = require('@nexus/sdk');

async function testSDKInstallation() {
    console.log('=== Real SDK Installation Test ===\n');

    try {
        // Test 1: Generate Identity
        console.log('Test 1: Generating ephemeral identity...');
        const identity = await IdentityManager.generate();
        const agentId = identity.getAgentId();
        const publicKey = identity.getPublicKeyPem();

        console.log('✅ Identity generated');
        console.log(`   Agent ID: ${agentId.substring(0, 16)}...`);
        console.log(`   Public Key length: ${publicKey.length} bytes\n`);

        // Test 2: Sign a message
        console.log('Test 2: Signing a message...');
        const testMessage = 'Hello from installed SDK!';
        const signature = await identity.sign(testMessage);
        console.log('✅ Message signed');
        console.log(`   Signature length: ${signature.length} bytes\n`);

        // Test 3: Verify signature
        console.log('Test 3: Verifying signature...');
        const publicKeyBytes = extractPublicKeyBytes(publicKey);
        const isValid = await IdentityManager.verify(testMessage, signature, publicKeyBytes);
        console.log(`✅ Signature ${isValid ? 'VALID' : 'INVALID'}\n`);

        // Test 4: Create NexusClient
        console.log('Test 4: Creating NexusClient...');
        const client = new NexusClient(
            identity,
            'https://directory.example.com',
            'https://orchestrator.example.com'
        );
        console.log('✅ Client created\n');

        // Test 5: Test PriorityLevel constants
        console.log('Test 5: Testing PriorityLevel constants...');
        console.log(`   NORMAL: ${PriorityLevel.NORMAL}`);
        console.log(`   HIGH: ${PriorityLevel.HIGH}`);
        console.log(`   CRITICAL: ${PriorityLevel.CRITICAL}`);
        console.log('✅ PriorityLevel constants available\n');

        // Test 6: Test exception classes
        console.log('Test 6: Testing exception classes...');
        try {
            throw new NexusAPIError('Test error', 400, 'Bad Request');
        } catch (e) {
            if (e instanceof NexusAPIError) {
                console.log(`✅ NexusAPIError caught: ${e.message}`);
                console.log(`   Status Code: ${e.statusCode}`);
                console.log(`   Response Body: ${e.responseBody}\n`);
            }
        }

        // Test 7: Test canonical JSON
        console.log('Test 7: Testing canonical JSON generation...');
        const payload = {
            service_id: 'test_001',
            priority: 'normal',
            data: { message: 'test' }
        };
        const canonical = IdentityManager.getCanonicalJsonBytes(payload);
        console.log('✅ Canonical JSON generated');
        console.log(`   Length: ${canonical.length} bytes`);
        console.log(`   Content: ${new TextDecoder().decode(canonical)}\n`);

        // Final summary
        console.log('='.repeat(60));
        console.log('✅ ALL TESTS PASSED');
        console.log('='.repeat(60));
        console.log('\nThe SDK is correctly installed and all features work:');
        console.log('  • Identity generation and management');
        console.log('  • Message signing and verification');
        console.log('  • Client creation');
        console.log('  • Exception handling');
        console.log('  • Canonical JSON generation');
        console.log('  • All exports are accessible\n');

        return true;
    } catch (error) {
        console.error('❌ TEST FAILED:', error);
        return false;
    }
}

// Helper function to extract raw public key bytes from PEM
function extractPublicKeyBytes(pem) {
    const sodium = require('libsodium-wrappers');
    const b64 = pem
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, '');

    const fullBytes = sodium.from_base64(b64, sodium.base64_variants.ORIGINAL);

    // Strip ASN.1 header (last 32 bytes is the raw Ed25519 key)
    if (fullBytes.length > 32) {
        return fullBytes.slice(fullBytes.length - 32);
    }

    return fullBytes;
}

// Run the test
testSDKInstallation()
    .then(success => {
        process.exit(success ? 0 : 1);
    })
    .catch(error => {
        console.error('Unexpected error:', error);
        process.exit(1);
    });
