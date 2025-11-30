/**
 * Amorce SDK for JavaScript/TypeScript
 * Version 0.1.7
 * 
 * Aligned with nexus-py-sdk v0.1.7
 */

export const SDK_VERSION = "0.1.7";
export const AATP_VERSION = "0.1.0";

// Export Exception Classes
export * from './exceptions';

// Export Identity Module (with Provider Pattern)
export * from './identity';

// Export Envelope Module (Legacy/Future Use)
export * from './envelope';

// Export Client Module
export * from './client';

console.log(`Amorce JS SDK v${SDK_VERSION} loaded.`);