/**
 * Amorce Exceptions Module
 * Defines custom exceptions for the Amorce SDK to allow fine-grained error handling.
 * Matches the exception hierarchy from nexus-py-sdk v0.1.7
 */

/**
 * Base class for all Amorce SDK exceptions.
 */
export class AmorceError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AmorceError';
        // Maintains proper stack trace for where our error was thrown (only available on V8)
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}

/**
 * Raised when there is a configuration issue (e.g. invalid URL, missing key).
 */
export class AmorceConfigError extends AmorceError {
    constructor(message: string) {
        super(message);
        this.name = 'AmorceConfigError';
    }
}

/**
 * Raised when a network operation fails (e.g. connection timeout, DNS error).
 */
export class AmorceNetworkError extends AmorceError {
    constructor(message: string) {
        super(message);
        this.name = 'AmorceNetworkError';
    }
}

/**
 * Raised when the Amorce API returns an error response (4xx, 5xx).
 */
export class AmorceAPIError extends AmorceError {
    public statusCode?: number;
    public responseBody?: string;

    constructor(message: string, statusCode?: number, responseBody?: string) {
        super(message);
        this.name = 'AmorceAPIError';
        this.statusCode = statusCode;
        this.responseBody = responseBody;
    }
}

/**
 * Raised when a security-related operation fails (e.g. signing, key loading).
 */
export class AmorceSecurityError extends AmorceError {
    constructor(message: string) {
        super(message);
        this.name = 'AmorceSecurityError';
    }
}

/**
 * Raised when data validation fails (e.g. invalid envelope structure).
 */
export class AmorceValidationError extends AmorceError {
    constructor(message: string) {
        super(message);
        this.name = 'AmorceValidationError';
    }
}
