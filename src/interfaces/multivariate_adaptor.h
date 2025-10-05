/**
 * @file multivariate_adaptor.h
 * @brief Multivariate Post-Quantum Adaptor Signature Framework
 * 
 * This header provides the complete interface for multivariate post-quantum
 * adaptor signatures, supporting both UOV (Unbalanced Oil and Vinegar) and
 * MAYO (Multivariate Asymmetric YO) signature schemes.
 * 
 * Features:
 * - UOV and MAYO signature scheme integration
 * - Adaptor signature operations (PreSign, Adapt, Verify, Extract)
 * - Witness hiding and extractability
 * - HMAC-SHA256 commitment schemes
 * - Unified API for multiple multivariate schemes
 * 
 * @author Post-Quantum Cryptography Research Team
 * @date 2024
 */

#ifndef MULTIVARIATE_ADAPTOR_H
#define MULTIVARIATE_ADAPTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// ADAPTOR SIGNATURE DATA STRUCTURES
// ============================================================================

// Multivariate adaptor signature scheme types
typedef enum {
    ADAPTOR_SCHEME_UOV = 0,  // UOV from OQS
    ADAPTOR_SCHEME_MAYO = 1, // MAYO from OQS
    ADAPTOR_SCHEME_MAX = 2
} adaptor_scheme_type_t;

// Pre-signature structure
typedef struct {
    uint32_t security_level;
    uint8_t* commitment;      // Commitment to randomness r
    uint8_t* signature;       // UOV signature component
    uint8_t* message_hash;    // Hash of message and commitment μ = H(m || c)
    size_t commitment_size;
    size_t signature_size;
    size_t message_hash_size;
    uint8_t* randomness;      // Randomness r used in commitment
    size_t randomness_size;
    size_t witness_size;      // Original witness size for extraction
} adaptor_presignature_t;

// Complete signature structure
typedef struct {
    adaptor_presignature_t presignature;
    uint8_t* witness;         // Witness w for completion
    size_t witness_size;
    uint8_t* signature;       // Complete signature data
    size_t signature_size;    // Size of complete signature
} adaptor_signature_t;

// Multivariate adaptor signature parameters
typedef struct {
    uint32_t security_level;  // 128, 192, or 256 bits
    uint32_t commitment_size; // Size of commitment (64 bytes: key + HMAC)
    uint32_t witness_size;    // Size of witness
    uint32_t hash_size;       // Size of hash output (32 for SHA-256, 64 for SHA3-512)
    adaptor_scheme_type_t scheme; // UOV or MAYO scheme
    bool witness_hiding;
    bool witness_extractable;
    bool presignature_unforgeable;
} adaptor_params_t;

// Multivariate adaptor signature context
typedef struct {
    adaptor_params_t params;
    void* private_key;        // UOV or MAYO private key
    void* public_key;         // UOV or MAYO public key
    void* cached_sig_obj;     // Cached OQS_SIG object for constant-time verification
} adaptor_context_t;

// ============================================================================
// ERROR CODES AND VALIDATION
// ============================================================================

// Comprehensive error codes for robust error handling
typedef enum {
    ADAPTOR_SUCCESS = 0,                    // Operation successful
    ADAPTOR_ERROR_NULL_POINTER = -1,        // Null pointer provided
    ADAPTOR_ERROR_INVALID_PARAMS = -2,      // Invalid parameters
    ADAPTOR_ERROR_INVALID_SECURITY_LEVEL = -3, // Invalid security level
    ADAPTOR_ERROR_MEMORY_ALLOCATION = -4,   // Memory allocation failed
    ADAPTOR_ERROR_INVALID_INPUT_SIZE = -5,  // Invalid input size
    ADAPTOR_ERROR_CRYPTO_OPERATION = -6,    // Cryptographic operation failed
    ADAPTOR_ERROR_INVALID_SIGNATURE = -7,   // Invalid signature
    ADAPTOR_ERROR_INVALID_WITNESS = -8,     // Invalid witness
    ADAPTOR_ERROR_COMMITMENT_FAILED = -9,   // Commitment operation failed
    ADAPTOR_ERROR_VERIFICATION_FAILED = -10, // Verification failed
    ADAPTOR_ERROR_EXTRACTION_FAILED = -11,  // Witness extraction failed
    ADAPTOR_ERROR_SERIALIZATION = -12,      // Serialization/deserialization failed
    ADAPTOR_ERROR_CONTEXT_NOT_INITIALIZED = -13, // Context not properly initialized
    ADAPTOR_ERROR_INVALID_MESSAGE = -14,    // Invalid message
    ADAPTOR_ERROR_LIBOQS_ERROR = -15,       // liboqs operation failed
    ADAPTOR_ERROR_OPENSSL_ERROR = -16,      // OpenSSL operation failed
    ADAPTOR_ERROR_INTERNAL = -17,           // Internal error
    ADAPTOR_ERROR_BUFFER_OVERFLOW = -18,    // Buffer overflow detected
    ADAPTOR_ERROR_INVALID_ALIGNMENT = -19,  // Invalid memory alignment
    ADAPTOR_ERROR_TIMEOUT = -20,            // Operation timeout
    ADAPTOR_ERROR_RESOURCE_EXHAUSTED = -21, // System resource exhausted
    ADAPTOR_ERROR_CONCURRENT_ACCESS = -22,  // Concurrent access violation
    ADAPTOR_ERROR_CORRUPTED_DATA = -23,     // Data corruption detected
    ADAPTOR_ERROR_INVALID_STATE = -24,      // Invalid state transition
    ADAPTOR_ERROR_RATE_LIMIT = -25,         // Rate limit exceeded
    ADAPTOR_ERROR_ENTROPY_INSUFFICIENT = -26, // Insufficient entropy
    ADAPTOR_ERROR_MEMORY_CORRUPTION = -27,  // Memory corruption detected
    ADAPTOR_ERROR_CRYPTOGRAPHIC_WEAKNESS = -28, // Cryptographic weakness detected
    ADAPTOR_ERROR_SIDE_CHANNEL_DETECTED = -29,  // Side channel attack detected
    ADAPTOR_ERROR_FAULT_INJECTION = -30,    // Fault injection detected
    ADAPTOR_ERROR_MAX_ERROR = -31           // Maximum error code
} adaptor_error_t;

// Input validation limits
#define ADAPTOR_MAX_MESSAGE_SIZE (64 * 1024)    // 64KB max message size
#define ADAPTOR_MAX_WITNESS_SIZE (1024)         // 1KB max witness size
#define ADAPTOR_MIN_MESSAGE_SIZE 1              // Minimum message size
#define ADAPTOR_MIN_WITNESS_SIZE 1              // Minimum witness size

// Constant-time operation buffer sizes
#define ADAPTOR_MAX_SIGNATURE_SIZE (1024 * 1024)  // 1MB max signature size for constant-time operations
#define ADAPTOR_MAX_MESSAGE_BUFFER_SIZE 1024      // 1KB message buffer for constant-time operations
#define ADAPTOR_MAX_WITNESS_BUFFER_SIZE 80        // 80 bytes witness buffer for constant-time operations

// Statement/commitment constants - always use SHA256 for consistency
#define ADAPTOR_COMMITMENT_KEY_SIZE 32          // Commitment key size
#define ADAPTOR_COMMITMENT_MAC_SIZE 32          // HMAC-SHA256 commitment size
#define ADAPTOR_STATEMENT_SIZE (ADAPTOR_COMMITMENT_KEY_SIZE + ADAPTOR_COMMITMENT_MAC_SIZE) // 64 bytes total
// Statement layout: statement_c = key[32] || mac[32] where mac = HMAC(key, ADAPTOR_DS || w)
#define ADAPTOR_HASH_SIZE 32                    // SHA256 output size (fixed)
#define ADAPTOR_DS "ADAPTORv1"                  // Domain separation string for HMAC

// Compile-time assertions for constant consistency
_Static_assert(ADAPTOR_STATEMENT_SIZE == 64, "Statement size must be exactly 64 bytes");
_Static_assert(ADAPTOR_COMMITMENT_KEY_SIZE == 32, "Commitment key size must be exactly 32 bytes");
_Static_assert(ADAPTOR_COMMITMENT_MAC_SIZE == 32, "Commitment MAC size must be exactly 32 bytes");
_Static_assert(ADAPTOR_HASH_SIZE == 32, "Hash size must be exactly 32 bytes for SHA256");

// ============================================================================
// PARAMETER MANAGEMENT
// ============================================================================

/**
 * Get adaptor signature parameters for a given security level and scheme
 * @param security_level The desired security level (128, 192, 256)
 * @param scheme The signature scheme (UOV or MAYO)
 * @return Pointer to adaptor parameters, NULL if invalid
 */
const adaptor_params_t* adaptor_get_params(uint32_t security_level, adaptor_scheme_type_t scheme);

/**
 * Validate UOV adaptor signature parameters with detailed error reporting
 * @param params The parameters to validate
 * @param error_code Output parameter for detailed error code
 * @return true if valid, false otherwise
 */
bool adaptor_validate_params_detailed(const adaptor_params_t* params, adaptor_error_t* error_code);

/**
 * Validate UOV adaptor signature parameters
 * @param params The parameters to validate
 * @return true if valid, false otherwise
 */
bool adaptor_validate_params(const adaptor_params_t* params);

/**
 * Get error string for error code
 * @param error_code The error code
 * @return Human-readable error string
 */
const char* adaptor_get_error_string(adaptor_error_t error_code);

// ============================================================================
// CONTEXT MANAGEMENT
// ============================================================================

/**
 * Initialize multivariate adaptor signature context
 * @param ctx The context to initialize
 * @param params The adaptor parameters
 * @param priv_key The private key (UOV or MAYO) - can be NULL for attacker contexts
 * @param pub_key The public key (UOV or MAYO)
 * @return 0 on success, -1 on failure
 */
int adaptor_context_init(adaptor_context_t* ctx, const adaptor_params_t* params,
                        void* priv_key, void* pub_key);


/**
 * Clean up multivariate adaptor signature context
 * @param ctx The context to clean up
 * @return 0 on success, -1 on failure
 */
int adaptor_context_cleanup(adaptor_context_t* ctx);

/**
 * Get context size in bytes
 * @param ctx The context
 * @return Size in bytes
 */
size_t adaptor_context_size(const adaptor_context_t* ctx);

// ============================================================================
// PRE-SIGNATURE GENERATION
// ============================================================================

/**
 * Initialize pre-signature structure
 * @param presig The pre-signature to initialize
 * @param ctx The adaptor context
 * @return 0 on success, -1 on failure
 */
int adaptor_presignature_init(adaptor_presignature_t* presig, 
                             const adaptor_context_t* ctx);

/**
 * Generate pre-signature for a message and statement
 * @param presig The pre-signature to generate
 * @param ctx The adaptor context
 * @param message The message to sign
 * @param message_len Length of the message
 * @param statement_c The statement/commitment (MUST be generated by witness holder using adaptor_generate_statement_from_witness)
 * @param c_len Length of the statement (must be exactly 64 bytes: key[32] || HMAC[32])
 * @return 0 on success, -1 on failure
 */
int adaptor_presignature_generate(adaptor_presignature_t* presig,
                                 const adaptor_context_t* ctx,
                                 const uint8_t* message, size_t message_len,
                                 const uint8_t* statement_c, size_t c_len);

/**
 * Verify pre-signature without revealing witness
 * @param presig The pre-signature to verify
 * @param ctx The adaptor context
 * @param message The original message
 * @param message_len Length of the message
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int adaptor_presignature_verify(const adaptor_presignature_t* presig,
                               const adaptor_context_t* ctx,
                               const uint8_t* message, size_t message_len);

/**
 * Clean up pre-signature
 * @param presig The pre-signature to clean up
 * @return 0 on success, -1 on failure
 */
int adaptor_presignature_cleanup(adaptor_presignature_t* presig);

/**
 * Get pre-signature size in bytes
 * @param presig The pre-signature
 * @return Size in bytes
 */
size_t adaptor_presignature_size(const adaptor_presignature_t* presig);

// ============================================================================
// SIGNATURE COMPLETION
// ============================================================================

/**
 * Initialize complete signature structure
 * @param sig The signature to initialize
 * @param presig The pre-signature to copy
 * @param ctx The adaptor context
 * @return 0 on success, -1 on failure
 */
int adaptor_signature_init(adaptor_signature_t* sig, 
                          const adaptor_presignature_t* presig,
                          const adaptor_context_t* ctx);

/**
 * Complete signature using witness
 * @param sig The complete signature to generate
 * @param presig The pre-signature
 * @param witness The witness for completion
 * @param witness_len Length of the witness
 * @return 0 on success, -1 on failure
 */
int adaptor_signature_complete(adaptor_signature_t* sig,
                              const adaptor_presignature_t* presig,
                              const uint8_t* witness, size_t witness_len);

/**
 * Verify complete signature
 * @param sig The signature to verify
 * @param ctx The adaptor context
 * @param message The original message
 * @param message_len Length of the message
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int adaptor_signature_verify(const adaptor_signature_t* sig,
                            const adaptor_context_t* ctx,
                            const uint8_t* message, size_t message_len);

/**
 * Clean up complete signature
 * @param sig The signature to clean up
 * @return 0 on success, -1 on failure
 */
int adaptor_signature_cleanup(adaptor_signature_t* sig);


/**
 * Get complete signature size in bytes
 * @param sig The signature
 * @return Size in bytes
 */
size_t adaptor_signature_size(const adaptor_signature_t* sig);

// ============================================================================
// WITNESS EXTRACTION
// ============================================================================

/**
 * Extract witness from pre-signature and complete signature
 * @param witness Buffer to store extracted witness
 * @param witness_size Size of witness buffer
 * @param presig The pre-signature
 * @param sig The complete signature
 * @return 0 on success, -1 on failure
 */
int adaptor_witness_extract(uint8_t* witness, size_t witness_size,
                           const adaptor_presignature_t* presig,
                           const adaptor_signature_t* sig);

/**
 * Get required witness size for extraction
 * @param ctx The adaptor context
 * @return Required witness size in bytes
 */
size_t adaptor_witness_size(const adaptor_context_t* ctx);

/**
 * Verify witness is valid for pre-signature
 * @param presig The pre-signature
 * @param witness The witness to verify
 * @param witness_len Length of the witness
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int adaptor_witness_verify(const adaptor_presignature_t* presig,
                          const uint8_t* witness, size_t witness_len);



// ============================================================================
// STATEMENT GENERATION (for witness holders)
// ============================================================================

/**
 * Generate statement/commitment from witness using HMAC-SHA256 with embedded random key
 * @param witness The witness to commit to
 * @param witness_len Length of the witness
 * @param statement_c Output buffer for the statement (must be at least 64 bytes: key[32] || mac[32])
 * @param c_len Length of output buffer (must be exactly 64)
 * @return 0 on success, -1 on failure
 */
int adaptor_generate_statement_from_witness(const uint8_t* witness, size_t witness_len,
                                           uint8_t* statement_c, size_t c_len);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Get description of multivariate adaptor signature scheme
 * @param scheme The scheme type (UOV or MAYO)
 * @return Description string
 */
const char* adaptor_get_scheme_description(adaptor_scheme_type_t scheme);

/**
 * Get security level of adaptor parameters
 * @param params The parameters
 * @return Security level in bits
 */
uint32_t adaptor_get_security_level(const adaptor_params_t* params);

/**
 * Check if adaptor parameters are secure
 * @param params The parameters
 * @return true if secure, false otherwise
 */
bool adaptor_is_secure(const adaptor_params_t* params);

// ============================================================================
// PERFORMANCE OPTIMIZATION AND MEMORY EFFICIENCY
// ============================================================================
// Note: Performance optimization functions removed to eliminate unimplemented code
// The core implementation uses standard memory management for reliability and security

#ifdef __cplusplus
}
#endif

#endif // MULTIVARIATE_ADAPTOR_H
