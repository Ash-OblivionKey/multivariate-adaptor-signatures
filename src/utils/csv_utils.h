/**
 * @file csv_utils.h
 * @brief Utility functions for CSV output and data logging
 * @author Post-Quantum Cryptography Research Team
 * @date 2024
 */

#ifndef CSV_UTILS_H
#define CSV_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Portable UNUSED macro for cross-compiler compatibility
#if defined(__GNUC__) || defined(__clang__)
#  define UNUSED __attribute__((unused))
#else
#  define UNUSED
#endif

// Include the main adaptor header to get the enum definition
#include "../interfaces/multivariate_adaptor.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Write cryptographic results to CSV for analysis
 * @param test_name Name of the test being run
 * @param signature The generated signature
 * @param sig_len Length of the signature
 * @param hash The hash that was signed
 * @param hash_len Length of the hash
 * @param witness The witness (if any)
 * @param witness_len Length of the witness
 * @param commitment The commitment (if any)
 * @param commit_len Length of the commitment
 * @param security_level The security level used
 */
void write_crypto_results_to_csv(const char* test_name, 
                                const uint8_t* signature, 
                                size_t sig_len,
                                const uint8_t* hash, 
                                size_t hash_len,
                                const uint8_t* witness, 
                                size_t witness_len,
                                const uint8_t* commitment, 
                                size_t commit_len,
                                uint32_t security_level);

/**
 * @brief Write clean research-grade CSV results
 * @param filename Output CSV filename
 * @param scheme Scheme name (UOV/MAYO)
 * @param algorithm Algorithm name
 * @param security_level Security level in bits
 * @param mean_time_ms Mean execution time in milliseconds
 * @param std_dev_ms Standard deviation in milliseconds
 * @param min_time_ms Minimum time in milliseconds
 * @param max_time_ms Maximum time in milliseconds
 * @param success_rate Success rate percentage
 * @param memory_peak_mb Peak memory usage in MB
 * @param iterations Number of test iterations
 * @param notes Additional notes
 */
void write_clean_research_csv(const char* filename,
                             const char* scheme,
                             const char* algorithm,
                             uint32_t security_level,
                             double mean_time_ms,
                             double std_dev_ms,
                             double min_time_ms,
                             double max_time_ms,
                             double success_rate,
                             double memory_peak_mb,
                             int iterations,
                             const char* notes);

/**
 * @brief Write UOV cryptographic results to CSV for analysis
 * @param test_name Name of the test being run
 * @param signature The generated signature
 * @param sig_len Length of the signature
 * @param message The message that was signed
 * @param msg_len Length of the message
 * @param security_level The security level used
 */
void mv_uov_write_crypto_results_to_csv(const char* test_name, 
                                       const uint8_t* signature, 
                                       size_t sig_len,
                                       const uint8_t* message, 
                                       size_t msg_len,
                                       uint32_t security_level);

/**
 * @brief Write stress test results to CSV for analysis
 * @param results Array of stress test results
 * @param num_results Number of results in the array
 * @param filename Output filename for CSV
 */
void write_stress_test_results_to_csv(const void* results, int num_results, const char* filename);

// Professional test result structures for our 6 core tests
typedef struct {
    uint32_t security_level;
    adaptor_scheme_type_t scheme;
    const char* algorithm;
    int total_iterations;
    int successful_iterations;
    int failed_iterations;
    double success_rate_percent;
    double mean_total_time_ms;
    double min_total_time_ms;
    double max_total_time_ms;
    double std_deviation_ms;
    double coefficient_of_variation;
    double performance_stability_score;
    int memory_leaks_detected;
    int error_count;
    char test_status[64];
    char timestamp[32];
} benchmark_test_result_t;

typedef struct {
    uint32_t security_level;
    adaptor_scheme_type_t scheme;
    const char* algorithm;
    bool presignature_success;
    bool presignature_verification_success;
    bool signature_completion_success;
    bool witness_extraction_success;
    bool complete_signature_verification_success;
    int error_count;
    char test_status[64];
    char timestamp[32];
} correctness_test_result_t;

typedef struct {
    uint32_t security_level;
    adaptor_scheme_type_t scheme;
    const char* algorithm;
    bool workflow_complete_success;
    int error_count;
    char test_status[64];
    char timestamp[32];
} integration_test_result_t;

typedef struct {
    uint32_t security_level;
    adaptor_scheme_type_t scheme;
    const char* algorithm;
    bool validation_success;
    int error_count;
    char test_status[64];
    char timestamp[32];
} validation_test_result_t;

typedef struct {
    uint32_t security_level;
    adaptor_scheme_type_t scheme;
    const char* algorithm;
    int message_size;
    int total_iterations;
    int successful_iterations;
    int failed_iterations;
    double success_rate_percent;
    double mean_total_time_ms;
    double min_total_time_ms;
    double max_total_time_ms;
    double std_deviation_ms;
    double coefficient_of_variation;
    double performance_stability_score;
    int memory_leaks_detected;
    int error_count;
    char test_status[64];
    char timestamp[32];
} comprehensive_test_result_t;

typedef struct {
    uint32_t security_level;
    adaptor_scheme_type_t scheme;
    const char* algorithm;
    const char* test_name;
    int passed;
    double confidence_level;
    double mean_timing_ms;
    double std_deviation_ms;
    double coefficient_of_variation;
    double min_timing_ms;
    double max_timing_ms;
    double tvla_t_statistic;
    double tvla_threshold;
    int leakage_detected;
    double mann_whitney_p_value;
    double autocorrelation_lag1;
    double autocorrelation_lag2;
    double autocorrelation_lag3;
    double trend_slope;
    int significant_patterns_detected;
    int timing_independence_pass;
    int constant_time_pass;
    char test_status[64];
    char details[256];
    char timestamp[32];
} timing_attack_test_result_t;

// CSV writing functions for our 7 professional tests
void write_benchmark_results_to_csv(const benchmark_test_result_t* results, size_t num_results, const char* filename);
void write_correctness_results_to_csv(const correctness_test_result_t* results, size_t num_results, const char* filename);
void write_integration_results_to_csv(const integration_test_result_t* results, size_t num_results, const char* filename);
void write_validation_results_to_csv(const validation_test_result_t* results, size_t num_results, const char* filename);
void write_comprehensive_results_to_csv(const comprehensive_test_result_t* results, size_t num_results, const char* filename);
void write_timing_attack_results_to_csv(const timing_attack_test_result_t* results, size_t num_results, const char* filename);

#ifdef __cplusplus
}
#endif

#endif // CSV_UTILS_H
