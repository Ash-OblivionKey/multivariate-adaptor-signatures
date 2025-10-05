/**
 * @file csv_utils.c
 * @brief Implementation of CSV utility functions
 * @author Post-Quantum Cryptography Research Team
 * @date 2024
 */

#include "csv_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Portable directory creation
#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

// Helper function to ensure results directory exists
static int ensure_results_directory(void) {
#ifdef _WIN32
    return _mkdir("results");
#else
    return mkdir("results", 0755);
#endif
}

// Function to write cryptographic results to CSV for analysis
void write_crypto_results_to_csv(const char* test_name, 
                                const uint8_t* signature, 
                                size_t sig_len,
                                const uint8_t* hash, 
                                size_t hash_len,
                                const uint8_t* witness, 
                                size_t witness_len,
                                const uint8_t* commitment, 
                                size_t commit_len,
                                uint32_t security_level) {
    
    // Validate input parameters
    if (!test_name || !signature || !hash || !witness || !commitment) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen("results/cryptographic_results.csv", "a");
    if (!csv_file) {
        // Create file with headers if it doesn't exist
        csv_file = fopen("results/cryptographic_results.csv", "w");
        if (csv_file) {
            fprintf(csv_file, "Timestamp,Test Name,Security Level,Signature (hex),Signature Length,Hash (hex),Hash Length,Witness (hex),Witness Length,Commitment (hex),Commitment Length\n");
        }
    }
    
    if (csv_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        // Write signature in hex with bounds checking
        fprintf(csv_file, "%s,%s,%u,", timestamp, test_name, security_level);
        const size_t max_hex_display = 32;
        for (size_t i = 0; i < sig_len && i < max_hex_display; i++) {
            fprintf(csv_file, "%02x", signature[i]);
        }
        if (sig_len > max_hex_display) fprintf(csv_file, "...");
        fprintf(csv_file, ",%zu,", sig_len);
        
        // Write hash in hex with bounds checking
        const size_t max_hash_display = 16;
        for (size_t i = 0; i < hash_len && i < max_hash_display; i++) {
            fprintf(csv_file, "%02x", hash[i]);
        }
        if (hash_len > max_hash_display) fprintf(csv_file, "...");
        fprintf(csv_file, ",%zu,", hash_len);
        
        // Write witness in hex with bounds checking
        for (size_t i = 0; i < witness_len && i < max_hash_display; i++) {
            fprintf(csv_file, "%02x", witness[i]);
        }
        if (witness_len > max_hash_display) fprintf(csv_file, "...");
        fprintf(csv_file, ",%zu,", witness_len);
        
        // Write commitment in hex with bounds checking
        for (size_t i = 0; i < commit_len && i < max_hash_display; i++) {
            fprintf(csv_file, "%02x", commitment[i]);
        }
        if (commit_len > max_hash_display) fprintf(csv_file, "...");
        fprintf(csv_file, ",%zu\n", commit_len);
        
        fclose(csv_file);
    }
}

// UOV-specific CSV writing function
void mv_uov_write_crypto_results_to_csv(const char* test_name, 
                                       const uint8_t* signature, 
                                       size_t sig_len,
                                       const uint8_t* message, 
                                       size_t msg_len,
                                       uint32_t security_level) {
    
    // Validate input parameters
    if (!test_name || !signature || !message) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen("results/uov_cryptographic_results.csv", "a");
    if (!csv_file) {
        // Create file with headers if it doesn't exist
        csv_file = fopen("results/uov_cryptographic_results.csv", "w");
        if (csv_file) {
            fprintf(csv_file, "Timestamp,Test Name,Security Level,Signature (hex),Signature Length,Message (hex),Message Length\n");
        }
    }
    
    if (csv_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        // Write signature in hex
        fprintf(csv_file, "%s,%s,%u,", timestamp, test_name, security_level);
        for (size_t i = 0; i < sig_len && i < 32; i++) { // Limit to first 32 bytes for readability
            fprintf(csv_file, "%02x", signature[i]);
        }
        if (sig_len > 32) fprintf(csv_file, "...");
        fprintf(csv_file, ",%zu,", sig_len);
        
        // Write message in hex
        for (size_t i = 0; i < msg_len && i < 16; i++) {
            fprintf(csv_file, "%02x", message[i]);
        }
        if (msg_len > 16) fprintf(csv_file, "...");
        fprintf(csv_file, ",%zu\n", msg_len);
        
        fclose(csv_file);
    }
}

// Stress test results CSV writing function - handles stress_test_result_t struct
void write_stress_test_results_to_csv(const void* results, int num_results, const char* filename) {
    // Validate input parameters
    if (!results || !filename || num_results <= 0) {
        // CSV validation failed
        return; // Fail silently for robustness
    }
    
    // CSV function called with valid parameters
    
    // Ensure results directory exists
    ensure_results_directory();
    
    // Define stress_test_result_t struct locally to match the test file
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
        char error_details[512];
        
        // Memory leak detection fields
        size_t initial_memory_usage;
        size_t post_warmup_memory_usage;
        size_t peak_memory_usage;
        size_t final_memory_usage;
        int64_t memory_growth_bytes;
        double memory_growth_percent;
        int64_t post_warmup_growth_bytes;
        double post_warmup_growth_percent;
        int memory_leak_iterations;
        size_t memory_samples[100]; // MAX_MEMORY_SAMPLES
        int memory_sample_count;
        
        // Enhanced error handling and reporting fields
        int total_errors;
        int critical_errors;
        int warning_errors;
        int recoverable_errors;
        int error_categories[10]; // MAX_ERROR_CATEGORIES
        char detailed_error_log[1024]; // MAX_ERROR_DETAILS
        int recovery_attempts;
        int successful_recoveries;
        double error_recovery_rate;
        bool test_aborted;
        char abort_reason[256];
        
        // Additional fields for CSV compatibility
        char test_status[64];
        char timestamp[32];
    } stress_test_result_t;
    
    const stress_test_result_t* stress_results = (const stress_test_result_t*)results;
    
    FILE* csv_file = fopen(filename, "w");
    if (!csv_file) {
        // Failed to create CSV file
        return; // Failed to create file
    }
    
    // CSV file opened successfully
    
    // Write CSV header matching stress_test_result_t struct
    fprintf(csv_file, "Security Level,Scheme,Algorithm,Total Iterations,Successful Iterations,Failed Iterations,");
    fprintf(csv_file, "Success Rate %%,Mean Time (ms),Min Time (ms),Max Time (ms),Std Deviation (ms),");
    fprintf(csv_file, "Coefficient of Variation %%,Performance Stability Score,Memory Leaks Detected,Error Count,Test Status,Timestamp\n");
    
    // Write data rows using correct struct fields
    // Starting to write data rows
    for (int i = 0; i < num_results; i++) {
        const stress_test_result_t* r = &stress_results[i];
        
        // Writing data row
        
        const char* scheme_name = (r->scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO";
        
        fprintf(csv_file, "%u,%s,%s,%d,%d,%d,", 
                r->security_level, scheme_name, r->algorithm ? r->algorithm : "Unknown",
                r->total_iterations, r->successful_iterations, r->failed_iterations);
        
        fprintf(csv_file, "%.2f,%.3f,%.3f,%.3f,%.3f,", 
                r->success_rate_percent, r->mean_total_time_ms, r->min_total_time_ms, 
                r->max_total_time_ms, r->std_deviation_ms);
        
        fprintf(csv_file, "%.2f,%.2f,%d,%d,%s,%s\n", 
                r->coefficient_of_variation, r->performance_stability_score, 
                r->memory_leaks_detected, r->error_count, r->test_status, r->timestamp);
    }
    // Finished writing data rows
    
    fclose(csv_file);
    // CSV file closed successfully
}

// Professional test results CSV writing functions for our 6 core tests

// Benchmark test results CSV writing function
void write_benchmark_results_to_csv(const benchmark_test_result_t* results, size_t num_results, const char* filename) {
    // Validate input parameters
    if (!results || !filename || num_results == 0) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen(filename, "w");
    if (!csv_file) {
        return;
    }
    
    // Write CSV header
    fprintf(csv_file, "test_name,timestamp,security_level,scheme,algorithm,total_iterations,successful_iterations,failed_iterations,success_rate_percent,mean_total_time_ms,min_total_time_ms,max_total_time_ms,std_deviation_ms,coefficient_of_variation,performance_stability_score,memory_leaks_detected,error_count,test_status\n");
    
    // Write data rows
    for (size_t i = 0; i < num_results; i++) {
        const benchmark_test_result_t* r = &results[i];
        const char* scheme_name = (r->scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO";
        fprintf(csv_file, "Benchmark_Test_%zu,%s,%u,%s,%s,%d,%d,%d,%.2f,%.3f,%.3f,%.3f,%.3f,%.2f,%.2f,%d,%d,%s\n",
                i, r->timestamp, r->security_level, scheme_name, r->algorithm ? r->algorithm : "Unknown",
                r->total_iterations, r->successful_iterations, r->failed_iterations,
                r->success_rate_percent, r->mean_total_time_ms, r->min_total_time_ms, r->max_total_time_ms,
                r->std_deviation_ms, r->coefficient_of_variation, r->performance_stability_score,
                r->memory_leaks_detected, r->error_count, r->test_status);
    }
    
    fclose(csv_file);
}

// Correctness test results CSV writing function
void write_correctness_results_to_csv(const correctness_test_result_t* results, size_t num_results, const char* filename) {
    // Validate input parameters
    if (!results || !filename || num_results == 0) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen(filename, "w");
    if (!csv_file) {
        return;
    }
    
    // Write CSV header
    fprintf(csv_file, "test_name,timestamp,security_level,scheme,algorithm,presignature_success,presignature_verification_success,signature_completion_success,witness_extraction_success,complete_signature_verification_success,error_count,test_status\n");
    
    // Write data rows
    for (size_t i = 0; i < num_results; i++) {
        const correctness_test_result_t* r = &results[i];
        const char* scheme_name = (r->scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO";
        fprintf(csv_file, "Correctness_Test_%zu,%s,%u,%s,%s,%s,%s,%s,%s,%s,%d,%s\n",
                i, r->timestamp, r->security_level, scheme_name, r->algorithm ? r->algorithm : "Unknown",
                r->presignature_success ? "TRUE" : "FALSE",
                r->presignature_verification_success ? "TRUE" : "FALSE",
                r->signature_completion_success ? "TRUE" : "FALSE",
                r->witness_extraction_success ? "TRUE" : "FALSE",
                r->complete_signature_verification_success ? "TRUE" : "FALSE",
                r->error_count, r->test_status);
    }
    
    fclose(csv_file);
}

// Integration test results CSV writing function
void write_integration_results_to_csv(const integration_test_result_t* results, size_t num_results, const char* filename) {
    // Validate input parameters
    if (!results || !filename || num_results == 0) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen(filename, "w");
    if (!csv_file) {
        return;
    }
    
    // Write CSV header
    fprintf(csv_file, "test_name,timestamp,security_level,scheme,algorithm,workflow_complete_success,error_count,test_status\n");
    
    // Write data rows
    for (size_t i = 0; i < num_results; i++) {
        const integration_test_result_t* r = &results[i];
        const char* scheme_name = (r->scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO";
        fprintf(csv_file, "Integration_Test_%zu,%s,%u,%s,%s,%s,%d,%s\n",
                i, r->timestamp, r->security_level, scheme_name, r->algorithm ? r->algorithm : "Unknown",
                r->workflow_complete_success ? "TRUE" : "FALSE",
                r->error_count, r->test_status);
    }
    
    fclose(csv_file);
}

// Validation test results CSV writing function
void write_validation_results_to_csv(const validation_test_result_t* results, size_t num_results, const char* filename) {
    // Validate input parameters
    if (!results || !filename || num_results == 0) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen(filename, "w");
    if (!csv_file) {
        return;
    }
    
    // Write CSV header
    fprintf(csv_file, "test_name,timestamp,security_level,scheme,algorithm,validation_success,error_count,test_status\n");
    
    // Write data rows
    for (size_t i = 0; i < num_results; i++) {
        const validation_test_result_t* r = &results[i];
        const char* scheme_name = (r->scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO";
        fprintf(csv_file, "Validation_Test_%zu,%s,%u,%s,%s,%s,%d,%s\n",
                i, r->timestamp, r->security_level, scheme_name, r->algorithm ? r->algorithm : "Unknown",
                r->validation_success ? "TRUE" : "FALSE",
                r->error_count, r->test_status);
    }
    
    fclose(csv_file);
}

// Comprehensive test results CSV writing function
void write_comprehensive_results_to_csv(const comprehensive_test_result_t* results, size_t num_results, const char* filename) {
    // Validate input parameters
    if (!results || !filename || num_results == 0) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen(filename, "w");
    if (!csv_file) {
        return;
    }
    
    // Write CSV header
    fprintf(csv_file, "test_name,timestamp,security_level,scheme,algorithm,message_size,total_iterations,successful_iterations,failed_iterations,success_rate_percent,mean_total_time_ms,min_total_time_ms,max_total_time_ms,std_deviation_ms,coefficient_of_variation,performance_stability_score,memory_leaks_detected,error_count,test_status\n");
    
    // Write data rows
    for (size_t i = 0; i < num_results; i++) {
        const comprehensive_test_result_t* r = &results[i];
        const char* scheme_name = (r->scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO";
        fprintf(csv_file, "Comprehensive_Test_%zu,%s,%u,%s,%s,%d,%d,%d,%d,%.2f,%.3f,%.3f,%.3f,%.3f,%.2f,%.2f,%d,%d,%s\n",
                i, r->timestamp, r->security_level, scheme_name, r->algorithm ? r->algorithm : "Unknown",
                r->message_size, r->total_iterations, r->successful_iterations, r->failed_iterations,
                r->success_rate_percent, r->mean_total_time_ms, r->min_total_time_ms, r->max_total_time_ms,
                r->std_deviation_ms, r->coefficient_of_variation, r->performance_stability_score,
                r->memory_leaks_detected, r->error_count, r->test_status);
    }
    
    fclose(csv_file);
}

// Timing attack test results CSV writing function
void write_timing_attack_results_to_csv(const timing_attack_test_result_t* results, size_t num_results, const char* filename) {
    // Validate input parameters
    if (!results || !filename || num_results == 0) {
        return; // Fail silently for robustness
    }
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen(filename, "w");
    if (!csv_file) {
        return;
    }
    
    // Write CSV header for comprehensive timing attack analysis
    fprintf(csv_file, "test_name,timestamp,security_level,scheme,algorithm,passed,confidence_level,");
    fprintf(csv_file, "mean_timing_ms,std_deviation_ms,coefficient_of_variation,min_timing_ms,max_timing_ms,");
    fprintf(csv_file, "tvla_t_statistic,tvla_threshold,leakage_detected,mann_whitney_p_value,");
    fprintf(csv_file, "autocorrelation_lag1,autocorrelation_lag2,autocorrelation_lag3,trend_slope,");
    fprintf(csv_file, "significant_patterns_detected,timing_independence_pass,constant_time_pass,test_status,details\n");
    
    // Write data rows
    for (size_t i = 0; i < num_results; i++) {
        const timing_attack_test_result_t* r = &results[i];
        const char* scheme_name = (r->scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO";
        
        fprintf(csv_file, "%s,%s,%u,%s,%s,%s,%.6f,", 
                r->test_name ? r->test_name : "Unknown_Test",
                r->timestamp, r->security_level, scheme_name, 
                r->algorithm ? r->algorithm : "Unknown",
                r->passed ? "TRUE" : "FALSE", r->confidence_level);
        
        fprintf(csv_file, "%.6f,%.6f,%.6f,%.6f,%.6f,", 
                r->mean_timing_ms, r->std_deviation_ms, r->coefficient_of_variation,
                r->min_timing_ms, r->max_timing_ms);
        
        fprintf(csv_file, "%.6f,%.6f,%s,%.6f,", 
                r->tvla_t_statistic, r->tvla_threshold, 
                r->leakage_detected ? "TRUE" : "FALSE", r->mann_whitney_p_value);
        
        fprintf(csv_file, "%.6f,%.6f,%.6f,%.8f,", 
                r->autocorrelation_lag1, r->autocorrelation_lag2, r->autocorrelation_lag3, r->trend_slope);
        
        fprintf(csv_file, "%d,%s,%s,%s,\"%s\"\n", 
                r->significant_patterns_detected,
                r->timing_independence_pass ? "TRUE" : "FALSE",
                r->constant_time_pass ? "TRUE" : "FALSE",
                r->test_status,
                r->details);
    }
    
    fclose(csv_file);
}

// Function to write clean research-grade CSV results
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
                             const char* notes) {
    
    // Validate input parameters
    if (!filename || !scheme || !algorithm || !notes) {
        return; // Fail silently for robustness
    }
    
    // Suppress unused parameter warnings
    (void)min_time_ms;
    (void)max_time_ms;
    (void)iterations;
    
    // Ensure results directory exists
    ensure_results_directory();
    
    FILE* csv_file = fopen(filename, "a");
    if (!csv_file) {
        // Create file with headers if it doesn't exist
        csv_file = fopen(filename, "w");
        if (csv_file) {
            fprintf(csv_file, "Configuration,Performance_ms,Memory_MB,Validation_Status,Notes\n");
        }
    }
    
    if (csv_file) {
        // Create configuration string
        char config[128];
        snprintf(config, sizeof(config), "%s-%s-%u", scheme, algorithm, security_level);
        
        // Create performance string with mean ± std dev
        char performance[64];
        snprintf(performance, sizeof(performance), "%.2f±%.2f", mean_time_ms, std_dev_ms);
        
        // Create validation status
        const char* status = (success_rate >= 99.9) ? "VALIDATED" : "PARTIAL";
        
        // Write clean CSV row
        fprintf(csv_file, "%s,%s,%.2f,%s,%s\n", 
                config, performance, memory_peak_mb, status, notes);
        
        fclose(csv_file);
    }
}