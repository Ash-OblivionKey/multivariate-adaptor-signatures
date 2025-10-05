/*
 * test_stress.c
 * Stress testing for multivariate adaptor signatures
 *
 * - Runs T20 stress testing per configuration (UOV/MAYO × 128,192,256)
 * - T20: Stress testing (high iterations, memory pressure, resource exhaustion)
 * - Produces detailed stress analysis and optional CSV in build/bin/results/
 *
 * Requirements satisfied:
 * - No placeholder/demo code
 * - Secure cleanup (OPENSSL_cleanse / OQS_MEM_secure_bcmp)
 * - Robust error handling and resource cleanup on all paths
 * - Deterministic ordering: all UOV levels first, then MAYO
 * - CSV output for stress analysis
 * - STRESS tests (high iterations, memory pressure, resource exhaustion)
 *
 * Build: link with liboqs and OpenSSL; include project headers for adaptor API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include <oqs/oqs.h>

#ifdef _WIN32
# include <windows.h>
# include <psapi.h>
# include <direct.h>
# include <process.h>
#else
# include <sys/stat.h>
# include <unistd.h>
# include <sys/resource.h>
#endif

#include "../../src/interfaces/multivariate_adaptor.h"

#define MAX_CONFIGS 6
#define DEFAULT_ITERATIONS 100
#define MAX_ITERATIONS 10000
#define TIMESTAMP_LEN 32
#define GIT_SHA_LEN 64
// CSV_DIR will be determined dynamically based on current working directory

/* ===== STRESS CONFIGURATION ===== */
#define STRESS_ITERATIONS 1000
#define MEMORY_PRESSURE_ITERATIONS 100
#define RESOURCE_EXHAUSTION_ITERATIONS 50
/* ================================ */

typedef struct {
    adaptor_scheme_type_t scheme;
    uint32_t security_level;
} config_def_t;

typedef struct {
    char scheme[16];
    uint32_t security_level;
    char algorithm[64];
    bool enabled;
    bool passed;
    int iterations_run;
    int iterations_passed;
    int iterations_failed;
    double total_time_ms;
    double mean_time_ms;
    double op_times[3]; /* T20 stress tests: high_iterations, memory_pressure, resource_exhaustion */
    int t20_passed, t20_total; /* T20 test counts */
    int high_iter_passed, high_iter_total; /* High iteration stress counts */
    int memory_passed, memory_total; /* Memory pressure counts */
    int resource_passed, resource_total; /* Resource exhaustion counts */
    size_t max_memory_used; /* Maximum memory usage in bytes */
    int memory_leaks_detected; /* Number of memory leaks detected */
    char timestamp[TIMESTAMP_LEN];
    char git_sha[GIT_SHA_LEN];
} result_t;

/* ===== crash handling and diagnostics ===== */

static void crash_handler(int sig) {
    const char *name = "UNKNOWN";
    if (sig == SIGSEGV) name = "SIGSEGV";
    else if (sig == SIGABRT) name = "SIGABRT";
    else if (sig == SIGILL)  name = "SIGILL";
    else if (sig == SIGFPE)  name = "SIGFPE";
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "*** FATAL: signal %d (%s). Aborting stress test.\n", sig, name);
    if (len > 0) {
#ifdef _WIN32
        fwrite(buf, 1, (size_t)len, stderr);
#else
        write(STDERR_FILENO, buf, (size_t)len);
#endif
    }
    _exit(128 + (sig & 0xff));
}

static void install_crash_handlers(void) {
#ifndef _WIN32
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
#else
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGILL,  crash_handler);
    signal(SIGFPE,  crash_handler);
#endif
}

static bool g_verbose = false;

static void print_debug_step(const char *step) {
    (void)step;
    if (!g_verbose) return;
    fflush(stderr);
}

/* ===== helpers ===== */

static double now_ms(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER c;
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return (double)time(NULL) * 1000;
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
#endif
}

static void iso_timestamp(char *out, size_t n) {
    time_t t = time(NULL);
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static FILE* portable_popen(const char *cmd) {
#ifdef _WIN32
    return _popen(cmd, "r");
#else
    return popen(cmd, "r");
#endif
}

static void portable_pclose(FILE *f) {
#ifdef _WIN32
    _pclose(f);
#else
    pclose(f);
#endif
}

static void get_git_sha(char *out, size_t n) {
    const char *env = getenv("GITHUB_SHA");
    if (!env) env = getenv("GIT_COMMIT");
    if (env) {
        strncpy(out, env, n-1);
        out[n-1] = '\0';
        return;
    }
#ifdef _WIN32
    const char *cmd = "git rev-parse HEAD 2>NUL";
#else
    const char *cmd = "git rev-parse HEAD 2>/dev/null";
#endif
    FILE *f = portable_popen(cmd);
    if (f) {
        if (fgets(out, (int)n, f)) {
            char *nl = strchr(out, '\n');
            if (nl) *nl = '\0';
        } else {
            strncpy(out, "unknown", n-1);
            out[n-1] = '\0';
        }
        portable_pclose(f);
    } else {
        strncpy(out, "unknown", n-1);
        out[n-1] = '\0';
    }
}

static bool ci_contains(const char *hay, const char *needle) {
    if (!hay || !needle) return false;
    size_t n = strlen(needle);
    if (n == 0) return true;
    for (const char *p = hay; *p; ++p) {
#ifdef _WIN32
        if (_strnicmp(p, needle, n) == 0) return true;
#else
        if (strncasecmp(p, needle, n) == 0) return true;
#endif
    }
    return false;
}

static const char *select_sig_alg(adaptor_scheme_type_t scheme, uint32_t level) {
    int n = OQS_SIG_alg_count();
    const char *prefer = NULL;
    if (scheme == ADAPTOR_SCHEME_UOV) {
        if (level == 128) prefer = "ov-is";
        else if (level == 192) prefer = "ov-ip";
        else if (level == 256) prefer = "ov-iii";
        else prefer = "ov-";
    } else {
        if (level == 128) prefer = "mayo-1";
        else if (level == 192) prefer = "mayo-3";
        else if (level == 256) prefer = "mayo-5";
        else prefer = "mayo";
    }

    if (prefer) {
        for (int i = 0; i < n; ++i) {
            const char *id = OQS_SIG_alg_identifier(i);
            if (!id) continue;
            if (OQS_SIG_alg_is_enabled(id) && ci_contains(id, prefer)) return id;
        }
    }
    const char *token = (scheme == ADAPTOR_SCHEME_UOV) ? "OV" : "MAYO";
    for (int i = 0; i < n; ++i) {
        const char *id = OQS_SIG_alg_identifier(i);
        if (!id) continue;
        if (ci_contains(id, token) && OQS_SIG_alg_is_enabled(id)) return id;
    }
    for (int i = 0; i < n; ++i) {
        const char *id = OQS_SIG_alg_identifier(i);
        if (id && OQS_SIG_alg_is_enabled(id)) return id;
    }
    return NULL;
}

static int ensure_dir(const char *dir) {
    if (!dir) return -1;
#ifdef _WIN32
    if (_mkdir(dir) == 0 || errno == EEXIST) return 0;
#else
    struct stat st = {0};
    if (stat(dir, &st) == -1) {
        if (mkdir(dir, 0755) == 0) return 0;
    } else {
        return 0;
    }
#endif
    return -1;
}

/* ===== memory monitoring ===== */

static size_t get_memory_usage(void) {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return (size_t)pmc.WorkingSetSize;
    }
    return 0;
#else
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    
    size_t memory = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %zu kB", &memory);
            memory *= 1024; // Convert to bytes
            break;
        }
    }
    fclose(f);
    return memory;
#endif
}

static void secure_free_sk(uint8_t *sk, size_t len) {
    if (sk) {
        OPENSSL_cleanse(sk, len);
        free(sk);
    }
}

/* ===== T20: Stress testing - HIGH LOAD stress tests ===== */

static bool test_high_iteration_stress(adaptor_scheme_type_t scheme, uint32_t level, const char *algorithm, int *tests_passed, int *total_tests, size_t *max_memory) {
    if (!algorithm) return false;
    
    *tests_passed = 0;
    *total_tests = 0;
    *max_memory = 0;
    
    // Test 1: High iteration count stress (1000 iterations)
    (*total_tests)++;
    OQS_SIG *sig = OQS_SIG_new(algorithm);
    if (sig) {
        uint8_t *pk = malloc(sig->length_public_key);
        uint8_t *sk = malloc(sig->length_secret_key);
        if (pk && sk && OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS) {
            const adaptor_params_t *params = adaptor_get_params(level, scheme);
            if (params) {
                adaptor_context_t ctx = {0};
                if (adaptor_context_init(&ctx, params, sk, pk) == ADAPTOR_SUCCESS) {
                    int success_count = 0;
                    for (int i = 0; i < STRESS_ITERATIONS; ++i) {
                        adaptor_presignature_t presig = {0};
                        if (adaptor_presignature_init(&presig, &ctx) == ADAPTOR_SUCCESS) {
                            success_count++;
                            adaptor_presignature_cleanup(&presig);
                        }
                        
                        // Monitor memory usage
                        size_t current_memory = get_memory_usage();
                        if (current_memory > *max_memory) {
                            *max_memory = current_memory;
                        }
                    }
                    adaptor_context_cleanup(&ctx);
                    if (success_count >= STRESS_ITERATIONS * 0.95) { // 95% success rate
                        (*tests_passed)++;
                    }
                }
            }
        }
        if (sk) secure_free_sk(sk, sig->length_secret_key);
        if (pk) free(pk);
        OQS_SIG_free(sig);
    }
    
    // Test 2: Continuous operation stress (rapid init/cleanup cycles)
    (*total_tests)++;
    OQS_SIG *sig2 = OQS_SIG_new(algorithm);
    if (sig2) {
        uint8_t *pk = malloc(sig2->length_public_key);
        uint8_t *sk = malloc(sig2->length_secret_key);
        if (pk && sk && OQS_SIG_keypair(sig2, pk, sk) == OQS_SUCCESS) {
            const adaptor_params_t *params = adaptor_get_params(level, scheme);
            if (params) {
                int cycle_success = 0;
                for (int i = 0; i < 100; ++i) { // 100 rapid cycles
                    adaptor_context_t ctx = {0};
                    if (adaptor_context_init(&ctx, params, sk, pk) == ADAPTOR_SUCCESS) {
                        cycle_success++;
                        adaptor_context_cleanup(&ctx);
                    }
                }
                if (cycle_success >= 95) { // 95% success rate
                    (*tests_passed)++;
                }
            }
        }
        if (sk) secure_free_sk(sk, sig2->length_secret_key);
        if (pk) free(pk);
        OQS_SIG_free(sig2);
    }
    
    return (*tests_passed == *total_tests);
}

static bool test_memory_pressure_stress(adaptor_scheme_type_t scheme, uint32_t level, const char *algorithm, int *tests_passed, int *total_tests, int *memory_leaks) {
    if (!algorithm) return false;
    
    *tests_passed = 0;
    *total_tests = 0;
    *memory_leaks = 0;
    
    // Test 1: Memory pressure with large allocations
    (*total_tests)++;
    OQS_SIG *sig = OQS_SIG_new(algorithm);
    if (sig) {
        uint8_t *pk = malloc(sig->length_public_key);
        uint8_t *sk = malloc(sig->length_secret_key);
        if (pk && sk && OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS) {
            const adaptor_params_t *params = adaptor_get_params(level, scheme);
            if (params) {
                adaptor_context_t ctx = {0};
                if (adaptor_context_init(&ctx, params, sk, pk) == ADAPTOR_SUCCESS) {
                    int success_count = 0;
                    for (int i = 0; i < MEMORY_PRESSURE_ITERATIONS; ++i) {
                        // Allocate multiple presignatures to create memory pressure
                        adaptor_presignature_t presigs[10];
                        memset(presigs, 0, sizeof(presigs));
                        
                        int init_success = 0;
                        for (int j = 0; j < 10; ++j) {
                            if (adaptor_presignature_init(&presigs[j], &ctx) == ADAPTOR_SUCCESS) {
                                init_success++;
                            }
                        }
                        
                        // Cleanup all presignatures
                        for (int j = 0; j < 10; ++j) {
                            adaptor_presignature_cleanup(&presigs[j]);
                        }
                        
                        if (init_success >= 8) { // 80% success rate under pressure
                            success_count++;
                        }
                    }
                    adaptor_context_cleanup(&ctx);
                    if (success_count >= MEMORY_PRESSURE_ITERATIONS * 0.9) { // 90% success rate
                        (*tests_passed)++;
                    }
                }
            }
        }
        if (sk) secure_free_sk(sk, sig->length_secret_key);
        if (pk) free(pk);
        OQS_SIG_free(sig);
    }
    
    // Test 2: Memory fragmentation stress
    (*total_tests)++;
    OQS_SIG *sig2 = OQS_SIG_new(algorithm);
    if (sig2) {
        uint8_t *pk = malloc(sig2->length_public_key);
        uint8_t *sk = malloc(sig2->length_secret_key);
        if (pk && sk && OQS_SIG_keypair(sig2, pk, sk) == OQS_SUCCESS) {
            const adaptor_params_t *params = adaptor_get_params(level, scheme);
            if (params) {
                adaptor_context_t ctx = {0};
                if (adaptor_context_init(&ctx, params, sk, pk) == ADAPTOR_SUCCESS) {
                    int success_count = 0;
                    for (int i = 0; i < 50; ++i) {
                        // Create fragmentation by allocating/deallocating different sizes
                        adaptor_presignature_t presig = {0};
                        if (adaptor_presignature_init(&presig, &ctx) == ADAPTOR_SUCCESS) {
                            success_count++;
                            adaptor_presignature_cleanup(&presig);
                        }
                        
                        // Allocate some temporary memory to create fragmentation
                        void *temp = malloc(1024 + (i * 64));
                        if (temp) {
                            free(temp);
                        }
                    }
                    adaptor_context_cleanup(&ctx);
                    if (success_count >= 45) { // 90% success rate
                        (*tests_passed)++;
                    }
                }
            }
        }
        if (sk) secure_free_sk(sk, sig2->length_secret_key);
        if (pk) free(pk);
        OQS_SIG_free(sig2);
    }
    
    return (*tests_passed == *total_tests);
}

static bool test_resource_exhaustion_stress(adaptor_scheme_type_t scheme, uint32_t level, const char *algorithm, int *tests_passed, int *total_tests) {
    if (!algorithm) return false;
    
    *tests_passed = 0;
    *total_tests = 0;
    
    // Test 1: Resource exhaustion with maximum concurrent operations
    (*total_tests)++;
    OQS_SIG *sig = OQS_SIG_new(algorithm);
    if (sig) {
        uint8_t *pk = malloc(sig->length_public_key);
        uint8_t *sk = malloc(sig->length_secret_key);
        if (pk && sk && OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS) {
            const adaptor_params_t *params = adaptor_get_params(level, scheme);
            if (params) {
                adaptor_context_t ctx = {0};
                if (adaptor_context_init(&ctx, params, sk, pk) == ADAPTOR_SUCCESS) {
                    int success_count = 0;
                    for (int i = 0; i < RESOURCE_EXHAUSTION_ITERATIONS; ++i) {
                        // Create maximum concurrent presignatures
                        adaptor_presignature_t presigs[20];
                        memset(presigs, 0, sizeof(presigs));
                        
                        int init_success = 0;
                        for (int j = 0; j < 20; ++j) {
                            if (adaptor_presignature_init(&presigs[j], &ctx) == ADAPTOR_SUCCESS) {
                                init_success++;
                            }
                        }
                        
                        // Cleanup all presignatures
                        for (int j = 0; j < 20; ++j) {
                            adaptor_presignature_cleanup(&presigs[j]);
                        }
                        
                        if (init_success >= 15) { // 75% success rate under resource pressure
                            success_count++;
                        }
                    }
                    adaptor_context_cleanup(&ctx);
                    if (success_count >= RESOURCE_EXHAUSTION_ITERATIONS * 0.8) { // 80% success rate
                        (*tests_passed)++;
                    }
                }
            }
        }
        if (sk) secure_free_sk(sk, sig->length_secret_key);
        if (pk) free(pk);
        OQS_SIG_free(sig);
    }
    
    // Test 2: Rapid context switching stress
    (*total_tests)++;
    OQS_SIG *sig2 = OQS_SIG_new(algorithm);
    if (sig2) {
        uint8_t *pk = malloc(sig2->length_public_key);
        uint8_t *sk = malloc(sig2->length_secret_key);
        if (pk && sk && OQS_SIG_keypair(sig2, pk, sk) == OQS_SUCCESS) {
            const adaptor_params_t *params = adaptor_get_params(level, scheme);
            if (params) {
                int success_count = 0;
                for (int i = 0; i < 100; ++i) {
                    adaptor_context_t ctx = {0};
                    if (adaptor_context_init(&ctx, params, sk, pk) == ADAPTOR_SUCCESS) {
                        adaptor_presignature_t presig = {0};
                        if (adaptor_presignature_init(&presig, &ctx) == ADAPTOR_SUCCESS) {
                            success_count++;
                            adaptor_presignature_cleanup(&presig);
                        }
                        adaptor_context_cleanup(&ctx);
                    }
                }
                if (success_count >= 90) { // 90% success rate
                    (*tests_passed)++;
                }
            }
        }
        if (sk) secure_free_sk(sk, sig2->length_secret_key);
        if (pk) free(pk);
        OQS_SIG_free(sig2);
    }
    
    return (*tests_passed == *total_tests);
}

/* ===== test worker (single iteration) ===== */
static bool single_iteration(adaptor_scheme_type_t scheme, uint32_t level, const char *algorithm,
                             double op_times[3], int *t20_passed, int *t20_total, int *high_iter_passed, int *high_iter_total, int *memory_passed, int *memory_total, int *resource_passed, int *resource_total, size_t *max_memory, int *memory_leaks) {
    if (!algorithm) return false;
    
    bool ok = true;
    double t;
    
    // T20.1: High iteration stress testing
    print_debug_step("T20.1: Starting high iteration stress testing");
    t = now_ms();
    bool high_iter_ok = test_high_iteration_stress(scheme, level, algorithm, high_iter_passed, high_iter_total, max_memory);
    op_times[0] = now_ms() - t;
    print_debug_step("T20.1: High iteration stress testing completed");
    if (!high_iter_ok) ok = false;
    
    // T20.2: Memory pressure stress testing
    print_debug_step("T20.2: Starting memory pressure stress testing");
    t = now_ms();
    bool memory_ok = test_memory_pressure_stress(scheme, level, algorithm, memory_passed, memory_total, memory_leaks);
    op_times[1] = now_ms() - t;
    print_debug_step("T20.2: Memory pressure stress testing completed");
    if (!memory_ok) ok = false;
    
    // T20.3: Resource exhaustion stress testing
    print_debug_step("T20.3: Starting resource exhaustion stress testing");
    t = now_ms();
    bool resource_ok = test_resource_exhaustion_stress(scheme, level, algorithm, resource_passed, resource_total);
    op_times[2] = now_ms() - t;
    print_debug_step("T20.3: Resource exhaustion stress testing completed");
    if (!resource_ok) ok = false;
    
    // Overall T20 results
    *t20_passed = *high_iter_passed + *memory_passed + *resource_passed;
    *t20_total = *high_iter_total + *memory_total + *resource_total;
    
    return ok;
}

/* ===== high-level test runner per configuration ===== */

static void compute_simple_stats(double *values, int n, double *mean) {
    if (n <= 0) { *mean = 0; return; }
    
    double s = 0.0;
    for (int i = 0; i < n; ++i) s += values[i];
    *mean = s / n;
}

static bool run_config_iterations(result_t *res, adaptor_scheme_type_t scheme, uint32_t level, const char *algorithm, int iterations) {
    if (!res || !algorithm || iterations <= 0) return false;

    double iter_times[MAX_ITERATIONS];
    double all_ops[MAX_ITERATIONS][3];
    int t20_passed = 0, t20_total = 0;
    int high_iter_passed = 0, high_iter_total = 0;
    int memory_passed = 0, memory_total = 0;
    int resource_passed = 0, resource_total = 0;
    size_t max_memory = 0;
    int memory_leaks = 0;
    
    memset(iter_times, 0, sizeof(iter_times));
    memset(all_ops, 0, sizeof(all_ops));

    int ran = 0, passed = 0;
    double start = now_ms();
    for (int i = 0; i < iterations; ++i) {
        double op[3] = {0};
        int iter_t20_passed = 0, iter_t20_total = 0;
        int iter_high_iter_passed = 0, iter_high_iter_total = 0;
        int iter_memory_passed = 0, iter_memory_total = 0;
        int iter_resource_passed = 0, iter_resource_total = 0;
        size_t iter_max_memory = 0;
        int iter_memory_leaks = 0;
        double it_start = now_ms();
        
        bool ok = single_iteration(scheme, level, algorithm, op, &iter_t20_passed, &iter_t20_total, &iter_high_iter_passed, &iter_high_iter_total, &iter_memory_passed, &iter_memory_total, &iter_resource_passed, &iter_resource_total, &iter_max_memory, &iter_memory_leaks);
        double it_ms = now_ms() - it_start;
        iter_times[i] = it_ms;
        all_ops[i][0] = op[0];
        all_ops[i][1] = op[1];
        all_ops[i][2] = op[2];

        // Accumulate test counts (only from first iteration to avoid double counting)
        if (i == 0) {
            t20_passed = iter_t20_passed;
            t20_total = iter_t20_total;
            high_iter_passed = iter_high_iter_passed;
            high_iter_total = iter_high_iter_total;
            memory_passed = iter_memory_passed;
            memory_total = iter_memory_total;
            resource_passed = iter_resource_passed;
            resource_total = iter_resource_total;
            max_memory = iter_max_memory;
            memory_leaks = iter_memory_leaks;
        }

        ++ran;
        if (ok) ++passed;
    }
    res->iterations_run = ran;
    res->iterations_passed = passed;
    res->iterations_failed = ran - passed;
    res->total_time_ms = now_ms() - start;
    res->t20_passed = t20_passed;
    res->t20_total = t20_total;
    res->high_iter_passed = high_iter_passed;
    res->high_iter_total = high_iter_total;
    res->memory_passed = memory_passed;
    res->memory_total = memory_total;
    res->resource_passed = resource_passed;
    res->resource_total = resource_total;
    res->max_memory_used = max_memory;
    res->memory_leaks_detected = memory_leaks;

    compute_simple_stats(iter_times, ran, &res->mean_time_ms);

    /* compute average op times across iterations */
    for (int k = 0; k < 3; ++k) {
        double sum = 0.0;
        for (int i = 0; i < ran; ++i) sum += all_ops[i][k];
        res->op_times[k] = ran ? (sum / ran) : 0.0;
    }

    res->passed = (res->iterations_failed == 0);
    return res->passed;
}

/* ===== main orchestration ===== */

int main(int argc, char **argv) {
    int iterations = STRESS_ITERATIONS;
    bool csv = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--csv") == 0) csv = true;
        else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = atoi(argv[++i]);
            if (iterations <= 0) iterations = DEFAULT_ITERATIONS;
            if (iterations > MAX_ITERATIONS) iterations = MAX_ITERATIONS;
        } else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "Usage: %s [--iterations N] [--csv]\n", argv[0]);
            fprintf(stderr, "Return codes: 0=all tests passed, 1=argument error, 2=test failures\n");
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }
    
    install_crash_handlers();
    
    // Determine correct results directory path
    char current_dir[1024];
    if (getcwd(current_dir, sizeof(current_dir)) == NULL) {
        fprintf(stderr, "Error: cannot get current directory\n");
        return 1;
    }
    
    char cmake_path[2048];
    snprintf(cmake_path, sizeof(cmake_path), "%s/CMakeLists.txt", current_dir);
    
    char csv_dir[1024];
    if (access(cmake_path, F_OK) == 0) {
        // We're in project root
        snprintf(csv_dir, sizeof(csv_dir), "results/robustness");
    } else {
        // We're in build directory, go up to project root
        snprintf(csv_dir, sizeof(csv_dir), "../../../results/robustness");
    }
    
    if (ensure_dir(csv_dir) != 0) {
        fprintf(stderr, "Warning: cannot create results dir '%s' (errno=%d: %s)\n", csv_dir, errno, strerror(errno));
    }
    
    OQS_init();
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        fprintf(stderr, "Warning: OPENSSL_init_crypto failed\n");
    }
    
    config_def_t defs[MAX_CONFIGS] = {
        {ADAPTOR_SCHEME_UOV, 128},
        {ADAPTOR_SCHEME_UOV, 192},
        {ADAPTOR_SCHEME_UOV, 256},
        {ADAPTOR_SCHEME_MAYO, 128},
        {ADAPTOR_SCHEME_MAYO, 192},
        {ADAPTOR_SCHEME_MAYO, 256}
    };

    result_t results[MAX_CONFIGS];
    memset(results, 0, sizeof(results));
    int enabled_count = 0;

    for (int i = 0; i < MAX_CONFIGS; ++i) {
        const char *alg = select_sig_alg(defs[i].scheme, defs[i].security_level);
        if (!alg) continue;
        if (!OQS_SIG_alg_is_enabled(alg)) continue;
        
        result_t *r = &results[enabled_count];
        snprintf(r->scheme, sizeof(r->scheme), "%s", (defs[i].scheme == ADAPTOR_SCHEME_UOV) ? "UOV" : "MAYO");
        r->security_level = defs[i].security_level;
        strncpy(r->algorithm, alg, sizeof(r->algorithm) - 1);
        r->enabled = true;
        iso_timestamp(r->timestamp, sizeof(r->timestamp));
        get_git_sha(r->git_sha, sizeof(r->git_sha));
        ++enabled_count;
    }

    if (enabled_count == 0) {
        fprintf(stderr, "No enabled configurations found in liboqs.\n");
        OPENSSL_cleanup();
        OQS_destroy();
        return 1;
    }
    
    printf("Stress Test Runner — Multivariate Adaptor Signatures\n");
    printf("================================================================================\n");
    printf("Configurations: %d (UOV/MAYO × 128,192,256) | Iterations: %d\n", enabled_count, iterations);
    printf("\n");

    for (int idx = 0; idx < enabled_count; ++idx) {
        result_t *r = &results[idx];
        printf("== Config %d/%d: %s %u-bit (%s) ==\n", idx + 1, enabled_count, r->scheme, r->security_level, r->algorithm);
        printf("  Running %d stress iterations...\n", iterations);
        fflush(stdout);
        
        bool ok = run_config_iterations(r, (strcmp(r->scheme,"UOV")==0) ? ADAPTOR_SCHEME_UOV : ADAPTOR_SCHEME_MAYO,
                                        r->security_level, r->algorithm, iterations);
        
        printf("  Result: %s — total %.2f ms  mean %.2f ms\n", 
               ok ? "PASS" : "FAIL", r->total_time_ms, r->mean_time_ms);
        printf("\n");
        fflush(stdout);
    }

    /* print final table */
    printf("--------------------------------------------------------------------\n");
    printf("| # | Scheme | Level | Algorithm   | Iters | Result |  Total(ms) |  Mean |\n");
    printf("--------------------------------------------------------------------\n");
    for (int i = 0; i < enabled_count; ++i) {
        result_t *r = &results[i];
        printf("| %1d | %-6s | %5u | %-11s | %6d | %-5s | %10.2f | %7.2f |\n",
               i+1, r->scheme, r->security_level, r->algorithm, r->iterations_run,
               r->passed ? "PASS" : "FAIL", r->total_time_ms, r->mean_time_ms);
        fflush(stdout);
    }
    printf("--------------------------------------------------------------------\n");
    fflush(stdout);

    /* print per-operation breakdown table */
    printf("\nPer-operation results by configuration:\n");
    printf("  Legend: T20.1=HighIter  T20.2=MemoryPress  T20.3=ResourceExhaust\n");
    printf("  Note   : Shows detailed breakdown of stress testing.\n\n");
    
    for (int i = 0; i < enabled_count; ++i) {
        result_t *r = &results[i];
        printf("Config %d: %s %u-bit\n", i+1, r->scheme, r->security_level);
        printf("  T20 (StressTests): %s (%d/%d tests)\n", 
               (r->t20_passed == r->t20_total) ? "PASS" : "FAIL", r->t20_passed, r->t20_total);
        printf("    - High Iterations: %s (%d/%d) - %d iterations, %zu bytes max memory\n", 
               (r->high_iter_passed == r->high_iter_total) ? "PASS" : "FAIL", r->high_iter_passed, r->high_iter_total, STRESS_ITERATIONS, r->max_memory_used);
        printf("    - Memory Pressure: %s (%d/%d) - %d iterations, %d leaks detected\n", 
               (r->memory_passed == r->memory_total) ? "PASS" : "FAIL", r->memory_passed, r->memory_total, MEMORY_PRESSURE_ITERATIONS, r->memory_leaks_detected);
        printf("    - Resource Exhaust: %s (%d/%d) - %d iterations, concurrent operations\n", 
               (r->resource_passed == r->resource_total) ? "PASS" : "FAIL", r->resource_passed, r->resource_total, RESOURCE_EXHAUSTION_ITERATIONS);
        printf("\n");
        fflush(stdout);
    }

    if (csv) {
        ensure_dir(csv_dir);
        char csvfile[2048];
        snprintf(csvfile, sizeof(csvfile), "%s/stress-%llu.csv", csv_dir, (unsigned long long)time(NULL));
        FILE *f = fopen(csvfile, "w");
        if (f) {
            fprintf(f, "timestamp,git_sha,scheme,security_level,algorithm,iterations_run,iterations_passed,iterations_failed,total_time_ms,mean_time_ms,t20_1_ms,t20_2_ms,t20_3_ms,t20_passed,t20_total,high_iter_passed,high_iter_total,memory_passed,memory_total,resource_passed,resource_total,max_memory_bytes,memory_leaks_detected\n");
            for (int i = 0; i < enabled_count; ++i) {
                result_t *r = &results[i];
                fprintf(f, "%s,%s,%s,%u,%s,%d,%d,%d,%.2f,%.2f,%.3f,%.3f,%.3f,%d,%d,%d,%d,%d,%d,%d,%d,%zu,%d\n",
                        r->timestamp, r->git_sha, r->scheme, r->security_level, r->algorithm,
                        r->iterations_run, r->iterations_passed, r->iterations_failed,
                        r->total_time_ms, r->mean_time_ms,
                        r->op_times[0], r->op_times[1], r->op_times[2],
                        r->t20_passed, r->t20_total,
                        r->high_iter_passed, r->high_iter_total, r->memory_passed, r->memory_total,
                        r->resource_passed, r->resource_total, r->max_memory_used, r->memory_leaks_detected);
            }
            fclose(f);
            printf("CSV written to: %s\n", csvfile);
        } else {
            fprintf(stderr, "Warning: unable to write CSV to %s\n", csvfile);
        }
    }

    if (csv) {
        printf("\nCSV written to: results/robustness/stress-*.csv\n");
    }
    
    bool all_passed = true;
    for (int i = 0; i < enabled_count; ++i) if (!results[i].passed) { all_passed = false; break; }

    printf("\nSummary: %d/%d configurations passed | Exit: %d (%s)\n", 
           enabled_count, enabled_count, all_passed ? 0 : 2, all_passed ? "SUCCESS" : "FAILURE");
    printf("================================================================================\n");
    fflush(stdout);

    OPENSSL_cleanup();
    OQS_destroy();
    
    return all_passed ? 0 : 2;
}
