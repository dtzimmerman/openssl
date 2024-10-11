/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "crypto/rand.h"
#include "crypto/dso_conf.h"
#include "internal/thread_once.h"
#include "internal/cryptlib.h"
#include "internal/e_os.h"
#include "buildinf.h"

#ifndef OPENSSL_NO_JITTER
# include <stdio.h>
# include <jitterentropy.h>
#endif

#if defined(__arm__) || defined(__arm) || defined(__aarch64__)
# include "arm_arch.h"
# define CPU_INFO_STR_LEN 128
# define CPU_INFO_DETAILED_STR_LEN 1
# define CPU_INFO_FEATURES_STR_LEN 1
#elif defined(__s390__) || defined(__s390x__)
# include "s390x_arch.h"
# define CPU_INFO_STR_LEN 2048
# define CPU_INFO_DETAILED_STR_LEN 1
# define CPU_INFO_FEATURES_STR_LEN 1
#elif defined(__riscv)
# include "crypto/riscv_arch.h"
# define CPU_INFO_STR_LEN 2048
# define CPU_INFO_DETAILED_STR_LEN 1
# define CPU_INFO_FEATURES_STR_LEN 1
#else
# define CPU_INFO_STR_LEN 256
# define CPU_INFO_DETAILED_STR_LEN 1024
# define CPU_INFO_FEATURES_STR_LEN 2100
#endif
#if defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
    defined(__x86_64) || defined(__x86_64__) || \
    defined(_M_AMD64) || defined(_M_X64)


/* OPENSSL_ia32cap_P mapping

OPENSSL_ia32cap_P[0] = cpuid(EAX=0x1).EDX
OPENSSL_ia32cap_P[1] = cpuid(EAX=0x1).ECX
OPENSSL_ia32cap_P[2] = cpuid(EAX=0x7, ECX=0x0).EBX
OPENSSL_ia32cap_P[3] = cpuid(EAX=0x7, ECX=0x0).ECX

OPENSSL_ia32cap_P[4] = cpuid(EAX=0x7, ECX=0x0).EDX <-- Hybrid Core, MSR Enumeration Support
OPENSSL_ia32cap_P[5] = cpuid(EAX=0x7, ECX=0x1).EAX <-- SHA512, SM3, SM4, AVX-IFMA
OPENSSL_ia32cap_P[6] = cpuid(EAX=0x7, ECX=0x1).EDX <-- AVX10, APX Foundation
OPENSSL_ia32cap_P[7] = cpuid(EAX=0x7, ECX=0x1).EBX <-- Reserved for future features

OPENSSL_ia32cap_P[8] = cpuid(EAX=0x7, ECX=0x1).ECX <-- Reserverd for future features
OPENSSL_ia32cap_P[9] = cpuid(EAX=0x24, ECX=0x0).EBX <-- AVX10 Details

*/
/* Configure our CPUID feature flag definitions based on
   information stored in OPENSSL_ia32cap_P[OPENSSL_IA32CAP_P_MAX_INDEXES]
   and noted here: https://docs.openssl.org/master/man3/OPENSSL_ia32cap/#description
 */

#define CPUID_TSC               (OPENSSL_ia32cap_P[0] & (1<<4))
#define CPUID_CLFLUSH           (OPENSSL_ia32cap_P[0] & (1<<19))
#define CPUID_RC4               (OPENSSL_ia32cap_P[0] & (1<<20))
#define CPUID_MMX               (OPENSSL_ia32cap_P[0] & (1<<23))
#define CPUID_FXSR              (OPENSSL_ia32cap_P[0] & (1<<24))
#define CPUID_SSE               (OPENSSL_ia32cap_P[0] & (1<<25))
#define CPUID_SSE2              (OPENSSL_ia32cap_P[0] & (1<<26))
#define CPUID_HYPERTHREADING    (OPENSSL_ia32cap_P[0] & (1<<28))
#define CPUID_GENUINE_INTEL     (OPENSSL_ia32cap_P[0] & (1<<30))

#define CPUID_SSE3              (OPENSSL_ia32cap_P[1] & (1<<(32-32)))
#define CPUID_PCLMULQDQ         (OPENSSL_ia32cap_P[1] & (1<<(33-32)))
#define CPUID_SSSE3             (OPENSSL_ia32cap_P[1] & (1<<(41-32)))
#define CPUID_AMD_XOP           (OPENSSL_ia32cap_P[1] & (1<<(43-32)))
#define CPUID_AUTHENTIC_AMD     (OPENSSL_ia32cap_P[1] & (1<<(43-32)))
#define CPUID_MOVBE             (OPENSSL_ia32cap_P[1] & (1<<(54-32)))
#define CPUID_AESNI             (OPENSSL_ia32cap_P[1] & (1<<(57-32)))
#define CPUID_XSAVE             (OPENSSL_ia32cap_P[1] & (1<<(58-32)))
#define CPUID_OSXSAVE           (OPENSSL_ia32cap_P[1] & (1<<(59-32)))
#define CPUID_AVX               (OPENSSL_ia32cap_P[1] & (1<<(60-32)))
#define CPUID_RDRAND            (OPENSSL_ia32cap_P[1] & (1<<(62-32)))

#define CPUID_BMI1              (OPENSSL_ia32cap_P[2] & (1<<3))
#define CPUID_AVX2              (OPENSSL_ia32cap_P[2] & (1<<5))
#define CPUID_BMI2              (OPENSSL_ia32cap_P[2] & (1<<8))
#define CPUID_AVX512F           (OPENSSL_ia32cap_P[2] & (1<<16))
#define CPUID_AVX512DQ          (OPENSSL_ia32cap_P[2] & (1<<17))
#define CPUID_RDSEED            (OPENSSL_ia32cap_P[2] & (1<<18))
#define CPUID_ADCX_ADOX         (OPENSSL_ia32cap_P[2] & (1<<19))
#define CPUID_AVX512IFMA        (OPENSSL_ia32cap_P[2] & (1<<21))
#define CPUID_SHA               (OPENSSL_ia32cap_P[2] & (1<<29))
#define CPUID_AVX512BW          (OPENSSL_ia32cap_P[2] & (1<<30))
#define CPUID_AVX512VL          (OPENSSL_ia32cap_P[2] & (1<<31))

#define CPUID_VAES              (OPENSSL_ia32cap_P[3] & (1<<(41-32)))
#define CPUID_VPCLMULQDQ        (OPENSSL_ia32cap_P[3] & (1<<(42-32)))

#define CPUID_HYBRID_CPU        (OPENSSL_ia32cap_P[4] & (1<<15))
#define CPUID_IA32_ARCH_CAP_MSR (OPENSSL_ia32cap_P[4] & (1<<29))

#define CPUID_SHA512            (OPENSSL_ia32cap_P[5] & (1<<0))
#define CPUID_SM3               (OPENSSL_ia32cap_P[5] & (1<<1))
#define CPUID_SM4               (OPENSSL_ia32cap_P[5] & (1<<2))
#define CPUID_AVXIFMA           (OPENSSL_ia32cap_P[5] & (1<<23))

#define CPUID_USER_MSR          (OPENSSL_ia32cap_P[6] & (1<<(47-32)))
#define CPUID_AVX10             (OPENSSL_ia32cap_P[6] & (1<<(51-32)))
#define CPUID_APXF              (OPENSSL_ia32cap_P[6] & (1<<(53-32)))

#define CPUID_AVX10_VER         (OPENSSL_ia32cap_P[9] & (0xFF)) // First 8 bits are version so mask out the rest
#define CPUID_AVX10_XMM         (OPENSSL_ia32cap_P[9] & (1<<16))
#define CPUID_AVX10_YMM         (OPENSSL_ia32cap_P[9] & (1<<17))
#define CPUID_AVX10_ZMM         (OPENSSL_ia32cap_P[9] & (1<<18))

#endif

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c %c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0')

/* extern declaration to avoid warning */
extern char ossl_cpu_info_str[];
extern char ossl_cpu_info_str_env[];
extern char ossl_cpu_info_str_detailed[];
extern char ossl_cpu_info_str_features[];

static char *seed_sources = NULL;

char ossl_cpu_info_str[CPU_INFO_STR_LEN] = "";
char ossl_cpu_info_str_env[CPU_INFO_STR_LEN] = "";
char ossl_cpu_info_str_detailed[CPU_INFO_DETAILED_STR_LEN] = "";
char ossl_cpu_info_str_features[CPU_INFO_FEATURES_STR_LEN] = "";
#define CPUINFO_PREFIX "CPUINFO: "

static CRYPTO_ONCE init_info = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(init_info_strings)
{
#if defined(OPENSSL_CPUID_OBJ)
# if defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__) || \
     defined(_M_AMD64) || defined(_M_X64)
    const char *env;

    BIO_snprintf(ossl_cpu_info_str, sizeof(ossl_cpu_info_str),
                 CPUINFO_PREFIX "OPENSSL_ia32cap=0x%.16llx:0x%.16llx:0x%.16llx:0x%.16llx:0x%.16llx",
                 ((unsigned long long)OPENSSL_ia32cap_P[0] |
                 (unsigned long long)OPENSSL_ia32cap_P[1] << 32),
                 (unsigned long long)OPENSSL_ia32cap_P[2] |
                 (unsigned long long)OPENSSL_ia32cap_P[3] << 32,
                 (unsigned long long)OPENSSL_ia32cap_P[4] |
                 (unsigned long long)OPENSSL_ia32cap_P[5] << 32,
                 (unsigned long long)OPENSSL_ia32cap_P[6] |
                 (unsigned long long)OPENSSL_ia32cap_P[7] << 32,
                 (unsigned long long)OPENSSL_ia32cap_P[8] |
                 (unsigned long long)OPENSSL_ia32cap_P[9] << 32);

    if ((env = getenv("OPENSSL_ia32cap")) != NULL) {
        BIO_snprintf(ossl_cpu_info_str + strlen(ossl_cpu_info_str),
                     sizeof(ossl_cpu_info_str) - strlen(ossl_cpu_info_str),
                     " env=%s", env);
        BIO_snprintf(ossl_cpu_info_str_env, sizeof(ossl_cpu_info_str_env),"%s", env);
    }

    for (int i = 0; i < OPENSSL_IA32CAP_P_MAX_INDEXES; i++) {

        // Allocate for 32 bit uint and 8 spaces for binary representation
        char binStr[40] = "0";
        unsigned int x = OPENSSL_ia32cap_P[i];

        BIO_snprintf(binStr, sizeof(binStr),""BYTE_TO_BINARY_PATTERN" "BYTE_TO_BINARY_PATTERN" "BYTE_TO_BINARY_PATTERN" "BYTE_TO_BINARY_PATTERN" ",  BYTE_TO_BINARY(x>>24), BYTE_TO_BINARY(x>>16),  BYTE_TO_BINARY(x>>8), BYTE_TO_BINARY(x));

        BIO_snprintf(ossl_cpu_info_str_detailed + strlen(ossl_cpu_info_str_detailed), sizeof(ossl_cpu_info_str_detailed),"OPENSSL_ia32cap_P[%d]:\t%08X\t%s\n", i, (unsigned int)OPENSSL_ia32cap_P[i], binStr);

    }

        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][04]\tCPUID_TSC:\t\t%s\n", (CPUID_TSC ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][19]\tCPUID_CLFLUSH:\t\t%s\n", (CPUID_CLFLUSH ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][20]\tCPUID_RC4:\t\t%s\n", (CPUID_RC4 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][23]\tCPUID_MMX:\t\t%s\n", (CPUID_MMX ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][24]\tCPUID_FXSR:\t\t%s\n", (CPUID_FXSR ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][25]\tCPUID_SSE:\t\t%s\n", (CPUID_SSE ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][26]\tCPUID_SSE2:\t\t%s\n", (CPUID_SSE2 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][28]\tCPUID_HYPERTHREADING:\t%s\n", (CPUID_HYPERTHREADING ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[0][29]\tCPUID_GENUINE_INTEL:\t%s\n", (CPUID_GENUINE_INTEL ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][00]\tCPUID_SSE3:\t\t%s\n", (CPUID_SSE3 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][01]\tCPUID_PCLMULQDQ:\t%s\n", (CPUID_PCLMULQDQ ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][09]\tCPUID_SSSE3:\t\t%s\n", (CPUID_SSSE3 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][11]\tCPUID_AUTHENTIC_AMD:\t%s\n", (CPUID_AUTHENTIC_AMD ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][11]\tCPUID_AMD_XOP:\t\t%s\n", (CPUID_AMD_XOP ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][22]\tCPUID_MOVBE:\t\t%s\n", (CPUID_MOVBE ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][25]\tCPUID_AESNI:\t\t%s\n", (CPUID_AESNI ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][26]\tCPUID_XSAVE:\t\t%s\n", (CPUID_XSAVE ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][27]\tCPUID_OSXSAVE:\t\t%s\n", (CPUID_OSXSAVE ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][28]\tCPUID_AVX:\t\t%s\n", (CPUID_AVX ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[1][30]\tCPUID_RDRAND:\t\t%s\n", (CPUID_RDRAND ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][03]\tCPUID_BMI1:\t\t%s\n", (CPUID_BMI1 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][05]\tCPUID_AVX2:\t\t%s\n", (CPUID_AVX2 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][08]\tCPUID_BMI2:\t\t%s\n", (CPUID_BMI2 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][16]\tCPUID_AVX512F:\t\t%s\n", (CPUID_AVX512F ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][17]\tCPUID_AVX512DQ:\t\t%s\n", (CPUID_AVX512DQ ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][18]\tCPUID_RDSEED:\t\t%s\n", (CPUID_RDSEED ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][19]\tCPUID_ADCX_ADOX:\t%s\n", (CPUID_ADCX_ADOX ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][21]\tCPUID_AVX512IFMA:\t%s\n", (CPUID_AVX512IFMA ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][29]\tCPUID_SHA:\t\t%s\n", (CPUID_SHA ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][30]\tCPUID_AVX512BW:\t\t%s\n", (CPUID_AVX512BW ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[2][31]\tCPUID_AVX512VL:\t\t%s\n", (CPUID_AVX512VL ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[3][09]\tCPUID_VAES:\t\t%s\n", (CPUID_VAES ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[3][10]\tCPUID_VPCLMULQDQ:\t%s\n", (CPUID_VPCLMULQDQ ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[4][15]\tCPUID_HYBRID_CPU:\t%s\n", (CPUID_HYBRID_CPU ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[4][29]\tCPUID_IA32_ARCHCAP_MSR:\t%s\n", (CPUID_IA32_ARCH_CAP_MSR ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[5][00]\tCPUID_SHA512:\t\t%s\n", (CPUID_SHA512 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[5][01]\tCPUID_SM3:\t\t%s\n", (CPUID_SM3 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[5][02]\tCPUID_SM4:\t\t%s\n", (CPUID_SM4 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[5][23]\tCPUID_AVXIFMA:\t\t%s\n", (CPUID_AVXIFMA ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[6][15]\tCPUID_USER_MSR:\t\t%s\n", (CPUID_USER_MSR ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[6][19]\tCPUID_AVX10:\t\t%s\n", (CPUID_AVX10 ? "TRUE" : "FALSE"));
        BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[6][21]\tCPUID_APXF:\t\t%s\n", (CPUID_APXF ? "TRUE" : "FALSE"));

        if (CPUID_AVX10) {
            BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[9][00]\tCPUID_AVX10_VER:\t%d\n", CPUID_AVX10_VER);
            BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[9][16]\tCPUID_AVX10_XMM:\t%s\n", (CPUID_AVX10_XMM ? "TRUE" : "FALSE"));
            BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[9][17]\tCPUID_AVX10_YMM:\t%s\n", (CPUID_AVX10_YMM ? "TRUE" : "FALSE"));
            BIO_snprintf(ossl_cpu_info_str_features + strlen(ossl_cpu_info_str_features), sizeof(ossl_cpu_info_str_features),"OPENSSL_ia32cap_P[9][18]\tCPUID_AVX10_ZMM:\t%s\n", (CPUID_AVX10_ZMM ? "TRUE" : "FALSE"));
        }


# elif defined(__arm__) || defined(__arm) || defined(__aarch64__)
    const char *env;

    BIO_snprintf(ossl_cpu_info_str, sizeof(ossl_cpu_info_str),
                 CPUINFO_PREFIX "OPENSSL_armcap=0x%x", OPENSSL_armcap_P);
    if ((env = getenv("OPENSSL_armcap")) != NULL)
        BIO_snprintf(ossl_cpu_info_str + strlen(ossl_cpu_info_str),
                     sizeof(ossl_cpu_info_str) - strlen(ossl_cpu_info_str),
                     " env:%s", env);

# elif defined(__s390__) || defined(__s390x__)
    const char *env;

    BIO_snprintf(ossl_cpu_info_str, sizeof(ossl_cpu_info_str),
                 CPUINFO_PREFIX "OPENSSL_s390xcap="
                 "stfle:0x%llx:0x%llx:0x%llx:0x%llx:"
                 "kimd:0x%llx:0x%llx:"
                 "klmd:0x%llx:0x%llx:"
                 "km:0x%llx:0x%llx:"
                 "kmc:0x%llx:0x%llx:"
                 "kmac:0x%llx:0x%llx:"
                 "kmctr:0x%llx:0x%llx:"
                 "kmo:0x%llx:0x%llx:"
                 "kmf:0x%llx:0x%llx:"
                 "prno:0x%llx:0x%llx:"
                 "kma:0x%llx:0x%llx:"
                 "pcc:0x%llx:0x%llx:"
                 "kdsa:0x%llx:0x%llx",
                 OPENSSL_s390xcap_P.stfle[0], OPENSSL_s390xcap_P.stfle[1],
                 OPENSSL_s390xcap_P.stfle[2], OPENSSL_s390xcap_P.stfle[3],
                 OPENSSL_s390xcap_P.kimd[0], OPENSSL_s390xcap_P.kimd[1],
                 OPENSSL_s390xcap_P.klmd[0], OPENSSL_s390xcap_P.klmd[1],
                 OPENSSL_s390xcap_P.km[0], OPENSSL_s390xcap_P.km[1],
                 OPENSSL_s390xcap_P.kmc[0], OPENSSL_s390xcap_P.kmc[1],
                 OPENSSL_s390xcap_P.kmac[0], OPENSSL_s390xcap_P.kmac[1],
                 OPENSSL_s390xcap_P.kmctr[0], OPENSSL_s390xcap_P.kmctr[1],
                 OPENSSL_s390xcap_P.kmo[0], OPENSSL_s390xcap_P.kmo[1],
                 OPENSSL_s390xcap_P.kmf[0], OPENSSL_s390xcap_P.kmf[1],
                 OPENSSL_s390xcap_P.prno[0], OPENSSL_s390xcap_P.prno[1],
                 OPENSSL_s390xcap_P.kma[0], OPENSSL_s390xcap_P.kma[1],
                 OPENSSL_s390xcap_P.pcc[0], OPENSSL_s390xcap_P.pcc[1],
                 OPENSSL_s390xcap_P.kdsa[0], OPENSSL_s390xcap_P.kdsa[1]);
    if ((env = getenv("OPENSSL_s390xcap")) != NULL)
        BIO_snprintf(ossl_cpu_info_str + strlen(ossl_cpu_info_str),
                     sizeof(ossl_cpu_info_str) - strlen(ossl_cpu_info_str),
                     " env:%s", env);
# elif defined(__riscv)
    const char *env;
    char sep = '=';

    BIO_snprintf(ossl_cpu_info_str, sizeof(ossl_cpu_info_str),
                 CPUINFO_PREFIX "OPENSSL_riscvcap");
    for (size_t i = 0; i < kRISCVNumCaps; ++i) {
        if (OPENSSL_riscvcap_P[RISCV_capabilities[i].index]
                & (1 << RISCV_capabilities[i].bit_offset)) {
            /* Match, display the name */
            BIO_snprintf(ossl_cpu_info_str + strlen(ossl_cpu_info_str),
                         sizeof(ossl_cpu_info_str) - strlen(ossl_cpu_info_str),
                         "%c%s", sep, RISCV_capabilities[i].name);
            /* Only the first sep is '=' */
            sep = '_';
        }
    }
    /* If no capability is found, add back the = */
    if (sep == '=') {
        BIO_snprintf(ossl_cpu_info_str + strlen(ossl_cpu_info_str),
                     sizeof(ossl_cpu_info_str) - strlen(ossl_cpu_info_str),
                     "%c", sep);
    }
    if ((env = getenv("OPENSSL_riscvcap")) != NULL)
        BIO_snprintf(ossl_cpu_info_str + strlen(ossl_cpu_info_str),
                     sizeof(ossl_cpu_info_str) - strlen(ossl_cpu_info_str),
                     " env:%s", env);
# endif
#endif

    {
        static char seeds[512] = "";

#define add_seeds_string(str)                                           \
        do {                                                            \
            if (seeds[0] != '\0')                                       \
                OPENSSL_strlcat(seeds, " ", sizeof(seeds));             \
            OPENSSL_strlcat(seeds, str, sizeof(seeds));                 \
        } while (0)
#define add_seeds_stringlist(label, strlist)                            \
        do {                                                            \
            add_seeds_string(label "(");                                \
            {                                                           \
                const char *dev[] =  { strlist, NULL };                 \
                const char **p;                                         \
                int first = 1;                                          \
                                                                        \
                for (p = dev; *p != NULL; p++) {                        \
                    if (!first)                                         \
                        OPENSSL_strlcat(seeds, " ", sizeof(seeds));     \
                    first = 0;                                          \
                    OPENSSL_strlcat(seeds, *p, sizeof(seeds));          \
                }                                                       \
            }                                                           \
            OPENSSL_strlcat(seeds, ")", sizeof(seeds));                 \
        } while (0)

#ifdef OPENSSL_RAND_SEED_NONE
        add_seeds_string("none");
#endif
#ifdef OPENSSL_RAND_SEED_RDTSC
        add_seeds_string("rdtsc");
#endif
#ifdef OPENSSL_RAND_SEED_RDCPU
# ifdef __aarch64__
        add_seeds_string("rndr ( rndrrs rndr )");
# else
        add_seeds_string("rdrand ( rdseed rdrand )");
# endif
#endif
#ifdef OPENSSL_RAND_SEED_GETRANDOM
        add_seeds_string("getrandom-syscall");
#endif
#ifdef OPENSSL_RAND_SEED_DEVRANDOM
        add_seeds_stringlist("random-device", DEVRANDOM);
#endif
#ifdef OPENSSL_RAND_SEED_EGD
        add_seeds_stringlist("EGD", DEVRANDOM_EGD);
#endif
#ifdef OPENSSL_RAND_SEED_OS
        add_seeds_string("os-specific");
#endif
#ifndef OPENSSL_NO_JITTER
        {
            char jent_version_string[32];

            sprintf(jent_version_string, "JITTER (%d)", jent_version());
            add_seeds_string(jent_version_string);
        }
#endif
        seed_sources = seeds;
    }
    return 1;
}

const char *OPENSSL_info(int t)
{
    /*
     * We don't care about the result.  Worst case scenario, the strings
     * won't be initialised, i.e. remain NULL, which means that the info
     * isn't available anyway...
     */
    (void)RUN_ONCE(&init_info, init_info_strings);

    switch (t) {
    case OPENSSL_INFO_CONFIG_DIR:
        return ossl_get_openssldir();
    case OPENSSL_INFO_ENGINES_DIR:
        return ossl_get_enginesdir();
    case OPENSSL_INFO_MODULES_DIR:
        return ossl_get_modulesdir();
    case OPENSSL_INFO_DSO_EXTENSION:
        return DSO_EXTENSION;
    case OPENSSL_INFO_DIR_FILENAME_SEPARATOR:
#if defined(_WIN32)
        return "\\";
#elif defined(__VMS)
        return "";
#else  /* Assume POSIX */
        return "/";
#endif
    case OPENSSL_INFO_LIST_SEPARATOR:
        {
            static const char list_sep[] = { LIST_SEPARATOR_CHAR, '\0' };
            return list_sep;
        }
    case OPENSSL_INFO_SEED_SOURCE:
        return seed_sources;
    case OPENSSL_INFO_CPU_SETTINGS:
        /*
         * If successfully initialized, ossl_cpu_info_str will start
         * with CPUINFO_PREFIX, if failed it will be an empty string.
         * Strip away the CPUINFO_PREFIX which we don't need here.
         */
        if (ossl_cpu_info_str[0] != '\0')
            return ossl_cpu_info_str + strlen(CPUINFO_PREFIX);
        break;
    case OPENSSL_INFO_CPU_SETTINGS_DETAILED:
        if (ossl_cpu_info_str_detailed[0] != '\0')
            return ossl_cpu_info_str_detailed;
        break;
    case OPENSSL_INFO_CPU_SETTINGS_FEATURES:
        if (ossl_cpu_info_str[0] != '\0')
            return ossl_cpu_info_str_features;
        break;
    case OPENSSL_INFO_CPU_SETTINGS_ENV:
        if (ossl_cpu_info_str_env[0] != '\0')
            return ossl_cpu_info_str_env;
        break;
    default:
        break;
    }
    /* Not an error */
    return NULL;
}
