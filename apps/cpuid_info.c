/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include "progs.h"

#include "crypto/cryptlib.h"

static BIO *bio_s_out = NULL;

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_A,
    OPT_F
} OPTION_CHOICE;


void cpuid_info_display_extended()
{
#if defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
    defined(__x86_64) || defined(__x86_64__) || \
    defined(_M_AMD64) || defined(_M_X64)

    BIO_printf(bio_s_out, "\nCPUID Extended Details:\n");
    BIO_printf(bio_s_out, "Cap Bit Vector\t\tValue (HEX)\tValue (Binary)\t\t\t  [LSB]\n");

    const char *ossl_cpu_info_str_detailed = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS_DETAILED);
    BIO_printf(bio_s_out, "\n%s\n", ossl_cpu_info_str_detailed);

#endif
}

void cpuid_info_display_features()
{
#if defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
    defined(__x86_64) || defined(__x86_64__) || \
    defined(_M_AMD64) || defined(_M_X64)

    BIO_printf(bio_s_out, "CPUID Feature Support:\n");

    const char *ossl_cpu_info_str_features = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS_FEATURES);
    BIO_printf(bio_s_out, "\n%s\n", ossl_cpu_info_str_features);

#endif
}

const OPTIONS cpuid_info_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Output"),
    {"a", OPT_A, '-', "Show all CPUID data"},
    {"f", OPT_F, '-', "Show CPUID feature support"},

    {NULL}
};

int cpuid_info_main(int argc, char **argv)
{
    int ret = 1;
    int all_data = 0; 
    int all_features = 0;

    const char *ossl_cpu_info_str = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS);

    const char *ossl_cpu_info_str_env = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS_ENV);

    if (bio_s_out == NULL)
        bio_s_out = dup_bio_out(FORMAT_TEXT);

    if (bio_s_out == NULL)
        goto end;

    char *prog;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, cpuid_info_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(cpuid_info_options);
            ret = 0;
            goto end;
        case OPT_A:
            all_data = 1;
            all_features = 1;
            break;
        case OPT_F:
            all_features = 1;
            break;
        }
    }

    /* No extra arguments. */
    if (!opt_check_rest_arg(NULL))
        goto opthelp;

    BIO_printf(bio_s_out, "CPUID Information:\n");

    BIO_printf(bio_s_out, "\nOPENSSL_ia32cap:\n");
    char ossl_cpu_info_str_tmp[256] ="";
    char *startPtr = strchr(ossl_cpu_info_str, '=');
    char *endPtr = strchr(ossl_cpu_info_str, ' ');
    if (startPtr != NULL && endPtr != NULL) {
        strncpy(ossl_cpu_info_str_tmp, startPtr + 1, endPtr - startPtr - 1);
        ossl_cpu_info_str_tmp[endPtr - startPtr - 1] = '\0';
    }

    if (ossl_cpu_info_str_tmp != NULL)
        BIO_printf(bio_s_out, "\n\t%s\n", ossl_cpu_info_str_tmp);

    if (ossl_cpu_info_str_env != NULL) {
        BIO_printf(bio_s_out, "\nOPENSSL_ia32cap Environment Variable:\n");

        BIO_printf(bio_s_out, "\n\t%s\n", ossl_cpu_info_str_env);

    }

    if (all_data) 
        cpuid_info_display_extended();

    if (all_features)
        cpuid_info_display_features();

end:
    if (bio_s_out != NULL) {
        BIO_free(bio_s_out);
        bio_s_out = NULL;
    }
    return ret;
}
