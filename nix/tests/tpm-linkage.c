/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

static int check_library(void *symbol, const char *directory) {
    Dl_info info = {0};
    if (!dladdr(symbol, &info) || !info.dli_fname)
        return 1;
    char *path = realpath(info.dli_fname, NULL);
    if (!path)
        return 1;
    printf("loaded=%s\n", path);
    size_t length = strlen(directory);
    int wrong = strncmp(path, directory, length) || path[length] != '/';
    free(path);
    return wrong;
}

int main(void) {
    if (check_library((void *)Tss2_MU_UINT32_Marshal, EXPECTED_TSS_LIBDIR) ||
        check_library((void *)Esys_Initialize, EXPECTED_TSS_LIBDIR) ||
        check_library((void *)Tss2_TctiLdr_Initialize_Ex, EXPECTED_TSS_LIBDIR) ||
        check_library((void *)OpenSSL_version, EXPECTED_OPENSSL_LIBDIR) ||
        OpenSSL_version_num() != 0x30500090L)
        return 1;
    uint8_t encoded[4] = {0};
    size_t offset = 0;
    const uint8_t expected[] = {0x12, 0x34, 0x56, 0x78};
    if (Tss2_MU_UINT32_Marshal(0x12345678, encoded, sizeof encoded, &offset) ||
        offset != 4 || memcmp(encoded, expected, sizeof expected))
        return 2;

    /* The explicit libtpms backend is an in-process software TPM. NULL config
     * keeps its state in memory. Never fall back to the loader's device default. */
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    TPM2B_DIGEST *random = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize_Ex("libtpms", NULL, &tcti);
    if (!rc) rc = Esys_Initialize(&esys, tcti, NULL);
    if (!rc) rc = Esys_Startup(esys, TPM2_SU_CLEAR);
    if (!rc) rc = Esys_GetRandom(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 8, &random);
    int failed = rc || !random || random->size != 8;
    printf("software-tpm rc=0x%x random-bytes=%u openssl=%s\n", rc,
           random ? random->size : 0, OpenSSL_version(OPENSSL_VERSION));
    Esys_Free(random);
    Esys_Finalize(&esys);
    Tss2_TctiLdr_Finalize(&tcti);
    return failed ? 3 : 0;
}
