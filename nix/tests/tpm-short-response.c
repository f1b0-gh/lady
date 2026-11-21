/* SPDX-License-Identifier: MIT */
/* Regression for GHSA-h664-qxhh-gx3w. Compile against the upstream helper
 * sources, separately for each bus. No device is opened. The fake bus permits
 * exactly a status read and a six-byte response header, then interrupts any
 * further operation before it can access a payload buffer. */
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef TEST_SPI
#include "tcti-spi-helper.h"
typedef TSS2_TCTI_SPI_HELPER_CONTEXT helper_context;
#define HELPER_MAGIC TCTI_SPI_HELPER_MAGIC
#define receive_response tcti_spi_helper_receive
#define BUS_NAME "SPI"
#else
#include "tcti-i2c-helper.h"
typedef TSS2_TCTI_I2C_HELPER_CONTEXT helper_context;
#define HELPER_MAGIC TCTI_I2C_HELPER_MAGIC
#define receive_response tcti_i2c_helper_receive
#define BUS_NAME "I2C"
#endif

extern TSS2_RC receive_response(TSS2_TCTI_CONTEXT *, size_t *, unsigned char *, int32_t);

static jmp_buf bus_limit;
static unsigned bus_reads;
static uint32_t wire_size;
static unsigned char output[64];

static TSS2_RC read_register(uint8_t reg, void *data, size_t count) {
    if (bus_reads == 0 && reg == 0x18 && count == 4) {
        /* VALID | DATA_AVAIL, no burst bytes offered. */
        const uint8_t status[] = { 0x90, 0, 0, 0 };
        memcpy(data, status, sizeof status);
    } else if (bus_reads == 1 && reg == 0x24 && count == 6) {
        const uint8_t header[] = {
            0x80, 0x01, (uint8_t)(wire_size >> 24), (uint8_t)(wire_size >> 16),
            (uint8_t)(wire_size >> 8), (uint8_t)wire_size
        };
        memcpy(data, header, sizeof header);
    } else {
        longjmp(bus_limit, 1);
    }
    ++bus_reads;
    return TSS2_RC_SUCCESS;
}

static TSS2_RC timer(void *user, int32_t milliseconds) {
    (void)user;
    (void)milliseconds;
    return TSS2_RC_SUCCESS;
}

static TSS2_RC expired(void *user, bool *result) {
    (void)user;
    *result = true;
    return TSS2_RC_SUCCESS;
}

#ifdef TEST_SPI
static TSS2_RC transfer(void *user, const void *data_out, void *data_in, size_t count) {
    (void)user;
    const uint8_t *request = data_out;
    /* Non-wait-state SPI transfer: four-byte prefix plus register data. */
    if (count < 4 || !data_in || !(request[0] & 0x80) ||
        request[1] != 0xd4 || request[2] != 0 ||
        (size_t)((request[0] & 0x3f) + 1) != count - 4)
        longjmp(bus_limit, 2);
    /* The helper uses the same allocation for transmit and receive. */
    uint8_t reg = request[3];
    memset(data_in, 0, 4);
    return read_register(reg, (uint8_t *)data_in + 4, count - 4);
}
#else
static TSS2_RC read_i2c(void *user, uint8_t reg, void *data, size_t count) {
    (void)user;
    return read_register(reg, data, count);
}

static TSS2_RC write_i2c(void *user, uint8_t reg, const void *data, size_t count) {
    (void)user; (void)reg; (void)data; (void)count;
    longjmp(bus_limit, 2);
}
#endif

static int check_response(uint32_t advertised, size_t capacity, bool size_query,
                          bool wrong_state, TSS2_RC expected) {
    helper_context ctx = {0};
    TSS2_TCTI_MAGIC(&ctx) = HELPER_MAGIC;
    ctx.common.state = wrong_state ? TCTI_STATE_TRANSMIT : TCTI_STATE_RECEIVE;
    ctx.platform.start_timeout = timer;
    ctx.platform.sleep_ms = timer;
    ctx.platform.timeout_expired = expired;
#ifdef TEST_SPI
    ctx.platform.spi_transfer = transfer;
#else
    ctx.platform.i2c_read = read_i2c;
    ctx.platform.i2c_write = write_i2c;
#endif
    bus_reads = 0;
    wire_size = advertised;
    memset(output, 0xa5, sizeof output);
    /* A longjmp only reads static state afterwards; locals changed by the
     * library across setjmp are never inspected on the interrupted branch. */
    if (setjmp(bus_limit)) {
        fprintf(stderr, "%s size=%u: unexpected bus operation after %u reads\n",
                BUS_NAME, wire_size, bus_reads);
        return 1;
    }
    TSS2_RC rc = receive_response((TSS2_TCTI_CONTEXT *)&ctx, &capacity,
                                size_query ? NULL : output, 0);
    if (rc != expected || bus_reads != (wrong_state ? 0u : 2u) ||
        (size_query && capacity != advertised)) {
        fprintf(stderr, "%s size=%u: rc=0x%x expected=0x%x reads=%u\n",
                BUS_NAME, advertised, rc, expected, bus_reads);
        return 1;
    }
    for (size_t i = 0; i < sizeof output; ++i) {
        if (output[i] != 0xa5) {
            fprintf(stderr, "%s size=%u: output changed at %zu\n", BUS_NAME, advertised, i);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    unsigned failures = 0;
    for (uint32_t n = 0; n <= 7; ++n) {
        failures += check_response(n, sizeof output, false, false,
                                   TSS2_TCTI_RC_MALFORMED_RESPONSE);
        /* A zero-capacity destination must also remain untouched. */
        failures += check_response(n, 0, false, false, TSS2_TCTI_RC_MALFORMED_RESPONSE);
        failures += check_response(n, 0, true, false, TSS2_RC_SUCCESS);
    }
    /* Eight is above this guard: the ordinary buffer-size refusal must still
     * work. This is not a claim that an eight-byte TPM response is valid. */
    failures += check_response(8, 7, false, false, TSS2_TCTI_RC_INSUFFICIENT_BUFFER);
    failures += check_response(10, 9, false, false, TSS2_TCTI_RC_INSUFFICIENT_BUFFER);
    failures += check_response(10, sizeof output, false, true, TSS2_TCTI_RC_BAD_SEQUENCE);
    printf("%s: %u/27 checks passed\n", BUS_NAME, 27 - failures);
    return failures ? 1 : 0;
}
