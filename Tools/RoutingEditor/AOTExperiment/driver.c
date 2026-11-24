// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern uint32_t evaluate(uint8_t event, uint8_t present, uint16_t port, uint32_t ip);

enum { corpus_size = 8192, repetitions = 1024 };
typedef struct {
    uint8_t event, present;
    uint16_t port;
    uint32_t ip;
} Input;
static Input corpus[corpus_size];

static size_t verify(const char *path, int keep, uint64_t *sum) {
    FILE *file = fopen(path, "r");
    if (!file) { perror(path); exit(1); }
    size_t count = 0;
    unsigned event, present, port, ip, expected;
    int fields;
    while ((fields = fscanf(file, "%u %u %u %u %u", &event, &present, &port, &ip, &expected)) == 5) {
        uint32_t result = evaluate(event, present, port, ip);
        if (result != expected) {
            fprintf(stderr, "%s line %zu: got %u, expected %u\n", path, count+1, result, expected);
            exit(1);
        }
        if (keep) {
            if (count >= corpus_size) exit(1);
            corpus[count] = (Input){event, present, port, ip};
            *sum += result;
        }
        count++;
    }
    if (fields != EOF || ferror(file)) exit(1);
    fclose(file);
    return count;
}

static uint64_t nanos(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(1);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

int main(void) {
    uint64_t one_pass = 0, sum = 0;
    if (verify("oracle.tsv", 0, &one_pass) != 16864 ||
        verify("mixed.tsv", 1, &one_pass) != corpus_size) return 1;
    uint64_t start = nanos();
    for (size_t round = 0; round < repetitions; round++) {
        for (size_t i = 0; i < corpus_size; i++) {
            Input e = corpus[i];
            sum += evaluate(e.event, e.present, e.port, e.ip);
        }
    }
    uint64_t elapsed = nanos() - start;
    if (sum != repetitions * one_pass) return 1;
    printf("%.6f\n", (double)elapsed / (repetitions * corpus_size));
    return 0;
}
