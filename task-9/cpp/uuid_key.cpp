#pragma once

#include <iostream>

#include "defs.h"
#include "keytester.h"

const unsigned long long duration = 11 * 10000000; // 11 seconds in 100-nanosecond intervals

static byte key[] = "3c4f4a00-b42d-11ec"; // 2022-04-04T11:38:23-04:00 - 11 seconds

static inline bool inc_char(unsigned char* c) {
    if (*c == '9') {
        *c = 'a';
    } else if (*c == 'f') {
        *c = '0';
        return true;
    } else {
        (*c)++;
    }
    return false;
}

static void inc_key() {
    int i;
    for (i = 7; i >= 0; i--)
        if (!inc_char(key + i))
            return;
    for (i = 12; i >= 9; i--)
        if (!inc_char(key + i))
            return;
    std::cerr << "Panic: reached limit!" << std::endl;
    exit(1);
}

bool test() {
    for (unsigned long long i = 0; i < duration; i++) {
        if (i % 1000000 == 0) {
            printf("\33[2K\r%llu (%02.2f%%): %s", i, (double)i / duration * 100, key);
            std::cout << std::flush;
        }
        if (testkey(key))
            return true;
        inc_key();
    }
    if (testkey(key))
        return true;
    std::cout << std::endl;
    return false;
}