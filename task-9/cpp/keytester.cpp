#include <fstream>
#include <iostream>

#include "evplib.h"
#include "keytester.h"

static byte IV[BLOCK_SIZE];
static secure_string ciphertext, g_plaintext;
static std::string res_filename;
static int n_tested_keys = 0;

int read_enc_file(const char* filename, char* iv, secure_string& data);
void printhex(byte* bytes, int len);
bool testkey(byte key[KEY_SIZE], secure_string& plaintext);

static inline int hex_to_int(char c) {
    return c <= '9' ? c - '0' : c - 'a' + 10;
}

void init_tester(const char* infile, const char* outfile) {
    res_filename = std::string(outfile);
    read_enc_file(infile, (char*)IV, ciphertext);
    std::cout << "IV: ";
    printhex(IV, BLOCK_SIZE);

    EVP_add_cipher(EVP_aes_128_cbc());
}

bool testkey(byte key[KEY_SIZE]) {
    return testkey(key, g_plaintext);
}

bool testkey(byte key[KEY_SIZE], secure_string& plaintext) {
    n_tested_keys++;
    int res = aes_decrypt(key, IV, ciphertext, plaintext);
    if (res == 1 && plaintext[0] == '%' && plaintext[1] == 'P' && plaintext[2] == 'D' && plaintext[3] == 'F') {
        std::cout << "\n!!FOUND KEY!!: " << key << std::endl;
        // printhex(key, KEY_SIZE);
        
        std::ofstream fout;
        fout.open(res_filename, std::ios::binary);
        fout.write(plaintext.data(), plaintext.length());
        fout.close();

        return true;
    }
    return false;
}

void printhex(byte* bytes, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    std::cout << std::endl;
}

int read_enc_file(const char* filename, char* iv, secure_string& data) {
    std::ifstream fin;
    fin.open(filename, std::ios::binary | std::ios::ate);

    int size = fin.tellg();
    fin.seekg(0, std::ios::beg);
    data.resize(size - 2 * BLOCK_SIZE);

    byte raw_iv[2 * BLOCK_SIZE];
    fin.read((char*)raw_iv, 2 * BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; i++) {
        iv[i] = 16 * hex_to_int(raw_iv[2 * i]) + hex_to_int(raw_iv[2 * i + 1]);
    }

    fin.read(&data[0], size - 2 * BLOCK_SIZE);
    fin.close();

    return size;
}

void report_nkeys_tested() {
    std::cout << "Tested " << n_tested_keys << " keys" << std::endl;
}