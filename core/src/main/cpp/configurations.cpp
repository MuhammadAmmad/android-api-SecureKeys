//
// Created by Santiago Aguilera on 6/21/17.
//

#include "configurations.h"
#include "crypto/crypto_wrapper.h"
#include "protocol.h"
#include "crypto/base64.h"

unsigned char Configurations::aes_iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                                        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char Configurations::aes_key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71,
                                             0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c,
                                             0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
                                             0xf4 };

std::string find(std::string what, std::map<std::string, std::string> where) {
    return where[what];
}

Configurations::Configurations(std::map<std::string, std::string> map) {
    // Initialize variables
    safe = true;
    CryptoWrapper cryptoWrapper;

    // Get aes values
    std::string map_aes_rnd_key = find(cryptoWrapper.encode_key(SECUREKEYS_AES_RANDOM_SEED), map);

    if (!map_aes_rnd_key.empty()) {
        // Create from random seed
        unsigned char map_aes_seed[map_aes_rnd_key.length()];
        strncpy(static_cast<char*>(map_aes_seed), map_aes_rnd_key.c_str(), sizeof(map_aes_seed));

        for (int i = 0 ; i < 32 ; ++i) {
            if (i < 16) {
                aes_iv[i] = map_aes_seed[i];
            }
            aes_key[i] = map_aes_seed[map_aes_rnd_key.length() - i - 1];
        }
    } else {
        // Check if unique values are present, else use defaults
        std::string map_aes_key = find(cryptoWrapper.encode_key(SECUREKEYS_AES_KEY), map);
        std::string map_aes_iv = find(cryptoWrapper.encode_key(SECUREKEYS_AES_INITIAL_VECTOR), map);

        if (!map_aes_key.empty()) {
            std::string map_aes_key_b64 = base64_decode(map_aes_key);
            strncpy(static_cast<char*>(aes_key), map_aes_key_b64.c_str(), sizeof(aes_key));
        }
        if (!map_aes_iv.empty()) {
            std::string map_aes_iv_b64 = base64_decode(map_aes_iv);
            strncpy(static_cast<char*>(aes_iv), map_aes_iv_b64.c_str(), sizeof(aes_iv));
        }
    }
}

unsigned char * Configurations::get_initial_vector() {
    return aes_iv;
}

unsigned char * Configurations::get_key() {
    return aes_key;
}

bool Configurations::is_safe_to_use() {
    return safe;
}
