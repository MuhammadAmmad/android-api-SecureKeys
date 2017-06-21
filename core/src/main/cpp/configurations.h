//
// Created by Santiago Aguilera on 6/21/17.
//

#ifndef SECUREKEYS_CONFIGURATIONS_H
#define SECUREKEYS_CONFIGURATIONS_H

#include <map>
#include <string>

class Configurations {
private:
    bool is_rnd_aes;
    static unsigned char aes_key[32];
    static unsigned char aes_iv[16];
    bool safe;
public:
    Configurations(std::map<std::string, std::string> map);
    unsigned char * get_initial_vector();
    unsigned char * get_key();
    bool is_safe_to_use();
};


#endif //SECUREKEYS_CONFIGURATIONS_H
