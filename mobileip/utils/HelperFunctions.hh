// This file contains certain helper functions used in the project
#include <stdint.h>
#include <stdint.h>

// Generates a random number between a and b
inline unsigned int generateRandomNumber(unsigned int a, unsigned int b){
    return rand() % b + a;
}

bool sameNetwork(IPAddress ip1, IPAddress ip2);
