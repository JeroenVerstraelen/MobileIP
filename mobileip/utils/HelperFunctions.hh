// This file contains certain helper functions used in the project

// Generates a random number between a and b
inline unsigned int generateRandomNumber(unsigned int a, unsigned int b){
    return rand() % b + a;
}
