// This file contains certain helper functions used in the project
#include <stdint.h>
#include "Configurables.hh"

#if PRINTDEBUG
	#define LOG(...) click_chatter(__VA_ARGS__) 
#else
	#define LOG(...) 0
#endif

// Generates a random number between a and b
inline unsigned int generateRandomNumber(unsigned int a, unsigned int b){
    return rand() % b + a;
}

// Only for ipv4 Class C network ID comparison, other configurations will not work!
inline bool sameNetwork(IPAddress ip1, IPAddress ip2) {
	// Compare ipv4 Class C network IDs
	IPAddress mask = IPAddress("255.255.255.0");
	return ip1.matches_prefix(ip2, mask);
}
