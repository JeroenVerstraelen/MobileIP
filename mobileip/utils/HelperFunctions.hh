// This file contains certain helper functions used in the project
#include <stdint.h>
#include "Configurables.hh"

#if PRINTDEBUG
	#define LOG(...) click_chatter(__VA_ARGS__)
#else
	#define LOG(...) 0
#endif
#if PRINTERROR
	#define LOGERROR(msg, ...) click_chatter("\033[1;31m" msg "\033[0m", ##__VA_ARGS__)
#else
	#define LOGERROR(...) 0
#endif

// Generates a random number between a and b
inline unsigned int generateRandomNumber(unsigned int min, unsigned int max){
    return rand() % max + min;
}

// Only for ipv4 Class C network ID comparison, other configurations will not work!
inline bool sameNetwork(IPAddress ip1, IPAddress ip2) {
	// Compare ipv4 Class C network IDs
	IPAddress mask = IPAddress("255.255.255.0");
	return ip1.matches_prefix(ip2, mask);
}
