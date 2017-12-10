#include <click/timer.hh>

// An entry in the list of available routers for a host.
struct ICMPRouterEntry {
	uint32_t routerAddress;
	uint32_t preferenceLevel;
};
