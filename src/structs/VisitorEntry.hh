/*
* The FA MUST maintain a visitor list entry containing the following
* information obtained from the mobile node’s Registration Request
*/
struct VisitorEntry{
	uint32_t linkLayerAddress;
	uint32_t sourceIPAddress;
	uint32_t destinationIPAddress;
	uint16_t udpSourcePort;
	uint32_t homeAgentAddress;
	uint64_t identification;
	uint16_t requestLifetime;
	uint16_t remainingLifetime;
};
