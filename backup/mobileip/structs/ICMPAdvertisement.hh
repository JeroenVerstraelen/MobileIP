// This file contains the struct for an ICMP advertisement message
// (sent by an agent to let neigboring interfaces know it's presence)
struct ICMPAdvertisement {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t numAddrs;
    uint8_t addrEntrySize;
    uint16_t lifetime;
    uint32_t routerAddress;
    uint32_t preferenceLevel;
};
