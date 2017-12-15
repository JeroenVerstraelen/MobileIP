// This file contains the struct for a registration request
// sent by a Mobile Node to request a registration with an agent (home or foreign)

struct RegistrationRequest{
    uint8_t type;
    unsigned int x:1;
    unsigned int T:1;
    unsigned int r:1;
    unsigned int G:1;
    unsigned int M:1;
    unsigned int D:1;
    unsigned int B:1;
    unsigned int S:1;
    uint16_t lifetime;
    uint32_t homeAddress;
    uint32_t homeAgent;
    uint32_t careOfAddress;
    uint64_t identification;
};
