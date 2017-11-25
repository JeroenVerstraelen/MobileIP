// This file will contain some configurable values for the project
#pragma once

// ICMP related configurables
const unsigned int advertisementLifetimeICMP = 45; // seconds
const unsigned int maxResponseDelay = 2; // max number of seconds that a router can wait before sending a response to a solicitation

// Extension related configurables
const unsigned int registrationLifetime = 30; // seconds

// Requests related configurables
const unsigned int requestLifetime = 60; // seconds

const IPAddress broadCast = IPAddress("255.255.255.255");
