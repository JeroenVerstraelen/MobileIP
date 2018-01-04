// This file will contain some configurable values for the project
#pragma once

#define PRINTDEBUG true
#define PRINTERROR true

const IPAddress broadCast = IPAddress("255.255.255.255");

/* ====================
 * ICMP Router Discovery
 * ====================
 */

/*
 * ROUTER CONFIGURATION
 */
// Destination for Router Advertisement messages.
const IPAddress AdvertisementAddress = broadCast;

// Maximum time allowed between sending advertisements, in seconds.
// No less than 4 seconds and no greater than 1800 seconds.
const unsigned int MaxAdvertisementInterval = 600;

// Minimum time allowed between sending advertisements, in seconds.
// No less than 3 seconds and no greater than MaxAdvertisementInterval.
const unsigned int MinAdvertisementInterval = 0.75 * MaxAdvertisementInterval;

// Maximum number of seconds router address is valid.
// No less than MaxAdvertisementInterval and no greater than 9000 seconds.
const unsigned int AdvertisementLifetime = 1800;

// max number of seconds that a router can wait before sending a response to a solicitation.
const unsigned int MaxResponseDelay = 2;

/*
 * HOST CONFIGURATION
 */
// Destination for solicitation messages.
const IPAddress SolicitationAddress = broadCast;

/* ===================================
 * Registration related configurables
 * ===================================
 */
const unsigned int maxLifetimeForeignAgent = 1800; // seconds
const unsigned int maxLifetimeHomeAgent = maxLifetimeForeignAgent;

// Extension related configurables
const unsigned int registrationLifetime = 30; // seconds

// Requests related configurables
const unsigned int requestLifetime = 60; // seconds

// Source port of registrations at the MN
const unsigned int portUDP = 63344;
