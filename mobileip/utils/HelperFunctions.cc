bool sameNetwork(IPAddress ip1, IPAddress ip2) {
	IPAddress mask = IPAddress("255.255.255.0");
	return ip1.matches_prefix(ip2, mask);
}
