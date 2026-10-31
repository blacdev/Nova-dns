/** Address helpers: whether an address is public (the probe never reaches into private networks). */

import { BlockList, isIP } from "node:net";

// Two lists: with both kinds in one, Node matched public IPv6 addresses against IPv4 rules.
const PRIVATE4 = new BlockList();
const PRIVATE6 = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) PRIVATE4.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32]] as const) {
  PRIVATE6.addSubnet(net, bits, "ipv6");
}

export function isPublicAddress(ip: string): boolean {
  const kind = isIP(ip);
  if (!kind) return false;
  if (kind === 4) return !PRIVATE4.check(ip, "ipv4");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return !PRIVATE4.check(mapped[1], "ipv4");
  return !PRIVATE6.check(ip, "ipv6");
}
