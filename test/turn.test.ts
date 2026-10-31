import { describe, expect, it } from "vitest";
import { tally } from "../src/turn/shipper.js";

// Lines exactly as coturn 4.6 wrote them in a real run (see deploy/turn).
const LOG = [
  "2026-10-31T18:54:22+0000: session 000000000000000001: usage: realm=<turn.example.test>, username=<1793494455:11111111-2222-3333-4444-555555555555>, rp=31, rb=3788, sp=31, sb=3012",
  "2026-10-31T18:54:22+0000: session 000000000000000001: peer usage: realm=<turn.example.test>, username=<1793494455:11111111-2222-3333-4444-555555555555>, rp=20, rb=2000, sp=20, sb=2000",
  "2026-10-31T18:54:22+0000: session 000000000000000001: closed (2nd stage), user <1793494455:11111111-2222-3333-4444-555555555555> realm <turn.example.test> origin <>, local 192.0.2.2:3478, remote 192.0.2.2:57439, reason: allocation timeout",
  "2026-10-31T18:54:22+0000: session 000000000000000001: peer 192.0.2.2:3481 deleted",
];

describe("TURN usage from coturn's log", () => {
  it("adds bytes and sessions per studio and day, ignoring peer-side lines", () => {
    expect(tally(LOG)).toEqual([{ studio_id: "11111111-2222-3333-4444-555555555555", day: "2026-10-31", bytes: 6800, sessions: 1 }]);
  });
});
