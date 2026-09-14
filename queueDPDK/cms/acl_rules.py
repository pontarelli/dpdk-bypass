#!/usr/bin/env python3
"""
Genera ruleset in formato l3fwd-acl per traffico con SIP e DIP dentro una /16.

Due popolazioni di regole:
  - "core"  : prefissi dentro la subnet del traffico -> determinano il match rate
  - "decoy" : prefissi fuori dalla subnet           -> gonfiano il trie, mai match

La frazione di decoy e' la manopola di pressione cache: cambia la dimensione
della struttura runtime di rte_acl a semantica invariata.

Formato emesso (parser l3fwd-acl):
  @SIP/len DIP/len sp_lo : sp_hi dp_lo : dp_hi proto/mask
"""

import argparse
import ipaddress
import random

WELL_KNOWN = [22, 53, 80, 123, 443, 3306, 5060, 8080]
PORT_RANGES = [(1024, 65535), (0, 1023), (32768, 65535), (6000, 6100)]
PROTOS = [6, 17]

# distribuzione lunghezze prefisso dentro la /16 (bimodale, stile ClassBench)
CORE_PLEN = [(24, 0.45), (28, 0.20), (32, 0.35)]
DECOY_PLEN = [(8, 0.05), (16, 0.25), (24, 0.50), (32, 0.20)]


def weighted(rng, pairs):
    vals, wts = zip(*pairs)
    return rng.choices(vals, weights=wts, k=1)[0]


def prefix_in(rng, net, plen):
    """Prefisso di lunghezza plen allineato dentro net."""
    if plen <= net.prefixlen:
        return net.network_address, net.prefixlen
    base = int(net.network_address)
    slots = 1 << (plen - net.prefixlen)
    off = rng.randrange(slots) << (32 - plen)
    return ipaddress.IPv4Address(base + off), plen


def decoy_prefix(rng):
    """Prefisso pubblico fuori da 10/8, 127/8, 172.16/12, 192.168/16, multicast."""
    while True:
        a = rng.randrange(1, 224)
        if a in (10, 127):
            continue
        b = rng.randrange(256)
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        plen = weighted(rng, DECOY_PLEN)
        addr = ipaddress.IPv4Address((a << 24) | (b << 16) |
                                     (rng.randrange(256) << 8) |
                                     rng.randrange(256))
        net = ipaddress.IPv4Network(f"{addr}/{plen}", strict=False)
        return net.network_address, plen


def port_field(rng, p_wild, p_known):
    r = rng.random()
    if r < p_wild:
        return 0, 65535
    if r < p_wild + p_known:
        p = rng.choice(WELL_KNOWN)
        return p, p
    return rng.choice(PORT_RANGES)


def proto_field(rng, p_wild):
    if rng.random() < p_wild:
        return "0x00/0x00"
    return f"0x{rng.choice(PROTOS):02x}/0xff"


def make_rule(rng, net, core, p_wild_port, p_known_port, p_wild_proto):
    if core:
        sip, slen = prefix_in(rng, net, weighted(rng, CORE_PLEN))
        dip, dlen = prefix_in(rng, net, weighted(rng, CORE_PLEN))
    else:
        sip, slen = decoy_prefix(rng)
        dip, dlen = decoy_prefix(rng)
    sp = port_field(rng, p_wild_port, p_known_port)
    dp = port_field(rng, p_wild_port, p_known_port)
    proto = proto_field(rng, p_wild_proto)
    return (f"@{sip}/{slen} {dip}/{dlen} "
            f"{sp[0]} : {sp[1]} {dp[0]} : {dp[1]} {proto}"), \
           (int(sip), slen, int(dip), dlen, sp, dp, proto)


def matches(pkt, r):
    sip, dip, sp, dp, proto = pkt
    rsip, rslen, rdip, rdlen, rsp, rdp, rproto = r
    if rslen and (sip >> (32 - rslen)) != (rsip >> (32 - rslen)):
        return False
    if rdlen and (dip >> (32 - rdlen)) != (rdip >> (32 - rdlen)):
        return False
    if not (rsp[0] <= sp <= rsp[1]):
        return False
    if not (rdp[0] <= dp <= rdp[1]):
        return False
    val, mask = rproto.split("/")
    m = int(mask, 16)
    if m and (proto & m) != (int(val, 16) & m):
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--rules", type=int, default=1000)
    ap.add_argument("--subnet", default="10.0.0.0/16")
    ap.add_argument("--decoy-frac", type=float, default=0.0,
                    help="frazione di regole fuori subnet (pressione cache)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--default-rule", action="store_true",
                    help="appende una catch-all permit in coda")
    ap.add_argument("--p-wild-port", type=float, default=0.55)
    ap.add_argument("--p-known-port", type=float, default=0.30)
    ap.add_argument("--p-wild-proto", type=float, default=0.20)
    ap.add_argument("-o", "--out", default="-")
    ap.add_argument("--check", type=int, default=0, metavar="N",
                    help="stima empirica del match rate su N pacchetti sintetici")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    net = ipaddress.IPv4Network(args.subnet)
    n_decoy = int(args.rules * args.decoy_frac)
    n_core = args.rules - n_decoy

    lines, parsed, seen = [], [], set()
    for i in range(args.rules):
        core = i < n_core
        tries = 0
        while True:
            txt, p = make_rule(rng, net, core, args.p_wild_port,
                               args.p_known_port, args.p_wild_proto)
            tries += 1
            if txt not in seen or tries > 50:
                break
        seen.add(txt)
        lines.append(txt)
        parsed.append(p)

    if args.default_rule:
        lines.append("@0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x00/0x00")

    body = "\n".join(lines) + "\n"
    if args.out == "-":
        print(body, end="")
    else:
        with open(args.out, "w") as f:
            f.write(body)

    if args.check:
        lo, hi = int(net.network_address), int(net.broadcast_address)
        hit = 0
        for _ in range(args.check):
            pkt = (rng.randint(lo, hi), rng.randint(lo, hi),
                   rng.randrange(65536), rng.randrange(65536),
                   rng.choice(PROTOS))
            if any(matches(pkt, r) for r in parsed):
                hit += 1
        print(f"# rules={args.rules} core={n_core} decoy={n_decoy} "
              f"match_rate={hit / args.check:.3f}")


if __name__ == "__main__":
    main()
