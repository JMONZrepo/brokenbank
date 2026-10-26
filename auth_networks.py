# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank - Source Network Table for Authentication Events
# Version: 1.7.0
#
# The netbank_auth stream used to pick a country at random, independent of
# the source IP, so XSIAM's own IP enrichment contradicted the event and any
# geo or ASN rule a learner wrote was learning noise. Every generated source
# address is now drawn from one of the announced prefixes below (the seeded
# suspicious_ips in anomaly_seeds.yaml are emitted exactly as configured),
# and the country and ASN emitted with it are the ones the routing registry
# holds.
#
# Country and ASN for each prefix were checked against RIPEstat
# (prefix-overview and maxmind-geo-lite) on 2026-10-10. City is indicative
# only: most of these prefixes geolocate no finer than country, so the city
# is a plausible one for that ISP, not a lookup result.
#
# kind is NOT emitted on the event. Whether an address is hosting, a proxy,
# VPN or Tor is enrichment the learner is meant to bring, not a flag handed
# to them.

import ipaddress
from collections import namedtuple
from functools import lru_cache

# Country reported for addresses this table cannot place: loopback, RFC 1918,
# the Docker bridge and the IPv6 documentation prefix, which XSIAM cannot
# enrich either, and real public addresses outside the table, which it can.
# Matches the value every event carried before the table existed. Generated
# traffic only ever uses addresses inside the table (seeded values aside), so
# for real traffic use XSIAM's own IP enrichment rather than this field.
HOME_COUNTRY = "AU"

Network = namedtuple("Network", "cidr country asn asn_org kind cities")

NETWORKS = (
    # Australia - residential and mobile
    Network("1.120.0.0/13", "AU", 1221, "Telstra Limited", "mobile",
            ("Sydney", "Melbourne", "Brisbane", "Perth")),
    Network("101.160.0.0/11", "AU", 1221, "Telstra Limited", "residential",
            ("Sydney", "Melbourne", "Brisbane", "Adelaide")),
    Network("2001:8003::/32", "AU", 1221, "Telstra Limited", "residential",
            ("Sydney", "Melbourne", "Brisbane")),
    Network("49.176.0.0/13", "AU", 4804, "Microplex PTY LTD", "mobile",
            ("Sydney", "Melbourne")),
    Network("120.18.0.0/19", "AU", 133612, "Vodafone Australia Pty Ltd", "mobile",
            ("Sydney",)),
    Network("110.174.0.0/16", "AU", 7545, "TPG Telecom Limited", "residential",
            ("Sydney", "Melbourne")),
    Network("124.168.8.0/21", "AU", 7545, "TPG Telecom Limited", "residential",
            ("Sydney",)),
    Network("14.200.10.0/24", "AU", 7545, "TPG Telecom Limited", "residential",
            ("Melbourne",)),
    Network("203.206.8.0/21", "AU", 7545, "TPG Telecom Limited", "residential",
            ("Adelaide",)),
    Network("150.101.0.0/16", "AU", 4739, "Internode Pty Ltd", "residential",
            ("Adelaide", "Melbourne")),

    # South Korea
    Network("121.128.0.0/13", "KR", 4766, "Korea Telecom", "residential",
            ("Seoul", "Busan", "Incheon")),
    Network("175.216.0.0/13", "KR", 4766, "Korea Telecom", "mobile",
            ("Seoul",)),
    Network("175.112.0.0/12", "KR", 9318, "SK Broadband Co Ltd", "residential",
            ("Seoul", "Daegu")),
    Network("1.224.0.0/11", "KR", 9318, "SK Broadband Co Ltd", "residential",
            ("Seoul", "Busan")),
    Network("223.32.0.0/11", "KR", 9644, "SK Telecom", "mobile",
            ("Seoul",)),
    Network("106.240.0.0/12", "KR", 3786, "LG DACOM Corporation", "residential",
            ("Seoul", "Incheon")),

    # United States
    Network("73.0.0.0/8", "US", 7922, "Comcast Cable Communications, LLC", "residential",
            ("Philadelphia", "Chicago", "Denver")),
    Network("2601::/20", "US", 7922, "Comcast Cable Communications, LLC", "residential",
            ("Philadelphia", "Chicago")),
    Network("99.96.0.0/13", "US", 7018, "AT&T Enterprises, LLC", "residential",
            ("Dallas", "Atlanta")),
    Network("172.56.0.0/14", "US", 21928, "T-Mobile USA, Inc.", "mobile",
            ("Seattle", "Los Angeles")),

    # United Kingdom
    Network("86.128.0.0/10", "GB", 2856, "British Telecommunications Limited", "residential",
            ("London", "Manchester", "Birmingham")),
    Network("2a00:23c0::/27", "GB", 2856, "British Telecommunications Limited", "residential",
            ("London", "Manchester")),
    Network("82.0.0.0/14", "GB", 5089, "NTL Virgin Media Limited", "residential",
            ("London", "Leeds")),
    Network("90.192.0.0/11", "GB", 5607, "Sky UK Limited", "residential",
            ("London",)),

    # Hosting. The Sydney ranges are deliberate: an attacker on cloud in the
    # victim's own country is exactly the case a country-only rule misses.
    Network("13.236.0.0/14", "AU", 16509, "Amazon.com, Inc.", "hosting",
            ("Sydney",)),
    Network("170.64.128.0/18", "AU", 14061, "DigitalOcean, LLC", "hosting",
            ("Sydney",)),
    Network("139.180.160.0/20", "AU", 20473, "The Constant Company, LLC", "hosting",
            ("Sydney",)),
    # Microsoft Azure Australia East: Windows 365 Cloud PCs and Azure Virtual
    # Desktop, which customers also bank from at work
    Network("20.5.0.0/16", "AU", 8075, "Microsoft Corporation", "hosting",
            ("Sydney",)),
    Network("4.196.0.0/16", "AU", 8075, "Microsoft Corporation", "hosting",
            ("Sydney",)),
    Network("159.89.192.0/20", "SG", 14061, "DigitalOcean, LLC", "hosting",
            ("Singapore",)),
    Network("167.99.0.0/20", "US", 14061, "DigitalOcean, LLC", "hosting",
            ("North Bergen",)),
    Network("134.209.0.0/20", "US", 14061, "DigitalOcean, LLC", "hosting",
            ("Santa Clara",)),
    Network("95.216.0.0/16", "FI", 24940, "Hetzner Online GmbH", "hosting",
            ("Helsinki",)),
    Network("88.198.0.0/16", "DE", 24940, "Hetzner Online GmbH", "hosting",
            ("Falkenstein",)),
    Network("45.33.32.0/19", "US", 63949, "Akamai Connected Cloud", "hosting",
            ("Fremont",)),
    Network("91.240.118.0/24", "HK", 201738, "UFO TECHNOLOGIES LIMITED", "hosting",
            ("Hong Kong",)),
    Network("193.142.146.0/24", "DE", 213438, "ColocaTel Inc.", "hosting",
            ("Frankfurt am Main",)),

    # Corporate secure web gateway egress. Customers signing in from a work
    # laptop come out of their employer's cloud proxy: benign traffic from a
    # non-residential ASN, and a classic impossible-travel false positive.
    Network("165.225.114.0/24", "AU", 53813, "ZSCALER, INC.", "proxy",
            ("Sydney",)),
    Network("165.225.226.0/23", "AU", 53813, "ZSCALER, INC.", "proxy",
            ("Melbourne",)),
    Network("147.161.212.0/23", "AU", 53813, "ZSCALER, INC.", "proxy",
            ("Melbourne",)),
    Network("165.225.98.0/24", "US", 22616, "ZSCALER, INC.", "proxy",
            ("Chicago",)),
    Network("136.226.80.0/23", "US", 22616, "ZSCALER, INC.", "proxy",
            ("New York",)),
    Network("147.161.236.0/23", "GB", 62044, "Zscaler Switzerland GmbH", "proxy",
            ("Manchester",)),

    # Commercial VPN egress and Tor
    Network("89.187.162.0/23", "SG", 60068, "Datacamp Limited", "vpn",
            ("Singapore",)),
    Network("37.19.200.0/24", "US", 212238, "Datacamp Limited", "vpn",
            ("Dallas",)),
    Network("146.70.10.0/24", "CR", 9009, "M247 Europe SRL", "vpn",
            ("San José",)),
    Network("185.159.157.0/24", "CH", 209103, "Proton AG", "vpn",
            ("Zurich",)),
    Network("185.220.101.0/24", "DE", 60729, "Stiftung Erneuerbare Freiheit", "tor",
            ("Brandenburg an der Havel",)),
)

_PARSED = sorted(
    ((ipaddress.ip_network(n.cidr), n) for n in NETWORKS),
    key=lambda pair: pair[0].prefixlen,
    reverse=True,
)


@lru_cache(maxsize=4096)
def lookup(ip):
    """Return the Network holding ip, or None if the table cannot place it."""
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    for net, entry in _PARSED:
        if address.version == net.version and address in net:
            return entry
    return None


def networks(country=None, kinds=None, asn=None):
    """Networks filtered by country code, a collection of kinds and/or ASN."""
    return [
        n for n in NETWORKS
        if (country is None or n.country == country)
        and (kinds is None or n.kind in kinds)
        and (asn is None or n.asn == asn)
    ]


def random_ip(network, rng):
    """A host address inside network, avoiding .0 and .255 on IPv4."""
    net = ipaddress.ip_network(network.cidr)
    while True:
        address = net.network_address + rng.randrange(1, net.num_addresses - 1)
        if address.version == 6 or address.packed[-1] not in (0, 255):
            return str(address)
