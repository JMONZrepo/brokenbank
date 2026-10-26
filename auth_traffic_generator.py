# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank - Background Authentication Traffic Generator
# Version: 1.7.0
#
# This module generates simulated authentication traffic for SIEM testing.
# A fixed, seeded population of customers, staff and service accounts signs
# in from stable home networks and devices, so novelty (a new ASN, device or
# country for an account) means something. Attack scenarios are scheduled on
# top as multi-event sequences, and the normal traffic deliberately contains
# the benign lookalikes each detection has to tell apart from them: consumer
# VPN users, a budgeting app that signs in from cloud with a script, mobile
# sessions that change address and are resumed days after they were issued,
# trips abroad, replaced phones, missed and denied MFA prompts.
#
# Events are scheduled into a small time-ordered queue and shipped when due,
# so a scenario can spread its events across a realistic window without the
# generator sleeping inside it. Each event's timestamp is its scheduled time.

import hashlib
import heapq
import ipaddress
import itertools
import logging
import math
import random
import threading
import time
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

import yaml
from faker import Faker

import auth_networks
from log_shipping import build_auth_event, get_log_shipper, _detect_client_app, _detect_device_type
import observability.metrics as metrics

LOCALES = ['en_AU', 'en_GB', 'en_US']

# Unseeded: throwaway names an attacker guesses, never members of the population
fake = Faker(LOCALES)

# Synthetic TLS client fingerprints, JA4-shaped and stable per TLS stack.
# They are NOT real JA4 values for these clients. What matters for detection
# is that they follow the TLS stack rather than the User-Agent, so a script
# claiming to be Chrome still shows a script's fingerprint.
_TLS_STACKS = {
    "chromium": (15, 16, "h2"),
    "firefox": (17, 15, "h2"),
    "apple": (20, 14, "h2"),
    "okhttp": (17, 14, "h2"),
    "python": (18, 12, "00"),
    "curl": (31, 13, "h2"),
    "go": (13, 11, "h2"),
    "openssl": (30, 13, "00"),
}


def _synthetic_ja4(stack):
    ciphers, extensions, alpn = _TLS_STACKS[stack]
    digest = hashlib.sha256(f"brokenbank-ja4:{stack}".encode()).hexdigest()
    return f"t13d{ciphers:02d}{extensions:02d}{alpn}_{digest[:12]}_{digest[12:24]}"


# family -> (User-Agent, TLS stack)
CLIENT_FAMILIES = {
    "chrome_windows": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "chromium"),
    "chrome_mac": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "chromium"),
    "edge_windows": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "chromium"),
    "firefox_windows": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", "firefox"),
    "firefox_mac": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0", "firefox"),
    "safari_mac": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", "apple"),
    "safari_iphone": ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", "apple"),
    "chrome_iphone": ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1", "apple"),
    "chrome_android": ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", "chromium"),
    "samsung_android": ("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36", "chromium"),
    "safari_ipad": ("Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", "apple"),
    "bb_ios_app": ("BrokenBankMobile/4.2.1 (iPhone; iOS 17.2; Scale/3.00)", "apple"),
    "bb_android_app": ("BrokenBankMobile/4.2.1 (Android 14; SM-S918B)", "okhttp"),
    "python_requests": ("python-requests/2.31.0", "python"),
    "curl": ("curl/8.4.0", "curl"),
    "go_http": ("Go-http-client/2.0", "go"),
    "hydra": ("Mozilla/4.0 (Hydra)", "openssl"),
}

DESKTOP_FAMILIES = ("chrome_windows", "chrome_mac", "edge_windows",
                    "firefox_windows", "firefox_mac", "safari_mac")
MOBILE_BROWSER_FAMILIES = ("safari_iphone", "chrome_iphone",
                           "chrome_android", "samsung_android")
MOBILE_APP_FAMILIES = ("bb_ios_app", "bb_android_app")
BROWSER_FAMILIES = DESKTOP_FAMILIES + MOBILE_BROWSER_FAMILIES

# Seconds a session lives, by how it was obtained. Anything over an hour is
# what a token-validity marker would flag, which is most of a real bank's
# mobile and remembered sessions: that is the baseline, not the anomaly.
SESSION_SECONDS = {
    "browser": 1800,
    "mobile_app": 30 * 86400,
    "remember_me": 30 * 86400,
    "sso_saml": 8 * 3600,
    "api_key": 3600,
    "script": 3600,
}

LOGIN_PATHS = {
    "browser": "/netbank/login",
    "mobile_app": "/api/v2/auth/token",
    "script": "/api/v2/auth/token",
    "sso_saml": "/sso/saml/acs",
}

MFA_HTTP_STATUS = {"approved": 200, "denied": 401, "timeout": 408, "expired": 401}

# What a second-factor challenge returns when the person answering it does
# not hold the factor: nobody approves the push, the SMS code lapses, a
# guessed TOTP code is wrong.
NO_FACTOR_RESULT = {"push": "timeout", "sms_otp": "expired", "totp": "denied"}

# Chance per customer sign-in that a trip abroad starts. A trip spends its
# route's transit time with no sign-ins, 2-10 days abroad, then the same
# transit back, so a velocity check sees a flight's worth of time pass.
TRIP_START_PROBABILITY = 0.0002

# Door-to-door hours between home countries, slow enough that even the
# farthest city pair in auth_networks.py stays under 1000 km/h
TRANSIT_HOURS = {
    frozenset(("AU", "KR")): (10, 15),
    frozenset(("AU", "US")): (20, 28),
    frozenset(("AU", "GB")): (22, 30),
    frozenset(("KR", "US")): (13, 19),
    frozenset(("GB", "KR")): (14, 20),
    frozenset(("GB", "US")): (9, 14),
}
DEFAULT_TRANSIT_HOURS = (20, 30)

# Chance per customer sign-in that a genuinely new phone or laptop appears.
# It replaces an old one rather than accumulating, so this benign novelty
# continues for as long as the range runs.
NEW_DEVICE_PROBABILITY = 0.0015

Device = namedtuple("Device", "device_id user_agent tls_ja4")
Source = namedtuple("Source", "ip city")
Session = namedtuple("Session", "session_id issued_at issued_ts expires_at expires_ts username "
                                "account device source auth_method")

# Returned by a scenario that could not find a suitable victim and emitted nothing
SKIPPED = object()


@dataclass
class Account:
    username: str
    user_id: str
    account_type: str
    privilege: str
    home_country: str = auth_networks.HOME_COUNTRY
    home: Source = None
    mobile_network: object = None
    devices: list = field(default_factory=list)
    mfa_method: str = "none"
    default_auth: str = "password"
    weight: int = 1
    interval_minutes: float = 0.0
    vpn_network: object = None
    work_proxy: object = None
    cloud_pc: object = None
    aggregator_device: Device = None
    aggregator_source: Source = None
    trip: dict = None
    sessions: dict = field(default_factory=dict)
    primed: set = field(default_factory=set)
    trusted: set = field(default_factory=set)
    # When each device first appeared during the run (absent: before it)
    born: dict = field(default_factory=dict)
    pending_devices: list = field(default_factory=list)
    busy_until: float = 0.0


# Scenario defaults. Anything set under scenarios: in anomaly_seeds.yaml
# overrides these key by key, so an older config file that only knows the
# original four scenarios still gets the rest at their defaults.
DEFAULT_SCENARIOS = {
    "brute_force": {
        "description": "Multiple failed logins from same IP within short timeframe",
        "frequency_minutes": 30,
        "pattern": {"failed_attempts": 10, "time_window_seconds": 60,
                    "source_ip": "91.240.118.172", "then_success": True,
                    "user_agent": "Mozilla/4.0 (Hydra)"},
    },
    "credential_stuffing": {
        "description": "Multiple usernames attempted from same IP",
        "frequency_minutes": 45,
        "pattern": {"unique_usernames": 20, "time_window_seconds": 120,
                    "source_ip": "193.142.146.35", "successes": 1},
    },
    "impossible_travel": {
        "description": "Same user authenticates from AU then KR within 5 minutes",
        "frequency_minutes": 60,
        "pattern": {"first_country": "AU", "second_country": "KR",
                    "time_gap_minutes": 5},
    },
    "account_takeover": {
        "description": "Successful login after multiple failures, then password change",
        "frequency_minutes": 90,
        "pattern": {"failed_attempts_before": 5, "successful_login": True,
                    "password_change": True},
    },
    "password_spray": {
        "description": "One password tried once against many real usernames, low and slow",
        "frequency_minutes": 65,
        "pattern": {"usernames": 15, "time_window_seconds": 600,
                    "source_ip": "88.198.47.12"},
    },
    "session_token_replay": {
        "description": "A live session is reused from a second address and client",
        "frequency_minutes": 40,
        "pattern": {"replay_delay_seconds": [60, 300], "replays": 3,
                    "orphan_probability": 0.3},
    },
    "mfa_push_bombing": {
        "description": "Repeated push challenges denied or ignored, then one approved",
        "frequency_minutes": 50,
        "pattern": {"denied_pushes": 8, "time_window_seconds": 180},
    },
    "mfa_enrolment_after_failure": {
        "description": "Failed login, failed challenge, success, then a new MFA device",
        "frequency_minutes": 70,
        "pattern": {},
    },
    "helpdesk_mfa_reset": {
        "description": "Helpdesk clears a customer's MFA and password, then the account re-enrols",
        "frequency_minutes": 80,
        "pattern": {"malicious_probability": 0.5},
    },
    "username_case_variance": {
        "description": "MFA demanded for the username, skipped for a case variant of it",
        "frequency_minutes": 100,
        "pattern": {},
    },
    "scripted_client_login": {
        "description": "Customer account signed in by a scripting runtime, then refreshed at machine rate",
        "frequency_minutes": 55,
        "pattern": {"user_agent": "python-requests/2.31.0", "refreshes": 6,
                    "refresh_window_seconds": 60},
    },
    "dormant_account_login": {
        "description": "A departed staff account that was never disabled signs in",
        "frequency_minutes": 120,
        "pattern": {"accounts": [
            {"username": "r.okafor", "user_id": "stf-4211730",
             "privilege": "teller", "departed": "2026-03-31"},
            {"username": "m.lindqvist", "user_id": "stf-4209951",
             "privilege": "helpdesk_agent", "departed": "2026-06-12"},
        ]},
    },
    "break_glass_login": {
        "description": "Sign-in attempts against the emergency access account",
        "frequency_minutes": 180,
        "pattern": {"username": "bb-breakglass-01", "attempts": 3,
                    "time_window_seconds": 90},
    },
}

DEFAULT_COUNTRIES = [
    {"code": "AU", "weight": 70}, {"code": "KR", "weight": 20},
    {"code": "US", "weight": 5}, {"code": "GB", "weight": 5},
]
DEFAULT_DEVICE_TYPES = [
    {"type": "desktop", "weight": 45}, {"type": "mobile", "weight": 40},
    {"type": "tablet", "weight": 15},
]
DEFAULT_MFA_METHODS = [
    {"method": "push", "weight": 50}, {"method": "totp", "weight": 20},
    {"method": "sms_otp", "weight": 15}, {"method": "passkey", "weight": 8},
    {"method": "none", "weight": 7},
]


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _weighted(rng, items, weight_key="weight"):
    total = sum(i.get(weight_key, 1) for i in items)
    r = rng.uniform(0, total)
    current = 0
    for item in items:
        current += item.get(weight_key, 1)
        if r <= current:
            return item
    return items[-1]


# ----------------------------------------------------------------------
# Config validation. anomaly_seeds.yaml is hand-edited and bind-mounted,
# so every value is checked here and a bad one falls back to its default
# with a warning, rather than stopping the generator or the app with it.
# ----------------------------------------------------------------------

def _mapping(parent, key, where=""):
    value = parent.get(key) if isinstance(parent, dict) else None
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    logging.warning(f"Ignoring {where}{key}: expected a mapping, got {type(value).__name__}")
    return {}


def _number(value, default, where, minimum=None, maximum=None, integer=False, exclusive_min=False):
    if value is None:
        return default
    try:
        if isinstance(value, bool):
            raise ValueError
        number = float(value)
        if integer:
            number = int(round(number))
    except (TypeError, ValueError, OverflowError):
        logging.warning(f"Ignoring {where}={value!r}: not a number, using {default}")
        return default
    too_low = minimum is not None and (number <= minimum if exclusive_min else number < minimum)
    if too_low or (maximum is not None and number > maximum) or not math.isfinite(number):
        logging.warning(f"Ignoring {where}={value!r}: out of range, using {default}")
        return default
    return number


def _weighted_items(value, key, default, where):
    if value is None:
        return default
    valid = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and isinstance(item.get(key), str):
                weight = _number(item.get("weight", 1), None, f"{where}.weight", minimum=0)
                if weight is not None:
                    valid.append({**item, "weight": weight})
    if not valid or sum(i["weight"] for i in valid) <= 0:
        logging.warning(f"Ignoring {where}: expected a list of {{{key}, weight}} entries, using defaults")
        return default
    return valid


def _valid_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


# Pattern keys that count things (at least 1) and keys that are durations
# (kept as floats rather than rounded)
_COUNT_KEYS = {"failed_attempts", "unique_usernames", "usernames", "replays",
               "denied_pushes", "refreshes", "attempts", "failed_attempts_before"}
_DURATION_SUFFIXES = ("_seconds", "_minutes")
# Anything spread across a session must finish inside the shortest one the
# scenario can use (a 30-minute browser session)
_WITHIN_SESSION_MAX_SECONDS = 1500


def _coerce_pattern(name, default, user):
    pattern = dict(default)
    if user is None:
        return pattern
    if not isinstance(user, dict):
        logging.warning(f"Ignoring scenarios.{name}.pattern: expected a mapping")
        return pattern
    for key, value in user.items():
        where = f"scenarios.{name}.pattern.{key}"
        if key not in default:
            continue
        base = default[key]
        if isinstance(base, bool):
            if isinstance(value, bool):
                pattern[key] = value
            else:
                logging.warning(f"Ignoring {where}={value!r}: expected true or false")
        elif isinstance(base, (int, float)):
            duration = key.endswith(_DURATION_SUFFIXES)
            maximum = None
            if key.endswith("probability"):
                maximum = 1
            elif key in _COUNT_KEYS or key == "successes":
                maximum = 1000
            elif key.endswith("_seconds"):
                maximum = 86400
            elif key.endswith("_minutes"):
                maximum = 1440
            if key == "refresh_window_seconds":
                maximum = _WITHIN_SESSION_MAX_SECONDS
            pattern[key] = _number(value, base, where,
                                   minimum=1 if key in _COUNT_KEYS else 0,
                                   maximum=maximum,
                                   integer=isinstance(base, int) and not duration)
        elif key == "source_ip":
            if _valid_ip(value):
                pattern[key] = str(value)
            else:
                logging.warning(f"Ignoring {where}={value!r}: not an IP address")
        elif isinstance(base, str):
            if isinstance(value, str) and value:
                pattern[key] = value
            else:
                logging.warning(f"Ignoring {where}={value!r}: expected text")
        elif key == "replay_delay_seconds":
            ok = (isinstance(value, list) and len(value) == 2
                  and all(_number(v, None, where, minimum=0) is not None for v in value)
                  and float(value[0]) <= float(value[1]))
            if ok and float(value[1]) > _WITHIN_SESSION_MAX_SECONDS:
                logging.warning(f"Ignoring {where}={value!r}: the replay must land inside a "
                                f"30-minute browser session, so at most "
                                f"{_WITHIN_SESSION_MAX_SECONDS} seconds")
            elif ok:
                pattern[key] = [float(value[0]), float(value[1])]
            else:
                logging.warning(f"Ignoring {where}={value!r}: expected [min, max] seconds")
        elif key == "accounts":
            accounts = [a for a in value if isinstance(a, dict)
                        and isinstance(a.get("username"), str) and a.get("user_id")] \
                if isinstance(value, list) else []
            if accounts:
                pattern[key] = accounts
            else:
                logging.warning(f"Ignoring {where}: expected a list of {{username, user_id}} entries")
    if name == "impossible_travel":
        placeable = {n.country for n in auth_networks.networks(kinds={"residential"})}
        first, second = pattern["first_country"], pattern["second_country"]
        if first not in placeable or second not in placeable or first == second:
            logging.warning(f"scenarios.impossible_travel countries {first!r} -> {second!r} "
                            f"must be two different codes from {sorted(placeable)}; "
                            f"using AU -> KR")
            pattern["first_country"], pattern["second_country"] = "AU", "KR"
    return pattern


class AuthTrafficGenerator:
    """Generates simulated authentication traffic with seeded anomalies."""

    def __init__(self, logging_config_path="config/logging.yaml",
                 anomaly_config_path="config/anomaly_seeds.yaml"):
        logging_config = self._load_config(logging_config_path)
        self.logging_config = logging_config if isinstance(logging_config, dict) else {}
        anomaly_config = self._load_config(anomaly_config_path)
        if anomaly_config is not None and not isinstance(anomaly_config, dict):
            logging.warning(f"Ignoring {anomaly_config_path}: expected a mapping at the top level")
        self.anomaly_config = anomaly_config if isinstance(anomaly_config, dict) else {}
        self._anomaly_cfg = _mapping(self.anomaly_config, "anomaly_config")
        self._normal_cfg = _mapping(self.anomaly_config, "normal_traffic")
        self.running = False
        self.thread = None
        self.last_anomaly_time = {}
        self.rng = random.Random()
        self.scenarios = self._scenario_config()
        self.base_success_percent = _number(self._normal_cfg.get("success_rate_percent"), 92,
                                            "normal_traffic.success_rate_percent",
                                            minimum=0, maximum=100)
        self.suspicious_ips = [
            i for i in _weighted_items(self.anomaly_config.get("suspicious_ips"), "ip", [], "suspicious_ips")
            if _valid_ip(i["ip"])
        ]
        self.suspicious_user_agents = _weighted_items(
            self.anomaly_config.get("suspicious_user_agents"), "agent", [], "suspicious_user_agents")

        self._pending = []
        self._seq = itertools.count()

        self._build_population()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.warning(f"Config not found at {config_path}")
            return {}
        except Exception as e:
            logging.error(f"Error loading config {config_path}: {e}")
            return {}

    def _scenario_config(self):
        configured = self.anomaly_config.get("scenarios")
        if not isinstance(configured, dict):
            if configured is not None:
                logging.warning("Ignoring scenarios: expected a mapping")
            configured = {}
        unknown = set(configured) - set(DEFAULT_SCENARIOS)
        if unknown:
            logging.warning(f"Ignoring unknown auth scenario(s): {sorted(unknown)}")
        merged = {}
        for name, default in DEFAULT_SCENARIOS.items():
            user = configured.get(name)
            enabled = True
            if user is False:
                user, enabled = {}, False
            elif not isinstance(user, dict):
                if user not in (None, True):
                    logging.warning(f"Ignoring scenarios.{name}: expected a mapping")
                user = {}
            if "enabled" in user:
                if isinstance(user["enabled"], bool):
                    enabled = user["enabled"]
                else:
                    logging.warning(f"Ignoring scenarios.{name}.enabled={user['enabled']!r}: expected true or false")
            merged[name] = {
                "description": user.get("description") or default["description"],
                "enabled": enabled,
                "frequency_minutes": _number(user.get("frequency_minutes"),
                                             default["frequency_minutes"],
                                             f"scenarios.{name}.frequency_minutes",
                                             minimum=0, exclusive_min=True),
                "pattern": _coerce_pattern(name, default["pattern"], user.get("pattern")),
            }
        return merged

    def _generator_settings(self):
        endpoints = _mapping(self.logging_config, "endpoints")
        netbank_auth = _mapping(endpoints, "netbank_auth", "endpoints.")
        return _mapping(netbank_auth, "generator", "endpoints.netbank_auth.")

    def _success_rate(self):
        base = self.base_success_percent
        # Lower success rates during early morning (potential automated
        # attacks) and higher during business hours
        hour = datetime.now().hour
        if 2 <= hour <= 5:
            modifier = -5
        elif 9 <= hour <= 17:
            modifier = 3
        else:
            modifier = 0
        return max(60, min(98, base + modifier)) / 100

    # ------------------------------------------------------------------
    # Population
    # ------------------------------------------------------------------

    def _build_population(self):
        """Build a population that is identical on every start for a given seed."""
        population = _mapping(self._normal_cfg, "population", "normal_traffic.")
        seed = population.get("seed", 1337)
        if not isinstance(seed, (int, str)) or isinstance(seed, bool):
            logging.warning(f"Ignoring normal_traffic.population.seed={seed!r}, using 1337")
            seed = 1337
        customer_count = _number(population.get("customers"), 100,
                                 "normal_traffic.population.customers",
                                 minimum=1, maximum=10000, integer=True)
        rng = random.Random(seed)
        # One seeded Faker per locale, chosen by rng: a multi-locale Faker
        # picks its locale from an unseeded source, so names would drift
        fakers = []
        for locale in LOCALES:
            locale_fake = Faker(locale)
            locale_fake.seed_instance(seed)
            fakers.append(locale_fake)

        def pfake():
            return rng.choice(fakers)

        countries = _weighted_items(self._normal_cfg.get("countries"), "code",
                                    DEFAULT_COUNTRIES, "normal_traffic.countries")
        device_types = self._known_values(
            _weighted_items(self._normal_cfg.get("device_types"), "type",
                            DEFAULT_DEVICE_TYPES, "normal_traffic.device_types"),
            "type", ("desktop", "mobile", "tablet"), DEFAULT_DEVICE_TYPES,
            "normal_traffic.device_types")
        mfa_methods = self._known_values(
            _weighted_items(population.get("mfa_methods"), "method",
                            DEFAULT_MFA_METHODS, "normal_traffic.population.mfa_methods"),
            "method", ("push", "totp", "sms_otp", "passkey", "none"), DEFAULT_MFA_METHODS,
            "normal_traffic.population.mfa_methods")

        placeable = {n.country for n in auth_networks.networks(kinds={"residential"})}
        unplaceable = sorted({c["code"] for c in countries} - placeable)
        if unplaceable:
            logging.warning(f"normal_traffic.countries {unplaceable} have no residential prefixes "
                            f"in auth_networks.py; those customers are placed in "
                            f"{auth_networks.HOME_COUNTRY} (supported: {sorted(placeable)})")

        taken = set()

        def unique(make):
            for _ in range(1000):
                value = make()
                if value not in taken:
                    taken.add(value)
                    return value
            value = f"{make()}{len(taken)}"
            taken.add(value)
            return value

        def staff_name():
            first = "".join(c for c in pfake().first_name().lower() if c.isalpha())
            last = "".join(c for c in pfake().last_name().lower() if c.isalpha())
            return f"{first}.{last}"

        vpns = auth_networks.networks(kinds={"vpn"})
        cloud = auth_networks.networks(country=auth_networks.HOME_COUNTRY, kinds={"hosting"},
                                       asn=16509)[0]
        vultr = auth_networks.networks(country=auth_networks.HOME_COUNTRY, kinds={"hosting"},
                                       asn=20473)[0]
        # A budgeting app's sync service: fixed egress addresses on two cloud
        # providers (AWS and Vultr Sydney), shared by every customer who linked it
        aggregator_sources = [Source(auth_networks.random_ip(n, rng), n.cities[0])
                              for n in (cloud, vultr)]
        self._aggregator_sources = aggregator_sources

        self.customers = []
        for _ in range(customer_count):
            country = _weighted(rng, countries)["code"]
            account = Account(
                username=unique(lambda: pfake().user_name()),
                user_id=unique(lambda: f"cus-{rng.randrange(10**7, 10**8)}"),
                account_type="customer",
                privilege="business_customer" if rng.random() < 0.15 else "retail_customer",
                weight=rng.randint(1, 10),
            )
            self._place(account, country, rng)
            kind = _weighted(rng, device_types)["type"]
            if kind == "desktop":
                families = [rng.choice(DESKTOP_FAMILIES), rng.choice(MOBILE_APP_FAMILIES)]
            elif kind == "mobile":
                families = [rng.choice(MOBILE_APP_FAMILIES + MOBILE_BROWSER_FAMILIES),
                            rng.choice(DESKTOP_FAMILIES)]
            else:
                families = ["safari_ipad", rng.choice(MOBILE_APP_FAMILIES)]
            if rng.random() < 0.5:
                families = families[:1]
            account.devices = [self._device(f, rng) for f in families]
            account.mfa_method = _weighted(rng, mfa_methods)["method"]
            account.default_auth = "passkey" if account.mfa_method == "passkey" else "password"
            account.trusted = {d.device_id for d in account.devices}
            # Benign anonymiser use: a consumer VPN for some sign-ins
            if vpns and rng.random() < 0.05:
                account.vpn_network = rng.choice(vpns)
            # Benign non-residential egress: signing in from a work laptop
            # behind the employer's cloud web gateway
            proxies = auth_networks.networks(country=account.home_country, kinds={"proxy"})
            if proxies and rng.random() < 0.1:
                account.work_proxy = rng.choice(proxies)
            # Benign hosting egress for a human: a work Windows 365 Cloud PC
            if account.home_country == "AU" and rng.random() < 0.05:
                account.cloud_pc = rng.choice(auth_networks.networks(
                    country="AU", kinds={"hosting"}, asn=8075))
            # Benign scripted access from cloud: a linked budgeting app. A
            # screen-scraper can answer TOTP (it holds the seed), not a push
            if account.mfa_method in ("totp", "none") and rng.random() < 0.25:
                account.aggregator_device = self._device("python_requests", rng)
                account.aggregator_source = rng.choice(aggregator_sources)
                if rng.random() < 0.5:
                    # Linked during the run: no token from before the stream
                    account.primed.add(account.aggregator_device.device_id)
            self.customers.append(account)

        self.office = Source("124.168.10.25", "Sydney")
        # Staff working remotely through the bank's cloud desktop service: a
        # pool of addresses, not one, so it cannot be allow-listed by eye
        self.cloud_desktop = cloud
        self.staff = []
        for role, count in (("teller", 4), ("helpdesk_agent", 3), ("platform_admin", 1)):
            for _ in range(count):
                account = Account(
                    username=unique(staff_name),
                    user_id=unique(lambda: f"stf-{rng.randrange(10**6, 10**7)}"),
                    account_type="admin" if role == "platform_admin" else "staff",
                    privilege=role,
                    mfa_method="passkey" if role == "platform_admin" else "push",
                    default_auth="sso_saml",
                    weight=3,
                )
                self._place(account, auth_networks.HOME_COUNTRY, rng)
                account.devices = [self._device("chrome_windows", rng)]
                account.trusted = {account.devices[0].device_id}
                self.staff.append(account)

        self.service_accounts = [
            Account(username="svc-statement-batch", user_id="svc-0000001",
                    account_type="service", privilege="service",
                    home=Source(auth_networks.random_ip(cloud, rng), cloud.cities[0]),
                    devices=[self._device("python_requests", rng)],
                    default_auth="api_key", interval_minutes=15),
            Account(username="svc-openbanking-gw", user_id="svc-0000002",
                    account_type="service", privilege="service",
                    home=Source(auth_networks.random_ip(cloud, rng), cloud.cities[0]),
                    devices=[self._device("go_http", rng)],
                    default_auth="api_key", interval_minutes=5),
        ]

        self._interactive = self.customers + self.staff
        self._interactive_weights = [a.weight for a in self._interactive]
        self.usernames = {a.username for a in self._interactive + self.service_accounts}

    @staticmethod
    def _known_values(items, key, allowed, default, where):
        unknown = sorted({i[key] for i in items} - set(allowed))
        if unknown:
            logging.warning(f"Ignoring {where} entries {unknown}: expected one of {list(allowed)}")
        known = [i for i in items if i[key] in allowed and i["weight"] > 0]
        if not known:
            logging.warning(f"{where} has no usable entries, using defaults")
        return known or default

    def _place(self, account, country, rng):
        residential = (auth_networks.networks(country=country, kinds={"residential"})
                       or auth_networks.networks(country=auth_networks.HOME_COUNTRY,
                                                 kinds={"residential"}))
        home = rng.choice(residential)
        account.home_country = home.country
        account.home = Source(auth_networks.random_ip(home, rng), rng.choice(home.cities))
        mobile = auth_networks.networks(country=home.country, kinds={"mobile"})
        account.mobile_network = rng.choice(mobile) if mobile else None

    def _device(self, family, rng=None):
        rng = rng or self.rng
        user_agent, stack = CLIENT_FAMILIES[family]
        return Device(f"dev-{rng.getrandbits(48):012x}", user_agent, _synthetic_ja4(stack))

    def _device_for_ua(self, user_agent):
        ua = user_agent.lower()
        if "python" in ua or "sqlmap" in ua:
            stack = "python"
        elif "curl" in ua:
            stack = "curl"
        elif "go-http" in ua:
            stack = "go"
        elif "brokenbankmobile" in ua:
            stack = "okhttp" if "android" in ua else "apple"
        elif "firefox" in ua:
            stack = "firefox"
        elif "safari" in ua and "chrome" not in ua:
            stack = "apple"
        elif "chrome" in ua:
            stack = "chromium"
        else:
            stack = "openssl"
        return Device(f"dev-{self.rng.getrandbits(48):012x}", user_agent, _synthetic_ja4(stack))

    @staticmethod
    def _is_mobile(device):
        return _detect_device_type(device.user_agent) == "mobile"

    # ------------------------------------------------------------------
    # Picking accounts, devices and sources
    # ------------------------------------------------------------------

    @staticmethod
    def _on_trip(account, t):
        """True while the account is away or travelling (no side effects)."""
        return account.trip is not None and t < account.trip["back"]

    def _pick_customer(self, predicate=None, t=None):
        """A random customer matching predicate and not on a trip at t, or None."""
        pool = [a for a in self.customers
                if (predicate is None or predicate(a))
                and (t is None or (not self._on_trip(a, t) and t >= a.busy_until))]
        return self.rng.choice(pool) if pool else None

    def _travel_state(self, account, t):
        """home, abroad, or transit (in the air: no sign-ins)."""
        trip = account.trip
        if trip:
            if t < trip["arrive"]:
                return "transit"
            if t < trip["leave"]:
                return "abroad"
            if t < trip["back"]:
                return "transit"
            account.trip = None
            return "home"
        if account.account_type == "customer" and self.rng.random() < TRIP_START_PROBABILITY:
            countries = sorted({n.country for n in auth_networks.networks(kinds={"residential"})}
                               - {account.home_country})
            if countries:
                country = self.rng.choice(countries)
                lo, hi = TRANSIT_HOURS.get(frozenset((account.home_country, country)),
                                           DEFAULT_TRANSIT_HOURS)
                arrive = t + self.rng.uniform(lo, hi) * 3600
                leave = arrive + self.rng.uniform(2, 10) * 86400
                account.trip = {"country": country, "arrive": arrive, "leave": leave,
                                "back": leave + self.rng.uniform(lo, hi) * 3600}
                return "transit"
        return "home"

    def _pick_interactive(self, t):
        for _ in range(20):
            account = self.rng.choices(self._interactive, self._interactive_weights)[0]
            if t < account.busy_until:
                continue
            state = self._travel_state(account, t)
            if state != "transit":
                return account, state
        return None, None

    def _pick_device(self, account, t=None):
        if t is not None and account.pending_devices:
            due = [d for d, at in account.pending_devices if at <= t]
            account.pending_devices = [(d, at) for d, at in account.pending_devices if at > t]
            for device in due:
                self._adopt_device(account, device, make_primary=self._is_mobile(device), t=t)
        if account.account_type == "customer" and self.rng.random() < NEW_DEVICE_PROBABILITY:
            # A genuinely new phone or laptop. It replaces an old device once
            # the account has three, and sometimes becomes the main one
            device = self._device(self.rng.choice(BROWSER_FAMILIES + MOBILE_APP_FAMILIES))
            self._adopt_device(account, device, make_primary=self.rng.random() < 0.3, t=t)
            return device
        if len(account.devices) > 1 and self.rng.random() < 0.15:
            return self.rng.choice(account.devices[1:])
        return account.devices[0]

    def _adopt_device(self, account, device, make_primary=False, t=None):
        """Add a genuinely new device, retiring an old one once there are three."""
        if len(account.devices) >= 3:
            retired = account.devices.pop(self.rng.randrange(1, len(account.devices)))
            account.sessions.pop(retired.device_id, None)
            account.trusted.discard(retired.device_id)
            account.primed.discard(retired.device_id)
            account.born.pop(retired.device_id, None)
        if t is not None:
            account.born[device.device_id] = t
        # A device bought during the run cannot hold a session from before it
        account.primed.add(device.device_id)
        account.devices.append(device)
        if make_primary:
            account.devices.insert(0, account.devices.pop())

    def _source_in(self, network):
        return Source(auth_networks.random_ip(network, self.rng), self.rng.choice(network.cities))

    def _source_for_ip(self, ip):
        network = auth_networks.lookup(ip)
        return Source(ip, self.rng.choice(network.cities) if network else None)

    def _pick_source(self, account, device, state="home"):
        if account.account_type in ("staff", "admin"):
            roll = self.rng.random()
            if roll < 0.7:
                return self.office
            return self._source_in(self.cloud_desktop) if roll < 0.85 else account.home
        if state == "abroad":
            # Hotel wifi or roaming in the trip's country
            return self._source_in(self.rng.choice(auth_networks.networks(
                country=account.trip["country"], kinds={"residential", "mobile"})))
        if account.vpn_network and self.rng.random() < 0.3:
            return self._source_in(account.vpn_network)
        desktop = _detect_device_type(device.user_agent) == "desktop"
        if account.work_proxy and desktop and self.rng.random() < 0.3:
            return self._source_in(account.work_proxy)
        if account.cloud_pc and desktop and self.rng.random() < 0.3:
            return self._source_in(account.cloud_pc)
        roll = self.rng.random()
        if self._is_mobile(device) and account.mobile_network and roll < 0.6:
            return self._source_in(account.mobile_network)
        if roll > 0.97:
            # Cafe, work or a friend's: another ISP in the same country
            return self._source_in(self.rng.choice(
                auth_networks.networks(country=account.home_country, kinds={"residential"})))
        return account.home

    def _churn_source(self, session, source):
        """Where a session's next request comes from. Phones move between
        cell towers and home wifi, so a benign session can change address."""
        account = session.account
        if account is None or account.trip is not None:
            # Abroad, or about to leave: stay where the session already is
            return source
        if (account.mobile_network is not None
                and self._is_mobile(session.device) and self.rng.random() < 0.4):
            if self.rng.random() < 0.7:
                return self._source_in(account.mobile_network)
            return account.home
        return source

    def _attacker_source(self, kinds=("hosting", "vpn", "tor"), country=None, exclude_country=None):
        pool = [n for n in auth_networks.networks(country=country, kinds=set(kinds))
                if n.country != exclude_country]
        return self._source_in(self.rng.choice(pool or auth_networks.networks(kinds={"hosting"})))

    def _residential_proxy(self, account):
        """A residential address in the victim's own country, on another ISP."""
        home = auth_networks.lookup(account.home.ip)
        pool = [n for n in auth_networks.networks(country=account.home_country,
                                                   kinds={"residential", "mobile"})
                if home is None or n.asn != home.asn]
        return self._source_in(self.rng.choice(pool)) if pool else self._attacker_source()

    # ------------------------------------------------------------------
    # Event construction
    # ------------------------------------------------------------------

    @staticmethod
    def _who(account):
        if account is None:
            return {"user_id": None, "account_type": None, "privilege": None}
        return {"user_id": account.user_id, "account_type": account.account_type,
                "privilege": account.privilege}

    @staticmethod
    def _session_fields(session):
        if session is None:
            return {}
        return {"session_id": session.session_id, "session_issued_at": session.issued_at,
                "session_expires_at": session.expires_at, "auth_method": session.auth_method}

    def _emit(self, due, username, status, device, source, anomaly, **fields):
        event = build_auth_event(
            username, status,
            source_ip=source.ip, user_agent=device.user_agent, simulated=True,
            timestamp=_iso(due), device_id=device.device_id,
            tls_ja4=device.tls_ja4, geo_city=source.city, **fields,
        )
        heapq.heappush(self._pending, (due, next(self._seq), event, anomaly))

    def _login_path(self, auth_method, device):
        if auth_method == "sso_saml":
            return LOGIN_PATHS["sso_saml"]
        return LOGIN_PATHS.get(_detect_client_app(device.user_agent), LOGIN_PATHS["browser"])

    def _session_seconds(self, auth_method, device):
        if auth_method in SESSION_SECONDS:
            return SESSION_SECONDS[auth_method]
        return SESSION_SECONDS.get(_detect_client_app(device.user_agent), SESSION_SECONDS["browser"])

    def _normal_challenges(self, method):
        if self.rng.random() < 0.04:
            # Benign: the first prompt was missed, the second answered
            return [NO_FACTOR_RESULT[method], "approved"]
        return ["approved"]

    def _new_session(self, issued, lifetime, username, account, device, source, auth_method):
        return Session(
            session_id=f"sess-{self.rng.getrandbits(96):024x}",
            issued_at=_iso(issued), issued_ts=issued, expires_at=_iso(issued + lifetime),
            expires_ts=issued + lifetime, username=username, account=account,
            device=device, source=source, auth_method=auth_method,
        )

    def _login(self, t, account, device, source, *, anomaly, username=None,
               password_ok=True, failure_reason="bad_password", auth_method=None,
               challenges=None, challenge_gap=None, mfa_override=None, lifetime=None):
        """
        Schedule one sign-in starting at t: the second-factor challenges it
        needs, then the login result. Returns (end_time, Session or None).
        account may be None for a username that does not exist.
        """
        username = username or account.username
        auth_method = auth_method or (account.default_auth if account else "password")
        path = self._login_path(auth_method, device)
        who = self._who(account)

        if not password_ok or account is None:
            self._emit(t, username, "failure", device, source, anomaly,
                       event_action="login", failure_reason=failure_reason,
                       auth_method=auth_method, url_path=path, http_status=401, **who)
            return t, None

        if mfa_override is not None:
            mfa, challenges = dict(mfa_override), []
        elif auth_method in ("remember_me", "api_key"):
            mfa, challenges = {"mfa_used": False, "mfa_method": "none", "mfa_result": "not_required"}, []
        elif account.mfa_method == "passkey":
            mfa, challenges = {"mfa_used": True, "mfa_method": "passkey", "mfa_result": "approved"}, []
        elif account.mfa_method == "none":
            mfa, challenges = {"mfa_used": False, "mfa_method": "none", "mfa_result": "not_enrolled"}, []
        else:
            if challenges is None:
                challenges = self._normal_challenges(account.mfa_method)
            mfa = {"mfa_used": True, "mfa_method": account.mfa_method, "mfa_result": challenges[-1]}

        for result in challenges:
            t += challenge_gap if challenge_gap is not None else self.rng.uniform(5, 25)
            self._emit(t, username, "success" if result == "approved" else "failure",
                       device, source, anomaly,
                       event_action="mfa_challenge", auth_method=auth_method,
                       mfa_used=True, mfa_method=account.mfa_method, mfa_result=result,
                       url_path="/api/v2/auth/mfa/verify",
                       http_status=MFA_HTTP_STATUS[result], **who)

        t += self.rng.uniform(0.3, 1.5)
        if mfa["mfa_result"] not in ("approved", "not_required", "not_enrolled"):
            self._emit(t, username, "failure", device, source, anomaly,
                       event_action="login", failure_reason="mfa_failed",
                       auth_method=auth_method, url_path=path, http_status=401,
                       **mfa, **who)
            return t, None

        lifetime = lifetime or self._session_seconds(auth_method, device)
        session = self._new_session(t, lifetime, username, account, device, source, auth_method)
        self._emit(t, username, "success", device, source, anomaly,
                   event_action="login", url_path=path, http_status=200,
                   **self._session_fields(session), **mfa, **who)
        if not anomaly and (device in account.devices or device is account.aggregator_device):
            if mfa["mfa_used"]:
                account.trusted.add(device.device_id)
            if lifetime >= 86400:
                # Long-lived mobile and remembered sessions are kept and resumed
                account.sessions[device.device_id] = session
        return t, session

    def _refresh(self, t, session, anomaly=False, device=None, source=None):
        self._emit(t, session.username, "success", device or session.device,
                   source or session.source, anomaly,
                   event_action="session_refresh",
                   url_path="/api/v2/auth/refresh", http_status=200,
                   **self._session_fields(session), **self._who(session.account))

    def _logout(self, t, session, anomaly=False, source=None):
        if (session.account is not None
                and session.account.sessions.get(session.device.device_id) is session):
            del session.account.sessions[session.device.device_id]
        self._emit(t, session.username, "success", session.device, source or session.source,
                   anomaly, event_action="logout", url_path="/netbank/logout", http_status=200,
                   **self._session_fields(session), **self._who(session.account))

    def _account_change(self, t, actor, action, target, device, source, anomaly,
                        path, session=None, **fields):
        # Inside a session the actor keeps the username it signed in with
        username = session.username if session is not None and session.account is actor else actor.username
        self._emit(t, username, "success", device, source, anomaly,
                   event_action=action, target_user=target.username,
                   url_path=path, http_status=200,
                   **self._session_fields(session), **self._who(actor), **fields)

    def _follow_ups(self, t, session, anomaly=False, source=None, not_before=None):
        """
        Refreshes and maybe a logout after a sign-in, all before the session
        expires, and the logout after anything else already scheduled on it.
        """
        source = source or session.source
        mobile_app = _detect_client_app(session.device.user_agent) == "mobile_app"
        refreshes = self.rng.randint(1, 3) if mobile_app and self.rng.random() < 0.7 else (
            1 if self.rng.random() < 0.35 else 0)
        last = t
        for _ in range(refreshes):
            when = last + self.rng.uniform(300, 1500)
            if when >= session.expires_ts - 30:
                break
            if not anomaly:
                source = self._churn_source(session, source)
            self._refresh(when, session, anomaly=anomaly, source=source)
            last = when
        if self.rng.random() < 0.4:
            floor = max(last, not_before or last) + 1
            when = min(last + self.rng.uniform(120, 1800),
                       session.expires_ts - self.rng.uniform(5, 30))
            if floor < session.expires_ts:
                self._logout(max(when, floor), session, anomaly=anomaly, source=source)

    def _open_session(self, account, device, t, prime_probability):
        """
        A live long-lived session on this device, if there is one. The first
        time a device is seen this run it may already hold one, issued days
        before the stream began, so token use with no sign-in in the window
        is ordinary for apps and remembered browsers.
        """
        session = account.sessions.get(device.device_id)
        if session is not None:
            if session.issued_ts > t:
                # Its login is still being scheduled (MFA in progress)
                return None
            if session.expires_ts > t + 300:
                return session
            del account.sessions[device.device_id]
        first_sighting = device.device_id not in account.primed
        account.primed.add(device.device_id)
        # On first sighting a device may already hold a token from before the
        # stream; afterwards, now and then, one renewed silently in the
        # background that no logged sign-in issued. Never older than the device
        renew = (not first_sighting and prime_probability > 0
                 and self.rng.random() < 0.03 * prime_probability)
        born = account.born.get(device.device_id)
        if (first_sighting and self.rng.random() < prime_probability) or renew:
            oldest = t - 25 * 86400 if born is None else born + 3600
            newest = t - 86400
            if oldest < newest:
                issued = self.rng.uniform(oldest, newest)
                session = self._new_session(issued, SESSION_SECONDS["remember_me"],
                                            account.username, account, device, account.home,
                                            "remember_me")
                if session.expires_ts > t + 300:
                    account.sessions[device.device_id] = session
                    return session
        return None

    def _resume(self, t, session, source):
        """Reuse a live session: refreshes only, from wherever the device is now."""
        self._refresh(t, session, source=source)
        for _ in range(self.rng.randint(0, 2)):
            t += self.rng.uniform(120, 900)
            if t >= session.expires_ts - 60:
                break
            source = self._churn_source(session, source)
            self._refresh(t, session, source=source)

    # ------------------------------------------------------------------
    # Normal traffic
    # ------------------------------------------------------------------

    def _should_inject_anomaly(self, anomaly_type):
        """Check if it's time to inject a seeded suspicious IP or User-Agent."""
        now = time.time()
        last_time = self.last_anomaly_time.get(anomaly_type, 0)
        if anomaly_type == "ip":
            frequency_minutes = _number(self._anomaly_cfg.get("frequency_minutes"), 10,
                                        "anomaly_config.frequency_minutes",
                                        minimum=0, exclusive_min=True)
        else:
            frequency_minutes = 10
        if now - last_time >= frequency_minutes * 60:
            self.last_anomaly_time[anomaly_type] = now
            self._count_injection(anomaly_type)
            return True
        return False

    @staticmethod
    def _count_injection(kind):
        if metrics.auth_anomaly_injections is not None:
            metrics.auth_anomaly_injections.add(1, {"type": kind})

    def _get_suspicious_ip(self):
        """Get a suspicious IP from the seeded list."""
        return _weighted(self.rng, self.suspicious_ips)["ip"] if self.suspicious_ips else None

    def _get_suspicious_user_agent(self):
        """Get a suspicious user agent from the seeded list."""
        agents = self.suspicious_user_agents
        return _weighted(self.rng, agents)["agent"] if agents else None

    def _typo(self, username):
        for _ in range(100):
            chars = list(username)
            i = self.rng.randrange(len(chars))
            roll = self.rng.random()
            if roll < 0.4 and len(chars) > 3:
                del chars[i]
            elif roll < 0.7 and i < len(chars) - 1:
                chars[i], chars[i + 1] = chars[i + 1], chars[i]
            else:
                chars.insert(i, self.rng.choice("abcdefghijklmnopqrstuvwxyz0123456789"))
            typo = "".join(chars)
            if typo != username and typo not in self.usernames:
                return typo
        return username + "x"

    def _normal_flow(self, t):
        account, state = self._pick_interactive(t)
        if account is None:
            return

        if account.aggregator_device is not None and self.rng.random() < 0.12:
            self._aggregator_flow(t, account)
            return

        device = self._pick_device(account, t)
        source = self._pick_source(account, device, state)
        anomaly = False

        # The original seeded anomalies: a suspicious address or User-Agent
        # swapped into an otherwise normal sign-in
        if self._should_inject_anomaly("ip"):
            ip = self._get_suspicious_ip()
            if ip:
                source, anomaly = self._source_for_ip(ip), True
        if self._should_inject_anomaly("user_agent"):
            agent = self._get_suspicious_user_agent()
            if agent:
                device, anomaly = self._device_for_ua(agent), True

        if not anomaly:
            client = _detect_client_app(device.user_agent)
            # Phones hold app tokens and some browsers a remembered session,
            # often issued before the stream began
            if client == "mobile_app":
                prime = 0.5
            elif (client == "browser" and account.account_type == "customer"
                  and account.default_auth == "password" and device is account.devices[0]):
                prime = 0.2
            else:
                prime = 0.0
            session = self._open_session(account, device, t, prime)
            if session is not None and self.rng.random() < 0.7:
                self._resume(t, session, source)
                return

        if self.rng.random() >= self._success_rate():
            self._failed_flow(t, account, device, source, anomaly)
            return

        auth_method, username, mfa_override = None, None, None
        client = _detect_client_app(device.user_agent)
        if (account.account_type == "customer" and account.default_auth == "password"
                and device.device_id in account.trusted and client == "browser"
                and self.rng.random() < 0.15):
            auth_method = "remember_me"
        elif (account.account_type == "customer" and account.mfa_method in NO_FACTOR_RESULT
              and client == "browser" and self.rng.random() < 0.025):
            # Benign: a phone keyboard, caps lock or a password manager entry
            # capitalised the username. The MFA policy matches usernames
            # case-sensitively, so a genuine user skips the second factor
            # too: the flaw is real for everyone
            username = account.username.capitalize()
            if username != account.username:
                mfa_override = {"mfa_used": False, "mfa_method": "none",
                                "mfa_result": "not_required"}
            else:
                username = None
        t, session = self._login(t, account, device, source, anomaly=anomaly,
                                 auth_method=auth_method, username=username,
                                 mfa_override=mfa_override)
        if session is None:
            return

        roll = self.rng.random()
        changed_at = None
        if account.privilege == "helpdesk_agent" and roll < 0.25:
            # Benign: helpdesk resets a customer's forgotten password
            changed_at = t + self.rng.uniform(30, 600)
            self._account_change(changed_at, account, "password_reset",
                                 self._pick_customer(), device, source, anomaly,
                                 "/admin/helpdesk/password-reset", session)
        elif account.privilege == "platform_admin" and roll < 0.2:
            changed_at = t + self.rng.uniform(30, 600)
            self._account_change(changed_at, account, "role_change",
                                 self.rng.choice([s for s in self.staff if s is not account]),
                                 device, source, anomaly, "/admin/users/roles", session)
        elif account.account_type == "customer" and roll < 0.005:
            changed_at = t + self.rng.uniform(20, 120)
            self._account_change(changed_at, account, "password_reset",
                                 account, device, source, anomaly,
                                 "/api/v2/account/password/reset", session)
        elif account.account_type == "customer" and roll < 0.008 and account.mfa_method in NO_FACTOR_RESULT:
            # Benign: a new phone enrolled from home after a normal sign-in
            changed_at = t + self.rng.uniform(20, 120)
            self._account_change(changed_at, account, "mfa_device_register",
                                 account, device, source, anomaly,
                                 "/api/v2/account/mfa/devices", session,
                                 mfa_method=account.mfa_method)
        self._follow_ups(t, session, anomaly, source, not_before=changed_at)

    def _failed_flow(self, t, account, device, source, anomaly):
        kind = self.rng.choices(("bad_password", "unknown_user", "mfa_failed"), (80, 12, 8))[0]
        if account.mfa_method == "passkey" and kind != "unknown_user":
            # No password to get wrong: the passkey prompt was cancelled
            self._login(t, account, device, source, anomaly=anomaly,
                        mfa_override={"mfa_used": True, "mfa_method": "passkey",
                                      "mfa_result": "denied"})
            return
        if kind == "unknown_user":
            self._login(t, None, device, source, anomaly=anomaly,
                        username=self._typo(account.username), failure_reason="unknown_user")
            if self.rng.random() < 0.6:
                end, session = self._login(t + self.rng.uniform(8, 40), account, device, source,
                                           anomaly=anomaly)
                if session:
                    self._follow_ups(end, session, anomaly, source)
            return
        if kind == "mfa_failed" and account.mfa_method in NO_FACTOR_RESULT:
            # Benign: a prompt the user ignored or abandoned, or a misconfigured
            # device denying repeatedly, from the account's own address and
            # with no approval after it
            results = [self.rng.choice(("denied", NO_FACTOR_RESULT[account.mfa_method]))
                       for _ in range(self.rng.randint(1, 4))]
            self._login(t, account, device, source, anomaly=anomaly, challenges=results)
            return
        self._login(t, account, device, source, anomaly=anomaly, password_ok=False)
        if self.rng.random() < 0.7:
            # Benign failure-then-success: a mistyped password
            end, session = self._login(t + self.rng.uniform(10, 40), account, device, source,
                                       anomaly=anomaly)
            if session:
                self._follow_ups(end, session, anomaly, source)

    def _aggregator_flow(self, t, account):
        """
        A budgeting app syncing a customer's accounts: a scripting runtime on
        cloud addresses, a long-lived remembered token and no MFA. The benign
        twin of scripted_client_login, told apart by its fixed source and
        token rather than by its client.
        """
        device, source = account.aggregator_device, account.aggregator_source
        session = self._open_session(account, device, t, 1.0)
        if session is None or self.rng.random() < 0.15:
            # A full re-link: the stored password, and the TOTP code from the
            # stored seed. The same shape as scripted_client_login, from a
            # fixed egress shared by many customers and at a human-free but
            # gentle pace
            end, fresh = self._login(t, account, device, source, anomaly=False,
                                     auth_method="password",
                                     challenges=["approved"] if account.mfa_method == "totp" else None,
                                     lifetime=SESSION_SECONDS["remember_me"])
            if fresh is not None and self.rng.random() < 0.5:
                self._refresh(end + self.rng.uniform(20, 90), fresh, source=source)
            return
        if self.rng.random() < 0.1:
            # Refresh-token rotation: a new token from the old one, with no
            # sign-in behind it
            session = self._new_session(t, SESSION_SECONDS["remember_me"], account.username,
                                        account, device, source, "remember_me")
            account.sessions[device.device_id] = session
        self._refresh(t, session, source=source)
        if self.rng.random() < 0.5:
            self._refresh(t + self.rng.uniform(20, 90), session, source=source)

    def _service_flow(self, t, account):
        """Automation that legitimately signs in with a scripting runtime and no MFA."""
        _, session = self._login(t, account, account.devices[0], account.home, anomaly=False)
        if session:
            self._logout(t + self.rng.uniform(30, 120), session)

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def _fire_scenario(self, name, t):
        pattern = self.scenarios[name]["pattern"]
        result = getattr(self, f"_scenario_{name}")(t, pattern)
        if result is SKIPPED:
            logging.warning(f"Auth scenario skipped: {name} (no suitable account or network "
                            f"for the configured pattern)")
            return
        label = result or name
        self._count_injection(label)
        logging.info(f"Auth scenario injected: {label}")

    def _scenario_brute_force(self, t, p):
        # Passkey accounts have no password to guess
        victim = self._pick_customer(lambda a: a.mfa_method != "passkey", t)
        if victim is None:
            return SKIPPED
        source = self._source_for_ip(p["source_ip"])
        device = self._device_for_ua(p["user_agent"])
        attempts = max(1, int(p["failed_attempts"]))
        step = p["time_window_seconds"] / attempts
        for i in range(attempts):
            self._login(t + i * step, victim, device, source, anomaly=True, password_ok=False)
        if p.get("then_success"):
            # Without the second factor the password alone only gets them a
            # challenge that fails, unless the victim never enrolled one
            challenges = ([NO_FACTOR_RESULT[victim.mfa_method]]
                          if victim.mfa_method in NO_FACTOR_RESULT else None)
            end, session = self._login(t + attempts * step, victim, device, source,
                                       anomaly=True, auth_method="password", challenges=challenges)
            if session:
                self._refresh(end + self.rng.uniform(60, 120), session, anomaly=True)
        return None

    def _scenario_credential_stuffing(self, t, p):
        source = self._source_for_ip(p["source_ip"])
        count = max(1, int(p["unique_usernames"]))
        successes = int(p["successes"])
        # Passkey-only accounts have no password for a leaked pair to match
        passworded = [a for a in self.customers if a.mfa_method != "passkey"]
        real = self.rng.sample(passworded, min(len(passworded), max(1, round(count * 0.3))))
        no_mfa = [a for a in real if a.mfa_method == "none"]
        if len(no_mfa) < successes:
            extra = [a for a in passworded if a.mfa_method == "none" and a not in real]
            real += extra[:successes - len(no_mfa)]
            no_mfa = [a for a in real if a.mfa_method == "none"]
            if len(no_mfa) < successes:
                logging.warning(f"credential_stuffing: only {len(no_mfa)} customer(s) without MFA, "
                                f"so {successes - len(no_mfa)} configured success(es) cannot happen")
        winners = set(a.username for a in no_mfa[:successes])
        attempts = [(a, a.username) for a in real]
        while len(attempts) < count:
            guess = fake.user_name()
            if guess not in self.usernames:
                attempts.append((None, guess))
        self.rng.shuffle(attempts)
        step = p["time_window_seconds"] / len(attempts)
        for i, (account, username) in enumerate(attempts):
            # Stuffing tools rotate browser User-Agents, but every request
            # comes from the same scripting runtime underneath
            ua = CLIENT_FAMILIES[self.rng.choice(BROWSER_FAMILIES)][0]
            device = Device(f"dev-{self.rng.getrandbits(48):012x}", ua, _synthetic_ja4("python"))
            if account is None:
                self._login(t + i * step, None, device, source, anomaly=True,
                            username=username, failure_reason="unknown_user")
            else:
                self._login(t + i * step, account, device, source, anomaly=True,
                            password_ok=username in winners, auth_method="password")
        return None

    def _scenario_impossible_travel(self, t, p):
        abroad = auth_networks.networks(country=p["second_country"], kinds={"residential", "mobile"})
        victim = self._pick_customer(lambda a: a.home_country == p["first_country"]
                                     and a.mfa_method != "passkey", t)
        if victim is None or not abroad:
            return SKIPPED
        end, _ = self._login(t, victim, victim.devices[0], victim.home, anomaly=False)
        source = self._source_in(self.rng.choice(abroad))
        device = self._device(self.rng.choice(BROWSER_FAMILIES))
        self._login(end + p["time_gap_minutes"] * 60, victim, device, source, anomaly=True,
                    auth_method="password",
                    challenges=["approved"] if victim.mfa_method in NO_FACTOR_RESULT else None)
        return None

    def _scenario_account_takeover(self, t, p):
        victim = self._pick_customer(lambda a: a.mfa_method in ("none", "sms_otp"), t)
        if victim is None:
            return SKIPPED
        source = self._attacker_source(kinds=("hosting", "vpn"))
        device = self._device(self.rng.choice(DESKTOP_FAMILIES))
        for _ in range(int(p["failed_attempts_before"])):
            self._login(t, victim, device, source, anomaly=True, password_ok=False)
            t += self.rng.uniform(8, 20)
        if not p.get("successful_login"):
            return None
        # sms_otp victims: the code is answered after a SIM swap
        end, session = self._login(t, victim, device, source, anomaly=True, auth_method="password",
                                   challenges=["approved"] if victim.mfa_method == "sms_otp" else None)
        if session and p.get("password_change"):
            self._account_change(end + self.rng.uniform(30, 90), victim, "password_reset", victim,
                                 device, source, True, "/api/v2/account/password/reset", session)
        return None

    def _scenario_password_spray(self, t, p):
        source = self._source_for_ip(p["source_ip"])
        device = self._device(self.rng.choice(DESKTOP_FAMILIES))
        pool = [a for a in self._interactive if a.mfa_method != "passkey" or a.account_type != "customer"]
        targets = self.rng.sample(pool, min(max(1, int(p["usernames"])), len(pool)))
        step = p["time_window_seconds"] / len(targets)
        for i, account in enumerate(targets):
            # Staff are sprayed at the SSO identity provider, customers at the portal
            self._login(t + i * step + self.rng.uniform(0, step / 2), account, device, source,
                        anomaly=True, password_ok=False,
                        auth_method="sso_saml" if account.account_type != "customer" else "password")
        return None

    def _scenario_session_token_replay(self, t, p):
        victim = self._pick_customer(
            lambda a: _detect_client_app(a.devices[0].user_agent) == "browser"
            and a.default_auth == "password" and a.devices[0].device_id not in a.born, t)
        if victim is None:
            return SKIPPED
        device = victim.devices[0]
        if self.rng.random() < p["orphan_probability"]:
            # A remembered session issued days ago, outside anything the SIEM
            # holds: token use with no sign-in behind it
            issued = t - self.rng.uniform(3, 20) * 86400
            session = self._new_session(issued, SESSION_SECONDS["remember_me"], victim.username,
                                        victim, device, victim.home, "remember_me")
            label, start = "session_token_replay_orphan", t
        else:
            start, session = self._login(t, victim, device, victim.home, anomaly=False)
            if session is None:
                return None
            label = "session_token_replay"
        lo, hi = p["replay_delay_seconds"]
        when = start + self.rng.uniform(lo, hi)
        # Half the time the attacker sits on cloud in the victim's own
        # country, where the table has hosting there (AU, US); otherwise,
        # and for other countries, abroad
        local_cloud = auth_networks.networks(country=victim.home_country, kinds={"hosting"})
        source = (self._source_in(self.rng.choice(local_cloud))
                  if local_cloud and self.rng.random() < 0.5 else
                  self._attacker_source(exclude_country=victim.home_country))
        ua = self.rng.choice((CLIENT_FAMILIES["python_requests"][0],
                              CLIENT_FAMILIES[self.rng.choice(BROWSER_FAMILIES)][0]))
        # Same device_id: the stolen token carries the binding claim it was
        # issued with; the address, client and TLS stack are the attacker's
        replayer = Device(device.device_id, ua, _synthetic_ja4("python"))
        replayed = 0
        for _ in range(max(1, int(p["replays"]))):
            if when >= session.expires_ts:
                break
            self._refresh(when, session, anomaly=True, device=replayer, source=source)
            replayed += 1
            when += self.rng.uniform(20, 60)
        if not replayed:
            logging.warning("session_token_replay: the replay fell after the session expired; "
                            "only the victim's own login was sent")
        return label

    def _scenario_mfa_push_bombing(self, t, p):
        victim = self._pick_customer(lambda a: a.mfa_method == "push", t)
        if victim is None:
            return SKIPPED
        source = (self._residential_proxy(victim) if self.rng.random() < 0.6
                  else self._attacker_source(kinds=("vpn",)))
        device = self._device(self.rng.choice(DESKTOP_FAMILIES))
        pushes = max(1, int(p["denied_pushes"]))
        challenges = [self.rng.choice(("denied", "timeout")) for _ in range(pushes)] + ["approved"]
        self._login(t, victim, device, source, anomaly=True, auth_method="password",
                    challenges=challenges, challenge_gap=p["time_window_seconds"] / (pushes + 1))
        return None

    def _scenario_mfa_enrolment_after_failure(self, t, p):
        victim = self._pick_customer(lambda a: a.mfa_method in NO_FACTOR_RESULT, t)
        if victim is None:
            return SKIPPED
        source = self._residential_proxy(victim)
        device = self._device(self.rng.choice(DESKTOP_FAMILIES))
        self._login(t, victim, device, source, anomaly=True, password_ok=False)
        challenges = [NO_FACTOR_RESULT[victim.mfa_method], "approved"]
        end, session = self._login(t + self.rng.uniform(20, 40), victim, device, source,
                                   anomaly=True, auth_method="password", challenges=challenges)
        if session:
            self._account_change(end + self.rng.uniform(30, 90), victim, "mfa_device_register",
                                 victim, device, source, True, "/api/v2/account/mfa/devices",
                                 session, mfa_method="totp")
        return None

    def _scenario_helpdesk_mfa_reset(self, t, p):
        agents = [s for s in self.staff if s.privilege == "helpdesk_agent"]
        victim = self._pick_customer(lambda a: a.mfa_method in NO_FACTOR_RESULT, t)
        if victim is None or not agents:
            return SKIPPED
        agent = self.rng.choice(agents)
        malicious = self.rng.random() < p["malicious_probability"]
        # With its factor deleted the account cannot pass MFA until it
        # re-enrols, so it is kept out of normal sign-ins until then
        victim.busy_until = t + 1200
        self._account_change(t, agent, "mfa_device_delete", victim, agent.devices[0],
                             self.office, malicious, "/admin/helpdesk/mfa-reset",
                             mfa_method=victim.mfa_method)
        t += self.rng.uniform(30, 90)
        self._account_change(t, agent, "password_reset", victim, agent.devices[0],
                             self.office, malicious, "/admin/helpdesk/password-reset")
        t += self.rng.uniform(180, 600)
        # Either variant may re-enrol from a phone or a computer: what tells
        # them apart is where the account signs in from, not on what
        device = self._device(self.rng.choice(BROWSER_FAMILIES + MOBILE_APP_FAMILIES))
        if malicious:
            source = (self._residential_proxy(victim) if self.rng.random() < 0.5
                      else self._attacker_source(kinds=("vpn", "hosting")))
        elif self._is_mobile(device) and victim.mobile_network and self.rng.random() < 0.5:
            source = self._source_in(victim.mobile_network)
        else:
            # Genuine device replacement: the same sequence, from home
            source = victim.home
        end, session = self._login(t, victim, device, source, anomaly=malicious,
                                   auth_method="password",
                                   mfa_override={"mfa_used": False, "mfa_method": "none",
                                                 "mfa_result": "not_enrolled"})
        if session:
            method = self.rng.choice(("push", "totp")) if malicious else victim.mfa_method
            registered = end + self.rng.uniform(30, 120)
            self._account_change(registered, victim, "mfa_device_register",
                                 victim, device, source, malicious, "/api/v2/account/mfa/devices",
                                 session, mfa_method=method)
            victim.busy_until = registered + 1
            if not malicious:
                # The replacement becomes one of the customer's own devices
                # from the moment it is enrolled
                victim.trusted.add(device.device_id)
                victim.pending_devices.append((device, registered))
        else:
            victim.busy_until = end + 1
        return "helpdesk_mfa_reset" if malicious else "helpdesk_mfa_reset_benign"

    def _scenario_username_case_variance(self, t, p):
        victim = self._pick_customer(lambda a: a.mfa_method in NO_FACTOR_RESULT
                                     and a.username.lower() != a.username.upper(), t)
        if victim is None:
            return SKIPPED
        source = (self._residential_proxy(victim) if self.rng.random() < 0.5
                  else self._attacker_source(kinds=("vpn",)))
        device = self._device(self.rng.choice(BROWSER_FAMILIES))
        end, _ = self._login(t, victim, device, source, anomaly=True, auth_method="password",
                             challenges=[NO_FACTOR_RESULT[victim.mfa_method]])
        variant = victim.username.capitalize()
        if variant == victim.username:
            variant = victim.username.upper()
        if variant == victim.username:
            variant = victim.username.swapcase()
        # The MFA policy matched the username case-sensitively; the directory
        # resolved the variant to the same account
        self._login(end + self.rng.uniform(20, 60), victim, device, source, anomaly=True,
                    username=variant, auth_method="password",
                    mfa_override={"mfa_used": False, "mfa_method": "none",
                                  "mfa_result": "not_required"})
        return None

    def _scenario_scripted_client_login(self, t, p):
        # A TOTP victim: a stolen seed lets a script answer the code
        victim = self._pick_customer(lambda a: a.mfa_method in ("totp", "none"), t)
        if victim is None:
            return SKIPPED
        # Half the time on the same cloud providers the budgeting app uses
        if self.rng.random() < 0.5:
            source = self._source_in(self.rng.choice(
                [auth_networks.lookup(s.ip) for s in self._aggregator_sources]))
        else:
            source = self._attacker_source(kinds=("hosting",))
        device = self._device_for_ua(p["user_agent"])
        end, session = self._login(t, victim, device, source, anomaly=True, auth_method="password",
                                   challenges=["approved"] if victim.mfa_method == "totp" else None)
        if session:
            refreshes = max(1, int(p["refreshes"]))
            step = p["refresh_window_seconds"] / refreshes
            for i in range(refreshes):
                if end + (i + 1) * step >= session.expires_ts:
                    break
                self._refresh(end + (i + 1) * step, session, anomaly=True)
        return None

    def _scenario_dormant_account_login(self, t, p):
        entry = self.rng.choice(p["accounts"])
        # The leaver kept the phone their push factor is on, so MFA passes
        account = Account(username=entry["username"], user_id=str(entry["user_id"]),
                          account_type="staff", privilege=str(entry.get("privilege", "teller")),
                          mfa_method="push", default_auth="sso_saml")
        # Half the time from home, like any member of staff working remotely
        if self.rng.random() < 0.5:
            source = self._source_in(self.rng.choice(auth_networks.networks(
                country=auth_networks.HOME_COUNTRY, kinds={"residential", "mobile"})))
        else:
            source = self._attacker_source(kinds=("vpn", "hosting"))
        device = self._device(self.rng.choice(DESKTOP_FAMILIES))
        end, session = self._login(t, account, device, source, anomaly=True,
                                   challenges=["approved"] if account.mfa_method == "push" else None)
        if session:
            self._refresh(end + self.rng.uniform(300, 900), session, anomaly=True)
        return None

    def _scenario_break_glass_login(self, t, p):
        account = Account(username=p["username"], user_id="adm-0000099",
                          account_type="break_glass", privilege="global_admin",
                          mfa_method="passkey")
        source = self._attacker_source(exclude_country=auth_networks.HOME_COUNTRY)
        device = self._device(self.rng.choice(DESKTOP_FAMILIES))
        attempts = max(1, int(p["attempts"]))
        for i in range(attempts):
            self._login(t + i * p["time_window_seconds"] / attempts, account, device, source,
                        anomaly=True, password_ok=False, auth_method="password")
        return None

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _ship_due(self, shipper, now):
        while self._pending and self._pending[0][0] <= now:
            _, _, event, anomaly = heapq.heappop(self._pending)
            shipper.ship_log_async("netbank_auth", event)
            if metrics.auth_events is not None:
                metrics.auth_events.add(1, {
                    "status": event["status"],
                    "anomaly": "true" if anomaly else "false",
                    "action": event["event_action"],
                })
            logging.debug(f"Generated auth event: {event['username']} - "
                          f"{event['event_action']} {event['status']}")

    def _run_generator(self):
        """Main generator loop."""
        try:
            self._loop()
        except Exception as e:
            logging.error(f"Auth traffic generator stopped on an error: {e}")
        finally:
            self.running = False
        logging.info("Auth traffic generator stopped")

    def _loop(self):
        shipper = get_log_shipper()

        rate_per_minute = _number(self._generator_settings().get("rate_per_minute"), 4,
                                  "endpoints.netbank_auth.generator.rate_per_minute",
                                  minimum=0, exclusive_min=True)
        interval = 60.0 / rate_per_minute
        start = time.time()
        max_delay = _number(self._anomaly_cfg.get("scenario_initial_delay_max_minutes"), 15,
                            "anomaly_config.scenario_initial_delay_max_minutes", minimum=1)
        next_flow = start
        next_scenario = {
            name: start + 60 * self.rng.uniform(1, max(1, min(cfg["frequency_minutes"], max_delay)))
            for name, cfg in self.scenarios.items() if cfg["enabled"]
        }
        next_service = {a.username: start + self.rng.uniform(5, 60) for a in self.service_accounts}

        logging.info(f"Auth traffic generator started: {rate_per_minute:g} sign-ins/minute, "
                     f"{len(next_scenario)} scenario(s) enabled")

        while self.running:
            now = time.time()
            # Advance from the schedule, not the tick, so high rates are met;
            # after a stall (a sleeping laptop) skip ahead rather than burst
            if now - next_flow > 10 * interval:
                next_flow = now
            flows = 0
            while now >= next_flow and flows < 50:
                next_flow += interval * self.rng.uniform(0.8, 1.2)
                flows += 1
                self._guarded(self._normal_flow, now)
            for name, due in next_scenario.items():
                if now >= due:
                    frequency = self.scenarios[name]["frequency_minutes"]
                    next_scenario[name] = now + 60 * frequency * self.rng.uniform(0.9, 1.1)
                    self._guarded(self._fire_scenario, name, now)
            for account in self.service_accounts:
                if now >= next_service[account.username]:
                    next_service[account.username] = now + 60 * account.interval_minutes
                    self._guarded(self._service_flow, now, account)
            self._guarded(self._ship_due, shipper, now)
            wake = min([next_flow] + list(next_scenario.values()) + list(next_service.values())
                       + ([self._pending[0][0]] if self._pending else []))
            time.sleep(min(0.25, max(0.01, wake - time.time())))

    @staticmethod
    def _guarded(fn, *args):
        try:
            fn(*args)
        except Exception as e:
            logging.error(f"Error generating auth traffic in {fn.__name__}: {e}")

    def start(self):
        """Start the background traffic generator."""
        if self.running:
            logging.warning("Auth traffic generator already running")
            return

        if not self._generator_settings().get("enabled", False):
            logging.info("Auth traffic generator disabled in config")
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_generator, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the background traffic generator."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None


# Global generator instance
_generator = None


def get_auth_generator():
    """Get or create the global auth traffic generator."""
    global _generator
    if _generator is None:
        _generator = AuthTrafficGenerator()
    return _generator


def start_auth_generator():
    """
    Start the background auth traffic generator. Called at app import, so a
    generator problem is logged and the bank keeps serving without it.
    """
    try:
        get_auth_generator().start()
    except Exception as e:
        logging.error(f"Auth traffic generator not started: {e}")


def stop_auth_generator():
    """Stop the background auth traffic generator."""
    if _generator is not None:
        _generator.stop()
