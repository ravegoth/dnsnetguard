DOMAIN_PATTERNS = {
    "WHITELIST": [
        # Essential OS/CDN/Services to prevent breaking basic functionality.
        # These domains are generally considered safe and necessary for system operation.
        r".*\.windowsupdate\.com$", r".*\.apple\.com$", r".*\.google\.com$",
        r".*\.cdn\.mozilla\.net$", r".*\.cloudfront\.net$", r".*\.akadns\.net$",
        r".*\.akamaiedge\.net$", r".*\.g-core\.com$", r".*\.fastly\.net$",
        r"github\.com$", r"pypi\.org$", r".*\.microsoft\.com$",
    ],
    "MALWARE_C2": [
        # Patterns often associated with Malware Command & Control (C2) servers.
        # These are frequently dynamic DNS services or specific keywords found in C2 communication.
        r".*\.ddns\.net$", r".*\.no-ip\.com$", r".*\.duckdns\.org$",
        r".*onion\..*$",  # Domains associated with Tor hidden services.
        r".*\.bazar$",  # Common top-level domain (TLD) for BazarLoader.
        r".*\.emotet$", # Common TLD for Emotet malware.
        r"cobaltstrike\..*",  # Cobalt Strike framework indicators.
        r"metasploit\..*",    # Metasploit framework indicators.
    ],
    "TELEMETRY/SPYWARE": [
        # Domains commonly used for collecting user data, system telemetry, or aggressive tracking.
        # This category includes domains from operating systems, applications, and advertising platforms.

        # Generic Telemetry & Analytics Services
        r".*\.analytics\..*", r".*\.telemetry\..*", r".*metrics\..*",
        r".*crash-reports\..*", r".*tracking\..*", r".*insights\..*",
        r"app-measurement\.com$",  # Google Analytics for Firebase.

        # Microsoft Telemetry
        r".*\.vortex\.microsoft\.com.*", r"telemetry\.microsoft\.com",
        r"watson\.telemetry\.microsoft\.com", r"settings-win\.data\.microsoft\.com",
        r"v10\.events\.data\.microsoft\.com", r".*copilot\.microsoft\.com",
        r"officeclient\.microsoft\.com",

        # Google Telemetry & Ads (some overlap with ADWARE)
        r".*\.googleapis\.com", r"clients1\.google\.com",
        r"adservice\.google\..*", r"pagead2\.googlesyndication\.com",

        # Adobe Telemetry
        r".*\.adobe-identity\.com", r".*\.adobesc\.com", r".*\.omtrdc\.net",
        
        # NVIDIA Telemetry
        r"gfe\.nvidia\.com", r"telemetry\.gfe\.nvidia\.com",

        # Other Software Telemetry
        r".*\.facebook\.net", r".*\.fbcdn\.net", r"graph\.facebook\.com",
        r".*\.autodesk\.com", r"stats\.unity3d\.com", r".*\.discordapp\.com",
        r".*\.sentry\.io", # Error tracking and performance monitoring.
    ],
    "ADWARE/TRACKER": [
        # Domains primarily associated with serving advertisements, tracking user behavior for ad targeting,
        # or collecting marketing data.
        r".*\.doubleclick\.net", r".*\.googlesyndication\.com",
        r".*\.googleadservices\.com", r".*\.adnxs\.com",
        r".*\.adsrvr\.org", r".*\.openx\.net", r".*pubmatic\.com",
        r".*rubiconproject\.com", r"bidswitch\.net", r"criteo\..*",
        r"scorecardresearch\.com", r"taboola\.com", r"outbrain\.com",
        r"quantserve\.com", r"adform\.net", r"applovin\.com",
        r"braze\.com", r"onesignal\.com", r"segment\.io",
        r"tidaltv\.com", r"yieldlab\.net", r"zemanta\.com",
    ]
}
