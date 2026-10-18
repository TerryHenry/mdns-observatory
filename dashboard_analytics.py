"""Small, dependency-free helpers for dashboard vendor attribution."""

def mac_manufacturer(mac):
    """Best-effort vendor label from commonly seen MAC OUIs; not a full OUI database."""
    value = str(mac or "").strip().lower().replace("-", ":")
    parts = value.split(":")
    if len(parts) < 3 or any(len(x) != 2 for x in parts[:3]):
        return "Unknown / unavailable"
    oui = ":".join(parts[:3])
    # OUI matches are intentionally conservative and only identify known prefixes.
    ranges = {
        "Apple": {"00:03:93","00:0a:95","00:0d:93","00:11:24","00:14:51","00:16:cb","00:17:f2","00:19:e3","00:1b:63","00:1e:c2","00:1f:f3","00:21:e9","00:23:12","00:25:00","00:26:08","04:0c:ce","0c:4d:e9","10:40:f3","14:10:9f","18:af:61","1c:36:bb","20:ab:37","24:a0:74","28:6a:ba","2c:be:08","30:90:ab","34:12:98","38:c9:86","3c:07:54","40:a6:d9","44:2a:60","48:60:bc","4c:32:75","50:ed:3c","54:26:96","58:55:ca","5c:59:48","60:03:08","60:fb:42","64:20:0c","68:5b:35","6c:40:08","70:de:e2","74:e2:f5","78:7b:8a","7c:d1:c3","80:ea:96","84:38:35","88:66:5a","8c:85:90","90:72:40","98:01:a7","98:fe:94","9c:20:7b","a4:83:e7","a8:5c:2c","ac:bc:32","b0:34:95","b8:17:c2","bc:52:b7","c0:84:7d","c8:2a:14","cc:08:8d","d0:03:4b","d4:9a:20","d8:30:62","dc:2b:2a","e0:b5:2d","e4:ce:8f","e8:80:2e","ec:35:86","f0:18:98","f0:db:e2","f4:5c:89","f8:ff:c2"},
        "Samsung": {"00:12:fb","00:15:99","00:16:32","00:1d:25","00:21:19","00:23:39","00:26:37","08:08:c2","14:49:e0","5c:0a:5b","78:bd:bc","8c:77:12"},
        "Google": {"00:1a:11","3c:5a:b4","54:60:09","f4:f5:d8"},
        "Amazon": {"00:fc:8b","0c:47:c9","18:74:2e","40:b4:cd","a0:02:dc"},
        "Cisco": {"00:00:0c","00:01:42","00:1b:0c","00:1e:49","00:25:45"},
        "RUCKUS / CommScope": {"00:13:60","00:1d:aa","58:fb:84","74:91:1a","8c:0c:90"},
        "Intel": {"00:02:b3","00:13:02","00:15:00","00:1b:21","3c:97:0e","a4:34:d9"},
        "HP": {"00:01:e6","00:11:0a","00:1f:29","3c:d9:2b"},
        "Microsoft": {"00:15:5d","28:18:78","7c:1e:52"},
    }
    for manufacturer, prefixes in ranges.items():
        if oui in prefixes:
            return manufacturer
    # Locally administered addresses are commonly randomized and cannot reliably
    # identify the hardware vendor from the OUI.
    try:
        if int(parts[0], 16) & 2:
            return "Private / randomized MAC"
    except ValueError:
        pass
    return "Other / unknown vendor"


def packet_manufacturer(mac, source_ip="", ip_to_host=None, records=(), questions=()):
    """Best-effort packet vendor attribution with explicit hostname evidence.

    MAC OUI is the strongest signal. For locally randomized MACs, recognize
    explicit Apple product names in hostnames; do not infer Apple merely from
    generic Bonjour service names such as AirPlay or _companion-link.
    """
    vendor = mac_manufacturer(mac)
    if vendor == "Apple":
        return "Apple"
    names = []
    if ip_to_host:
        host = ip_to_host.get(str(source_ip))
        if host:
            names.append(str(host))
    for item in questions or ():
        if isinstance(item, dict):
            names.append(str(item.get("name", "")))
        else:
            names.append(str(item))
    for item in records or ():
        if isinstance(item, dict):
            names.extend((str(item.get("name", "")), str(item.get("value", ""))))
    text = " ".join(names).casefold()
    # Deliberately use explicit device-name terms, not service type alone.
    apple_name = __import__("re").search(
        r"(?i)(?:^|[\s._-])(iphone|ipad|ipod|macbook|imac|mac-mini|mac-studio|mac-pro|apple-tv|appletv|homepod|airpods|vision-pro)(?:[\s._-]|$)",
        text,
    )
    if apple_name:
        return "Apple (hostname inferred)"
    return vendor
