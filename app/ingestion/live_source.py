"""Live capture availability and interface listing.

Opening a capture interface is attempted only by the live monitor.
If Npcap or permission is missing, callers receive an explanation
instead of an empty successful capture.
"""

import os


def unavailable_reason() -> str | None:
    try:
        from scapy.config import conf
    except Exception:
        return (
            "Scapy could not be loaded, so live capture is unavailable. "
            "PCAP file analysis can still be used."
        )
    if os.name == "nt" and not bool(getattr(conf, "use_pcap", False)):
        return (
            "Live capture needs Npcap installed and permission to open a capture interface. "
            "PCAP file analysis does not require Npcap."
        )
    return None


def list_interfaces() -> list[dict[str, str]]:
    if unavailable_reason() is not None:
        return []
    try:
        from scapy.config import conf

        interfaces = getattr(conf, "ifaces", None)
        if not interfaces:
            return []
        items = []
        for key, iface in interfaces.items():
            description = (
                getattr(iface, "description", None)
                or getattr(iface, "name", None)
                or str(key)
            )
            items.append({"name": str(key), "description": str(description)})
        return items
    except Exception:
        return []
