"""The detector list used by PCAP analysis and live capture."""

from app.detection.detectors.arp_mapping import ArpMappingDetector
from app.detection.detectors.beaconing import BeaconingDetector
from app.detection.detectors.cleartext_protocol import FtpDetector, TelnetDetector
from app.detection.detectors.dns_anomaly import DnsAnomalyDetector
from app.detection.detectors.icmp_anomaly import IcmpAnomalyDetector
from app.detection.detectors.port_scan import HorizontalPortScanDetector
from app.detection.detectors.syn_burst import SynBurstDetector
from app.detection.detectors.vertical_port_scan import VerticalPortScanDetector
from app.detection.detectors.volume_outlier import LargeOutboundDetector


def default_detectors() -> list:
    return [
        HorizontalPortScanDetector(),
        VerticalPortScanDetector(),
        SynBurstDetector(),
        BeaconingDetector(),
        DnsAnomalyDetector(),
        IcmpAnomalyDetector(),
        TelnetDetector(),
        FtpDetector(),
        LargeOutboundDetector(),
        ArpMappingDetector(),
    ]
