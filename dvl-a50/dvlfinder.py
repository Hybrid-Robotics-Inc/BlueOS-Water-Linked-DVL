import json
import time
from typing import List, Optional

import nmap3
import urllib.request
from loguru import logger

from blueoshelper import request


def check_for_proper_dvl(ip: str) -> bool:
    # Check the API for the product_name field
    url = f"http://{ip}/api/v1/about"
    try:
        return "DVL" in json.loads(request(url))["product_name"]
    except Exception as e:
        logger.debug(f"{ip} is not a dvl: {e}")
        return False


def get_ips_wildcards(ips: List[str]):
    # Takes a list of ip strings and replaces the last field with * for it to be used by nmap
    return [".".join([*(ip.split(".")[0:-1]), "*"]) for ip in ips]


def find_the_dvl() -> Optional[str]:
    # Try default IP first before network scan
    default_ip = "192.168.2.95"
    logger.info(f"Trying default DVL IP at {default_ip}...")
    try:
        with urllib.request.urlopen(f"http://{default_ip}/api/v1/about", timeout=2) as response:
            if response.status == 200:
                logger.info(f"DVL found at default IP: {default_ip}")
                return default_ip
    except Exception as e:
        logger.debug(f"Default DVL IP not responding: {e}")

    # The dvl always reports 192.168.194.95 on mdns, so we need to take drastic measures.
    # Nmap to the rescue!
    nmap = nmap3.Nmap()

    # Generate the scan mask from our current IPs
    networks = json.loads(request("http://host.docker.internal/cable-guy/v1.0/ethernet"))
    current_networks = [network["addresses"] for network in networks]
    current_ips = []
    for network in current_networks:
        for entry in network:
            current_ips.append(entry["ip"])

    scans = get_ips_wildcards(current_ips)
    logger.info(f"Scanning: {scans} for DVLs")
    candidates = []
    for ip in scans:
        results = []
        while not results:
            try:
                results = nmap.scan_top_ports(ip, args="-p 80 --open")
            except nmap3.exceptions.NmapExecutionError as e:
                logger.debug(f"Error running nmap: {e}, trying again in 1 second")
                time.sleep(1)
        for result in results:
            if result in current_ips:
                continue
            if result in ("runtime", "stats"):
                continue
            candidates.append(result)

    logger.info(f"Candidates for being a DVL: {candidates}")

    for candidate in candidates:
        if check_for_proper_dvl(candidate):
            logger.info(f"DVL found at {candidate}")
            return candidate

    return None
