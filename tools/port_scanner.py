"""Nmap port scanner wrapper."""

import json
import subprocess
import shutil
import re

from rich.console import Console


class PortScanner:
    def __init__(self, config: dict, console: Console):
        self.config = config
        self.console = console
        self.tool_config = config.get("tools", {}).get("nmap", {})

    def _check_tool(self) -> bool:
        return shutil.which("nmap") is not None

    def scan(self, target: str, recon_data: dict = None) -> dict:
        self.console.print(f"  [dim]Running nmap scan on {target}...[/]")

        data = {"target": target, "hosts": []}

        if not self._check_tool():
            self.console.print("  [yellow]nmap not installed — skipping[/]")
            return data

        scan_type = self.tool_config.get("scan_type", "-sV -sC")
        timeout = self.tool_config.get("timeout", 600)

        cmd = ["nmap"] + scan_type.split() + ["-oX", "-", target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            xml_output = result.stdout
        except subprocess.TimeoutExpired:
            self.console.print("  [yellow]nmap timed out[/]")
            return data
        except FileNotFoundError:
            self.console.print("  [yellow]nmap not found[/]")
            return data

        data["hosts"] = self._parse_nmap_xml(xml_output)
        return data

    def _parse_nmap_xml(self, xml: str) -> list[dict]:
        hosts = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            for host_elem in root.findall(".//host"):
                if host_elem.get("status", {}).get("state") != "up" if hasattr(host_elem.get("status"), "get") else True:
                    pass

                addr = host_elem.get("address", {}).get("addr", "") if hasattr(host_elem.get("address"), "get") else ""
                hostname = ""
                hostnames = host_elem.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name", "")

                ports = []
                for port_elem in host_elem.findall(".//port"):
                    port_id = port_elem.get("portid", "")
                    protocol = port_elem.get("protocol", "")
                    state = port_elem.find("state")
                    state_str = state.get("state", "") if state is not None else ""
                    service = port_elem.find("service")
                    service_name = service.get("name", "") if service is not None else ""
                    service_version = service.get("version", "") if service is not None else ""

                    ports.append({
                        "port": int(port_id) if port_id.isdigit() else 0,
                        "protocol": protocol,
                        "state": state_str,
                        "service": service_name,
                        "version": service_version,
                    })

                os_elem = host_elem.find("os")
                os_name = ""
                if os_elem is not None:
                    os_match = os_elem.find("osmatch")
                    if os_match is not None:
                        os_name = os_match.get("name", "")

                if ports:
                    hosts.append({
                        "ip": addr,
                        "hostname": hostname,
                        "ports": ports,
                        "os": os_name,
                    })
        except ET.ParseError as e:
            hosts = [{"error": f"Failed to parse nmap XML: {e}"}]

        return hosts
