from .tools import (
    ping_sweep,
    nmap_services_detection,
    host_probe,
    rustscan_range_ports,
)


def register(mcp):
    mcp.tool(name="recon.ping_sweep")(ping_sweep)
    mcp.tool(name="recon.nmap_services_detection")(nmap_services_detection)
    mcp.tool(name="recon.host_probe")(host_probe)
    mcp.tool(name="recon.rustscan_range_ports")(rustscan_range_ports)

