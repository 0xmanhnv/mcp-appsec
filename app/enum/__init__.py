from .tools import (
    ffuf_fuzz,
    whatweb_scan,
    gobuster_dir,
)


def register(mcp):
    mcp.tool(name="enum.ffuf_fuzz")(ffuf_fuzz)
    mcp.tool(name="enum.whatweb_scan")(whatweb_scan)
    mcp.tool(name="enum.gobuster_dir")(gobuster_dir)


