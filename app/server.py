import os
import logging

from app.recon import register as register_recon
from app.enum import register as register_enum

log = logging.getLogger("mcp.server")
log.setLevel(logging.INFO)

try:
    from fastmcp import FastMCP
except Exception as e:
    raise RuntimeError("MCP SDK not found. Install the MCP SDK (pip install 'mcp[cli]') or use server_stdio.py") from e


from fastmcp import FastMCP

mcp = FastMCP("mcp-appsec")

# Register grouped tools
register_recon(mcp)
register_enum(mcp)

# TODO: Register tools from other modules



if __name__ == "__main__":
    mode = os.getenv("MCP_MODE", "sse")
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    print(host, port)
    if mode == "http":
        mcp.run(transport="http", host=host, port=port, path="/mcp")
    elif mode == "sse":
        mcp.run(transport="sse", host=host, port=port, path="/sse")
    else:
        mcp.run(transport="stdio")


