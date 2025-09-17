import ipaddress
import asyncio
import time
from typing import List, Optional, Tuple
from app.tools import run_cmd_capture


def expand_to_ips(spec: str) -> List[str]:
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    ips = []
    for p in parts:
        if "/" in p:
            net = ipaddress.ip_network(p, strict=False)
            for ip in net.hosts():
                ips.append(str(ip))
        else:
            if "-" in p and p.count(".") == 3:
                left, right = p.split("-", 1)
                try:
                    base = left.rsplit(".", 1)[0]
                    start = int(left.rsplit(".", 1)[1])
                    end = int(right)
                    for i in range(start, end + 1):
                        ips.append(f"{base}.{i}")
                except Exception:
                    try:
                        ipaddress.ip_address(p)
                        ips.append(p)
                    except Exception:
                        continue
            else:
                try:
                    ipaddress.ip_address(p)
                    ips.append(p)
                except Exception:
                    continue
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


async def _probe_tcp(ip: str, port: int, timeout_s: int) -> Tuple[bool, Optional[float]]:
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout_s)
        rtt = (time.perf_counter() - start) * 1000.0
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return True, round(rtt, 2)
    except Exception:
        return False, None


async def _probe_icmp(ip: str, timeout_s: int) -> Tuple[bool, Optional[float]]:
    cmd = ["ping", "-c", "1", "-W", str(int(timeout_s)), ip]
    rc, out, err = await run_cmd_capture(cmd, timeout=timeout_s + 2)
    if rc != 0:
        txt = out or err or ""
        import re
        m = re.search(r"time=([0-9.]+)\s*ms", txt)
        if m:
            return True, float(m.group(1))
        return False, None
    import re
    m = re.search(r"time=([0-9.]+)\s*ms", out)
    if m:
        return True, float(m.group(1))
    return True, None


