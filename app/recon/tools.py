import os
import re
import asyncio
from typing import Dict, Any, List

from app.tools import (
    build_nmap_cmd,
    run_cmd_capture,
    parse_nmap_json,
    make_job_tmpdir,
    cleanup_tmpdir,
    run_in_docker,
)
from app.models import (
    NmapParams,
    HostProbeParams,
    PingSweepParams,
)
from app.helpers import (
    expand_to_ips,
    _probe_icmp,
    _probe_tcp
)


async def ping_sweep(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ping-sweep a range of IPs.
    Thăm dò host trong một CIDR/list.
    nên dùng khi cần tìm host sống trong một dải IP.

    PURPOSE:
      - Quickly determine which hosts in a CIDR/list are alive.

    WHEN TO USE:
      - Use before deeper scans (nmap, rustscan) to reduce targets.
      - Useful when you want a fast host discovery step.

    PARAMETERS (PingSweepParams):
      - network (str, required): CIDR (e.g. "10.0.0.0/24"), single IP, or comma-separated list.
      - method (str): "icmp" or "tcp". "icmp" uses system ping (may require CAP_NET_RAW).
      - tcp_port (int): port to attempt when method="tcp" (default 80).
      - concurrency (int): parallel workers (default 50).
      - timeout_s (int): timeout per host in seconds (default 2).
      - max_hosts (int): safe cap on number of hosts to probe (default 1024).

    RETURN (JSON):
      - success: bool
      - scanned: int
      - alive_count: int
      - hosts: [{ "ip": "...", "alive": true|false, "rtt_ms": 12.34|null }]
      - errors: optional list of strings

    EXAMPLE:
      await ping_sweep({"network":"10.0.0.0/28", "method":"tcp", "tcp_port":22})
    """
    try:
        p = PingSweepParams(**params)
    except Exception as e:
        return {"success": False, "error": f"invalid params: {e}"}

    ips = expand_to_ips(p.network)
    if not ips:
        return {"success": False, "error": "no valid hosts parsed from network"}

    if len(ips) > p.max_hosts:
        return {"success": False, "error": "too_many_hosts", "count": len(ips)}

    q = asyncio.Queue()
    for ip in ips:
        q.put_nowait(ip)

    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    async def worker():
        while True:
            try:
                ip = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                if p.method.lower() == "icmp":
                    alive, rtt = await _probe_icmp(ip, p.timeout_s)
                else:
                    alive, rtt = await _probe_tcp(ip, p.tcp_port, p.timeout_s)
                results.append({"ip": ip, "alive": bool(alive), "rtt_ms": rtt})
            except Exception as e:
                errors.append(f"{ip}: {e}")
                results.append({"ip": ip, "alive": False, "rtt_ms": None})

    concurrency = min(p.concurrency, max(1, len(ips)))
    tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await asyncio.gather(*tasks)

    alive_count = sum(1 for r in results if r.get("alive"))
    return {
        "success": True,
        "scanned": len(ips),
        "alive_count": alive_count,
        "hosts": sorted(results, key=lambda x: x["ip"]),
        "errors": errors[:20]
    }


async def nmap_services_detection(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Thực hiện quét nhanh bằng Nmap và trả về kết quả ở dạng JSON.
    Nếu có danh sách ports rồi thì dùng nmap_services_detection để phát hiện service.

    MỤC ĐÍCH:
      - Dùng để phát hiện nhanh dịch vụ cơ bản trên một host dựa trên danh sách ports.
      - Phù hợp khi cần scan tổng quan trước khi fuzzing hoặc khai thác.

    THAM SỐ (theo schema NmapParams):
      - target (str, bắt buộc): IPv4/IPv6 hoặc hostname cần scan.
      - ports (str, mặc định "1-1024"): danh sách cổng (ví dụ "22,80,443") hoặc dải (ví dụ "1-65535").
      - timeout_s (int, mặc định 300): thời gian chờ tối đa cho job (giây).
      - fast (bool, mặc định True): bật T4 và --min-rate để tăng tốc độ quét.
      - service_detection (bool, mặc định True): bật -sV để phát hiện service/version.

    ĐẦU RA (JSON):
      - {"success": true, "nmap": {...}} nếu scan thành công (payload từ `nmap -oJ`).
      - {"success": false, "error": "..."} nếu lỗi validate, out-of-scope, timeout, hoặc tool fail.
      - {"success": false, "stderr": "..."} nếu Nmap trả lỗi.

    VÍ DỤ GỌI:
      await nmap_services_detection({
        "target": "10.0.0.5",
        "ports": "22,80,443",
        "timeout_s": 300,
        "fast": true,
        "service_detection": true
      })

    GHI CHÚ:
      - Hàm sẽ kiểm tra scope trước khi chạy (theo ALLOWED_PREFIX).
      - Kết quả trả về là JSON parse được từ `nmap -oJ`, giúp dễ xử lý tự động.
    """
    try:
        p = NmapParams(**params)
    except Exception as e:
        return {"success": False, "error": f"invalid params: {e}"}

    job_tmp = make_job_tmpdir()
    try:
        cmd = build_nmap_cmd(p.target, ports=p.ports, fast=p.fast, service_detection=p.service_detection)
        use_docker = os.getenv("NMAP_USE_DOCKER", "false").lower() in {"1", "true", "yes"}
        if use_docker:
            image = os.getenv("NMAP_DOCKER_IMAGE", "my-nmap:latest")
            network_mode = os.getenv("NMAP_DOCKER_NETWORK", "host")
            caps_env = os.getenv("NMAP_DOCKER_CAPS", "NET_RAW,NET_ADMIN")
            cap_add = [c.strip() for c in caps_env.split(",") if c.strip()]
            rc, out, err = await run_in_docker(
                image=image,
                cmd=cmd,
                mounts=None,
                timeout=p.timeout_s,
                network_mode=network_mode,
                cap_add=cap_add,
            )
        else:
            rc, out, err = await run_cmd_capture(cmd, timeout=p.timeout_s)
        if rc == -1:
            return {"success": False, "error": "timeout"}
        if rc != 0:
            return {"success": False, "stderr": err[:2000]}

        payload = parse_nmap_json(out)
        return {"success": True, "nmap": payload}
    finally:
        cleanup_tmpdir(job_tmp)


async def host_probe(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    quick probe: ping or tcp connect
    params: {"host":"127.0.0.1", "timeout_s":3}
    """
    try:
        p = HostProbeParams(**params)
    except Exception as e:
        return {"success": False, "error": f"invalid params: {e}"}

    cmd = ["ping", "-c", "1", "-W", str(max(1, p.timeout_s)), p.host]
    rc, out, err = await run_cmd_capture(cmd, timeout=p.timeout_s + 1)
    return {"success": rc == 0, "rc": rc, "stdout": out[:1000], "stderr": err[:1000]}


async def rustscan_range_ports(
    target: str,
    range: str = "1-65535",
    timeout_s: int = 30
) -> dict:
    """
    Quét toàn bộ dải ports trên một host bằng RustScan mà KHÔNG chạy tiếp Nmap.
    Nếu có danh sách ports rồi thì dùng nmap_services_detection để phát hiện service.
    
    DÙNG KHI:
      - Cần nhanh danh sách port mở để tiếp bước (fuzz / probe).
      - Kết quả chỉ là danh sách cổng (dạng greppable/raw), không có thông tin service chi tiết.

    THAM SỐ:
      - target (str, bắt buộc): Địa chỉ IP hoặc hostname bắt buộc để quét.
      - range (str, mặc định "1-65535"): Dải ports hoặc danh sách ports, ví dụ:  "1-65535" (mặc định "1-1024").
      - timeout_s (int, mặc định 30): Thời gian tối đa (giây) cho toàn bộ job. 
        RustScan nội bộ dùng timeout tính bằng mili-giây.

    ĐẦU RA:
      - success: true/false.
      - range (list[int])  — danh sách cổng mở (nếu success)
      - stdout: raw output từ RustScan (dạng greppable, liệt kê port mở).
      - stderr (tùy chọn): nếu có lỗi.

    VÍ DỤ GỌI:
      rustscan_range_ports(target="10.10.10.10", range="1-65535", timeout_s=60)

    GHI CHÚ:
      - Dùng flag "-g" để output ở chế độ greppable, thuận tiện parse danh sách cổng.
      - Không kèm bước gọi Nmap (nên nhanh hơn nhiều).
    """
    range = range.replace(" ", "")
    timeout_ms = int(timeout_s * 1000)
    cmd = [
        "rustscan",
        "-a", target,
        "-r", range,
        "--timeout", str(timeout_ms),
        "--ulimit", "10000",
        "-g"
    ]
    rc, out, err = await run_cmd_capture(cmd, timeout=timeout_s + 5)
    if rc != 0:
        return {"success": False, "stderr": err[:2000], "stdout": out[:1000]}
    nums = re.findall(r"\b([1-9][0-9]{0,4})\b", out)
    ports_found = sorted({int(n) for n in nums if 1 <= int(n) <= 65535})
    return {"success": True, "ports": ports_found, "stdout": out}
