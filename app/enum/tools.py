import os
from typing import Dict, Any

from app.tools import (
    run_cmd_capture,
    run_in_docker,
    parse_ffuf_json,
    make_job_tmpdir,
    cleanup_tmpdir,
)
from app.models import (
    FfufParams,
    WhatwebParams,
    GobusterParams,
)


async def ffuf_fuzz(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Web fuzzing using ffuf. params must follow FfufParams schema.
    Quét thư mục/đường dẫn web bằng ffuf và trả kết quả ở dạng JSON.
    Returns parsed JSON (if -of json) in 'ffuf' key, plus stdout/stderr.
    Tìm kiếm đường dẫn/ứng dụng ẩn (directory / file) trên 1 URL bằng wordlist.

    MỤC ĐÍCH:
      - Phát hiện đường dẫn/ứng dụng ẩn (directory / file) trên 1 URL bằng wordlist.

    KHI NÀO DÙNG:
      - Khi cần enumerate nội dung web (common files, directories) để tìm điểm tấn công.
      - Trước khi bắt đầu fuzz sâu hoặc manual testing.

    THAM SỐ (theo FfufParams):
      - url (str, bắt buộc): URL chứa token FUZZ, ví dụ "http://target/FUZZ"
      - wordlist (str): đường dẫn tới wordlist
      - threads (int): số luồng đồng thời
      - timeout_s (int): timeout tổng cho job (giây)
      - store_raw (bool): nếu true thì trả thêm stdout thô

    ĐẦU RA:
      - success: bool
      - ffuf: dict (JSON parse từ ffuf -of json)
      - stdout: (tuỳ) raw output nếu store_raw=True
      - stderr: lỗi nếu có

    VÍ DỤ GỌI:
      ffuf_fuzz({
        "url": "http://10.10.10.5/FUZZ",
        "wordlist": "/opt/SecLists/Discovery/Web-Content/common.txt",
        "threads": 40,
        "timeout_s": 120
      })

    GHI CHÚ:
      - Luôn kiểm tra host trong URL với ALLOWED_PREFIX trước khi chạy.
      - ffuf có thể tạo nhiều request: set resource limits (threads, timeout).
      - Nếu kết quả quá lớn, lưu raw output vào storage (S3/MinIO) và trả pointer thay vì chèn toàn bộ vào JSON.
    """
    try:
        p = FfufParams(**params)
    except Exception as e:
        return {"success": False, "error": f"invalid params: {e}"}

    tmp = make_job_tmpdir()
    try:
        cmd = ["ffuf", "-u", p.url, "-w", p.wordlist, "-t", str(p.threads), "-of", "json", "-o", "-"]
        use_docker = os.getenv("FFUF_USE_DOCKER", "false").lower() in {"1", "true", "yes"}
        if use_docker:
            image = os.getenv("FFUF_DOCKER_IMAGE", "ffuf:latest")
            network_mode = os.getenv("FFUF_DOCKER_NETWORK", None)
            caps_env = os.getenv("FFUF_DOCKER_CAPS", "")
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
        if rc != 0 and not out:
            return {"success": False, "stderr": err[:2000]}
        payload = parse_ffuf_json(out)
        res = {"success": True, "ffuf": payload}
        if p.store_raw:
            res["stdout"] = out
        return res
    finally:
        cleanup_tmpdir(tmp)


async def whatweb_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Thu thập fingerprint ứng dụng web (server, CMS, headers) bằng WhatWeb.
    Tìm hiểu chi tiết về ứng dụng web đang chạy công nghệ, server, CMS, plugin, header info.

    MỤC ĐÍCH:
      - Xác định công nghệ, server, CMS, plugin, header info của một website.

    KHI NÀO DÙNG:
      - Sau khi xác định host sống; trước khi chọn kỹ thuật khai thác (vuln scanners, payloads).

    THAM SỐ (theo WhatwebParams):
      - target (str, bắt buộc): URL hoặc host
      - timeout_s (int): timeout cho job

    ĐẦU RA:
      - success: bool
      - stdout: raw WhatWeb output (parse tuỳ phiên bản)
      - stderr: nếu có lỗi

    VÍ DỤ:
      whatweb_scan({"target": "http://10.10.10.5", "timeout_s": 20})

    GHI CHÚ:
      - WhatWeb output format thay đổi theo phiên bản; nếu cần parse structured, bổ sung parser cụ thể.
      - Không gây thao tác destructive.
    """
    try:
        p = WhatwebParams(**params)
    except Exception as e:
        return {"success": False, "error": f"invalid params: {e}"}

    cmd = ["whatweb", "-a", "2", p.target]
    use_docker = os.getenv("WHATWEB_USE_DOCKER", "false").lower() in {"1", "true", "yes"}
    if use_docker:
        image = os.getenv("WHATWEB_DOCKER_IMAGE", "whatweb:latest")
        network_mode = os.getenv("WHATWEB_DOCKER_NETWORK", None)
        caps_env = os.getenv("WHATWEB_DOCKER_CAPS", "")
        cap_add = [c.strip() for c in caps_env.split(",") if c.strip()]
        rc, out, err = await run_in_docker(
            image=image, cmd=cmd, mounts=None, timeout=p.timeout_s, network_mode=network_mode, cap_add=cap_add
        )
    else:
        rc, out, err = await run_cmd_capture(cmd, timeout=p.timeout_s)
    if rc == -1:
        return {"success": False, "error": "timeout"}
    if rc != 0 and not out:
        return {"success": False, "stderr": err[:2000]}
    return {"success": True, "stdout": out}


async def gobuster_dir(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run gobuster dir mode. Returns raw stdout and simple parse of found paths.
    """
    try:
        p = GobusterParams(**params)
    except Exception as e:
        return {"success": False, "error": f"invalid params: {e}"}

    tmp = make_job_tmpdir()
    try:
        cmd = ["gobuster", "dir", "-u", p.url, "-w", p.wordlist, "-t", str(p.threads), "-q"]
        use_docker = os.getenv("GOBUSTER_USE_DOCKER", "false").lower() in {"1", "true", "yes"}
        if use_docker:
            image = os.getenv("GOBUSTER_DOCKER_IMAGE", "gobuster:latest")
            network_mode = os.getenv("GOBUSTER_DOCKER_NETWORK", None)
            caps_env = os.getenv("GOBUSTER_DOCKER_CAPS", "")
            cap_add = [c.strip() for c in caps_env.split(",") if c.strip()]
            rc, out, err = await run_in_docker(
                image=image, cmd=cmd, mounts=None, timeout=p.timeout_s, network_mode=network_mode, cap_add=cap_add
            )
        else:
            rc, out, err = await run_cmd_capture(cmd, timeout=p.timeout_s)
        if rc == -1:
            return {"success": False, "error": "timeout"}
        if rc != 0 and not out:
            return {"success": False, "stderr": err[:2000]}
        found = []
        for line in out.splitlines():
            if line.strip() and (line.startswith("/") or "Status:" in line):
                found.append(line.strip())
        return {"success": True, "stdout": out, "found": found}
    finally:
        cleanup_tmpdir(tmp)


