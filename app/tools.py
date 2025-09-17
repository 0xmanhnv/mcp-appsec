import asyncio
import os
import json
import shutil
import tempfile
import uuid
import logging
from typing import Tuple, List, Dict, Any, Optional

log = logging.getLogger("mcp.tools")
log.setLevel(logging.INFO)

ALLOWED_PREFIX = os.getenv("ALLOWED_PREFIX", "")  # legacy prefix scope
DEFAULT_MIN_RATE = os.getenv("DEFAULT_MIN_RATE", "1000")
DOCKER_CMD = os.getenv("DOCKER_CMD", "docker")


def in_allowed_scope(target: str) -> bool:
    if not ALLOWED_PREFIX:
        return True
    return target.startswith(ALLOWED_PREFIX)


def make_job_tmpdir(job_id: Optional[str] = None) -> str:
    jid = job_id or uuid.uuid4().hex
    path = os.path.join(tempfile.gettempdir(), f"mcp-job-{jid}")
    os.makedirs(path, exist_ok=True)
    return path


def cleanup_tmpdir(path: str) -> None:
    try:
        shutil.rmtree(path)
    except Exception:
        log.exception("cleanup_tmpdir failed for %s", path)


async def run_cmd_capture(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    log.debug("run_cmd_capture: %s timeout=%s", cmd, timeout)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        out = stdout.decode(errors="ignore") if stdout else ""
        err = stderr.decode(errors="ignore") if stderr else ""
        return proc.returncode, out, err
    except asyncio.TimeoutError:
        log.warning("timeout running cmd %s", cmd)
        try:
            proc.kill()
        except Exception:
            pass
        await proc.communicate()
        return -1, "", "timeout"


async def run_in_docker(
    image: str,
    cmd: List[str],
    mounts: Optional[List[Tuple[str, str]]] = None,
    timeout: int = 60,
    network_mode: Optional[str] = None,
    cap_add: Optional[List[str]] = None,
) -> Tuple[int, str, str]:
    docker_cmd = [DOCKER_CMD, "run", "--rm", "--init", "--cpus", "0.5", "--memory", "512m"]
    if network_mode:
        docker_cmd += ["--network", network_mode]
    if cap_add:
        for cap in cap_add:
            if cap:
                docker_cmd += ["--cap-add", cap]
    if mounts:
        for host, cont in mounts:
            docker_cmd += ["-v", f"{host}:{cont}:ro"]
    docker_cmd += [image] + cmd
    return await run_cmd_capture(docker_cmd, timeout=timeout)


def parse_nmap_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        s = text.strip()
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(s[start:end+1])
            except Exception:
                pass
    return {"raw": text}


def parse_ffuf_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        s = text.strip()
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1:
            try:
                return json.loads(s[start:end+1])
            except Exception:
                pass
    return {"raw": text}


def build_nmap_cmd(target: str, ports: str = "1-1024", fast: bool = True, service_detection: bool = True) -> List[str]:
    cmd = ["nmap"]
    if service_detection:
        cmd += ["-sV"]
    if fast:
        cmd += ["-T4", "--min-rate", os.getenv("DEFAULT_MIN_RATE", "1000")]
    cmd += ["-oJ", "-", "-p", ports, target]
    return cmd


