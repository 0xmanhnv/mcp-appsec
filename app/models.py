from pydantic import BaseModel, Field, ConfigDict


class NmapParams(BaseModel):
    model_config = ConfigDict(extra='ignore')
    target: str = Field(description="IPv4/IPv6 hoặc hostname trong scope")
    ports: str = Field("1-1024", description='VD: "22,80" hoặc "1-65535"')
    timeout_s: int = Field(60, ge=5, le=600, description="Giây")
    fast: bool = Field(True)
    service_detection: bool = Field(True)


class PingSweepParams(BaseModel):
    model_config = ConfigDict(extra="ignore")
    network: str = Field(..., description="CIDR (e.g. '10.0.0.0/24') or single IP or comma-separated list")
    method: str = Field("icmp", description="'icmp' or 'tcp' (tcp uses a connect to port)")
    tcp_port: int = Field(80, description="Port to try when method='tcp'")
    concurrency: int = Field(50, ge=1, le=500, description="Parallel workers")
    timeout_s: int = Field(2, ge=1, le=60, description="Per-host timeout in seconds")
    max_hosts: int = Field(1024, ge=1, le=65536, description="Max hosts to scan (safety cap)")


class HostProbeParams(BaseModel):
    host: str
    timeout_s: int = Field(5, ge=1, le=60)


class FfufParams(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str = Field(..., description="URL with FUZZ marker, e.g. http://target/FUZZ")
    wordlist: str = Field("/usr/share/seclists/Discovery/Web-Content/common.txt")
    threads: int = Field(40, ge=1, le=200)
    timeout_s: int = Field(120, ge=5, le=3600)
    store_raw: bool = Field(False)


class WhatwebParams(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target: str = Field(..., description="host or URL")
    timeout_s: int = Field(30, ge=1, le=600)


class GobusterParams(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str = Field(..., description="base url or dir, e.g. http://target")
    wordlist: str = Field("/opt/SecLists/Discovery/Web-Content/common.txt")
    threads: int = Field(40, ge=1, le=200)
    timeout_s: int = Field(120, ge=5, le=3600)


