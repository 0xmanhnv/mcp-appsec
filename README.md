### appsec-mcp-services

Dịch vụ MCP (Model Context Protocol) phục vụ cho hoạt động AppSec: thăm dò (recon) và liệt kê/fuzz (enum) các mục tiêu. Dự án gom nhóm các tool thành hai nhóm chính: `recon` và `enum`, và expose chúng qua một MCP server dùng FastMCP.

---

### Mục lục
- **Giới thiệu**
- **Cấu trúc dự án**
- **Yêu cầu hệ thống**
- **Cài đặt**
- **Biến môi trường**
- **Chạy server**
- **Danh sách tool MCP**
  - Recon
  - Enum
- **Tích hợp với Cursor (MCP client)**
- **Ghi chú an toàn & phạm vi (scope)**
- **Troubleshooting**

---

### Giới thiệu
Server MCP đăng ký hai nhóm tool:
- `recon`: quét ping, probe host, quét dịch vụ (nmap), quét dải cổng (rustscan)
- `enum`: fingerprint web (whatweb), brute-force đường dẫn (gobuster), fuzz (ffuf)

Bạn có thể chạy server qua stdio/SSE/HTTP để các client hỗ trợ MCP (như Cursor) gọi trực tiếp các tool.

---

### Cấu trúc dự án
```text
appsec-mcp-services/
  app/
    recon/
      __init__.py
      tools.py           # Tool nhóm Recon
    enum/
      __init__.py
      tools.py           # Tool nhóm Enum
    tools.py             # Helpers chung (subprocess, docker, nmap builders, parsers)
    helpers.py           # Hàm hỗ trợ ping/tcp probe, expand IPs
    models.py            # Pydantic models cho tham số tool
    server.py            # Khởi tạo FastMCP và đăng ký tool groups
  requirements.txt
  backup/                # Tham khảo (không chạy trực tiếp)
```

---

### Yêu cầu hệ thống
- Python 3.10+
- Các tool bên ngoài (tuỳ tool bạn định dùng):
  - nmap, rustscan, whatweb, gobuster, ffuf
  - Hoặc Docker nếu muốn chạy tool qua container

---

### Cài đặt
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

### Biến môi trường
- **Chung** (được `app/tools.py` sử dụng):
  - `ALLOWED_PREFIX`: Prefix cho phép (vd: "10.0."), nếu rỗng thì không giới hạn.
  - `DEFAULT_MIN_RATE`: Min rate cho Nmap khi ở chế độ nhanh (mặc định "1000").
  - `DOCKER_CMD`: Tên binary Docker (mặc định `docker`).

- **Server** (`app/server.py`):
  - `MCP_MODE`: `stdio` | `sse` | `http` (mặc định `sse`).
  - `HOST`: Địa chỉ bind khi dùng `sse` hoặc `http` (mặc định `0.0.0.0`).
  - `PORT`: Cổng bind (mặc định `8000`).

- **Nmap**:
  - `NMAP_USE_DOCKER`: `true/false` (mặc định false).
  - `NMAP_DOCKER_IMAGE`: (mặc định `my-nmap:latest`).
  - `NMAP_DOCKER_NETWORK`: (mặc định `host`).
  - `NMAP_DOCKER_CAPS`: (mặc định `NET_RAW,NET_ADMIN`).

- **WhatWeb**:
  - `WHATWEB_USE_DOCKER`, `WHATWEB_DOCKER_IMAGE`, `WHATWEB_DOCKER_NETWORK`, `WHATWEB_DOCKER_CAPS`.

- **Gobuster**:
  - `GOBUSTER_USE_DOCKER`, `GOBUSTER_DOCKER_IMAGE`, `GOBUSTER_DOCKER_NETWORK`, `GOBUSTER_DOCKER_CAPS`.

- **FFUF**:
  - `FFUF_USE_DOCKER`, `FFUF_DOCKER_IMAGE`, `FFUF_DOCKER_NETWORK`, `FFUF_DOCKER_CAPS`.

---

### Chạy server
```bash
# 1) Chạy qua stdio (phù hợp khi client MCP chạy cùng process)
export MCP_MODE=stdio
python -m app.server

# 2) Chạy SSE
export MCP_MODE=sse
export HOST=0.0.0.0
export PORT=8000
python -m app.server

# 3) Chạy HTTP
export MCP_MODE=http
export HOST=0.0.0.0
export PORT=8000
python -m app.server
```

Server đăng ký tool groups trong `app/server.py`:
```python
from app.recon import register as register_recon
from app.enum import register as register_enum

register_recon(mcp)
register_enum(mcp)
```

---

### Danh sách tool MCP

#### Recon
- **ping_sweep(params)**
  - **Mục đích**: Tìm host sống trong một CIDR/list nhanh chóng.
  - **Khi dùng**: Bước discovery trước khi quét sâu (nmap/rustscan).
  - **Tham số (PingSweepParams)**: `network`, `method` (icmp|tcp), `tcp_port`, `concurrency`, `timeout_s`, `max_hosts`.
  - **Đầu ra**: `success`, `scanned`, `alive_count`, `hosts[]`, `errors`.

- **nmap_services_detection(params)**
  - **Mục đích**: Quét dịch vụ/phiên bản nhanh với Nmap (-sV), trả JSON từ `-oJ`.
  - **Tham số (NmapParams)**: `target`, `ports` ("1-1024" | "22,80,443" ...), `timeout_s`, `fast`, `service_detection`.
  - **Đầu ra**: `{ success, nmap }` hoặc `{ success:false, error/stderr }`.

- **host_probe(params)**
  - **Mục đích**: Probe nhanh (ping hoặc tcp connect đơn giản) để kiểm tra reachability.
  - **Tham số (HostProbeParams)**: `host`, `timeout_s`.
  - **Đầu ra**: `{ success, rc, stdout, stderr }`.

- **rustscan_range_ports(target, range, timeout_s)**
  - **Mục đích**: Quét dải cổng tốc độ cao bằng RustScan (không chạy Nmap theo sau).
  - **Khi dùng**: Cần danh sách cổng mở nhanh để theo sau bằng service detection.
  - **Tham số**: `target`, `range` (mặc định "1-65535"), `timeout_s`.
  - **Đầu ra**: `{ success, ports[], stdout }` hoặc lỗi kèm `stderr`.

#### Enum
- **whatweb_scan(params)**
  - **Mục đích**: Fingerprint công nghệ web (server, CMS, plugins, headers).
  - **Tham số (WhatwebParams)**: `target`, `timeout_s`.
  - **Đầu ra**: `{ success, stdout }` (format tuỳ phiên bản WhatWeb).

- **gobuster_dir(params)**
  - **Mục đích**: Brute-force thư mục/đường dẫn web.
  - **Tham số (GobusterParams)**: `url`, `wordlist`, `threads`, `timeout_s`.
  - **Đầu ra**: `{ success, stdout, found[] }`.

- **ffuf_fuzz(params)**
  - **Mục đích**: Web fuzzing (tìm file/dir/route ẩn) bằng FFUF.
  - **Tham số (FfufParams)**: `url` (có token FUZZ), `wordlist`, `threads`, `timeout_s`, `store_raw`.
  - **Đầu ra**: `{ success, ffuf(JSON), stdout? }` hoặc lỗi.

---

### Tích hợp với Cursor (MCP client)
- Thêm server này vào cấu hình MCP của Cursor. Ví dụ (SSE):
```json
{
  "mcpServers": {
    "appsec-mcp": {
      "command": "python",
      "args": ["-m", "app.server"],
      "env": {
        "MCP_MODE": "sse",
        "HOST": "127.0.0.1",
        "PORT": "8000",
        "ALLOWED_PREFIX": "10.0."
      }
    }
  }
}
```
Lưu ý: tùy cách Cursor khởi chạy, bạn có thể dùng `stdio` thay cho `sse`.

---

### Ghi chú an toàn & phạm vi (scope)
- Dùng `ALLOWED_PREFIX` để giới hạn phạm vi IP/host được phép quét.
- Các tool có thể tạo nhiều request (đặc biệt FFUF/Gobuster). Điều chỉnh `threads`, `timeout_s` phù hợp.
- Với Nmap cần quyền mạng raw khi chạy trong container; thiết lập `NMAP_DOCKER_CAPS` tương ứng.

---

### Troubleshooting
- "MCP SDK not found": cài `pip install 'mcp[cli]'` theo thông báo trong `app/server.py`.
- Lỗi thiếu binary (nmap/rustscan/whatweb/gobuster/ffuf): cài đặt tool tương ứng hoặc bật chế độ Docker cho tool đó.
- Không thấy tool trong client: đảm bảo server đã chạy đúng `MCP_MODE`, client kết nối đúng host/port.


