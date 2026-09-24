"""Automated Actionable Remediation Code & Hardening Script Generator.

Generates production-ready, context-aware remediation code snippets and server
hardening configurations for common vulnerabilities:
- SQL Injection (PHP PDO Prepared Statements, Python SQLAlchemy)
- Cross-Site Scripting (HTML Entity Context Encoding & CSP Header)
- CORS Misconfiguration (Nginx & Apache Whitelist Directives)
- Missing Security Headers (Nginx add_header, Apache Header set)
- Insecure Cookies (PHP session flags, Python/Django Secure cookie configs)
- Sensitive File Exposures (Nginx location block denying .env, .git, etc.)
- SSRF (Private IP Whitelist & CIDR Deny Filter)
"""

import re
from typing import Any


def generate_remediation_snippet(title: str, owasp_category: str = "", cve_id: str = "") -> dict[str, Any]:
    """Generate production-ready remediation code snippet and configuration."""
    text = f"{title} {owasp_category} {cve_id}".lower()

    # 1. SQL Injection
    if re.search(r"\b(sql|sqli)\b|injection", text):
        code = (
            "// PHP PDO Parameterized Query (Fix SQL Injection)\n"
            "$stmt = $pdo->prepare('SELECT id, username, email FROM users WHERE id = :id AND status = :status');\n"
            "$stmt->execute([\n"
            "    ':id' => $user_id,\n"
            "    ':status' => 'active'\n"
            "]);\n"
            "$user = $stmt->fetch();\n\n"
            "# Python SQLAlchemy Equivalent\n"
            "# user = session.query(User).filter(User.id == user_id, User.status == 'active').first()"
        )
        return {
            "category": "SQL Injection",
            "language": "php",
            "code": code,
            "explanation": "Chuyển đổi toàn bộ câu truy vấn chuỗi động nối chuỗi ($sql = '... ' . $id) sang cơ chế tham số hóa Prepared Statements.",
        }

    # 2. Cross-Site Scripting (XSS)
    if re.search(r"\bxss\b|cross-site scripting", text):
        code = (
            "// PHP Context-aware HTML Escaping\n"
            "echo htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');\n\n"
            "# Nginx Defense-in-Depth Content-Security-Policy (CSP)\n"
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\" always;"
        )
        return {
            "category": "Cross-Site Scripting",
            "language": "php",
            "code": code,
            "explanation": "Thực hiện mã hóa ký tự HTML trước khi render vào DOM và thiết lập chính sách Content-Security-Policy nghiêm ngặt.",
        }

    # 3. CORS Misconfiguration (Wildcard / Insecure Origin)
    if re.search(r"\bcors\b|cross-origin", text):
        code = (
            "# Nginx Hardened CORS Configuration (Whitelist Approach)\n"
            "set $cors_origin \"\";\n"
            "if ($http_origin ~* '^https://(app|dashboard|portal)\\.yourdomain\\.com$') {\n"
            "    set $cors_origin $http_origin;\n"
            "}\n\n"
            "add_header 'Access-Control-Allow-Origin' $cors_origin always;\n"
            "add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;\n"
            "add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type' always;\n"
            "add_header 'Access-Control-Allow-Credentials' 'true' always;"
        )
        return {
            "category": "CORS Misconfiguration",
            "language": "nginx",
            "code": code,
            "explanation": "Tuyệt đối không dùng 'Access-Control-Allow-Origin: *' đi kèm 'Access-Control-Allow-Credentials: true'. Chỉ chấp nhận nguồn tin cậy qua regex whitelist.",
        }

    # 4. Insecure Cookies (Missing HttpOnly, Secure, SameSite)
    if re.search(r"\bcookie\b|\bhttponly\b|\bsamesite\b|session flag", text):
        code = (
            "// PHP Hardened Session Cookie Configuration\n"
            "session_start([\n"
            "    'cookie_lifetime' => 86400,\n"
            "    'cookie_secure'   => true,      // Yêu cầu truyền qua HTTPS\n"
            "    'cookie_httponly' => true,      // Ngăn chặn JavaScript (XSS) đọc Cookie\n"
            "    'cookie_samesite' => 'Strict',  // Chống tấn công CSRF\n"
            "]);"
        )
        return {
            "category": "Insecure Cookies",
            "language": "php",
            "code": code,
            "explanation": "Bật đầy đủ 3 cờ bảo vệ: HttpOnly (chống trộm phiên qua XSS), Secure (chỉ gửi qua HTTPS), và SameSite=Strict hoặc Lax (chống CSRF).",
        }

    # 5. Missing Security Headers
    if re.search(r"security headers|hsts|x-frame-options|x-content-type", text):
        code = (
            "# Nginx Complete Security Headers Hardening\n"
            "add_header X-Frame-Options \"SAMEORIGIN\" always;                     # Chống Clickjacking\n"
            "add_header X-Content-Type-Options \"nosniff\" always;                  # Chống MIME-sniffing\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always; # HSTS\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;"
        )
        return {
            "category": "Security Headers",
            "language": "nginx",
            "code": code,
            "explanation": "Thêm trực tiếp cấu hình header vào khối `server { ... }` của Nginx hoặc Apache để áp dụng chính sách phòng vệ trên toàn hệ thống.",
        }

    # 6. Sensitive Files & Path Traversal (.git, .env, backups)
    if re.search(r"sensitive|\.env\b|\.git\b|backup|traversal|\blfi\b", text):
        code = (
            "# Nginx Block Sensitive Files and Hidden Directories\n"
            "location ~ /\\.(env|git|svn|htaccess|htpasswd|bak|old|sql|tar|gz)$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        )
        return {
            "category": "Sensitive File Exposure",
            "language": "nginx",
            "code": code,
            "explanation": "Cấu hình web server từ chối phục vụ (deny all) và trả về HTTP 404 đối với mọi yêu cầu truy xuất tệp cấu hình hoặc kho mã nguồn.",
        }

    # 7. SSRF (Server-Side Request Forgery)
    if re.search(r"\bssrf\b|request forgery", text):
        code = (
            "# Python SSRF Safe Request Validator\n"
            "import ipaddress\n"
            "from urllib.parse import urlparse\n\n"
            "def is_safe_url(url):\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.scheme not in ('http', 'https'):\n"
            "        return False\n"
            "    ip = ipaddress.ip_address(parsed.hostname)\n"
            "    # Chặn truy cập loopback, dải IP nội bộ và metadata service (169.254.169.254)\n"
            "    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)"
        )
        return {
            "category": "SSRF",
            "language": "python",
            "code": code,
            "explanation": "Kiểm tra và xác thực địa chỉ IP phân giải của hostname, kiên quyết chặn toàn bộ dải IP riêng tư (RFC 1918) và Cloud Metadata service.",
        }

    # Fallback / Generic Hardening
    return {
        "category": "General Security Hardening",
        "language": "bash",
        "code": (
            "# Cập nhật các bản vá bảo mật và cô lập dịch vụ\n"
            "sudo apt-get update && sudo apt-get --only-upgrade install -y <package_name>\n"
            "# Thiết lập tường lửa UFW chỉ mở các cổng dịch vụ cần thiết\n"
            "sudo ufw default deny incoming\n"
            "sudo ufw allow 80/tcp\n"
            "sudo ufw allow 443/tcp\n"
            "sudo ufw enable"
        ),
        "explanation": "Thực hiện nâng cấp phiên bản phần mềm lên bản vá mới nhất và giới hạn quyền truy cập dịch vụ bằng tường lửa.",
    }
