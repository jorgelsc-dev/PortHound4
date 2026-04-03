import os
import re
import tempfile


_VERSION_FRAGMENT = r"[0-9A-Za-z][0-9A-Za-z.\-_+]*"
RE_I = re.IGNORECASE
RE_IM = re.IGNORECASE | re.MULTILINE


BANNER_REGEX_RULES = [
    {
        "id": "apache_http",
        "label": "Apache HTTP Server",
        "pattern": rf"^Server:\s*Apache(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "apache",
        "server": "Apache",
        "vendor": "apache",
    },
    {
        "id": "nginx_http",
        "label": "Nginx HTTP Server",
        "pattern": rf"^Server:\s*nginx(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "nginx",
        "server": "Nginx",
        "vendor": "nginx",
    },
    {
        "id": "iis_http",
        "label": "Microsoft IIS",
        "pattern": rf"^Server:\s*Microsoft-IIS(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "iis",
        "server": "IIS",
        "vendor": "microsoft",
    },
    {
        "id": "caddy_http",
        "label": "Caddy",
        "pattern": rf"^Server:\s*Caddy(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "caddy",
        "server": "Caddy",
    },
    {
        "id": "lighttpd_http",
        "label": "lighttpd",
        "pattern": rf"^Server:\s*lighttpd(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "lighttpd",
        "server": "lighttpd",
    },
    {
        "id": "openresty_http",
        "label": "OpenResty",
        "pattern": rf"^Server:\s*openresty(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "openresty",
        "server": "OpenResty",
    },
    {
        "id": "envoy_http",
        "label": "Envoy",
        "pattern": rf"^Server:\s*envoy(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "reverse_proxy",
        "service": "http",
        "protocol": "HTTP",
        "product": "envoy",
        "server": "Envoy",
    },
    {
        "id": "traefik_http",
        "label": "Traefik",
        "pattern": rf"^Server:\s*Traefik(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "reverse_proxy",
        "service": "http",
        "protocol": "HTTP",
        "product": "traefik",
        "server": "Traefik",
    },
    {
        "id": "squid_http",
        "label": "Squid Proxy",
        "pattern": rf"^Server:\s*squid(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "proxy",
        "service": "http",
        "protocol": "HTTP",
        "product": "squid",
        "server": "Squid",
    },
    {
        "id": "varnish_http",
        "label": "Varnish",
        "pattern": rf"^Server:\s*Varnish(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "cache",
        "service": "http",
        "protocol": "HTTP",
        "product": "varnish",
        "server": "Varnish",
    },
    {
        "id": "jetty_http",
        "label": "Jetty",
        "pattern": rf"^Server:\s*Jetty(?:[/(](?P<version>{_VERSION_FRAGMENT})\)?)?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "jetty",
        "server": "Jetty",
    },
    {
        "id": "tomcat_http",
        "label": "Apache Tomcat",
        "pattern": rf"^Server:\s*Apache(?:\s+Tomcat|[- ]Tomcat)(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "tomcat",
        "server": "Tomcat",
    },
    {
        "id": "coyote_http",
        "label": "Apache Coyote",
        "pattern": rf"^Server:\s*Apache[- ]Coyote(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "web_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "tomcat",
        "server": "Tomcat",
    },
    {
        "id": "gunicorn_http",
        "label": "Gunicorn",
        "pattern": rf"^Server:\s*gunicorn(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "application_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "gunicorn",
        "server": "Gunicorn",
        "runtime": "python",
    },
    {
        "id": "uvicorn_http",
        "label": "Uvicorn",
        "pattern": rf"^Server:\s*uvicorn(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "application_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "uvicorn",
        "server": "Uvicorn",
        "runtime": "python",
    },
    {
        "id": "werkzeug_http",
        "label": "Werkzeug",
        "pattern": rf"^Server:\s*Werkzeug(?:/(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "application_server",
        "service": "http",
        "protocol": "HTTP",
        "product": "werkzeug",
        "server": "Werkzeug",
        "runtime": "python",
    },
    {
        "id": "express_powered",
        "label": "Express Framework",
        "pattern": r"^X-Powered-By:\s*Express\b",
        "flags": RE_IM,
        "category": "framework",
        "service": "http",
        "protocol": "HTTP",
        "framework": "express",
        "runtime": "node.js",
        "product": "express",
    },
    {
        "id": "aspnet_powered",
        "label": "ASP.NET",
        "pattern": rf"^X-Powered-By:\s*ASP\.NET(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_IM,
        "category": "framework",
        "service": "http",
        "protocol": "HTTP",
        "framework": "asp.net",
        "runtime": ".net",
        "product": "asp.net",
        "vendor": "microsoft",
    },
    {
        "id": "php_powered_header",
        "label": "PHP via X-Powered-By",
        "pattern": rf"^X-Powered-By:\s*PHP/(?P<version>{_VERSION_FRAGMENT})",
        "flags": RE_IM,
        "category": "runtime",
        "service": "http",
        "protocol": "HTTP",
        "runtime": "php",
        "product": "php",
        "powered_by": "php",
    },
    {
        "id": "openssh",
        "label": "OpenSSH",
        "pattern": rf"OpenSSH[_/\-](?P<version>{_VERSION_FRAGMENT})",
        "flags": RE_I,
        "category": "remote_access",
        "service": "ssh",
        "protocol": "SSH",
        "product": "openssh",
        "server": "OpenSSH",
    },
    {
        "id": "dropbear",
        "label": "Dropbear SSH",
        "pattern": rf"dropbear[_/\-]?(?P<version>{_VERSION_FRAGMENT})",
        "flags": RE_I,
        "category": "remote_access",
        "service": "ssh",
        "protocol": "SSH",
        "product": "dropbear",
        "server": "Dropbear",
    },
    {
        "id": "libssh",
        "label": "libssh",
        "pattern": rf"libssh(?:[_/\-](?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "remote_access",
        "service": "ssh",
        "protocol": "SSH",
        "product": "libssh",
    },
    {
        "id": "rfb_vnc",
        "label": "RFB / VNC",
        "pattern": r"\bRFB\s*(?P<version>[0-9]{3}\.[0-9]{3})\b",
        "flags": RE_I,
        "category": "remote_access",
        "service": "vnc",
        "protocol": "RFB",
        "product": "vnc",
    },
    {
        "id": "vsftpd",
        "label": "vsftpd",
        "pattern": rf"vsftpd(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "file_transfer",
        "service": "ftp",
        "protocol": "FTP",
        "product": "vsftpd",
    },
    {
        "id": "proftpd",
        "label": "ProFTPD",
        "pattern": rf"ProFTPD(?:\s+Server)?(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "file_transfer",
        "service": "ftp",
        "protocol": "FTP",
        "product": "proftpd",
    },
    {
        "id": "pureftpd",
        "label": "Pure-FTPd",
        "pattern": rf"Pure-FTPd(?:\s*\[(?P<version>{_VERSION_FRAGMENT})\])?",
        "flags": RE_I,
        "category": "file_transfer",
        "service": "ftp",
        "protocol": "FTP",
        "product": "pure-ftpd",
    },
    {
        "id": "filezilla_ftp",
        "label": "FileZilla FTP Server",
        "pattern": rf"FileZilla\s+Server(?:\s+version)?\s*(?P<version>{_VERSION_FRAGMENT})?",
        "flags": RE_I,
        "category": "file_transfer",
        "service": "ftp",
        "protocol": "FTP",
        "product": "filezilla-server",
    },
    {
        "id": "postfix",
        "label": "Postfix",
        "pattern": rf"Postfix(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "mail_server",
        "service": "smtp",
        "protocol": "SMTP",
        "product": "postfix",
    },
    {
        "id": "exim",
        "label": "Exim",
        "pattern": rf"Exim(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "mail_server",
        "service": "smtp",
        "protocol": "SMTP",
        "product": "exim",
    },
    {
        "id": "sendmail",
        "label": "Sendmail",
        "pattern": rf"Sendmail(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "mail_server",
        "service": "smtp",
        "protocol": "SMTP",
        "product": "sendmail",
    },
    {
        "id": "exchange_smtp",
        "label": "Microsoft Exchange SMTP",
        "pattern": rf"Microsoft\s+ESMTP\s+MAIL\s+Service(?:\s+Version\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "mail_server",
        "service": "smtp",
        "protocol": "SMTP",
        "product": "exchange",
        "vendor": "microsoft",
    },
    {
        "id": "dovecot",
        "label": "Dovecot",
        "pattern": rf"Dovecot(?:\s+ready)?(?:\s+v?(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "mail_server",
        "service": "imap",
        "protocol": "IMAP",
        "product": "dovecot",
    },
    {
        "id": "cyrus_imap",
        "label": "Cyrus IMAP",
        "pattern": rf"Cyrus\s+IMAP(?:\s+v?(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "mail_server",
        "service": "imap",
        "protocol": "IMAP",
        "product": "cyrus-imap",
    },
    {
        "id": "qmail",
        "label": "qmail",
        "pattern": rf"qmail(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "mail_server",
        "service": "smtp",
        "protocol": "SMTP",
        "product": "qmail",
    },
    {
        "id": "mariadb",
        "label": "MariaDB",
        "pattern": rf"MariaDB(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "database",
        "service": "mysql",
        "protocol": "MYSQL",
        "product": "mariadb",
    },
    {
        "id": "mysql",
        "label": "MySQL",
        "pattern": rf"(?:MySQL|mysql_native_password)(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "database",
        "service": "mysql",
        "protocol": "MYSQL",
        "product": "mysql",
    },
    {
        "id": "postgresql",
        "label": "PostgreSQL",
        "pattern": rf"PostgreSQL(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "database",
        "service": "postgresql",
        "protocol": "POSTGRESQL",
        "product": "postgresql",
    },
    {
        "id": "redis_info",
        "label": "Redis",
        "pattern": rf"redis_version:(?P<version>{_VERSION_FRAGMENT})",
        "flags": RE_I,
        "category": "cache",
        "service": "redis",
        "protocol": "REDIS",
        "product": "redis",
    },
    {
        "id": "redis_server",
        "label": "Redis",
        "pattern": rf"\bRedis(?:\s+server)?(?:\s+v?(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "cache",
        "service": "redis",
        "protocol": "REDIS",
        "product": "redis",
    },
    {
        "id": "mongodb",
        "label": "MongoDB",
        "pattern": rf"\bMongoDB(?:\s+v?(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "database",
        "service": "mongodb",
        "protocol": "MONGODB",
        "product": "mongodb",
    },
    {
        "id": "mssql",
        "label": "Microsoft SQL Server",
        "pattern": rf"(?:Microsoft\s+SQL\s+Server|MSSQLServer)(?:\s*(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "database",
        "service": "mssql",
        "protocol": "TDS",
        "product": "microsoft sql server",
        "vendor": "microsoft",
    },
    {
        "id": "oracle",
        "label": "Oracle Database",
        "pattern": rf"Oracle(?:\s+Database)?(?:\s+Release\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "database",
        "service": "oracle",
        "protocol": "TNS",
        "product": "oracle",
    },
    {
        "id": "elasticsearch",
        "label": "Elasticsearch",
        "pattern": rf"\"tagline\"\s*:\s*\"You\s+Know,\s+for\s+Search\"|\"cluster_name\"\s*:\s*\"(?P<version>{_VERSION_FRAGMENT})\"",
        "flags": RE_I,
        "category": "search_engine",
        "service": "http",
        "protocol": "HTTP",
        "product": "elasticsearch",
    },
    {
        "id": "rabbitmq",
        "label": "RabbitMQ",
        "pattern": rf"RabbitMQ(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "message_broker",
        "service": "amqp",
        "protocol": "AMQP",
        "product": "rabbitmq",
    },
    {
        "id": "activemq",
        "label": "ActiveMQ",
        "pattern": rf"ActiveMQ(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "message_broker",
        "service": "jms",
        "protocol": "OPENWIRE",
        "product": "activemq",
    },
    {
        "id": "mosquitto",
        "label": "Mosquitto MQTT",
        "pattern": rf"Mosquitto(?:\s+version)?\s*(?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)?",
        "flags": RE_I,
        "category": "message_broker",
        "service": "mqtt",
        "protocol": "MQTT",
        "product": "mosquitto",
    },
    {
        "id": "nats_server",
        "label": "NATS Server",
        "pattern": rf"\bNATS\s+Server(?:\s+v?(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "message_broker",
        "service": "nats",
        "protocol": "NATS",
        "product": "nats",
    },
    {
        "id": "samba",
        "label": "Samba",
        "pattern": rf"Samba(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "file_sharing",
        "service": "smb",
        "protocol": "SMB",
        "product": "samba",
    },
    {
        "id": "windows_os",
        "label": "Windows",
        "pattern": r"Windows(?:\s+NT)?\s*(?P<version>(?:[0-9]{1,2}(?:\.[0-9]{1,2}){0,2})|XP|Vista|Server\s+[0-9]{4})?",
        "flags": RE_I,
        "category": "operating_system",
        "os": "windows",
    },
    {
        "id": "ubuntu_os",
        "label": "Ubuntu",
        "pattern": r"Ubuntu(?:[-/\s](?P<version>[0-9]{2}\.[0-9]{2}|[0-9]+\.[0-9]+))?",
        "flags": RE_I,
        "category": "operating_system",
        "os": "ubuntu",
    },
    {
        "id": "debian_os",
        "label": "Debian",
        "pattern": rf"Debian(?:[-/\s](?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "operating_system",
        "os": "debian",
    },
    {
        "id": "centos_os",
        "label": "CentOS",
        "pattern": rf"CentOS(?:\s+Linux)?(?:\s+release\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "operating_system",
        "os": "centos",
    },
    {
        "id": "rhel_os",
        "label": "RHEL",
        "pattern": rf"Red\s+Hat(?:\s+Enterprise\s+Linux)?(?:\s+release\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "operating_system",
        "os": "rhel",
    },
    {
        "id": "linux_kernel",
        "label": "Linux Kernel",
        "pattern": r"Linux(?:\s+kernel)?\s*(?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "flags": RE_I,
        "category": "operating_system",
        "os": "linux",
    },
    {
        "id": "freebsd_os",
        "label": "FreeBSD",
        "pattern": rf"FreeBSD(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "operating_system",
        "os": "freebsd",
    },
    {
        "id": "php_runtime",
        "label": "PHP",
        "pattern": rf"PHP/(?P<version>{_VERSION_FRAGMENT})",
        "flags": RE_I,
        "category": "runtime",
        "runtime": "php",
        "product": "php",
    },
    {
        "id": "python_runtime",
        "label": "Python",
        "pattern": rf"Python/(?P<version>{_VERSION_FRAGMENT})",
        "flags": RE_I,
        "category": "runtime",
        "runtime": "python",
        "product": "python",
    },
    {
        "id": "java_runtime",
        "label": "Java Runtime",
        "pattern": rf"(?:OpenJDK|Java(?:\s*Runtime(?:\s*Environment)?)?)(?:\s+version)?\s*\"?(?P<version>{_VERSION_FRAGMENT})\"?",
        "flags": RE_I,
        "category": "runtime",
        "runtime": "java",
        "product": "java",
    },
    {
        "id": "nodejs_runtime",
        "label": "Node.js",
        "pattern": rf"node\.js(?:\s+v?(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "runtime",
        "runtime": "node.js",
        "product": "node.js",
    },
    {
        "id": "dotnet_runtime",
        "label": ".NET",
        "pattern": rf"(?:ASP\.NET|\.NET(?:\s+Core)?)(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "runtime",
        "runtime": ".net",
        "product": ".net",
        "vendor": "microsoft",
    },
    {
        "id": "http_proto",
        "label": "HTTP Protocol",
        "pattern": r"\bHTTP/(?P<version>[0-9.]+)\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "http",
        "protocol": "HTTP",
    },
    {
        "id": "rtsp_proto",
        "label": "RTSP Protocol",
        "pattern": r"\bRTSP/(?P<version>[0-9.]+)\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "rtsp",
        "protocol": "RTSP",
    },
    {
        "id": "sip_proto",
        "label": "SIP Protocol",
        "pattern": r"\bSIP/(?P<version>[0-9.]+)\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "sip",
        "protocol": "SIP",
    },
    {
        "id": "ssh_proto",
        "label": "SSH Protocol",
        "pattern": r"\bSSH-(?P<version>[0-9.]+)-",
        "flags": RE_I,
        "category": "protocol",
        "service": "ssh",
        "protocol": "SSH",
    },
    {
        "id": "smtp_proto",
        "label": "SMTP Protocol",
        "pattern": r"\b(?:ESMTP|SMTP)\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "smtp",
        "protocol": "SMTP",
    },
    {
        "id": "ftp_proto",
        "label": "FTP Protocol",
        "pattern": r"^220[ -].*FTP",
        "flags": RE_IM,
        "category": "protocol",
        "service": "ftp",
        "protocol": "FTP",
    },
    {
        "id": "imap_proto",
        "label": "IMAP Protocol",
        "pattern": r"^\*\s+OK\s+.*IMAP",
        "flags": RE_IM,
        "category": "protocol",
        "service": "imap",
        "protocol": "IMAP",
    },
    {
        "id": "pop3_proto",
        "label": "POP3 Protocol",
        "pattern": r"^\+OK.*POP3",
        "flags": RE_IM,
        "category": "protocol",
        "service": "pop3",
        "protocol": "POP3",
    },
    {
        "id": "smb_proto",
        "label": "SMB Protocol",
        "pattern": r"\b(?:SMB|NT\s+LM\s+0\.12|LANMAN1\.0)\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "smb",
        "protocol": "SMB",
    },
    {
        "id": "mqtt_proto",
        "label": "MQTT Protocol",
        "pattern": r"\bMQTT\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "mqtt",
        "protocol": "MQTT",
    },
    {
        "id": "amqp_proto",
        "label": "AMQP Protocol",
        "pattern": r"\bAMQP\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "amqp",
        "protocol": "AMQP",
    },
    {
        "id": "redis_proto",
        "label": "Redis Protocol",
        "pattern": r"(?:redis_version:|\+PONG|\-ERR\s+unknown\s+command)",
        "flags": RE_I,
        "category": "protocol",
        "service": "redis",
        "protocol": "REDIS",
    },
    {
        "id": "ldap_proto",
        "label": "LDAP Protocol",
        "pattern": r"\bLDAP\b",
        "flags": RE_I,
        "category": "protocol",
        "service": "ldap",
        "protocol": "LDAP",
    },
    {
        "id": "dns_bind",
        "label": "BIND DNS",
        "pattern": rf"\bBIND(?:\s+(?P<version>{_VERSION_FRAGMENT}))?",
        "flags": RE_I,
        "category": "dns",
        "service": "dns",
        "protocol": "DNS",
        "product": "bind",
    },
]


def _compile_banner_rules(rules):
    compiled = []
    for raw_rule in rules or []:
        if not isinstance(raw_rule, dict):
            continue
        rule = dict(raw_rule)
        pattern = str(rule.get("pattern", "") or "")
        if not pattern:
            continue
        try:
            flags = int(rule.get("flags", 0) or 0)
        except Exception:
            flags = 0
        rule["flags"] = flags
        rule_id = str(rule.get("id", "") or "").strip()
        if not rule_id:
            rule_id = f"rule_{len(compiled) + 1:04d}"
        rule["id"] = rule_id
        label = str(rule.get("label", "") or "").strip() or rule_id
        rule["label"] = label
        try:
            rule["regex"] = re.compile(pattern, flags)
        except Exception:
            continue
        compiled.append(rule)
    return compiled


COMPILED_BANNER_REGEX_RULES = _compile_banner_rules(BANNER_REGEX_RULES)


def set_runtime_banner_rules(rules):
    global COMPILED_BANNER_REGEX_RULES
    compiled = _compile_banner_rules(rules)
    if not compiled:
        compiled = _compile_banner_rules(BANNER_REGEX_RULES)
    COMPILED_BANNER_REGEX_RULES = compiled
    return len(COMPILED_BANNER_REGEX_RULES)


def get_runtime_banner_rule_ids():
    output = []
    for rule in COMPILED_BANNER_REGEX_RULES:
        rule_id = str((rule or {}).get("id", "") or "").strip()
        if rule_id:
            output.append(rule_id)
    return output


_PROTOCOL_ALIASES = {
    "http": "HTTP",
    "https": "HTTPS",
    "ssh": "SSH",
    "ftp": "FTP",
    "smtp": "SMTP",
    "pop3": "POP3",
    "imap": "IMAP",
    "smb": "SMB",
    "dns": "DNS",
    "rtsp": "RTSP",
    "sip": "SIP",
    "mqtt": "MQTT",
    "amqp": "AMQP",
    "ldap": "LDAP",
    "redis": "REDIS",
    "rfb": "RFB",
    "tds": "TDS",
    "tns": "TNS",
    "mysql": "MYSQL",
    "postgresql": "POSTGRESQL",
    "mongodb": "MONGODB",
    "openwire": "OPENWIRE",
    "nats": "NATS",
}

_SERVER_ALIASES = {
    "nginx": "Nginx",
    "apache": "Apache",
    "microsoft-iis": "IIS",
    "iis": "IIS",
    "openresty": "OpenResty",
    "lighttpd": "lighttpd",
    "caddy": "Caddy",
    "envoy": "Envoy",
    "traefik": "Traefik",
    "squid": "Squid",
    "varnish": "Varnish",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "werkzeug": "Werkzeug",
    "apache-coyote": "Tomcat",
    "jetty": "Jetty",
}

_PRODUCT_ALIASES = {
    "microsoft-iis": "iis",
    "iis": "iis",
    "apache-coyote": "tomcat",
    "apache tomcat": "tomcat",
    "microsoft sql server": "microsoft sql server",
    "asp.net": "asp.net",
}

_VENDOR_BY_PRODUCT = {
    "iis": "microsoft",
    "asp.net": "microsoft",
    ".net": "microsoft",
    "microsoft sql server": "microsoft",
    "exchange": "microsoft",
    "mysql": "oracle",
    "oracle": "oracle",
    "nginx": "nginx",
    "apache": "apache",
    "postgresql": "postgresql",
    "mariadb": "mariadb",
    "redis": "redis",
    "rabbitmq": "vmware",
    "tomcat": "apache",
}

_HEADER_RE = re.compile(r"(?im)^([A-Za-z][A-Za-z0-9\-]{1,63}):\s*([^\r\n]{1,600})$")
_PROTO_LINE_RE = re.compile(r"(?im)^(HTTP|RTSP|SIP)/([0-9.]+)(?:\s+([0-9]{3}))?")
_AUTH_SCHEME_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_\-]{0,31})")
_REALM_RE = re.compile(r"realm=\"?([^\",]+)", re.IGNORECASE)
_SLASH_VERSION_RE = re.compile(r"/(?P<version>[0-9][0-9A-Za-z.\-_+]*)")
_GENERIC_VERSION_RE = re.compile(r"\b(?P<version>[0-9]{1,4}(?:\.[0-9A-Za-z]{1,12}){1,4})\b")


def _sanitize_value(value, max_len=240):
    cleaned = " ".join(str(value or "").split())
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def _stage_payload_with_tempfile(payload):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix="porthound-banner-",
            suffix=".bin",
            delete=False,
        ) as handler:
            handler.write(payload)
            handler.flush()
            tmp_path = handler.name
        with open(tmp_path, "rb") as handler:
            return handler.read()
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _normalize_protocol(value):
    raw = _sanitize_value(value, max_len=64)
    if not raw:
        return ""
    if "/" in raw:
        prefix, suffix = raw.split("/", 1)
        base = _PROTOCOL_ALIASES.get(prefix.strip().lower(), prefix.strip().upper())
        return _sanitize_value(f"{base}/{suffix.strip()}", max_len=64)
    return _PROTOCOL_ALIASES.get(raw.strip().lower(), raw.strip().upper())


def _normalize_server(value):
    raw = _sanitize_value(value, max_len=96)
    if not raw:
        return ""
    token = raw.split(",", 1)[0].split(";", 1)[0].strip()
    token = token.split(" ", 1)[0].strip()
    token = token.split("/", 1)[0].strip()
    token = token.split("(", 1)[0].strip()
    if not token:
        token = raw
    lookup = token.lower()
    if lookup in _SERVER_ALIASES:
        return _SERVER_ALIASES[lookup]
    if token.islower():
        return token.capitalize()
    return _sanitize_value(token, max_len=64)


def _normalize_product(value):
    raw = _sanitize_value(value, max_len=96)
    if not raw:
        return ""
    token = raw.split("/", 1)[0].strip().lower()
    return _sanitize_value(_PRODUCT_ALIASES.get(token, token), max_len=64)


def _infer_vendor(product):
    key = _sanitize_value(product, max_len=80).lower()
    return _VENDOR_BY_PRODUCT.get(key, "")


def _extract_version(text):
    value = _sanitize_value(text, max_len=200)
    if not value:
        return ""
    match = _SLASH_VERSION_RE.search(value)
    if match:
        return _sanitize_value(match.group("version"), max_len=64)
    match = _GENERIC_VERSION_RE.search(value)
    if not match:
        return ""
    candidate = _sanitize_value(match.group("version"), max_len=64)
    if candidate.count(".") == 3 and all(part.isdigit() for part in candidate.split(".")):
        return ""
    return candidate


def _rule_field(rule, groups, field, normalizer=None):
    value = rule.get(field, "") or groups.get(field, "")
    value = _sanitize_value(value, max_len=64)
    if normalizer:
        value = normalizer(value)
    return _sanitize_value(value, max_len=64)


def apply_banner_rules(banner_text):
    findings = []
    seen = set()
    text = str(banner_text or "")
    for rule in COMPILED_BANNER_REGEX_RULES:
        for match in rule["regex"].finditer(text):
            groups = {
                key: _sanitize_value(value, max_len=120)
                for key, value in (match.groupdict() or {}).items()
                if value
            }
            version = _rule_field(rule, groups, "version")
            protocol = _rule_field(rule, groups, "protocol", normalizer=_normalize_protocol)
            server = _rule_field(rule, groups, "server")
            if not server and groups.get("server"):
                server = _sanitize_value(_normalize_server(groups.get("server", "")), max_len=64)
            hit = _sanitize_value(match.group(0), max_len=180)
            key = (rule["id"], version, hit)
            if key in seen:
                continue
            seen.add(key)

            summary = rule["label"]
            if version:
                summary += f" v{version}"
            if hit:
                summary += f" | {hit}"

            findings.append(
                {
                    "rule_id": rule["id"],
                    "label": rule["label"],
                    "category": _rule_field(rule, groups, "category"),
                    "service": _rule_field(rule, groups, "service"),
                    "protocol": protocol,
                    "server": _sanitize_value(server, max_len=64),
                    "product": _rule_field(rule, groups, "product"),
                    "os": _rule_field(rule, groups, "os"),
                    "version": version,
                    "runtime": _rule_field(rule, groups, "runtime"),
                    "framework": _rule_field(rule, groups, "framework"),
                    "vendor": _rule_field(rule, groups, "vendor"),
                    "powered_by": _rule_field(rule, groups, "powered_by"),
                    "hit": hit,
                    "summary": _sanitize_value(summary, max_len=220),
                }
            )
    return findings


def _extract_banner_context(banner_text):
    text = str(banner_text or "")
    context = {
        "protocol": set(),
        "protocol_version": set(),
        "http_status": set(),
        "server": set(),
        "server_header": set(),
        "service": set(),
        "product": set(),
        "version": set(),
        "runtime": set(),
        "framework": set(),
        "vendor": set(),
        "powered_by": set(),
        "auth_scheme": set(),
        "realm": set(),
        "via": set(),
    }

    def add(field, value, normalizer=None, max_len=120):
        candidate = _sanitize_value(value, max_len=max_len)
        if normalizer:
            candidate = normalizer(candidate)
        candidate = _sanitize_value(candidate, max_len=max_len)
        if candidate:
            context[field].add(candidate)

    for match in _PROTO_LINE_RE.finditer(text):
        proto = _normalize_protocol(match.group(1))
        if proto:
            add("protocol", proto)
            version = _sanitize_value(match.group(2), max_len=16)
            if version:
                add("protocol_version", f"{proto}/{version}")
            status = _sanitize_value(match.group(3), max_len=8)
            if status:
                add("http_status", status)

    if re.search(r"(?im)^SSH-[0-9.]+-", text):
        add("protocol", "SSH")
        add("service", "ssh")
    if re.search(r"(?im)^220[ -].*ESMTP", text):
        add("protocol", "SMTP")
        add("service", "smtp")
    if re.search(r"(?im)^220[ -].*FTP", text):
        add("protocol", "FTP")
        add("service", "ftp")
    if re.search(r"(?im)^\*\s+OK\s+.*IMAP", text):
        add("protocol", "IMAP")
        add("service", "imap")
    if re.search(r"(?im)^\+OK.*POP3", text):
        add("protocol", "POP3")
        add("service", "pop3")

    headers = {}
    for match in _HEADER_RE.finditer(text):
        key = _sanitize_value(match.group(1), max_len=64).lower()
        value = _sanitize_value(match.group(2), max_len=240)
        if not key or not value:
            continue
        headers.setdefault(key, set()).add(value)

    for raw in headers.get("server", set()):
        add("server_header", raw, max_len=220)
        server = _normalize_server(raw)
        add("server", server)
        if server:
            product = _normalize_product(server)
            add("product", product)
            add("vendor", _infer_vendor(product))
        version = _extract_version(raw)
        if version:
            add("version", version)

    for raw in headers.get("x-powered-by", set()):
        add("powered_by", raw)
        token = raw.split(";", 1)[0].strip()
        product = _normalize_product(token)
        add("product", product)
        if product:
            add("vendor", _infer_vendor(product))
        version = _extract_version(raw)
        if version:
            add("version", version)
        lowered = raw.lower()
        if "php" in lowered:
            add("runtime", "php")
        if "express" in lowered:
            add("framework", "express")
            add("runtime", "node.js")
        if "asp.net" in lowered:
            add("framework", "asp.net")
            add("runtime", ".net")
            add("vendor", "microsoft")

    for header_name in ("x-generator", "generator"):
        for raw in headers.get(header_name, set()):
            token = raw.split(";", 1)[0].strip()
            add("framework", token)
            product = _normalize_product(token)
            add("product", product)
            if product:
                add("vendor", _infer_vendor(product))
            version = _extract_version(raw)
            if version:
                add("version", version)

    for header_name in ("x-aspnet-version", "x-aspnetmvc-version"):
        for raw in headers.get(header_name, set()):
            add("framework", "asp.net")
            add("runtime", ".net")
            add("vendor", "microsoft")
            add("version", _extract_version(raw))

    for raw in headers.get("www-authenticate", set()):
        match = _AUTH_SCHEME_RE.match(raw)
        if match:
            add("auth_scheme", match.group(1))
        realm_match = _REALM_RE.search(raw)
        if realm_match:
            add("realm", realm_match.group(1), max_len=120)

    for raw in headers.get("via", set()):
        add("via", raw, max_len=180)
        lowered = raw.lower()
        if "varnish" in lowered:
            add("server", "Varnish")
            add("product", "varnish")
        if "squid" in lowered:
            add("server", "Squid")
            add("product", "squid")

    return context


def _collect_findings_values(
    findings, field, normalizer=None, max_len=80, include=None
):
    values = set()
    for item in findings or []:
        if include and not include(item):
            continue
        raw = _sanitize_value(item.get(field, ""), max_len=max_len)
        if not raw:
            continue
        value = normalizer(raw) if normalizer else raw
        value = _sanitize_value(value, max_len=max_len)
        if value:
            values.add(value)
    return values


def review_banner_payload(payload):
    original_payload = bytes(payload or b"")
    try:
        staged_payload = _stage_payload_with_tempfile(original_payload)
    except Exception:
        staged_payload = original_payload
    text = staged_payload.decode("utf-8", errors="replace")
    try:
        findings = apply_banner_rules(text)
    except Exception:
        findings = []
    return {
        "payload": staged_payload,
        "text": text,
        "findings": findings,
    }


def build_banner_rule_tags(ip, port, proto, findings, banner_text=""):
    tag_rows = []
    used_keys = set()

    def push(key, value):
        safe_key = _sanitize_value(key, max_len=120)
        safe_value = _sanitize_value(value, max_len=240)
        if not safe_key or not safe_value:
            return
        if safe_key in used_keys:
            return
        used_keys.add(safe_key)
        tag_rows.append(
            {
                "ip": ip,
                "port": port,
                "proto": proto,
                "key": safe_key,
                "value": safe_value,
            }
        )

    findings = findings or []
    context = _extract_banner_context(banner_text)

    for finding in findings:
        rule_id = _sanitize_value(finding.get("rule_id", ""), max_len=80)
        if not rule_id:
            continue
        push(f"banner.rule.{rule_id}", finding.get("summary", ""))

    aggregate_fields = (
        "category",
        "service",
        "protocol",
        "protocol_version",
        "product",
        "server",
        "os",
        "version",
        "runtime",
        "framework",
        "vendor",
        "powered_by",
        "http_status",
        "auth_scheme",
        "realm",
        "via",
        "server_header",
    )

    merged_values = {field: set() for field in aggregate_fields}

    for field in aggregate_fields:
        if field in context:
            merged_values[field].update(context[field])

    for field in (
        "category",
        "service",
        "protocol",
        "product",
        "server",
        "os",
        "version",
        "runtime",
        "framework",
        "vendor",
        "powered_by",
    ):
        normalizer = _normalize_protocol if field == "protocol" else None
        include = None
        if field == "version":
            include = lambda item: _sanitize_value(  # noqa: E731
                item.get("category", ""), max_len=64
            ) != "protocol"
        merged_values[field].update(
            _collect_findings_values(
                findings,
                field,
                normalizer=normalizer,
                include=include,
            )
        )

    plain_fields = {
        "category",
        "service",
        "protocol",
        "protocol_version",
        "product",
        "server",
        "os",
        "version",
        "runtime",
        "framework",
        "vendor",
        "powered_by",
        "http_status",
        "auth_scheme",
        "realm",
        "via",
    }

    for field in aggregate_fields:
        values = sorted(merged_values.get(field, set()))
        if not values:
            continue
        joined = ", ".join(values)
        push(f"banner.{field}", joined)
        if field in plain_fields:
            push(field, joined)

    if findings:
        push("banner.rule_count", str(len(findings)))

    return tag_rows


__all__ = [
    "BANNER_REGEX_RULES",
    "apply_banner_rules",
    "review_banner_payload",
    "build_banner_rule_tags",
    "set_runtime_banner_rules",
    "get_runtime_banner_rule_ids",
]
