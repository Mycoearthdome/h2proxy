[Unit]
Description=HTTP/2 Proxy with Cloudflare IP Filtering
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/h2proxy/h2proxy.py
WorkingDirectory=/opt/h2proxy
Restart=always
RestartSec=5

# Capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true

# Logging (journald)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=h2proxy

# Resource hardening
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/log/h2proxy
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
