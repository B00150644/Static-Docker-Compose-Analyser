# checks/host_volumes.py
# detects services that mount sensitive host directories into containers
# when a host path is bind mounted into a container, the container can read/write
# those files directly which can expose system configs, credentials or allow host escape
CHECK_NAME = "Unsafe Host Volume Mount"
# paths flagged as HIGH - these are critical system directories
# / gives full filesystem access, /etc has passwd and sudoers, /root and /home have ssh keys,
# /proc and /sys are kernel interfaces used in escape attacks,
# /var/run contains the docker socket, /boot has kernel images,
# /lib and /usr/lib are system libraries, /dev can expose raw hardware devices
SENSITIVE_PATHS = [
    "/",
    # removed /var/run that wass here docker_socket.py handles that already
    "/etc",
    "/root",
    "/home",
    "/proc",
    "/sys",
    "/boot",
    "/lib",
    "/usr/lib",
    "/dev",
]
# known safe paths that fall under a sensitive directory but are common harmless mounts
# excluded to avoid false positives in the dataset
# /etc/localtime and /etc/timezone are mounted read only to sync the timezone between
# container and host they have no credentials or important info and are flagging would be pointless
EXCLUDED_PATHS = [
    "/etc/localtime",
    "/etc/timezone",
    "/var/run/docker.sock",  # handled already but by docker_socket.py kept here so host_volumes doesnt flag it as a LOW mount
]


def get_host_path(volume):
    # handles both short syntax "host:container" and long form dict syntax
    if isinstance(volume, str):
        parts = volume.split(":")
        host_part = parts[0] if len(parts) > 1 else None
        if host_part and (host_part.startswith("/") or host_part.startswith(".")):
            return host_part
    elif isinstance(volume, dict):
        source = volume.get("source", "")
        bind_type = volume.get("type", "")
        if bind_type == "bind" or (source and source.startswith("/")):
            return source
    return None


def is_excluded(host_path):
    for excluded in EXCLUDED_PATHS:
        if host_path == excluded:
            return True
    return False


def is_sensitive(host_path):
    for sensitive in SENSITIVE_PATHS:
        if host_path == sensitive or host_path.startswith(sensitive + "/"):
            return True
    return False


def run(compose):
    findings = []
    services = compose.get("services", {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        volumes = service_config.get("volumes", [])

        for volume in volumes:
            host_path = get_host_path(volume)
            if not host_path:
                continue
            # check exclusions first before anything else
            if is_excluded(host_path):
                continue

            if is_sensitive(host_path):
                findings.append({
                    "service": service_name,
                    "severity": "HIGH",
                    "value": str(volume),
                    "detail": f"Sensitive host path '{host_path}' is mounted into the container, exposing critical system resources.",
                    "fix": "Remove the host path mount. Use named Docker volumes for persistent data and avoid mounting system directories into containers.",
                })

            elif host_path.startswith("/"):
                # absolute path that isnt on the sensitive list above
                # flagged as LOW because without inspecting the directory contents cant
                # confirm this is actually a risk it depends entirely on what is in that path
                # if the path contains credentials or secrets or config files it becomes a real issue
                # but a path like /opt/myapp/data may be completely harmless
                # flagged for review rather than as a major vulnerability
                findings.append({
                    "service": service_name,
                    "severity": "LOW",
                    "value": str(volume),
                    "detail": f"Absolute host path '{host_path}' is bind-mounted into the container. The risk depends on the contents of this directory and cannot be confirmed by static analysis alone.",
                    "fix": "Review whether this bind mount is necessary and check the directory does not contain secrets or credentials. Prefer named Docker volumes where possible.",
                })

    return findings