# checks/docker_socket.py
# Detects services that mount the Docker socket from the host.
 
CHECK_NAME = "Docker Socket Exposure"
 
def run(compose: dict) -> list[dict]:
    #Check each service for a volume mount containing /var/run/docker.sock.Returns a list of finding dicts (empty if none found).
    findings = []
    services = compose.get("services", {})
 
    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue
 
        volumes = service_config.get("volumes", [])
 
        for volume in volumes:
            # volumes can be a string "host:container" or a dict with source/target
            if isinstance(volume, str):
                if "/var/run/docker.sock" in volume:
                    findings.append({
                        "service":  service_name,
                        "severity": "HIGH",
                        "value":    volume,
                        "detail":   "Mounting the Docker socket gives the container full control over the Docker daemon, enabling host takeover.",
                        "fix":      "Remove the Docker socket mount. If container management access is required, restrict access using Unix socket permissions or protect the API with TLS.",
                    })
 
            elif isinstance(volume, dict):
                source = volume.get("source", "")
                if "/var/run/docker.sock" in source:
                    findings.append({
                        "service":  service_name,
                        "severity": "HIGH",
                        "value":    source,
                        "detail":   "Mounting the Docker socket gives the container full control over the Docker daemon, enabling host takeover.",
                        "fix":      "Remove the Docker socket mount. If container management access is required, restrict access using Unix socket permissions or protect the API with TLS.",
                    })
 
    return findings