# checks/network_mode.py
# Detects services using host network mode, which removes Docker network isolation.
 
CHECK_NAME = "Host Network Mode"
def run(compose: dict) -> list[dict]:
   # Check each service for network_mode: host.Returns a list of finding dicts (empty if none found)
    findings = []
    services = compose.get("services", {})
 
    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue
 
        network_mode = service_config.get("network_mode", "")
 
        if network_mode == "host":
            findings.append({
                "service":  service_name,
                "severity": "MEDIUM",
                "value":    network_mode,
                "detail":   "Removes Docker network isolation, container shares host network stack directly.",
                "fix":      "Use bridge networking and expose only required ports with the 'ports' directive.",
            })
 
    return findings