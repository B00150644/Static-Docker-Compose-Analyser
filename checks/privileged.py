# checks/privileged.py
# Detects services ran with privileged mode enabled.
 
CHECK_NAME = "Privileged Container"
 
 
def run(compose: dict) -> list[dict]:
#Check each service for privileged: true.
#Returns a list of finding dicts (empty if none found).
    findings = []
    services = compose.get("services", {})
 
    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue
 
        privileged = service_config.get("privileged", False)
 
        if privileged is True:
            findings.append({
                "service":  service_name,
                "severity": "HIGH",
                "value":    "privileged: true",
                "detail":   "Grants the container full access to the host kernel, making container escape trivial.",
                "fix":      "Remove privileged mode and grant only the specific Linux capabilities the container needs.",
            })
 
    return findings