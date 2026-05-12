# checks/capabilities.py
# detects services that add excessive linux capabilities via cap_add
# cap_add lets you grant extra kernel privileges to a container beyond dockers defaults
# some of these are dangerous enough to allow full host escape
CHECK_NAME = "Excessive Linux Capabilities"
# these are flagged HIGH - they give broad kernel access and undermine container isolation
# ALL is equivalent to privileged:true, SYS_ADMIN is known as the new root,
# SYS_MODULE lets you load kernel code, SYS_PTRACE can attach to host processes,
# SYS_BOOT can replace the running kernel, SYS_RAWIO gives raw memory access
HIGH_CAPABILITIES = [
    "ALL",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_BOOT",
    "SYS_RAWIO",
]

# these are flagged MEDIUM still risky but more situational
# NET_ADMIN can modify firewall rules and routing, NET_RAW allows packet crafting,
# DAC_OVERRIDE bypasses file permissions, DAC_READ_SEARCH bypasses read checks
MEDIUM_CAPABILITIES = [
    "NET_ADMIN",
    "NET_RAW",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
]

def run(compose):
    findings = []
    services = compose.get("services", {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        cap_add = service_config.get("cap_add", [])

        if not isinstance(cap_add, list):
            continue

        for cap in cap_add:
            cap_upper = cap.upper()

            if cap_upper in HIGH_CAPABILITIES:
                findings.append({
                    "service": service_name,
                    "severity": "HIGH",
                    "value": f"cap_add: {cap}",
                    "detail": f"Capability '{cap}' grants broad kernel-level access and significantly undermines container isolation.",
                    "fix": "Remove this capability. If specific functionality is required, identify the minimal capability needed and document the justification.",
                })

            elif cap_upper in MEDIUM_CAPABILITIES:
                findings.append({
                    "service": service_name,
                    "severity": "MEDIUM",
                    "value": f"cap_add: {cap}",
                    "detail": f"Capability '{cap}' expands the container attack surface and may be exploited depending on the deployment context.",
                    "fix": "Review whether this capability is strictly necessary. If so, ensure the container is otherwise hardened and the justification is documented.",
                })

    return findings