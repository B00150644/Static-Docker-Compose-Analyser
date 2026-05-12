# checks/no_resource_limits.py
# detects services that have no memory or cpu limits set
# without resource limits a container can consume all available host memory and cpu
# this is a best practice violation rather than a confirmed vulnerability on its own
# it only becomes a real problem if the container misbehaves or is compromised
# but it increases risk and goes against the principle of least privilege for resources

# docker compose supports limits in two ways depending on the compose version:

#older compose v2 style
#mem_limit: 512m
#cpus: '0.5'

# compose v3+ deploy
#deploy:
#resources:
#limits:
#memory: 512m
#cpus: '0.5'
# both are checked here so files using either format are covered
CHECK_NAME = "No Resource Limits"

def has_memory_limit(service_config):
    # check short syntax
    if service_config.get("mem_limit"):
        return True
    # check long syntax under deploy.resources.limits
    deploy = service_config.get("deploy", {})
    if isinstance(deploy, dict):
        resources = deploy.get("resources", {})
        if isinstance(resources, dict):
            limits = resources.get("limits", {})
            if isinstance(limits, dict) and limits.get("memory"):
                return True
    return False


def has_cpu_limit(service_config):
    # check short syntax
    if service_config.get("cpus"):
        return True
    # check long syntax under deploy.resources.limits
    deploy = service_config.get("deploy", {})
    if isinstance(deploy, dict):
        resources = deploy.get("resources", {})
        if isinstance(resources, dict):
            limits = resources.get("limits", {})
            if isinstance(limits, dict) and limits.get("cpus"):
                return True
    return False


def run(compose):
    findings = []
    services = compose.get("services", {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        memory = has_memory_limit(service_config)
        cpu = has_cpu_limit(service_config)

        if not memory and not cpu:
            # no limits at all - best practice violation, risk increases if container
            # is compromised but not a confirmed vulnerability on its own
            findings.append({
                "service": service_name,
                "severity": "MEDIUM",
                "value": "no mem_limit or cpus set",
                "detail": "No memory or CPU limits are set. This is a best practice violation that may increase risk if the container misbehaves or is compromised, potentially impacting other services on the host.",
                "fix": "Set mem_limit and cpus at the service level, or define limits under deploy.resources.limits.",
            })

        elif not memory:
            # cpu is set but memory isnt partial coverage still worth flagging
            findings.append({
                "service": service_name,
                "severity": "LOW",
                "value": "no mem_limit set",
                "detail": "No memory limit is set. The container could potentially consume unlimited host memory if it misbehaves or is compromised.",
                "fix": "Set mem_limit at the service level or memory under deploy.resources.limits.",
            })

        elif not cpu:
            # memory is set but cpu isnt still worth flagging
            findings.append({
                "service": service_name,
                "severity": "LOW",
                "value": "no cpus limit set",
                "detail": "No CPU limit is set. The container could potentially consume unlimited host CPU if it misbehaves or is compromised.",
                "fix": "Set cpus at the service level or cpus under deploy.resources.limits.",
            })

    return findings