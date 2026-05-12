# checks/running_as_root.py
# detects services that are running as root inside the container
# if no user is set at all the container defaults to whatever the image specifies usually makes docker file safe
# if the image doesnt set a user it defaults to root
# if root is set as trrue overwrites any config in base image
# we flag both cases set to root and no user set at all
CHECK_NAME = "Running as Root"

ROOT_VALUES = ["root", "0", "0:0"]

def run(compose):
    findings = []
    services = compose.get("services", {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        user = service_config.get("user", None)

        if user is not None:
            # user is explicitly set - check if its root
            user_str = str(user).strip()
            if user_str in ROOT_VALUES:
                findings.append({
                    "service": service_name,
                    "severity": "HIGH",
                    "value": f"user: {user}",
                    "detail": "The container is explicitly configured to run as root. If compromised, an attacker has immediate root access within the container.",
                    "fix": "Create a non-root user in your Dockerfile and set user: to that user or a non-zero UID.",
                })
        else:
            # no user set may default to root depending on the image
            # cant confirm this without inspecting the image itself so flagged as informational
            findings.append({
                "service": service_name,
                "severity": "MEDIUM",
                "value": "no user set",
                "detail": "Informational: no user directive found in the Compose file. The container may run as root depending on the base image. If combined with other misconfigurations such as privileged mode or unsafe volume mounts this can become a medium risk issue.",
                "fix": "Set user: to a non-root user or non-zero UID to explicitly prevent root execution regardless of the base image.",
            })

    return findings