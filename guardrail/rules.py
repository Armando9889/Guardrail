import re


ALLOWED_SECURITY_PROFILES = {"web", "database", "general"}


def check_instance(instance, policy):
    """Verifica una VM e restituisce l'elenco delle violazioni."""
    violations = []

    def add_violation(rule, message, severity="medium"):
        violations.append({
            "rule": rule,
            "message": message,
            "severity": severity,
            "instance_id": str(instance.get("id", "")),
            "instance_name": str(instance.get("name", "")),
        })

    # R1: owner obbligatorio e valido.
    metadata = instance.get("metadata") or {}
    owner = metadata.get("owner")

    if not isinstance(owner, str) or not owner.strip():
        add_violation("R1", "Metadato owner mancante o vuoto.")

    # R2: limite di RAM per singola VM.
    ram_mb = instance.get("ram_mb")
    max_ram_mb = policy.get("max_ram_mb")

    if (
        isinstance(ram_mb, int)
        and not isinstance(ram_mb, bool)
        and isinstance(max_ram_mb, int)
        and ram_mb > max_ram_mb
    ):
        add_violation("R2", f"RAM {ram_mb} MB superiore al limite {max_ram_mb} MB.")

    # R3: limite di vCPU per singola VM.
    vcpus = instance.get("vcpus")
    max_vcpus = policy.get("max_vcpus")

    if (
        isinstance(vcpus, int)
        and not isinstance(vcpus, bool)
        and isinstance(max_vcpus, int)
        and vcpus > max_vcpus
    ):
        add_violation("R3", f"vCPU {vcpus} superiore al limite {max_vcpus}.")

    # R4: immagine presente nella allowlist.
    image_id = instance.get("image_id")
    allowed_images = policy.get("allowed_image_ids", [])

    if image_id not in allowed_images:
        add_violation(
            "R4",
            f"Immagine {image_id!r} non presente nella lista autorizzata.",
            severity="critical",
        )

    # R5: nome conforme al pattern configurato.
    name = instance.get("name") or ""
    name_pattern = policy.get("name_pattern", r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
    max_name_length = policy.get("max_name_length", 50)

    try:
        valid_name = (
            isinstance(name, str)
            and len(name) <= max_name_length
            and re.fullmatch(name_pattern, name) is not None
        )
    except (TypeError, re.error):
        valid_name = False

    if not valid_name:
        add_violation("R5", "Nome della VM non conforme alla policy.")

    # R6: profilo di sicurezza ammesso.
    profile = metadata.get("security_profile")

    if profile not in ALLOWED_SECURITY_PROFILES:
        add_violation(
            "R6",
            "security_profile mancante o non valido.",
            severity="critical",
        )

    # R7: stato ERROR persistente per più scansioni.
    error_count = instance.get("consecutive_error_scans", 0)
    required_error_scans = policy.get("error_scan_threshold", 3)

    if (
        isinstance(error_count, int)
        and not isinstance(error_count, bool)
        and isinstance(required_error_scans, int)
        and error_count >= required_error_scans
    ):
        add_violation(
            "R7",
            f"VM in stato ERROR per {error_count} scansioni consecutive.",
            severity="high",
        )

    # R8: superamento dei limiti aggregati del progetto.
    project_ram_mb = instance.get("project_ram_mb")
    project_vcpus = instance.get("project_vcpus")
    max_project_ram_mb = policy.get("max_project_ram_mb")
    max_project_vcpus = policy.get("max_project_vcpus")

    if (
        isinstance(project_ram_mb, int)
        and not isinstance(project_ram_mb, bool)
        and isinstance(max_project_ram_mb, int)
        and project_ram_mb > max_project_ram_mb
    ):
        add_violation(
            "R8",
            f"RAM complessiva del progetto {project_ram_mb} MB "
            f"superiore al limite {max_project_ram_mb} MB.",
        )

    if (
        isinstance(project_vcpus, int)
        and not isinstance(project_vcpus, bool)
        and isinstance(max_project_vcpus, int)
        and project_vcpus > max_project_vcpus
    ):
        add_violation(
            "R8",
            f"vCPU complessive del progetto {project_vcpus} "
            f"superiori al limite {max_project_vcpus}.",
        )

    return violations
