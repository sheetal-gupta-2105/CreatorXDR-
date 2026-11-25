def mask_email(email: str) -> str:
    """Mask an email address for safe logging (e.g., g***@gmail.com)."""
    if not email or "@" not in email:
        return "***"
    local, domain = email.rsplit("@", 1)
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"
