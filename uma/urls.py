def is_domain_local(domain: str) -> bool:
    domain_tld = domain.split(".")[-1].split(":")[0]
    return (
        domain.startswith("localhost:")
        or domain.startswith("127.0.0.1:")
        or domain_tld == "local"
        or domain_tld == "internal"
    )
