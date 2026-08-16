import dns.resolver
import dns.reversename


# --------------------------------------------------
# Get DNS records
# --------------------------------------------------

def get_record(domain, record_type):

    try:
        answers = dns.resolver.resolve(domain, record_type)

        return answers

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout
    ):
        return None

    except Exception:
        return None


# --------------------------------------------------
# Print normal DNS records
# --------------------------------------------------

def print_records(record_type, answers):

    print(f"\n[{record_type} RECORDS]")

    if answers is None:
        print("  No record found")
        return

    ttl = answers.rrset.ttl

    print(f"  TTL : {ttl} seconds\n")

    for answer in answers:
        print(f"  • {answer}")


# --------------------------------------------------
# SOA Record
# --------------------------------------------------

def print_soa(domain):

    answers = get_record(domain, "SOA")

    print("\n[SOA RECORD]")

    if answers is None:
        print("  No record found")
        return False

    soa = answers[0]

    print(f"  Primary Name Server : {soa.mname}")
    print(f"  Responsible Email   : {soa.rname}")
    print(f"  Serial Number       : {soa.serial}")
    print(f"  Refresh             : {soa.refresh} seconds")
    print(f"  Retry               : {soa.retry} seconds")
    print(f"  Expire              : {soa.expire} seconds")
    print(f"  Minimum TTL         : {soa.minimum} seconds")

    return True


# --------------------------------------------------
# CAA Record
# --------------------------------------------------

def print_caa(domain):

    answers = get_record(domain, "CAA")

    print("\n[CAA RECORDS]")

    if answers is None:
        print("  No CAA record found")
        return False

    print(f"  TTL : {answers.rrset.ttl} seconds\n")

    for answer in answers:
        print(f"  • {answer}")

    return True


# --------------------------------------------------
# Reverse DNS / PTR
# --------------------------------------------------

def reverse_dns(ip):

    try:

        reverse_name = dns.reversename.from_address(ip)

        answers = dns.resolver.resolve(
            reverse_name,
            "PTR"
        )

        return answers

    except Exception:
        return None


def print_reverse_dns(a_records):

    print("\n[REVERSE DNS / PTR]")

    if a_records is None:
        print("  No IPv4 address available")
        return False

    found = False

    for record in a_records:

        ip = str(record)

        ptr_records = reverse_dns(ip)

        print(f"\n  IP : {ip}")

        if ptr_records:

            for ptr in ptr_records:
                print(f"  PTR: {ptr}")

            found = True

        else:
            print("  PTR: No reverse DNS record")

    return found


# --------------------------------------------------
# Detect SPF
# --------------------------------------------------

def has_spf(txt_records):

    if txt_records is None:
        return False

    for record in txt_records:

        text = str(record).lower()

        if "v=spf1" in text:
            return True

    return False


# --------------------------------------------------
# Check DNSSEC
# --------------------------------------------------

def check_dnssec(domain):

    try:

        answers = dns.resolver.resolve(
            domain,
            "DNSKEY"
        )

        return len(answers) > 0

    except Exception:
        return False


# --------------------------------------------------
# Summary
# --------------------------------------------------

def print_summary(
    a_records,
    aaaa_records,
    mx_records,
    txt_records,
    caa_found,
    ptr_found,
    dnssec
):

    print("\n" + "=" * 60)
    print("                     DNS SUMMARY")
    print("=" * 60)

    print(
        f"  IPv4 Available      : "
        f"{'YES' if a_records else 'NO'}"
    )

    print(
        f"  IPv6 Available      : "
        f"{'YES' if aaaa_records else 'NO'}"
    )

    print(
        f"  Mail Server (MX)    : "
        f"{'YES' if mx_records else 'NO'}"
    )

    print(
        f"  SPF Record          : "
        f"{'YES' if has_spf(txt_records) else 'NO'}"
    )

    print(
        f"  CAA Record          : "
        f"{'YES' if caa_found else 'NO'}"
    )

    print(
        f"  Reverse DNS         : "
        f"{'YES' if ptr_found else 'NO'}"
    )

    print(
        f"  DNSSEC              : "
        f"{'YES' if dnssec else 'NO'}"
    )

    print("=" * 60)


# --------------------------------------------------
# Main DNS lookup
# --------------------------------------------------

def lookup(domain):

    # Remove accidental spaces
    domain = domain.strip()

    print("\n" + "=" * 60)
    print("                   DNS RECON REPORT")
    print("=" * 60)

    print(f"\nDomain : {domain}")

    # --------------------------------------------------
    # A
    # --------------------------------------------------

    a_records = get_record(domain, "A")

    print_records(
        "A",
        a_records
    )

    # --------------------------------------------------
    # AAAA
    # --------------------------------------------------

    aaaa_records = get_record(domain, "AAAA")

    print_records(
        "AAAA",
        aaaa_records
    )

    # --------------------------------------------------
    # MX
    # --------------------------------------------------

    mx_records = get_record(domain, "MX")

    print_records(
        "MX",
        mx_records
    )

    # --------------------------------------------------
    # NS
    # --------------------------------------------------

    ns_records = get_record(domain, "NS")

    print_records(
        "NS",
        ns_records
    )

    # --------------------------------------------------
    # CNAME
    # --------------------------------------------------

    cname_records = get_record(domain, "CNAME")

    print_records(
        "CNAME",
        cname_records
    )

    # --------------------------------------------------
    # TXT
    # --------------------------------------------------

    txt_records = get_record(domain, "TXT")

    print_records(
        "TXT",
        txt_records
    )

    # --------------------------------------------------
    # SOA
    # --------------------------------------------------

    print_soa(domain)

    # --------------------------------------------------
    # CAA
    # --------------------------------------------------

    caa_found = print_caa(domain)

    # --------------------------------------------------
    # Reverse DNS
    # --------------------------------------------------

    ptr_found = print_reverse_dns(
        a_records
    )

    # --------------------------------------------------
    # DNSSEC
    # --------------------------------------------------

    dnssec = check_dnssec(domain)

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    print_summary(
        a_records,
        aaaa_records,
        mx_records,
        txt_records,
        caa_found,
        ptr_found,
        dnssec
    )