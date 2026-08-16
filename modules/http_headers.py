import requests


# ---------------------------------------------------------
# Fetch Headers
# ---------------------------------------------------------

def fetch_headers(domain):

    try:

        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain

        response = requests.get(
            domain,
            timeout=5,
            allow_redirects=True
        )

        return response.headers

    except Exception as e:

        print(f"\nError : {e}")

        return None


# ---------------------------------------------------------
# Server Information
# ---------------------------------------------------------

def print_server_info(headers):

    print("\n" + "-" * 60)
    print("SERVER INFORMATION")
    print("-" * 60)

    print(f"Server              : {headers.get('Server', 'Unknown')}")
    print(f"Content-Type        : {headers.get('Content-Type', 'Unknown')}")
    print(f"Content-Length      : {headers.get('Content-Length', 'Unknown')}")
    print(f"Connection          : {headers.get('Connection', 'Unknown')}")


# ---------------------------------------------------------
# Security Header Analysis
# ---------------------------------------------------------

def print_security_headers(headers):

    print("\n" + "-" * 60)
    print("SECURITY HEADER ANALYSIS")
    print("-" * 60)

    score = 0

    recommendations = []

    # -------------------------------------------------
    # HSTS
    # -------------------------------------------------

    header = "Strict-Transport-Security"

    if header in headers:

        value = headers[header].lower()

        try:
            max_age = int(
                value.split("max-age=")[1].split(";")[0]
            )
        except:
            max_age = 0

        if (
            max_age >= 31536000
            and "includesubdomains" in value
            and "preload" in value
        ):

            print(f"{header:<35} ✓ Strong")
            score += 1

        elif max_age > 0:

            print(f"{header:<35} ! Moderate")
            score += 0.5

            recommendations.append(
                "Increase HSTS max-age to at least 31536000 and include preload."
            )

        else:

            print(f"{header:<35} ✗ Weak")

            recommendations.append(
                "Configure HSTS correctly."
            )

    else:

        print(f"{header:<35} ✗ Missing")

        recommendations.append(
            "Add Strict-Transport-Security header."
        )

    # -------------------------------------------------
    # CSP
    # -------------------------------------------------

    header = "Content-Security-Policy"

    if header in headers:

        value = headers[header].lower()

        if "'unsafe-inline'" in value:

            print(f"{header:<35} ! Weak")

            score += 0.5

            recommendations.append(
                "Avoid using 'unsafe-inline' in CSP."
            )

        else:

            print(f"{header:<35} ✓ Strong")

            score += 1

    else:

        print(f"{header:<35} ✗ Missing")

        recommendations.append(
            "Add a Content-Security-Policy."
        )

    # -------------------------------------------------
    # X Frame
    # -------------------------------------------------

    header = "X-Frame-Options"

    if header in headers:

        value = headers[header].upper()

        if value == "DENY":

            print(f"{header:<35} ✓ Strong")

            score += 1

        elif value == "SAMEORIGIN":

            print(f"{header:<35} ✓ Good")

            score += 1

        else:

            print(f"{header:<35} ! Weak")

            score += 0.5

    else:

        print(f"{header:<35} ✗ Missing")

        recommendations.append(
            "Add X-Frame-Options header."
        )

    # -------------------------------------------------
    # X Content
    # -------------------------------------------------

    header = "X-Content-Type-Options"

    if headers.get(header, "").lower() == "nosniff":

        print(f"{header:<35} ✓ Strong")

        score += 1

    elif header in headers:

        print(f"{header:<35} ! Weak")

        score += 0.5

    else:

        print(f"{header:<35} ✗ Missing")

        recommendations.append(
            "Set X-Content-Type-Options to nosniff."
        )

    # -------------------------------------------------
    # Referrer Policy
    # -------------------------------------------------

    header = "Referrer-Policy"

    if header in headers:

        value = headers[header].lower()

        if value in [

            "strict-origin",

            "strict-origin-when-cross-origin",

            "no-referrer"

        ]:

            print(f"{header:<35} ✓ Strong")

            score += 1

        else:

            print(f"{header:<35} ! Weak")

            score += 0.5

    else:

        print(f"{header:<35} ✗ Missing")

        recommendations.append(
            "Add Referrer-Policy."
        )

    # -------------------------------------------------
    # Permissions Policy
    # -------------------------------------------------

    header = "Permissions-Policy"

    if header in headers:

        print(f"{header:<35} ✓ Present")

        score += 1

    else:

        print(f"{header:<35} ✗ Missing")

        recommendations.append(
            "Add Permissions-Policy."
        )

    # -------------------------------------------------
    # XSS
    # -------------------------------------------------

    header = "X-XSS-Protection"

    if header in headers:

        value = headers[header]

        if value == "1; mode=block":

            print(f"{header:<35} ✓ Enabled")

            score += 1

        else:

            print(f"{header:<35} ! Weak")

            score += 0.5

    else:

        print(f"{header:<35} ✗ Missing")

        recommendations.append(
            "Add X-XSS-Protection."
        )

    return score, recommendations


# ---------------------------------------------------------
# Header Values
# ---------------------------------------------------------

def print_header_values(headers):

    print("\n" + "-" * 60)
    print("HEADER VALUES")
    print("-" * 60)

    security_headers = [

        "Strict-Transport-Security",

        "Content-Security-Policy",

        "X-Frame-Options",

        "X-Content-Type-Options",

        "Referrer-Policy",

        "Permissions-Policy",

        "X-XSS-Protection"

    ]

    for header in security_headers:

        if header in headers:

            print(f"\n{header}")

            print(headers[header])


# ---------------------------------------------------------
# Score
# ---------------------------------------------------------

def print_score(score):

    maximum = 7

    percentage = (score / maximum) * 100

    print("\n" + "=" * 60)

    print(f"Security Score : {score:.1f}/{maximum}")

    print(f"Percentage     : {percentage:.1f}%")

    if percentage >= 90:

        print("Overall Rating : A+ (Excellent)")

    elif percentage >= 75:

        print("Overall Rating : A (Very Good)")

    elif percentage >= 60:

        print("Overall Rating : B (Good)")

    elif percentage >= 40:

        print("Overall Rating : C (Average)")

    else:

        print("Overall Rating : F (Poor)")

    print("=" * 60)


# ---------------------------------------------------------
# Recommendations
# ---------------------------------------------------------

def print_recommendations(recommendations):

    if not recommendations:
        return

    print("\nRECOMMENDATIONS")
    print("-" * 60)

    for recommendation in recommendations:

        print(f"• {recommendation}")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def lookup(domain):

    headers = fetch_headers(domain)

    if headers is None:
        return

    print("\n" + "=" * 60)
    print("          HTTP SECURITY HEADER REPORT")
    print("=" * 60)

    print(f"\nTarget : {domain}")

    print_server_info(headers)

    score, recommendations = print_security_headers(headers)

    print_header_values(headers)

    print_score(score)

    print_recommendations(recommendations)