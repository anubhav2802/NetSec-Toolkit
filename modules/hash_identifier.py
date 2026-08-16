import re
import os

# =========================================================
# HASH DATABASE
# =========================================================

HASH_DATABASE = {

    "MD5": {

        "length": 32,
        "encoding": "hex",

        "hashcat": 0,
        "john": "Raw-MD5",

        "security": "Weak",

        "collision": "No",

        "category": "Cryptographic Hash",

        "usage": [
            "Checksums",
            "Legacy Password Storage",
            "File Integrity"
        ],

        "confidence": "High"

    },

    "NTLM": {

        "length": 32,
        "encoding": "hex",

        "hashcat": 1000,
        "john": "NT",

        "security": "Weak",

        "collision": "No",

        "category": "Windows Password Hash",

        "usage": [
            "Windows Authentication"
        ],

        "confidence": "Medium"

    },

    "SHA1": {

        "length": 40,
        "encoding": "hex",

        "hashcat": 100,
        "john": "Raw-SHA1",

        "security": "Weak",

        "collision": "No",

        "category": "Cryptographic Hash",

        "usage": [
            "Legacy Integrity Verification"
        ],

        "confidence": "High"

    },

    "SHA224": {

        "length": 56,
        "encoding": "hex",

        "hashcat": 1300,
        "john": "Raw-SHA224",

        "security": "Moderate",

        "collision": "Yes",

        "category": "Cryptographic Hash",

        "usage": [
            "Integrity Verification"
        ],

        "confidence": "High"

    },

    "SHA256": {

        "length": 64,
        "encoding": "hex",

        "hashcat": 1400,
        "john": "Raw-SHA256",

        "security": "Secure",

        "collision": "Yes",

        "category": "Cryptographic Hash",

        "usage": [
            "Integrity Verification",
            "Digital Signatures",
            "Certificates"
        ],

        "confidence": "High"

    },

    "SHA384": {

        "length": 96,
        "encoding": "hex",

        "hashcat": 10800,
        "john": "Raw-SHA384",

        "security": "Secure",

        "collision": "Yes",

        "category": "Cryptographic Hash",

        "usage": [
            "Certificates",
            "Integrity Verification"
        ],

        "confidence": "High"

    },

    "SHA512": {

        "length": 128,
        "encoding": "hex",

        "hashcat": 1700,
        "john": "Raw-SHA512",

        "security": "Secure",

        "collision": "Yes",

        "category": "Cryptographic Hash",

        "usage": [
            "Integrity Verification",
            "Password Storage"
        ],

        "confidence": "High"

    },

    "bcrypt": {

        "prefix": [
            "$2a$",
            "$2b$",
            "$2y$"
        ],

        "hashcat": 3200,
        "john": "bcrypt",

        "security": "Secure",

        "collision": "Yes",

        "category": "Password Hash",

        "usage": [
            "Password Storage"
        ],

        "confidence": "High"

    },

    "Argon2": {

        "prefix": [
            "$argon2"
        ],

        "hashcat": 8200,
        "john": "argon2",

        "security": "Secure",

        "collision": "Yes",

        "category": "Password Hash",

        "usage": [
            "Password Storage"
        ],

        "confidence": "High"

    },

    "PBKDF2": {

        "prefix": [
            "pbkdf2"
        ],

        "hashcat": 10900,
        "john": "PBKDF2",

        "security": "Secure",

        "collision": "Yes",

        "category": "Password Hash",

        "usage": [
            "Password Storage"
        ],

        "confidence": "High"

    }

}


# =========================================================
# BASIC INFORMATION
# =========================================================

def get_length(hash_value):

    return len(hash_value)


def detect_encoding(hash_value):

    if re.fullmatch(

        r"[0-9a-fA-F]+",

        hash_value

    ):

        return "Hexadecimal"

    elif re.fullmatch(

        r"[A-Za-z0-9+/=]+",

        hash_value

    ):

        return "Base64"

    return "Unknown"


# =========================================================
# IDENTIFY HASH
# =========================================================

def identify_hash(hash_value):

    matches = []

    length = len(hash_value)

    encoding = detect_encoding(hash_value)

    for algorithm, info in HASH_DATABASE.items():

        # Prefix Based

        if "prefix" in info:

            for prefix in info["prefix"]:

                if hash_value.lower().startswith(

                    prefix.lower()

                ):

                    matches.append(

                        (algorithm, info)

                    )

        # Length Based

        elif (

            info["length"] == length

            and

            info["encoding"].lower()

            ==

            encoding.lower()[:3]

        ):

            matches.append(

                (algorithm, info)

            )

    return matches


# =========================================================
# RECOMMENDATIONS
# =========================================================

def recommendation(level):

    if level == "Weak":

        return (
            "Do NOT use this algorithm for password storage.\n"
            "Recommended : Argon2id or bcrypt."
        )

    elif level == "Moderate":

        return (
            "Suitable for integrity verification.\n"
            "Prefer SHA-256 or SHA-512 for new systems."
        )

    else:

        return (
            "Considered secure for modern applications."
        )


# =========================================================
# PRINT USAGE
# =========================================================

def print_usage(usage):

    for item in usage:

        print(f"   • {item}")


# =========================================================
# PRINT SINGLE MATCH
# =========================================================

def print_match(number, algorithm, info):

    print("\n" + "-" * 70)

    print(f"Possible Match #{number}")

    print("-" * 70)

    print(f"Algorithm             : {algorithm}")

    print(f"Category              : {info['category']}")

    print(f"Confidence            : {info['confidence']}")

    print(f"Security Level        : {info['security']}")

    print(f"Collision Resistant   : {info['collision']}")

    print(f"Hashcat Mode          : {info['hashcat']}")

    print(f"John Format           : {info['john']}")

    print("\nCommon Usage")

    print_usage(

        info["usage"]

    )

    print("\nRecommendation")

    print(

        recommendation(

            info["security"]

        )

    )


# =========================================================
# PRINT REPORT
# =========================================================

def print_report(hash_value):

    matches = identify_hash(

        hash_value

    )

    print("\n" + "=" * 70)

    print("                HASH IDENTIFIER REPORT")

    print("=" * 70)

    print(f"\nHash Value\n")

    print(hash_value)

    print(f"\nLength      : {get_length(hash_value)} Characters")

    print(

        f"Encoding    : "

        f"{detect_encoding(hash_value)}"

    )

    print(

        f"Matches      : "

        f"{len(matches)}"

    )

    if not matches:

        print(

            "\nUnable to identify this hash."

        )

        print("=" * 70)

        return

    count = 1

    for algorithm, info in matches:

        print_match(

            count,

            algorithm,

            info

        )

        count += 1

    print("\n" + "=" * 70)

    print("End of Report")

    print("=" * 70)




# =========================================================
# VALIDATE HASH
# =========================================================

def validate_hash(hash_value):

    if not hash_value:

        return False

    if len(hash_value.strip()) == 0:

        return False

    return True


# =========================================================
# EXPORT REPORT
# =========================================================

def export_report(hash_value):

    matches = identify_hash(hash_value)

    os.makedirs(

        "reports",

        exist_ok=True

    )

    try:

        with open(

            "reports/hash_report.txt",

            "w",

            encoding="utf-8"

        ) as file:

            file.write(
                "HASH IDENTIFIER REPORT\n"
            )

            file.write("=" * 60 + "\n\n")

            file.write(
                f"Hash Value : {hash_value}\n"
            )

            file.write(
                f"Length     : {get_length(hash_value)}\n"
            )

            file.write(
                f"Encoding   : {detect_encoding(hash_value)}\n\n"
            )

            if not matches:

                file.write(
                    "No matching algorithm found.\n"
                )

            else:

                count = 1

                for algorithm, info in matches:

                    file.write(
                        "-" * 60 + "\n"
                    )

                    file.write(
                        f"Match #{count}\n"
                    )

                    file.write(
                        "-" * 60 + "\n"
                    )

                    file.write(
                        f"Algorithm            : {algorithm}\n"
                    )

                    file.write(
                        f"Category             : {info['category']}\n"
                    )

                    file.write(
                        f"Confidence           : {info['confidence']}\n"
                    )

                    file.write(
                        f"Security             : {info['security']}\n"
                    )

                    file.write(
                        f"Collision Resistant  : {info['collision']}\n"
                    )

                    file.write(
                        f"Hashcat Mode         : {info['hashcat']}\n"
                    )

                    file.write(
                        f"John Format          : {info['john']}\n\n"
                    )

                    file.write(
                        "Common Usage\n"
                    )

                    for item in info["usage"]:

                        file.write(
                            f" - {item}\n"
                        )

                    file.write("\n")

                    file.write(
                        "Recommendation\n"
                    )

                    file.write(
                        recommendation(
                            info["security"]
                        )
                    )

                    file.write("\n\n")

                    count += 1

        print(
            "\n✓ Report saved to reports/hash_report.txt"
        )

    except Exception as e:

        print(
            f"\nReport Export Error : {e}"
        )


# =========================================================
# MAIN
# =========================================================

def lookup():

    print("\n" + "=" * 60)
    print("             HASH IDENTIFIER")
    print("=" * 60)

    hash_value = input(
        "\nEnter Hash : "
    ).strip()

    if not validate_hash(hash_value):

        print("\nInvalid hash.")

        return

    print_report(hash_value)

    export_report(hash_value)

    print("\nAnalysis Complete.")