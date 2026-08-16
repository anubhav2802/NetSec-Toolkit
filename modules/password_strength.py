import math
import re
import os
import hashlib
import requests

# =========================================================
# COMMON PASSWORD DATABASE
# =========================================================

COMMON_PASSWORDS = {

    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "abc123",
    "admin",
    "admin123",
    "welcome",
    "welcome123",
    "root",
    "toor",
    "letmein",
    "dragon",
    "monkey",
    "football",
    "iloveyou",
    "login",
    "guest",
    "test",
    "passw0rd",
    "p@ssword",
    "qwerty123"

}


# =========================================================
# PASSWORD LENGTH
# =========================================================

def password_length(password):

    return len(password)


# =========================================================
# CHARACTER ANALYSIS
# =========================================================

def character_analysis(password):

    analysis = {

        "lower": False,

        "upper": False,

        "digit": False,

        "symbol": False

    }

    for ch in password:

        if ch.islower():

            analysis["lower"] = True

        elif ch.isupper():

            analysis["upper"] = True

        elif ch.isdigit():

            analysis["digit"] = True

        else:

            analysis["symbol"] = True

    return analysis


# =========================================================
# CHARACTER SET SIZE
# =========================================================

def charset_size(analysis):

    size = 0

    if analysis["lower"]:

        size += 26

    if analysis["upper"]:

        size += 26

    if analysis["digit"]:

        size += 10

    if analysis["symbol"]:

        size += 32

    return size


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(password):

    analysis = character_analysis(password)

    charset = charset_size(analysis)

    if charset == 0:

        return 0

    entropy = len(password) * math.log2(charset)

    return round(entropy, 2)


# =========================================================
# REPEATED CHARACTERS
# =========================================================

def repeated_characters(password):

    return bool(

        re.search(

            r"(.)\1{2,}",

            password

        )

    )


# =========================================================
# SEQUENTIAL CHARACTERS
# =========================================================

def sequential_characters(password):

    password = password.lower()

    sequences = [

        "abcdefghijklmnopqrstuvwxyz",

        "0123456789",

        "qwertyuiop",

        "asdfghjkl",

        "zxcvbnm"

    ]

    for seq in sequences:

        for i in range(len(seq)-3):

            piece = seq[i:i+4]

            reverse = piece[::-1]

            if piece in password:

                return True

            if reverse in password:

                return True

    return False


# =========================================================
# COMMON PASSWORD CHECK
# =========================================================

def common_password(password):

    return password.lower() in COMMON_PASSWORDS


# =========================================================
# PASSWORD SUMMARY
# =========================================================

def analyze_password(password):

    analysis = character_analysis(password)

    return {

        "length": password_length(password),

        "entropy": calculate_entropy(password),

        "lower": analysis["lower"],

        "upper": analysis["upper"],

        "digit": analysis["digit"],

        "symbol": analysis["symbol"],

        "common": common_password(password),

        "repeated": repeated_characters(password),

        "sequential": sequential_characters(password)

    }

# =========================================================
# SECURITY SCORE
# =========================================================

def security_score(password):

    analysis = analyze_password(password)

    score = 0

    # ---------------- Length ----------------

    if analysis["length"] >= 16:
        score += 30

    elif analysis["length"] >= 12:
        score += 20

    elif analysis["length"] >= 8:
        score += 10

    # ---------------- Character Types ----------------

    if analysis["lower"]:
        score += 10

    if analysis["upper"]:
        score += 10

    if analysis["digit"]:
        score += 10

    if analysis["symbol"]:
        score += 20

    # ---------------- Entropy Bonus ----------------

    if analysis["entropy"] >= 80:
        score += 20

    elif analysis["entropy"] >= 60:
        score += 15

    elif analysis["entropy"] >= 40:
        score += 10

    # ---------------- Penalties ----------------

    if analysis["common"]:
        score -= 30

    if analysis["sequential"]:
        score -= 15

    if analysis["repeated"]:
        score -= 15

    score = max(0, min(score, 100))

    return score


# =========================================================
# LETTER GRADE
# =========================================================

def password_grade(score):

    if score >= 90:
        return "A+", "Excellent"

    elif score >= 80:
        return "A", "Very Strong"

    elif score >= 70:
        return "B", "Strong"

    elif score >= 60:
        return "C", "Moderate"

    elif score >= 40:
        return "D", "Weak"

    else:
        return "F", "Very Weak"


# =========================================================
# ESTIMATED CRACK TIME
# =========================================================

def estimate_crack_time(entropy):

    if entropy < 28:
        return "Instantly"

    elif entropy < 36:
        return "Minutes"

    elif entropy < 60:
        return "Days"

    elif entropy < 80:
        return "Years"

    else:
        return "Centuries"




# =========================================================
# HAVE I BEEN PWNED CHECK
# =========================================================

def check_pwned(password):

    sha1 = hashlib.sha1(

        password.encode("utf-8")

    ).hexdigest().upper()

    prefix = sha1[:5]

    suffix = sha1[5:]

    try:

        response = requests.get(

            f"https://api.pwnedpasswords.com/range/{prefix}",

            timeout=5

        )

        if response.status_code != 200:

            return None

        hashes = response.text.splitlines()

        for line in hashes:

            hash_suffix, count = line.split(":")

            if hash_suffix == suffix:

                return int(count)

        return 0

    except:

        return None
    
# =========================================================
# RECOMMENDATIONS
# =========================================================



def recommendations(password):

    analysis = analyze_password(password)

    tips = []

    if analysis["length"] < 12:
        tips.append(
            "Increase password length to at least 12 characters."
        )

    if not analysis["upper"]:
        tips.append(
            "Add uppercase letters."
        )

    if not analysis["lower"]:
        tips.append(
            "Add lowercase letters."
        )

    if not analysis["digit"]:
        tips.append(
            "Include numbers."
        )

    if not analysis["symbol"]:
        tips.append(
            "Include special characters."
        )

    if analysis["common"]:
        tips.append(
            "Avoid common passwords."
        )

    if analysis["repeated"]:
        tips.append(
            "Avoid repeated characters."
        )

    if analysis["sequential"]:
        tips.append(
            "Avoid sequential keyboard or numeric patterns."
        )

    if not tips:
        tips.append(
            "Excellent password. Continue using unique passwords and enable MFA."
        )

    return tips

    breaches = check_pwned(password)

    if isinstance(breaches, int) and breaches > 0:

        tips.append(

            "This password has appeared in public data breaches. Change it immediately."

        )


# =========================================================
# PRINT REPORT
# =========================================================

def print_report(password):

    analysis = analyze_password(password)

    score = security_score(password)

    grade, strength = password_grade(score)

    crack_time = estimate_crack_time(

        analysis["entropy"]

    )

    breaches = check_pwned(password)
    print(f"Estimated Crack Time : {crack_time}")
    print()

    if breaches is None:

        print("Pwned Database       : Unable to Check")

    elif breaches == 0:

        print("Pwned Database       : Not Found")

    else:

        print("Pwned Database       : FOUND")

    print(f"Occurrences          : {breaches}")

    print("\n" + "=" * 70)

    print("              PASSWORD STRENGTH REPORT")

    print("=" * 70)

    print(f"\nPassword Length      : {analysis['length']}")

    print(f"Lowercase            : {'Yes' if analysis['lower'] else 'No'}")

    print(f"Uppercase            : {'Yes' if analysis['upper'] else 'No'}")

    print(f"Numbers              : {'Yes' if analysis['digit'] else 'No'}")

    print(f"Symbols              : {'Yes' if analysis['symbol'] else 'No'}")

    print(f"\nEntropy              : {analysis['entropy']} bits")

    print(f"Estimated Crack Time : {crack_time}")

    print(f"\nCommon Password      : {'Yes' if analysis['common'] else 'No'}")

    print(f"Repeated Characters  : {'Yes' if analysis['repeated'] else 'No'}")

    print(f"Sequential Pattern   : {'Yes' if analysis['sequential'] else 'No'}")

    print("\n" + "-" * 70)

    print(f"Security Score       : {score}/100")

    print(f"Grade                : {grade}")

    print(f"Strength             : {strength}")

    print("\nRecommendations")

    print("-" * 70)

    for tip in recommendations(password):

        print(f"• {tip}")

    print("\n" + "=" * 70)




# =========================================================
# EXPORT REPORT
# =========================================================

def export_report(password):

    analysis = analyze_password(password)

    score = security_score(password)

    grade, strength = password_grade(score)

    crack_time = estimate_crack_time(
        analysis["entropy"]
    )

    breaches = check_pwned(password)

    os.makedirs(
        "reports",
        exist_ok=True
    )

    try:

        with open(
            "reports/password_report.txt",
            "w",
            encoding="utf-8"
        ) as file:

            file.write("PASSWORD STRENGTH REPORT\n")
            file.write("=" * 70 + "\n\n")

            file.write(
                f"Password Length      : {analysis['length']}\n"
            )

            file.write(
                f"Lowercase            : {'Yes' if analysis['lower'] else 'No'}\n"
            )

            file.write(
                f"Uppercase            : {'Yes' if analysis['upper'] else 'No'}\n"
            )

            file.write(
                f"Numbers              : {'Yes' if analysis['digit'] else 'No'}\n"
            )

            file.write(
                f"Symbols              : {'Yes' if analysis['symbol'] else 'No'}\n\n"
            )

            file.write(
                f"Entropy              : {analysis['entropy']} bits\n"
            )

            file.write(
                f"Estimated Crack Time : {crack_time}\n"
            )

            # -----------------------------------
            # Pwned Passwords Result
            # -----------------------------------

            if breaches is None:

                file.write(
                    "Pwned Database       : Unable to Check\n"
                )

            elif breaches == 0:

                file.write(
                    "Pwned Database       : Not Found\n"
                )

            else:

                file.write(
                    "Pwned Database       : FOUND\n"
                )

                file.write(
                    f"Occurrences          : {breaches}\n"
                )

            file.write("\n")

            file.write(
                f"Common Password      : {'Yes' if analysis['common'] else 'No'}\n"
            )

            file.write(
                f"Repeated Characters  : {'Yes' if analysis['repeated'] else 'No'}\n"
            )

            file.write(
                f"Sequential Pattern   : {'Yes' if analysis['sequential'] else 'No'}\n\n"
            )

            file.write(
                f"Security Score       : {score}/100\n"
            )

            file.write(
                f"Grade                : {grade}\n"
            )

            file.write(
                f"Strength             : {strength}\n\n"
            )

            file.write("Recommendations\n")
            file.write("-" * 70 + "\n")

            for tip in recommendations(password):

                file.write(f"- {tip}\n")

        print(
            "\n✓ Report saved to reports/password_report.txt"
        )

    except Exception as e:

        print(
            f"\nReport Export Error : {e}"
        )

# =========================================================
# LOOKUP
# =========================================================

def lookup():

    print("\n" + "=" * 70)
    print("          PASSWORD STRENGTH ANALYZER")
    print("=" * 70)

    password = input(
        "\nEnter Password : "
    )

    if not password:

        print("\nPassword cannot be empty.")

        return

    print_report(password)

    export_report(password)

    print("\nAnalysis Complete.") 