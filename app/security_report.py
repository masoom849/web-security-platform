import requests
from datetime import datetime

SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps reduce cross-site scripting (XSS) risks.",
    "Strict-Transport-Security":
        "Encourages secure HTTPS connections.",
    "X-Content-Type-Options":
        "Helps prevent MIME-type sniffing.",
    "X-Frame-Options":
        "Helps reduce clickjacking risks.",
    "Referrer-Policy":
        "Controls referrer information.",
    "Permissions-Policy":
        "Controls access to browser features."
}


def scan_website(url):
    print("\n" + "=" * 50)
    print("       ADVANCED SECURITY REPORT")
    print("=" * 50)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers
        present = []
        missing = []

        print("Target:", url)
        print("Scan Time:", datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ))
        print("HTTP Status:", response.status_code)
        print("HTTPS:", response.url.startswith("https://"))

        print("\n--- SECURITY HEADERS ---")

        for header, advice in SECURITY_HEADERS.items():
            if header in headers:
                print("[PRESENT]", header)
                present.append(header)
            else:
                print("[MISSING]", header)
                print("  Advice:", advice)
                missing.append(header)

        score = round(
            len(present) / len(SECURITY_HEADERS) * 100
        )

        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 25:
            grade = "D"
        else:
            grade = "F"

        print("\n--- SECURITY SUMMARY ---")
        print(f"Headers Present: {len(present)}/6")
        print(f"Headers Missing: {len(missing)}/6")
        print(f"Header Score: {score}/100")
        print(f"Security Grade: {grade}")

        print("\nNote: This is a basic header check,")
        print("not a complete security assessment.")

    except requests.exceptions.RequestException as error:
        print("Scan failed:", error)


if __name__ == "__main__":
    target = input(
        "Enter an authorized test website URL: "
    ).strip()

    if not target.startswith(("https://", "http://")):
        print("Please enter a valid URL starting with http:// or https://")
    else:
        scan_website(target)
