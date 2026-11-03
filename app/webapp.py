from flask import Flask, request, render_template
import requests
from urllib.parse import urlparse
import ipaddress
import socket

app = Flask(__name__,
template_folder="../templates")

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def is_public_website(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False

    if parsed.username or parsed.password:
        return False

    try:
        addresses = socket.getaddrinfo(
            parsed.hostname, None, type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])
            if not ip.is_global:
                return False

        return True

    except (ValueError, socket.gaierror, OSError):
        return False


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None
    target_url = ""
    recommendations = []
    report = ""
    security_score = 0
    risk_level = "Not assessed"

    if request.method == "POST":
        target_url = request.form.get("url", "").strip()

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)

        if not parsed.hostname or not is_public_website(target_url):
            error = (
                "Please enter a valid public website URL. "
                "Use only websites you own or have permission to test."
            )
        else:
            try:
                response = requests.get(
                    target_url,
                    timeout=8,
                    allow_redirects=False,
                    headers={
                        "User-Agent": "WebSecurityPlatform/1.0"
                    },
                    stream=True,
                )

                try:
                    found_headers = [
                        name for name in SECURITY_HEADERS
                        if name.lower() in {
                            key.lower() for key in response.headers
                        }
                    ]

                    missing_headers = [
                        name for name in SECURITY_HEADERS
                        if name not in found_headers
                    ]

                    security_score = int(
                        len(found_headers) * 100 / len(SECURITY_HEADERS)
                    )

                    if security_score >= 80:
                        risk_level = "Low"
                    elif security_score >= 40:
                        risk_level = "Medium"
                    else:
                        risk_level = "High"

                    result = {
                        "url": target_url,
                        "status": response.status_code,
                        "https": response.url.startswith("https://"),
                        "headers": found_headers,
                        "missing_headers": missing_headers,
                    }

                    for header in missing_headers:
                        recommendations.append(
                            "Consider configuring " + header
                            + " after reviewing your site's requirements."
                        )

                    if not result["https"]:
                        recommendations.append(
                            "Use HTTPS to protect data in transit."
                        )

                    if not recommendations:
                        recommendations.append(
                            "The checked security headers are present. "
                            "Continue with regular security reviews."
                        )

                    report = (
                        f"Target: {result['url']}\n"
                        f"HTTP Status: {result['status']}\n"
                        f"HTTPS: {result['https']}\n"
                        f"Security Score: {security_score}/100\n"
                        f"Risk Level: {risk_level}\n"
                        f"Headers Found: {', '.join(found_headers) or 'None'}\n"
                        f"Headers Missing: "
                        f"{', '.join(missing_headers) or 'None'}\n\n"
                        "Note: This is a basic security-header check, "
                        "not a complete vulnerability assessment."
                    )

                finally:
                    response.close()

            except requests.RequestException:
                error = (
                    "Website could not be reached. Check the URL and "
                    "your internet connection, then try again."
                )

    return render_template(
        "dashboard.html",
        result=result,
        error=error,
        target_url=target_url,
        security_score=security_score,
        risk_level=risk_level,
        recommendations=recommendations,
        report=report,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
