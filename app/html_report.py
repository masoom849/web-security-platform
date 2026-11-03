import requests
from datetime import datetime
from html import escape
from pathlib import Path

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce XSS risks.",
    "Strict-Transport-Security": "Encourages secure HTTPS connections.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps reduce clickjacking risks.",
    "Referrer-Policy": "Controls referrer information.",
    "Permissions-Policy": "Controls browser feature access."
}


def scan_website(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        results = []
        present = 0

        for header, advice in SECURITY_HEADERS.items():
            if header in headers:
                status = "PRESENT"
                present += 1
            else:
                status = "MISSING"

            results.append({
                "header": header,
                "status": status,
                "advice": advice
            })

        score = round(present / len(SECURITY_HEADERS) * 100)

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

        rows = ""

        for item in results:
            rows += f"""
            <tr>
                <td>{escape(item['header'])}</td>
                <td>{escape(item['status'])}</td>
                <td>{escape(item['advice'])}</td>
            </tr>
            """

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 30px;
    background: #f2f5f9;
    color: #222;
}}
.container {{
    max-width: 900px;
    margin: auto;
    background: white;
    padding: 25px;
    border-radius: 12px;
}}
h1 {{ color: #173b68; }}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    border: 1px solid #ccc;
    padding: 12px;
    text-align: left;
}}
th {{ background: #173b68; color: white; }}
.score {{ font-size: 22px; font-weight: bold; }}
</style>
</head>
<body>
<div class="container">
<h1>Web Security Report</h1>
<p><b>Target:</b> {escape(response.url)}</p>
<p><b>Scan Time:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p><b>HTTP Status:</b> {response.status_code}</p>
<p><b>HTTPS:</b> {response.url.startswith("https://")}</p>
<p class="score">Header Score: {score}/100</p>
<p class="score">Header Grade: {grade}</p>
<table>
<tr><th>Security Header</th><th>Status</th><th>Recommendation</th></tr>
{rows}
</table>
<p><b>Note:</b> This checks HTTP security headers only.
It is not a complete security assessment.</p>
</div>
</body>
</html>"""

        output = Path("security_report.html")
        output.write_text(report, encoding="utf-8")

        print("\nReport created successfully!")
        print("File:", output.resolve())
        print("Header Score:", score, "/100")
        print("Grade:", grade)

    except requests.exceptions.RequestException as error:
        print("Scan failed:", error)


if __name__ == "__main__":
    target = input("Enter an authorized test website URL: ").strip()

    if not target.startswith(("https://", "http://")):
        print("Please enter a valid URL starting with http:// or https://")
    else:
        scan_website(target)
