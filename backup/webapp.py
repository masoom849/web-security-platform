from flask import Flask, request, render_template_string
from urllib.parse import urlparse
import requests

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Web Security Platform</title>
    <style>
        body {
            background: #101827;
            color: white;
            font-family: Arial;
            text-align: center;
            padding: 40px;
        }
        .box {
            background: #1e293b;
            padding: 25px;
            border-radius: 12px;
            max-width: 650px;
            margin: auto;
        }
        input {
            width: 75%;
            padding: 12px;
            margin: 10px;
        }
        button {
            padding: 12px 25px;
            background: #16a34a;
            color: white;
            border: none;
            cursor: pointer;
        }
        .result {
            text-align: left;
            margin-top: 20px;
            overflow-wrap: anywhere;
        }
    </style>
</head>
<body>
    <div class="box">
        <h1>🛡️ Web Security Platform</h1>
        <p>Basic Website Security Scanner</p>

        <form method="POST">
            <input name="url" placeholder="https://example.com"
                   required>
            <br>
            <button type="submit">Scan Website</button>
        </form>

        {% if result %}
        <div class="result">
            <h2>Scan Results</h2>
            <p><b>Website:</b> {{ result.url }}</p>
            <p><b>HTTPS Enabled:</b> {{ result.https }}</p>
            <p><b>HTTP Status:</b> {{ result.status }}</p>
            <h3>Security Headers</h3>
            {% for name, present in result.headers %}
                <p>{{ name }}:
                {{ "PRESENT" if present else "MISSING" }}</p>
            {% endfor %}
        </div>
        {% endif %}

        {% if error %}
            <p>{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
]

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url.startswith(("https://", "http://")):
            url = "https://" + url

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            error = "Please enter a valid website URL."
        else:
            try:
                response = requests.get(
                    url,
                    timeout=8,
                    allow_redirects=True,
                    headers={"User-Agent": "WebSecurityPlatform/1.0"}
                )

                result = {
                    "url": response.url,
                    "https": response.url.startswith("https://"),
                    "status": response.status_code,
                    "headers": [
                        (name, name.lower() in
                         {h.lower() for h in response.headers})
                        for name in SECURITY_HEADERS
                    ],
                }
            except requests.RequestException:
                error = "Website could not be reached or request failed."

    return render_template_string(
        HTML, result=result, error=error
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
