from flask import Flask, render_template, request
from scanner import run_scanner
import os

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url")

    if not url:
        return render_template("index.html", error="Please enter a valid URL")

    # NO change in logic
    result = run_scanner(url)

    return render_template("result.html", url=url, result=result)

# 🔹 Separate page ONLY for screenshots
@app.route("/screenshots")
def screenshots():
    folder = "static/screenshots"

    if not os.path.exists(folder):
        images = []
    else:
        images = [
            f"screenshots/{img}"
            for img in os.listdir(folder)
            if img.endswith(".png")
        ]

    return render_template("screenshots.html", images=images)

import os

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)