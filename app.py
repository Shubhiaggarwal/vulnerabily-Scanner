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
        return render_template("index.html", error="Please enter a valid URL.")

    result = run_scanner(url)

    return render_template("result.html", url=url, result=result)

# ----------- FIXED ROUTE -----------
@app.route("/screenshots")
def show_screenshots():
    folder = "static/screenshots"   # FIXED PATH

    if not os.path.exists(folder):
        return render_template("screenshots.html", images=[])

    images = [f for f in os.listdir(folder) if f.endswith(".png")]
    images.sort()

    image_paths = [f"static/screenshots/{img}" for img in images]

    return render_template("screenshots.html", images=image_paths)
# -----------------------------------

if __name__ == "__main__":
    app.run(debug=True)
