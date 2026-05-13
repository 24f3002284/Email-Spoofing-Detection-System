import os
import tempfile
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for

from parser  import parse_email
from checker import check_spf, check_dkim
from dmarc   import check_dmarc
from scorer  import compute_score

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB max upload


def _score_color(score: int):
    if score >= 80: return "#4caf50", "#1a3a1a"
    if score >= 50: return "#ffa726", "#3a2a00"
    return "#f44336", "#3a1a1a"


def run_analysis(eml_bytes, filename):
    # Write to temp file (parser needs a path for binary read)
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
        tmp.write(eml_bytes)
        tmp_path = tmp.name

    try:
        h     = parse_email(tmp_path)
        spf   = check_spf(h.return_path_domain or h.from_domain or "", h.originating_ip or "")
        dkim  = check_dkim(eml_bytes)
        dmarc = check_dmarc(
            from_domain = h.from_domain,
            spf_domain  = h.return_path_domain,
            spf_passed  = spf.result.value == "pass",
            dkim_domain = dkim.signing_domain,
            dkim_passed = dkim.result.value == "pass",
        )
        score_obj = compute_score(h, spf, dkim, dmarc)
    finally:
        os.unlink(tmp_path)

    sc, bg = _score_color(score_obj.score)

    return dict(
        filename    = filename,
        headers     = h,
        score       = score_obj.score,
        verdict     = score_obj.verdict,
        score_color = sc,
        verdict_bg  = bg,
        deductions  = [d for d in score_obj.details if d.deduction > 0],
        spf_result  = spf.result.value,
        spf_reason  = spf.reason,
        dkim_result = dkim.result.value,
        dkim_reason = dkim.reason,
        dmarc_result= dmarc.result.value,
        dmarc_reason= dmarc.reason,
        dmarc_policy= dmarc.policy.value,
        timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyse", methods=["POST"])
def analyse():
    eml_file    = request.files.get("eml_file")
    raw_headers = request.form.get("raw_headers", "").strip()

    if eml_file and eml_file.filename:
        eml_bytes = eml_file.read()
        filename  = eml_file.filename
    elif raw_headers:
        eml_bytes = raw_headers.encode("utf-8")
        filename  = "pasted-headers.eml"
    else:
        return render_template("index.html", error="Please upload a .eml file or paste some headers.")

    try:
        ctx = run_analysis(eml_bytes, filename)
        return render_template("result.html", **ctx)
    except Exception as e:
        return render_template("index.html", error=f"Analysis failed: {e}")

@app.route("/sample/<name>", methods=["POST"])
def sample(name):
    # Loading a sample email for demo
    samples = {
        "legitimate": "samples/legitimate.eml",
        "spoofed":    "samples/spoofed.eml",
    }
    path = samples.get(name)
    if not path or not os.path.exists(path):
        return redirect(url_for("index"))

    with open(path, "rb") as f:
        eml_bytes = f.read()

    try:
        ctx = run_analysis(eml_bytes, os.path.basename(path))
        return render_template("result.html", **ctx)
    except Exception as e:
        return render_template("index.html", error=f"Sample failed: {e}")

if __name__ == "__main__":
    print("\n  Email Spoofing Detector")
    print("  Open: http://localhost:5000\n")
    app.run(debug=True, port=5000)