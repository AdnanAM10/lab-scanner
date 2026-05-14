import os
import json
import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ── Approved lab targets only ──────────────────────────────────────────────────
APPROVED_TARGETS = {
    "scanme.nmap.org": "Nmap official public test host (Nmap.org)",
}
DEFAULT_TARGET = "scanme.nmap.org"

# Safe nmap flags: TCP-connect scan, top 100 ports, version detection, XML output
NMAP_FLAGS = ["-sT", "-sV", "--top-ports", "100", "-T4", "--open", "-oX", "-"]


def run_nmap(target: str) -> list[dict]:
    """Run nmap and parse XML output. Returns list of open-port dicts."""
    cmd = ["nmap"] + NMAP_FLAGS + [target]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        raise RuntimeError("nmap not found — install it and ensure it is on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Scan timed out after 120 s")

    if result.returncode not in (0, 1):
        raise RuntimeError(f"nmap error: {result.stderr.strip()}")

    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    ports = []
    for host in root.iter("host"):
        for port_el in host.iter("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            ports.append({
                "port": int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "service": service,
                "product": product,
                "version": version,
                "banner": f"{product} {version}".strip(),
            })
    return sorted(ports, key=lambda p: p["port"])


def analyze_with_ai(target: str, ports: list[dict]) -> str:
    """Use the Claude API to summarise scan findings. Returns empty string if no key set."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return ""

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        if not ports:
            summary = "No open ports detected."
        else:
            lines = [
                f"Port {p['port']}/{p['protocol']}: {p['service']}"
                + (f" — {p['banner']}" if p['banner'] else "")
                for p in ports
            ]
            summary = "\n".join(lines)

        prompt = (
            f"You are a network security educator reviewing a lab scan of '{target}'.\n\n"
            f"Open ports found:\n{summary}\n\n"
            "For each service, write ONE sentence explaining what it does and why it might be "
            "interesting in a lab/CTF context. Then add a single-paragraph overall assessment "
            "of the host's exposure. Be concise, technical, and educational. "
            "Do not suggest exploiting anything outside a controlled lab environment."
        )

        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    except Exception as exc:  # noqa: BLE001
        return f"AI analysis unavailable: {exc}"


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           default_target=DEFAULT_TARGET,
                           approved_targets=APPROVED_TARGETS)


@app.route("/scan", methods=["POST"])
def scan():
    body = request.get_json(force=True, silent=True) or {}
    target = body.get("target", DEFAULT_TARGET).strip()

    if target not in APPROVED_TARGETS:
        return jsonify({"error": f"'{target}' is not an approved lab target."}), 403

    try:
        ports = run_nmap(target)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500

    ai_analysis = analyze_with_ai(target, ports)

    return jsonify({
        "target": target,
        "ports": ports,
        "ai_analysis": ai_analysis,
    })


@app.route("/targets")
def targets():
    return jsonify(APPROVED_TARGETS)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
