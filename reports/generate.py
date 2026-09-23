"""
HTML report generator.

Takes the AttackReport objects produced by a run and renders a clean,
self-contained HTML findings report — the artifact you'd actually hand
to a client or screenshot for a portfolio.
"""

from datetime import datetime
from pathlib import Path

from jinja2 import Template

# Short, plain-English remediation guidance per attack module.
# Keep these grounded in what was actually tested — don't overclaim.
REMEDIATION = {
    "identity_override": (
        "Do not let user-supplied text alone establish elevated role or "
        "permission context. Role/identity should be set by the "
        "application layer from a verified, authenticated source (e.g. "
        "a signed session token) and passed to the model as trusted "
        "system context — never accepted as a claim inside user input."
    ),
    "session_persistence": (
        "Treat every claim made mid-conversation as re-verifiable, not "
        "permanently binding. If the application needs to remember a "
        "user's role across turns, store it server-side against the "
        "authenticated session — not by trusting the model to "
        "'remember' a claim it was told in-band."
    ),
    "prompt_extraction": (
        "Assume the system prompt WILL eventually leak and avoid putting "
        "secrets, credentials, or sensitive business logic in it. Where "
        "leakage matters, add explicit output filtering at the "
        "application layer rather than relying on the model to refuse."
    ),
    "config_exposure": (
        "This is an infrastructure finding, not a model-behavior one: "
        "bind the LLM serving API to localhost or an internal network "
        "only, and put it behind an authenticating reverse proxy or "
        "API gateway before any external or multi-user exposure."
    ),
}

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>LLM Red-Team Findings Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; max-width: 900px;
         margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.5; }
  h1 { border-bottom: 3px solid #1a1a1a; padding-bottom: 10px; }
  h2 { margin-top: 40px; border-bottom: 1px solid #ccc; padding-bottom: 6px; }
  .meta { color: #666; font-size: 0.9em; margin-bottom: 30px; }
  table { width: 100%; border-collapse: collapse; margin: 20px 0; }
  th, td { text-align: left; padding: 10px; border-bottom: 1px solid #ddd; }
  th { background: #f5f5f5; }
  .sev-high { color: #b30000; font-weight: bold; }
  .sev-medium { color: #b36b00; font-weight: bold; }
  .sev-low { color: #666; font-weight: bold; }
  .sev-none { color: #2e7d32; font-weight: bold; }
  .finding { background: #fafafa; border-left: 4px solid #ccc; padding: 12px 16px;
             margin: 12px 0; border-radius: 4px; }
  .finding.succeeded { border-left-color: #b30000; }
  .finding.resisted { border-left-color: #2e7d32; }
  .prompt { font-weight: 600; }
  .response { font-family: Consolas, monospace; font-size: 0.85em; background: #fff;
              padding: 8px; margin-top: 6px; border-radius: 4px; white-space: pre-wrap; }
  .remediation { background: #eef6ff; padding: 12px 16px; border-radius: 4px;
                 margin-top: 12px; }
  .tag { display: inline-block; background: #e0e0e0; padding: 2px 8px;
         border-radius: 10px; font-size: 0.8em; margin-right: 6px; }
</style>
</head>
<body>

<h1>LLM Red-Team Findings Report</h1>
<div class="meta">
  Target: {{ target_name }} &nbsp;|&nbsp;
  Generated: {{ generated_at }} &nbsp;|&nbsp;
  Toolkit: llm-redteam-toolkit
</div>

<h2>Executive Summary</h2>
<table>
  <tr><th>Attack</th><th>OWASP</th><th>ASR</th><th>Severity</th></tr>
  {% for r in reports %}
  <tr>
    <td>{{ r.attack_name }}</td>
    <td>{{ r.owasp_id }}</td>
    <td>{{ "%.0f"|format(r.asr * 100) }}%</td>
    <td class="sev-{{ r.severity }}">{{ r.severity|upper }}</td>
  </tr>
  {% endfor %}
</table>

{% for r in reports %}
<h2>{{ r.attack_name }}</h2>
<span class="tag">{{ r.owasp_id }}</span>
<span class="tag">{{ r.atlas_id }}</span>
<span class="tag sev-{{ r.severity }}">{{ r.severity|upper }} — {{ "%.0f"|format(r.asr * 100) }}% ASR</span>

{% for result in r.results %}
<div class="finding {{ 'succeeded' if result.succeeded else 'resisted' }}">
  <div class="prompt">{{ 'SUCCEEDED' if result.succeeded else 'resisted' }} — {{ result.test_case }}</div>
  <div>{{ result.prompt }}</div>
  {% if result.notes %}<div><em>{{ result.notes }}</em></div>{% endif %}
  <div class="response">{{ result.response[:500] }}{% if result.response|length > 500 %}...{% endif %}</div>
</div>
{% endfor %}

<div class="remediation">
  <strong>Remediation:</strong> {{ remediation.get(r.attack_name, "See detection rule for guidance.") }}
</div>
{% endfor %}

<h2>Disclaimer</h2>
<p style="color:#666; font-size:0.9em;">
  Findings generated against a locally-hosted test model for authorized
  research purposes only. ASR reflects behaviour of the specific model
  and configuration tested at the time of the run, not a guarantee
  about any other deployment.
</p>

</body>
</html>
"""


def generate_report(reports, target_name: str, output_dir: str = "reports") -> str:
    """
    Render an HTML report from a list of AttackReport objects.
    Returns the path to the generated file.
    """
    template = Template(REPORT_TEMPLATE)
    html = template.render(
        reports=reports,
        remediation=REMEDIATION,
        target_name=target_name,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )

    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(output_dir) / f"report_{timestamp}.html"
    out_path.write_text(html, encoding="utf-8")

    return str(out_path)
