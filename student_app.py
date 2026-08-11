"""Student-facing text-entry interface for the teaching attack-graph pipeline.

``app.py`` runs the current professional rule set and keeps v1.4 as its
frozen comparison baseline. This file
uses an isolated student rule set: type an incident description, press Generate,
and view the graph. Teaching fixes therefore cannot change professional results.

Run:
    python student_app.py
Then open http://127.0.0.1:5001
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from flask import Flask, render_template_string, request, send_from_directory

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from attack_graph import (quality_report_path, render_split,  # noqa: E402
                          tagged_output_path)
from run_metrics import run_metrics, tactic_progression  # noqa: E402
from extract import (extract_attack_graph, get_last_api_usage,  # noqa: E402
                     get_last_graph_restatement,
                     get_last_student_notes,
                     resolve_model)
from student_coverage import audit_source_coverage  # noqa: E402


REPORTS_DIR = ROOT / "reports"
OUTPUTS_DIR = ROOT / "outputs"
REPORTS_DIR.mkdir(exist_ok=True)
OUTPUTS_DIR.mkdir(exist_ok=True)

# Student rules are intentionally absent from the professional application.
# The visual syntax is the shared AGVS-SP profile, which is
# independent of the rule set version.
RULESET = "student-v1.3"
PROVIDER = "anthropic"
MODEL = resolve_model(PROVIDER)
MAX_SCENARIO_CHARS = 50_000

app = Flask(__name__)


_MOJIBAKE_PATTERNS = (
    re.compile(r"鈥[檚櫬淭淐淎淔]?"),
    re.compile(r"拢\s?\d"),
    re.compile(r"锟斤拷"),
    re.compile(r"â(?:€™|€˜|€œ|€\x9d|€“|€”|€¦)"),
    re.compile(r"Ã[\x80-\xBF]"),
)


def _has_probable_mojibake(text: str) -> bool:
    """Detect common UTF-8-as-legacy-encoding damage without rejecting Chinese."""
    return any(pattern.search(text) for pattern in _MOJIBAKE_PATTERNS)


def _save_submission(text: str) -> Path:
    """Atomically save a numbered submission without overwriting another user."""
    number = 1
    while True:
        path = REPORTS_DIR / f"student_submission_{number}.txt"
        try:
            with path.open("x", encoding="utf-8") as stream:
                stream.write(text)
            return path
        except FileExistsError:
            pass
        number += 1


def _friendly_error(error: Exception) -> str:
    message = str(error)
    lower = message.lower()
    if "api_key" in lower or "401" in lower or "authentication" in lower:
        return "The hosted model is not configured. Ask the instructor to check the API key."
    if "credit balance" in lower or "credit_balance" in lower or "billing" in lower:
        return ("The hosted model cannot use the configured billing workspace. "
                "Ask the instructor to check the API key workspace and spending limit.")
    if "cost guard" in lower:
        return ("Generation was stopped by the per-graph API cost limit. Shorten "
                "the incident description or ask the instructor for support.")
    if "stage a failed" in lower:
        return ("The model could not produce a validated evidence-grounded graph. "
                "No invalid graph was saved. Please retry once; if it repeats, "
                "keep the terminal diagnostic and ask the instructor for review.")
    if "stage b failed" in lower:
        return ("The graph structure was found, but technique mapping did not complete. "
                "Please try again or ask the instructor for support.")
    return f"Generation did not complete: {message}"


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Student Attack Graph Generator</title>
<style>
/* The same stylesheet as app.py with one variable changed. The teaching
   edition differs by structure and scaffolding, not by decoration: Sherzhanov
   et al. (2024) found brighter colour and denser line structure did not
   significantly improve comprehension among non-experts, and recommended
   structural clarity and conceptual scaffolding instead. Hence the step rail,
   the notation key and the counted review checklists, at the same density and
   palette weight as the professional edition.

   The grammar of the figure is the grammar of the page:
     sharp rectangle = action, large radius = state,
     dashed = annotation, dotted = uncertain, strict top-down flow. */
  :root{
    --accent:#2d5f5c; --accent-dark:#234a48;   /* app.py uses #33415e */
    --ink:#14181f; --ink-2:#454c58; --ink-3:#79808c;
    --paper:#fbfaf8; --surface:#fff;
    --rule:#ded9d1; --rule-2:#b5b0a7;
    --advisory:#a8631b; --fail:#9b2f2f;
    --advisory-wash:#fdf6ea; --fail-wash:#fbf0ee;
    --sans:ui-sans-serif,"Segoe UI",Inter,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,"Cascadia Mono","JetBrains Mono",Consolas,monospace;
    --t01:#4a5b7a; --t02:#43647d; --t03:#3d6d7d; --t04:#3d7a76;
    --t05:#47836a; --t06:#5c8a5e; --t07:#758f54; --t08:#8c914e;
    --t09:#a08f4c; --t10:#b18a4b; --t11:#bd804b; --t12:#c4744d;
    --t13:#c56650; --t14:#bd5453;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
       font-size:15px;line-height:1.55}
  .wrap{max-width:1100px;margin:0 auto;padding:0 28px 70px}
  a{color:var(--accent)}
  code{background:#f1efea;padding:1px 5px;font-size:12.5px}
  .top-rule{height:5px;background:var(--accent)}
  .masthead{display:flex;align-items:flex-end;gap:18px;padding:30px 0 16px;
            border-bottom:1px solid var(--rule)}
  .masthead svg{flex:none;margin-bottom:4px}
  h1{font-size:31px;line-height:1.05;letter-spacing:-.022em;font-weight:650;margin:0}
  .strap{margin:5px 0 0;font:500 11px/1 var(--mono);letter-spacing:.13em;
         text-transform:uppercase;color:var(--ink-3)}
  .masthead .right{margin-left:auto;text-align:right;font:500 11px/1.7 var(--mono);
                   color:var(--ink-3);letter-spacing:.06em}
  .masthead .right b{color:var(--accent)}
  /* step rail: scaffolding, the difference from the professional edition */
  .steps{display:flex;list-style:none;margin:0;padding:0;
         border-bottom:1px solid var(--rule)}
  .steps li{display:flex;align-items:center;gap:10px;padding:15px 26px 13px;
            font:600 11px/1 var(--mono);letter-spacing:.15em;
            text-transform:uppercase;color:var(--ink-3);
            border-bottom:2px solid transparent;margin-bottom:-1px}
  .steps li:first-child{padding-left:0}
  .steps li .n{display:inline-flex;align-items:center;justify-content:center;
               width:20px;height:20px;border:1px solid currentColor;
               border-radius:50%;font-size:10.5px;letter-spacing:0}
  .steps li.done{color:var(--ink-2)}
  .steps li.done .n{background:var(--ink-2);color:#fff;border-color:var(--ink-2)}
  .steps li.now{color:var(--accent);border-bottom-color:var(--accent)}
  .steps li.now .n{border-width:1.6px}
  .sec{display:flex;align-items:baseline;gap:12px;margin:38px 0 14px}
  .sec .num{font:600 11px/1 var(--mono);letter-spacing:.1em;color:var(--accent);
            font-variant-numeric:tabular-nums}
  .sec h2{margin:0;font:600 11px/1 var(--mono);letter-spacing:.18em;
          text-transform:uppercase;color:var(--ink-2)}
  .sec .line{flex:1;height:1px;background:var(--rule)}
  .sec .count{font:600 10px/1 var(--mono);letter-spacing:.1em;color:#fff;
              background:var(--advisory);padding:5px 8px;border-radius:2px}
  .sec .count.clear{background:var(--ink-3)}
  /* Editorial two-column opening: what to do on the left, the notation you
     will get back on the right. A single measure-limited paragraph left the
     right third of the page empty, and the notation key is exactly what a
     learner should be reading beside the instructions. */
  .opening{display:grid;gap:28px 40px;
           grid-template-columns:minmax(0,1.55fr) minmax(240px,1fr);
           align-items:start;padding:26px 0 4px}
  .lede{margin:0;max-width:62ch;color:var(--ink-2);font-size:16.5px;
        line-height:1.6}
  .lede b{color:var(--ink)}
  .lede .first{display:block;margin-bottom:12px;font-size:19px;line-height:1.45;
               color:var(--ink);letter-spacing:-.008em}
  /* notation key: learn the syntax before reading the figure */
  .key{display:flex;flex-direction:column;border-top:2px solid var(--ink)}
  .key .kh{font:600 9.5px/1 var(--mono);letter-spacing:.16em;
           text-transform:uppercase;color:var(--ink-3);padding:13px 0 11px;
           border-bottom:1px solid var(--rule)}
  .key .item{display:flex;align-items:center;gap:11px;padding:11px 0;
             border-bottom:1px solid var(--rule);font:11.5px/1.35 var(--mono);
             color:var(--ink-2)}
  .key .item svg{flex:none}
  @media(max-width:860px){.opening{grid-template-columns:1fr}}
  /* action surface */
  .panel-action{background:var(--surface);border:1px solid var(--rule-2);
                border-radius:0;padding:22px 24px}
  .panel-action label.top{display:block;font:600 10px/1 var(--mono);
        letter-spacing:.15em;text-transform:uppercase;color:var(--ink-3);
        margin-bottom:9px}
  textarea{width:100%;min-height:200px;resize:vertical;padding:14px 15px;
           border:1px solid var(--rule-2);background:var(--paper);
           color:var(--ink);font:15px/1.6 var(--sans);border-radius:0}
  textarea:focus{outline:2px solid var(--accent);outline-offset:-2px}
  .tips{margin:14px 0 0;padding:14px 16px;border-left:2px solid var(--accent);
        font-size:13.5px;color:var(--ink-2)}
  .tips b{color:var(--ink)}
  .actions{display:flex;align-items:center;gap:18px;margin-top:20px;
           padding-top:18px;border-top:1px solid var(--rule);flex-wrap:wrap}
  button{font:600 14px/1 var(--sans);color:#fff;background:var(--accent);
         border:none;border-radius:0;padding:13px 24px;cursor:pointer}
  button:hover{background:var(--accent-dark)}
  button:disabled{background:var(--ink-3);cursor:default}
  .actions .note{font:11px/1.5 var(--mono);color:var(--ink-3);margin:0}
  /* tactic progression */
  .tactics{border-bottom:1px solid var(--rule);padding:16px 0 15px}
  .tbar{display:flex;gap:3px;margin-bottom:14px}
  .tbar span{flex:1;height:9px;background:var(--rule);border-radius:1px}
  .tlist{display:flex;flex-wrap:wrap;gap:8px 18px}
  .tlist .t{display:flex;align-items:center;gap:8px;font:11.5px/1 var(--mono);
            color:var(--ink-2)}
  .tlist .t i{width:11px;height:11px;border-radius:2px;flex:none}
  .tlist .t.off{color:#a9aeb6}
  .tlist .t.off i{background:transparent;border:1px dashed var(--rule-2)}
  .tlist .t .n{color:var(--ink-3);font-variant-numeric:tabular-nums}
  /* measurements */
  .metrics{display:grid;grid-template-columns:repeat(6,1fr);
           border-bottom:1px solid var(--rule)}
  .metric{padding:16px 18px 15px;border-right:1px solid var(--rule)}
  .metric:first-child{padding-left:0}
  .metric:last-child{border-right:none;padding-right:0}
  .metric .k{display:block;font:600 9.5px/1 var(--mono);letter-spacing:.16em;
             text-transform:uppercase;color:var(--ink-3);margin-bottom:9px}
  .metric .v{font:400 25px/1 var(--mono);letter-spacing:-.02em;
             font-variant-numeric:tabular-nums}
  .metric .u{font-size:12px;color:var(--ink-3);margin-left:3px}
  .metric .sub{display:block;margin-top:7px;font:11px/1 var(--mono);
               color:var(--ink-3)}
  .metric.ok .v{color:var(--accent)}
  .metric.warn .v,.metric.warn .sub{color:var(--advisory)}
  .metric.bad .v,.metric.bad .sub{color:var(--fail)}
  /* advisory surface: dashed, matching the annotation convention */
  .panel-note{border:1.5px dashed var(--advisory);background:var(--advisory-wash);
              padding:18px 22px;margin:0 0 14px}
  .panel-note h3{margin:0 0 4px;font:600 11px/1 var(--mono);letter-spacing:.15em;
                 text-transform:uppercase;color:var(--advisory)}
  .panel-note.neutral{border:1px solid var(--rule-2);background:transparent}
  .panel-note.neutral h3{color:var(--ink-2)}
  .panel-note .tail,.small{margin:12px 0 0;font-size:12.5px;color:var(--ink-3)}
  .checklist{list-style:none;margin:10px 0 0;padding:0}
  .checklist li{padding:12px 0 12px 14px;border-top:1px solid #ecdfc8;
                font-size:14px;color:var(--ink-2);
                border-left:3px solid transparent}
  .checklist li:first-child{border-top:none}
  .panel-note.neutral .checklist li{border-top-color:var(--rule)}
  .coverage-warning{border-left-color:var(--advisory)}
  .coverage-summary{display:flex;flex-wrap:wrap;gap:7px;margin:12px 0 0}
  .coverage-summary span{border:1px solid var(--rule-2);padding:4px 10px;
             font:11px/1 var(--mono);color:var(--ink-2);
             font-variant-numeric:tabular-nums}
  details{margin-top:14px;font-size:13.5px;color:var(--ink-2)}
  details li{margin:6px 0}
  summary{cursor:pointer;font:600 11px/1 var(--mono);letter-spacing:.12em;
          text-transform:uppercase;color:var(--accent)}
  /* failure surface, the only place red appears */
  .panel-fail{border:1px solid var(--fail);border-left-width:4px;
              background:var(--fail-wash);padding:18px 22px;margin-bottom:14px}
  .panel-fail h3{margin:0 0 8px;font:600 11px/1 var(--mono);letter-spacing:.15em;
                 text-transform:uppercase;color:var(--fail)}
  .panel-fail p{margin:0;color:var(--ink-2);font-size:14px}
  /* state surface */
  .panel-state{background:var(--surface);border:1px solid var(--rule-2);
               border-radius:16px;padding:22px 24px 20px}
  .figtitle{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
  .figtitle h3{margin:0;font-size:19px;font-weight:620;letter-spacing:-.012em}
  .figtitle .meta{margin-left:auto;font:11px/1 var(--mono);color:var(--ink-3);
                  letter-spacing:.08em;text-transform:uppercase}
  .figframe{margin-top:16px;border:1px solid var(--rule);border-radius:10px;
            background:#fff;padding:14px;overflow-x:auto}
  img{max-width:100%;display:block}
  .vector{margin:12px 0 0;font:12px/1.6 var(--mono);color:var(--ink-3)}
  @media(max-width:900px){
    .metrics{grid-template-columns:repeat(3,1fr)}
    .metric{border-bottom:1px solid var(--rule)}}
</style>
</head>
<body>
<div class="top-rule"></div>
<div class="wrap">
<header class="masthead">
  <svg width="46" height="34" viewBox="0 0 46 34" aria-hidden="true">
    <rect x="1" y="1" width="26" height="11" fill="none" stroke="#2d5f5c" stroke-width="1.6"/>
    <path d="M14 12 L14 20" stroke="#2d5f5c" stroke-width="1.6"/>
    <path d="M14 21.5 l-3.2 -4 h6.4 z" fill="#2d5f5c"/>
    <ellipse cx="22" cy="27" rx="21" ry="6" fill="none" stroke="#2d5f5c" stroke-width="1.6"/>
  </svg>
  <div>
    <h1>Student Attack Graph Generator</h1>
    <p class="strap">Student edition &middot; same AGVS-SP syntax</p>
  </div>
  <div class="right"><b>Teaching</b><br>rules {{ ruleset }}</div>
</header>

<ol class="steps">
  <li class="{% if images or error %}done{% else %}now{% endif %}"><span class="n">{% if images or error %}&#10003;{% else %}1{% endif %}</span> Describe</li>
  <li class="{% if images %}done{% elif error %}now{% endif %}"><span class="n">{% if images %}&#10003;{% else %}2{% endif %}</span> Generate</li>
  <li class="{% if images %}now{% endif %}"><span class="n">3</span> Review</li>
</ol>

<div class="opening">
  <p class="lede"><span class="first">Describe a cyber incident below, and write
    the ATT&amp;CK technique and mitigation numbers you have decided on next to
    the step they belong to.</span>
    <b>Numbers you supply are drawn as you wrote them:</b> whether they are the
    right ones is your judgement, not the tool&#39;s. Where you leave a step
    without a number, the results page shows the model&#39;s suggestion and a
    short, tactic-scoped candidate list for you to review. A suggestion is not
    silently treated as your confirmed choice. Anything the tool could not use,
    or disagrees with, is listed beside the figure rather than corrected
    silently. Your text and the generated figure are saved for review. The
    figure uses the fixed AGVS-SP / Stolen Pencil visual syntax, and long graphs
    are split automatically at causal state boundaries.</p>
  <div class="key">
    <span class="kh">The notation you will get back</span>
    <span class="item"><svg width="42" height="20" aria-hidden="true"><rect x="1" y="3"
      width="40" height="14" fill="none" stroke="#2d5f5c" stroke-width="1.5"/></svg>
      action taken<br>by the attacker</span>
    <span class="item"><svg width="42" height="20" aria-hidden="true"><ellipse cx="21" cy="10"
      rx="20" ry="8" fill="none" stroke="#2d5f5c" stroke-width="1.5"/></svg>
      state of the system</span>
    <span class="item"><svg width="42" height="20" aria-hidden="true"><rect x="1" y="3"
      width="40" height="14" fill="none" stroke="#a8631b" stroke-width="1.4"
      stroke-dasharray="5 4"/></svg> annotation</span>
    <span class="item"><svg width="42" height="20" aria-hidden="true"><path d="M2 10 H40"
      stroke="#79808c" stroke-width="1.6" stroke-dasharray="2 4"/></svg>
      uncertain branch</span>
  </div>
</div>

<div class="sec"><span class="num">01</span><h2>Incident description</h2><div class="line"></div></div>
<div class="panel-action">
  <form method="post" action="/generate" accept-charset="UTF-8">
    <label class="top" for="scenario">Your text</label>
    <textarea id="scenario" name="scenario" required minlength="40"
      placeholder="Describe what the attacker did, what conditions enabled it, and what happened as a result.\n\nExample: An externally reachable service lacked multi-factor authentication. An attacker used stolen credentials to access the service, collected sensitive files, and encrypted systems for ransom.">{{ scenario or '' }}</textarea>
    <div class="tips"><b>For a clearer graph:</b> describe one attacker action per
      sentence; state the condition required before it; state the result; and
      identify alternatives explicitly (for example, "possible phishing or
      possible brute force"). Include only source-supported information. Do not
      enter passwords, API keys, or personal data.</div>
    <div class="actions">
      <button id="generate" type="submit">Generate attack graph</button>
      <p class="note">40 character minimum &middot; saved for review</p>
    </div>
  </form>
</div>

{% if error %}
<div class="sec"><h2>Error</h2><div class="line"></div></div>
<div class="panel-fail"><h3>Generation did not complete</h3><p>{{ error }}</p></div>
{% endif %}

{% if tactics %}
<div class="sec"><span class="num">02</span><h2>Tactics your graph reaches</h2><div class="line"></div>
  <span class="count clear">{{ tactics|selectattr('present')|list|length }} of {{ tactics|length }}</span></div>
<div class="tactics">
  <div class="tbar">
    {%- for t in tactics %}
    <span{% if t.present %} style="background:var(--t{{ '%02d'|format(loop.index) }})"{% endif %}></span>
    {%- endfor %}
  </div>
  <div class="tlist">
    {%- for t in tactics %}
    <span class="t{% if not t.present %} off{% endif %}">
      <i{% if t.present %} style="background:var(--t{{ '%02d'|format(loop.index) }})"{% endif %}></i>
      <span class="n">{{ '%02d'|format(loop.index) }}</span> {{ t.name }}</span>
    {%- endfor %}
  </div>
</div>
{% endif %}

{% if metrics and (metrics.calls or metrics.pages) %}
<div class="sec"><span class="num">03</span><h2>Measured this run</h2><div class="line"></div></div>
<div class="metrics">
  <div class="metric"><span class="k">Pages</span>
    <span class="v">{% if metrics.pages is none %}&mdash;{% else %}{{ metrics.pages }}{% endif %}</span>
    <span class="sub">{% if metrics.pages is none %}not rendered{% elif metrics.pages == 1 %}no split needed{% else %}lossless split{% endif %}</span></div>
  <div class="metric"><span class="k">Nodes</span>
    <span class="v">{% if metrics.nodes is none %}&mdash;{% else %}{{ metrics.nodes }}{% endif %}</span>
    <span class="sub">{% if metrics.nodes is none %}not rendered{% else %}{{ metrics.states }} states / {{ metrics.actions }} actions{% endif %}</span></div>
  <div class="metric {{ metrics.width_state }}"><span class="k">Width</span>
    <span class="v">{% if metrics.widest_px is none %}&mdash;{% else %}{{ metrics.widest_px }}<span class="u">px</span>{% endif %}</span>
    <span class="sub">{% if metrics.widest_px is none %}not measured{% elif metrics.width_state == 'warn' %}over {{ metrics.width_budget_px }} budget{% else %}budget {{ metrics.width_budget_px }}{% endif %}</span></div>
  <div class="metric {{ metrics.print_state }}"><span class="k">Prints at</span>
    <span class="v">{% if metrics.printed_pt is none %}&mdash;{% else %}{{ "%.1f"|format(metrics.printed_pt) }}<span class="u">pt</span>{% endif %}</span>
    <span class="sub">{% if metrics.printed_pt is none %}not measured{% elif metrics.print_state == 'warn' %}below {{ "%.1f"|format(metrics.print_floor_pt) }} floor{% else %}floor {{ "%.1f"|format(metrics.print_floor_pt) }}{% endif %}</span></div>
  <div class="metric"><span class="k">API calls</span><span class="v">{{ metrics.calls }}</span>
    <span class="sub">{{ metrics.input_tokens }} in / {{ metrics.output_tokens }} out</span></div>
  <div class="metric {{ metrics.cost_state }}"><span class="k">Cost</span>
    <span class="v">{{ "%.2f"|format(metrics.cost_usd) }}<span class="u">usd</span></span>
    <span class="sub">of {{ "%.2f"|format(metrics.limit_usd) }} limit</span></div>
</div>
{% endif %}

{% if notes %}
<div class="sec"><span class="num">04</span><h2>Review your ATT&amp;CK choices</h2><div class="line"></div>
  <span class="count">{{ notes|length }}</span></div>
<div class="panel-note">
  <h3>Steps that still need a decision from you</h3>
  <ul class="checklist">
  {% for note in notes %}<li>{{ note }}</li>{% endfor %}
  </ul>
  <p class="small">Numbers you wrote were kept as you wrote them. Nothing was
  silently corrected. For an open step, Stage B&#39;s suggestion and the
  tactic-scoped alternatives are prompts for your review, not an answer chosen
  on your behalf.</p>
</div>
{% endif %}

{% if restatement %}
<div class="sec"><span class="num">05</span><h2>What your graph says</h2><div class="line"></div>
  <span class="count clear">{{ restatement|length }} lines</span></div>
<div class="panel-note neutral">
  <h3>Read back from the arrows</h3>
  <ul class="checklist">
  {% for line in restatement %}<li>{{ line }}</li>{% endfor %}
  </ul>
  <p class="small">This is a reading of the figure, not an opinion about the
  incident: every sentence comes from an arrow you can see. Compare it with
  what you meant to say.</p>
</div>
{% endif %}

{% if source_coverage %}
<div class="sec"><span class="num">06</span><h2>Check the source coverage</h2><div class="line"></div>
  {% if source_coverage.warnings %}<span class="count">{{ source_coverage.warnings|length }}</span>
  {% else %}<span class="count clear">clear</span>{% endif %}</div>
<div class="panel-note{% if not source_coverage.warnings %} neutral{% endif %}">
  <h3>{% if source_coverage.warnings %}Statements that need a second look{% else %}Every statement is represented{% endif %}</h3>
  <div class="coverage-summary">
    <span>{{ source_coverage.count('event') }} action statement(s)</span>
    <span>{{ source_coverage.count('state') }} state/outcome statement(s)</span>
    <span>{{ source_coverage.count('context') }} context statement(s)</span>
    <span>{{ source_coverage.count('unrepresented') }} not represented</span>
  </div>
  {% if source_coverage.warnings %}
  <ul class="checklist">
  {% for item in source_coverage.warnings %}
    <li class="coverage-warning">
      &ldquo;{{ item.source }}&rdquo;
      {% if item.kind == 'state' and item.needs_action_review %}
        <br><span class="small">This sentence names an attacker action, but the
        graph represents it only as the state
        <b>{{ item.graph_labels|join(', ') }}</b>. Check whether the action
        should also be a rectangle.</span>
      {% elif item.kind == 'unrepresented' %}
        <br><span class="small">No event or state in the graph clearly
        represents this statement. Check whether it is relevant attack content
        or background context.</span>
      {% endif %}
    </li>
  {% endfor %}
  </ul>
  {% else %}
  <p class="small">Every source statement was matched to an action, a state,
  an outcome, or explicit report context.</p>
  {% endif %}
  <details>
    <summary>Show how every source statement was classified</summary>
    <ul>
    {% for item in source_coverage.items %}
      <li><b>{{ item.kind }}</b>: {{ item.source }}
      {% if item.graph_labels %}<br><span class="small">Graph node(s):
      {{ item.graph_labels|join(', ') }}</span>{% endif %}</li>
    {% endfor %}
    </ul>
  </details>
  <p class="small">This is a non-blocking teaching check. It does not change
  the graph or decide that a statement must be an attack step.</p>
</div>
{% endif %}

{% if images %}
<div class="sec"><span class="num">07</span><h2>Your graph</h2><div class="line"></div></div>
<div class="panel-state">
  <div class="figtitle"><h3>{{ title }}</h3>
    <span class="meta">{{ n_pre }} preconditions &middot; {{ n_ev }} events</span></div>
  {% for image in images %}
  <div class="figframe"><img src="/outputs/{{ image }}"
    alt="Generated attack graph, page {{ loop.index }} of {{ images|length }}"></div>
  {% endfor %}
  {% if vectors %}
  <p class="vector">Vector copies, if you are putting the figure in a document
    that will be printed:
    {% for vector in vectors %}<a href="/outputs/{{ vector }}">{{ vector }}</a>
    {%- if not loop.last %}, {% endif %}{% endfor %}</p>
  {% endif %}
  <p class="vector">Source saved as <code>{{ source_name }}</code>; graph saved as
  {% for image in images %}<code>{{ image }}</code>{% if not loop.last %},
  {% endif %}{% endfor %}; evidence audit saved as
  <a href="/outputs/{{ audit }}"><code>{{ audit }}</code></a>.</p>
</div>
{% endif %}
</div>

<script>
  document.querySelector("form").addEventListener("submit", function () {
    const button = document.getElementById("generate");
    button.disabled = true;
    button.textContent = "Generating...";
  });
</script>
</body>
</html>
"""


def _page_context(**overrides) -> dict:
    """Defaults every render of the page needs, so no branch can omit one.

    The page reads a dozen names and this file returns from six places. Listing
    the defaults once means a new panel cannot silently disappear from the
    branch whose author forgot to pass it.
    """

    context = {
        "scenario": "",
        "error": None,
        "images": None,
        "vectors": None,
        "usage": None,
        "metrics": None,
        "tactics": None,
        "notes": None,
        "restatement": None,
        "source_coverage": None,
        "audit": None,
        "source_name": None,
        "title": None,
        "n_pre": None,
        "n_ev": None,
        "ruleset": RULESET,
    }
    context.update(overrides)
    return context


@app.route("/")
def index():
    return render_template_string(PAGE, **_page_context())


@app.route("/generate", methods=["POST"])
def generate():
    scenario = (request.form.get("scenario") or "").strip()
    if len(scenario) < 40:
        return render_template_string(
            PAGE, **_page_context(
                scenario=scenario,
                error=("Please provide at least a short incident description "
                       "(40 characters).")))
    if len(scenario) > MAX_SCENARIO_CHARS:
        return render_template_string(
            PAGE, **_page_context(
                error=(f"The incident description is too long. The limit is "
                       f"{MAX_SCENARIO_CHARS:,} characters."))), 400
    if _has_probable_mojibake(scenario):
        return render_template_string(
            PAGE, **_page_context(
                scenario=scenario,
                error=("The text appears to contain damaged character encoding "
                       "(for example, UTF-8 read as GBK/ANSI). Re-copy it from "
                       "the source as UTF-8 or plain text before generating "
                       "the graph."))), 400

    source_path = _save_submission(scenario)
    output_stem = f"{source_path.stem}__rules-{RULESET}"
    output_path = tagged_output_path(OUTPUTS_DIR, output_stem, PROVIDER, MODEL)

    # Bound before the try so the failure path can still report the shape of a
    # graph that validated and then failed to draw.
    graph = None
    try:
        graph = extract_attack_graph(scenario, provider=PROVIDER, model=MODEL,
                                     ruleset=RULESET)
        source_coverage = audit_source_coverage(scenario, graph)
        usage = get_last_api_usage()
        paths = render_split(graph, str(output_path), dpi=170)
        images = [Path(path).name for path in paths]
        # The same pages in vector form, for a student writing the figure into
        # a report. Identical geometry, so it is the same drawing.
        vectors = [
            Path(path).name for path in
            render_split(graph, str(output_path.with_suffix(".svg")),
                         fmt="svg")
        ]
        audit_path = output_path.with_suffix(".json")
        audit_path.write_text(
            graph.model_dump_json(indent=2), encoding="utf-8")
    except Exception as error:
        app.logger.exception("Student attack-graph generation failed")
        usage = get_last_api_usage()
        return render_template_string(
            PAGE, **_page_context(
                scenario=scenario, error=_friendly_error(error), usage=usage,
                # Nothing was drawn, so no width was measured. Each absent
                # measurement prints as an em dash; a zero would read as a page
                # comfortably inside the budget.
                metrics=run_metrics(graph, None, None, usage),
                tactics=tactic_progression(graph) if graph else None))

    return render_template_string(
        PAGE, **_page_context(
            images=images, vectors=vectors, audit=audit_path.name,
            source_name=source_path.name, title=graph.title,
            n_pre=len(graph.preconditions), n_ev=len(graph.events),
            usage=usage,
            metrics=run_metrics(graph, quality_report_path(str(output_path)),
                                len(images), usage),
            tactics=tactic_progression(graph),
            notes=get_last_student_notes(),
            restatement=get_last_graph_restatement(),
            source_coverage=source_coverage))


@app.route("/outputs/<path:name>")
def outputs(name):
    return send_from_directory(str(OUTPUTS_DIR), name)


if __name__ == "__main__":
    # See the note in app.py: the interactive debugger is arbitrary code
    # execution for anyone who can reach the port, and a teaching tool is the
    # one most likely to be run on a shared machine.
    app.run(debug=os.environ.get("AGVS_DEBUG") == "1", port=5001)
