import json
import os
import re
import sys
from pathlib import Path

from flask import Flask, request, render_template_string, send_from_directory

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from ingest import ingest                     # noqa: E402
from extract import (extract_attack_graph, extract_attack_graph_semantic,  # noqa: E402
                     is_construct_ruleset, get_last_salvaged_nodes,
                     get_last_shape_notes, get_last_shape_measure,
                     get_last_api_usage, is_structural_stage_a_fault,
                     resolve_model, zero_api_usage)
from attack_graph import (quality_report_path, render_split,  # noqa: E402
                          tagged_output_path)
from run_metrics import run_metrics, tactic_progression  # noqa: E402
from reproducibility import (build_reproducibility_spec,  # noqa: E402
                             load_validated_graph,
                             store_validated_graph,
                             write_run_manifest)
from semantic_layout_renderer import render_semantic_layout  # noqa: E402

REPORTS_DIR = ROOT / "reports"
OUTPUTS_DIR = ROOT / "outputs"
REPORTS_DIR.mkdir(exist_ok=True)
OUTPUTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
ALLOWED_REPORT_SUFFIXES = {".pdf", ".txt", ".md"}


def list_claude_models():
    """List the Claude models available to this account, with a fallback."""
    fallback = ["claude-sonnet-5", "claude-opus-4-8", "claude-sonnet-4-6",
                "claude-haiku-4-5-20251001"]
    try:
        import os
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return fallback
        import anthropic
        ids = [m.id for m in anthropic.Anthropic(
            max_retries=0, timeout=30.0).models.list().data]
        claude = [i for i in ids if i.startswith("claude-")]
        return claude or fallback
    except Exception:
        return fallback


CLAUDE_MODELS = list_claude_models()

# Local models suited to a 6-8 GB GPU (Ollama). Pull one before selecting it,
# e.g. `ollama pull qwen3:8b`.
OLLAMA_MODELS = ["qwen3:8b", "phi4-mini", "llama3.1:8b", "deepseek-r1:8b",
                 "gemma3:4b"]

COMPARISON_BASELINE = "v1.4"
DEFAULT_RULESET = "v1.6"
RULES_DIR = ROOT / "rules"


def available_rulesets() -> list[str]:

    versions = sorted(
        path.stem.replace("ruleset_", "")
        for path in RULES_DIR.glob("ruleset_*.md")
        if not path.stem.startswith("ruleset_student-")
    )
    ordered = [DEFAULT_RULESET] + [
        version for version in versions if version != DEFAULT_RULESET
    ]
    return [version for version in ordered if version in set(versions)] or [
        DEFAULT_RULESET
    ]


RULESETS = available_rulesets()


def _selected_ruleset(value: str | None) -> str:
    """Accept only a rule set that exists on disk; fall back to the default."""
    return value if value in RULESETS else DEFAULT_RULESET


def _extraction_notes() -> list[str]:

    notes: list[str] = []
    dropped = get_last_salvaged_nodes()
    if dropped:
        notes.append(
            f"{len(dropped)} node(s) were left out because nothing in the "
            f"graph connected to them, and the model did not reconnect them "
            f"when asked: {', '.join(dropped)}. Everything else is as the "
            "model returned it.")
    shape = get_last_shape_measure()
    if shape and shape["events"]:
        notes.append(
            f"Graph shape: {shape['events']} events over {shape['ranks']} "
            f"ranks, widest {shape['widest']}; "
            f"{shape['on_critical_path']} of {shape['events']} events lie on "
            "the longest dependency path. A high share means the model read "
            "the steps as a single sequence rather than as work that could "
            "run in parallel.")
    notes.extend(get_last_shape_notes())
    return notes


def _layout_warnings(out_path: Path) -> list[str]:

    report_path = quality_report_path(str(out_path))
    if not report_path.is_file():
        return []
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [
        f"Page {page.get('page')}: {warning}"
        for page in report.get("pages", [])
        for warning in page.get("warnings", [])
    ]


def _friendly_error(e: Exception, provider: str) -> str:

    msg = str(e)
    low = msg.lower()
    status = getattr(e, "status_code", None)
    request_id = getattr(e, "request_id", None)
    diagnostic = ""
    if status or request_id:
        diagnostic = (f" [HTTP {status or 'unknown'}, request_id="
                      f"{request_id or 'unavailable'}]")

    def says(*words: str) -> bool:
        """Match whole words only, so one term cannot hide inside another."""
        return any(
            re.search(rf"\b{re.escape(word)}\b", low) for word in words
        )

    # --- failures this pipeline raised itself -----------------------------
    if is_structural_stage_a_fault(msg):
        return ("The model found the attack steps but returned an inconsistent "
                "graph, and the permitted Stage A correction did not resolve "
                "it. This is a structural failure, not a sign that the report "
                "lacks technical detail. No invalid graph was saved. Retry "
                f"once; keep this diagnostic if it repeats. Original error: {msg}")
    if "not a verbatim extract" in low:
        return ("The evidence rule set requires every event to quote the "
                "report word for word, and the model supplied a quotation it "
                "had reworded. The correction attempt did not resolve it. This "
                "is the abstention contract working, not a provider problem. "
                "No unsupported graph was saved. Retry once; if it repeats, "
                "the report may not state that action in one contiguous "
                f"passage. Original error: {msg}")
    if ("could not resolve authentication" in low or
            "authentication_error" in low or status == 401):
        return ("Anthropic could not authenticate the configured API key. "
                f"Check ANTHROPIC_API_KEY and restart the app.{diagnostic} "
                f"Original API message: {msg}")
    if "model" in low and ("not_found" in low or status == 404 or "not found" in low):
        return ("Anthropic did not recognise the selected model. Choose a model "
                f"listed for this API key.{diagnostic} Original API message: {msg}")
    if "credit balance" in low or "credit_balance" in low:
        return ("Anthropic rejected this API key for insufficient usable credit. "
                "The key may belong to a different workspace from the balance "
                "you are viewing, or that workspace/organization may have reached "
                "a spending limit. Check the key's workspace and Settings > "
                f"Limits, not only the Cost chart.{diagnostic} Original API "
                f"message: {msg}")
    if status == 429 or says("rate_limit", "quota") or "rate limit" in low:
        return ("Anthropic rejected the request because an organization or "
                "workspace rate/spend limit was reached. Check Settings > Limits."
                f"{diagnostic} Original API message: {msg}")
    if says("billing"):
        return ("Anthropic rejected the request because of a billing or workspace "
                f"configuration problem.{diagnostic} Original API message: {msg}")
    if "max_tokens" in low:
        return ("The structured graph exceeded the deliberately limited output "
                "budget. Use a shorter report; do not raise the limit without "
                f"reviewing the cost guard.{diagnostic} Original error: {msg}")
    if ("not tactic" in low or "literal_error" in low or
            "belongs to" in low and "tactic" in low):
        return ("Claude returned an ATT&CK technique outside the event's tactic, "
                "and the constrained Stage B correction did not complete. No "
                "invalid graph was saved. Please retry once; if it repeats, keep "
                f"this diagnostic for review.{diagnostic} Original error: {msg}")
    if ("no attack steps" in low or "produced no attack" in low or
            "stage a failed" in low or "returned no events" in low):
        return ("No attack steps were found in this report. It may have little "
                "technical detail, or the model may have returned an empty Stage "
                "A skeleton. No empty graph was saved. Try once more; if the same "
                "technical report fails again, keep the diagnostic for review. "
                "（未保存空图；同一技术报告再次失败时请保留诊断信息。）")
    if provider == "ollama" and ("connection" in low or "refused" in low
                                 or "11434" in low):
        return ("Cannot reach Ollama. Make sure the Ollama app is running "
                "before using the local model. "
                "(无法连接 Ollama：使用本地模型前请确认 Ollama 已在后台运行。)")
    return f"Something went wrong{diagnostic}: {msg}"

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack Graph Generator</title>
<style>
/* The interface uses the visual grammar of the artefact it produces, so that
   a reader who has learned the figure has already learned the page:

     sharp rectangle  = action surface     (the things you do)
     large radius     = state surface      (what came back)
     dashed border    = annotation         (needs your review)
     dotted border    = uncertain          (a suggestion, not a choice)
     strict top-down  = configure, run, result. No sidebar.

   Three colours carry meaning and nothing carries decoration: the edition
   accent for structure, ochre for anything a person must review, red only
   for failure. The figure itself gains no colour from any of this. Sherzhanov
   et al. (2024) found brighter hues and denser line structure did not
   significantly improve comprehension among non-experts, and a printed
   dissertation may be greyscale. */
  :root{
    --accent:#33415e; --accent-dark:#26304a;   /* student_app.py uses #2d5f5c */
    --ink:#14181f; --ink-2:#454c58; --ink-3:#79808c;
    --paper:#fbfaf8; --surface:#fff;
    --rule:#ded9d1; --rule-2:#b5b0a7;
    --advisory:#a8631b; --fail:#9b2f2f;
    --advisory-wash:#fdf6ea; --fail-wash:#fbf0ee;
    --sans:ui-sans-serif,"Segoe UI",Inter,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,"Cascadia Mono","JetBrains Mono",Consolas,monospace;
    /* ATT&CK tactic ramp, ordered cool to warm so that warmer reads as nearer
       Impact. Near-constant lightness, and always drawn beside the tactic
       name, so colour is a redundant channel and never the only carrier. */
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
  /* Numbered section rules. The number gives the page a spine the eye can
     follow, which is what a run of identically weighted panels lacked. */
  .sec{display:flex;align-items:baseline;gap:12px;margin:40px 0 14px}
  .sec .num{font:600 11px/1 var(--mono);letter-spacing:.1em;color:var(--accent);
            font-variant-numeric:tabular-nums}
  .sec h2{margin:0;font:600 11px/1 var(--mono);letter-spacing:.18em;
          text-transform:uppercase;color:var(--ink-2)}
  .sec .line{flex:1;height:1px;background:var(--rule)}
  /* Editorial two-column opening: statement left, fixed properties right.
     A single measure-limited paragraph left a third of the page empty, so the
     narrow column now carries the three things the tool does not let you
     change. Collapses to one column below 860px. */
  .opening{display:grid;gap:28px 40px;grid-template-columns:minmax(0,1.55fr) minmax(240px,1fr);
           align-items:start;padding:26px 0 4px}
  .opening .lede{margin:0;max-width:62ch;font-size:16.5px;line-height:1.6;
                 color:var(--ink-2)}
  .opening .lede b{color:var(--ink)}
  .opening .lede .first{font-size:19px;line-height:1.45;color:var(--ink);
                        display:block;margin-bottom:12px;letter-spacing:-.008em}
  .fixed-facts{display:flex;flex-direction:column;border-top:2px solid var(--ink)}
  .fixed-facts .fact{padding:13px 0 12px;border-bottom:1px solid var(--rule)}
  .fixed-facts .fact .k{display:block;font:600 9.5px/1 var(--mono);
        letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3);
        margin-bottom:7px}
  .fixed-facts .fact .v{font:12.5px/1.35 var(--mono);color:var(--ink)}
  .fixed-facts .fact .n{display:block;margin-top:5px;font:11px/1.4 var(--sans);
        color:var(--ink-3)}
  @media(max-width:860px){.opening{grid-template-columns:1fr}}
  .sec .count{font:600 10px/1 var(--mono);letter-spacing:.1em;color:#fff;
              background:var(--advisory);padding:5px 8px;border-radius:2px}
  .sec .count.clear{background:var(--ink-3)}
  /* action surface */
  .panel-action{background:var(--surface);border:1px solid var(--rule-2);
                border-radius:0;padding:24px 26px 22px}
  .fields{display:grid;gap:20px 26px;
          grid-template-columns:repeat(auto-fit,minmax(178px,1fr))}
  .field label{display:block;font:600 10px/1 var(--mono);letter-spacing:.15em;
               text-transform:uppercase;color:var(--ink-3);margin-bottom:7px}
  .field input[type=file],.field select{width:100%;border:1px solid var(--rule-2);
        background:var(--paper);padding:8px 10px;font:14px/1.3 var(--sans);
        color:var(--ink);border-radius:0}
  .field select:focus,.field input:focus{outline:2px solid var(--accent);
        outline-offset:-2px}
  .field .fixed{border:1px solid var(--rule);padding:9px 11px;color:var(--ink-2);
        font:12.5px/1.3 var(--mono)}
  .field .hint{margin:6px 0 0;font:11px/1.4 var(--mono);color:var(--ink-3)}
  .actions{display:flex;align-items:center;gap:18px;margin-top:24px;
           padding-top:20px;border-top:1px solid var(--rule);flex-wrap:wrap}
  button{font:600 14px/1 var(--sans);color:#fff;background:var(--accent);
         border:none;border-radius:0;padding:13px 24px;cursor:pointer}
  button:hover{background:var(--accent-dark)}
  .actions .note{font:11px/1.5 var(--mono);color:var(--ink-3);max-width:52ch;margin:0}
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
  /* the measurements are the content */
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
  .metric .sub{display:block;margin-top:7px;font:11px/1 var(--mono);color:var(--ink-3)}
  .metric.ok .v{color:var(--accent)}
  .metric.warn .v,.metric.warn .sub{color:var(--advisory)}
  .metric.bad .v,.metric.bad .sub{color:var(--fail)}
  /* advisory surface */
  .panel-note{border:1.5px dashed var(--advisory);background:var(--advisory-wash);
              padding:18px 22px;margin:0 0 16px}
  .panel-note h3{margin:0 0 4px;font:600 11px/1 var(--mono);letter-spacing:.15em;
                 text-transform:uppercase;color:var(--advisory)}
  /* A check that found nothing is still a result, so it keeps the panel shape
     and loses only the ochre that means "a person must look at this". */
  .panel-note.neutral{border:1px solid var(--rule-2);border-style:solid;
                      background:transparent}
  .panel-note.neutral h3{color:var(--ink-2)}
  .panel-note .tail{margin:12px 0 0;font-size:12.5px;color:var(--ink-3)}
  .checklist{list-style:none;margin:10px 0 0;padding:0}
  .checklist li{padding:12px 0;border-top:1px solid #ecdfc8;font-size:14px;
                color:var(--ink-2)}
  .checklist li:first-child{border-top:none}
  /* failure surface, the only place red appears */
  .panel-fail{border:1px solid var(--fail);border-left-width:4px;
              background:var(--fail-wash);padding:18px 22px;margin-bottom:16px}
  .panel-fail h3{margin:0 0 8px;font:600 11px/1 var(--mono);letter-spacing:.15em;
                 text-transform:uppercase;color:var(--fail)}
  .panel-fail p{margin:0;color:var(--ink-2);font-size:14px}
  /* state surface */
  .panel-state{background:var(--surface);border:1px solid var(--rule-2);
               border-radius:16px;padding:22px 24px 20px}
  .figtitle{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
  .figtitle h3{margin:0;font-size:19px;font-weight:620;letter-spacing:-.012em}
  .figtitle .meta{margin-left:auto;font:11px/1 var(--mono);color:var(--ink-3);
                  letter-spacing:.08em;text-transform:uppercase;
                  font-variant-numeric:tabular-nums}
  .figframe{margin-top:16px;border:1px solid var(--rule);border-radius:10px;
            background:#fff;padding:14px;overflow-x:auto}
  img{max-width:100%;display:block}
  .vector{margin:14px 0 0;font:12px/1.6 var(--mono);color:var(--ink-3)}
  /* run header: the configuration collapses to one line after a run, so the
     figure gets the vertical space. One form, one code path. */
  .runwrap{border-top:2px solid var(--accent);border-bottom:1px solid var(--rule);
           margin-top:26px}
  .runwrap>summary{list-style:none;cursor:pointer;display:flex;flex-wrap:wrap;
           align-items:center;padding:12px 0;font:12px/1.4 var(--mono);
           color:var(--ink-2)}
  .runwrap>summary::-webkit-details-marker{display:none}
  .runwrap>summary .seg{padding:0 16px;border-right:1px solid var(--rule)}
  .runwrap>summary .seg:first-child{padding-left:0}
  .runwrap>summary .seg b{color:var(--ink);font-weight:600}
  .runwrap>summary .seg .k{color:var(--ink-3);letter-spacing:.1em;
           text-transform:uppercase;font-size:10px;margin-right:7px}
  .runwrap>summary .toggle{margin-left:auto;color:var(--accent);
           border-bottom:1px solid currentColor;padding-bottom:1px}
  .runwrap[open]>summary .toggle::after{content:" (hide)"}
  .runwrap>.panel-action{border-top:none;margin:0 0 4px}
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
    <rect x="1" y="1" width="26" height="11" fill="none" stroke="#33415e" stroke-width="1.6"/>
    <path d="M14 12 L14 20" stroke="#33415e" stroke-width="1.6"/>
    <path d="M14 21.5 l-3.2 -4 h6.4 z" fill="#33415e"/>
    <ellipse cx="22" cy="27" rx="21" ry="6" fill="none" stroke="#33415e" stroke-width="1.6"/>
  </svg>
  <div>
    <h1>Attack Graph Generator</h1>
    <p class="strap">AGVS-SP visual syntax &middot; ATT&amp;CK aligned</p>
  </div>
  <div class="right"><b>Professional</b><br>rules {{ selected_ruleset }}</div>
</header>

<!-- Statement on the left, the three properties you cannot change on the
     right. The narrow column exists because a measure-limited paragraph on
     its own left the right third of the page empty. -->
<div class="opening">
  <p class="lede"><span class="first">Upload an incident report and the tool
    returns an ATT&amp;CK-aligned attack graph, drawn to a fixed visual
    syntax.</span>
    The rule set governs what the model is allowed to call a precondition, an
    action and a logical relation, and every version is kept on disk so a run
    can be repeated under the rules it was made with. <b>What the model decides
    is reported, not corrected silently:</b> anything the extraction had to give
    up, and any page that misses a legibility limit, is listed beside the figure
    rather than hidden.</p>
  <div class="fixed-facts">
    <div class="fact"><span class="k">Visual syntax</span>
      <span class="v">Layout: AGVS-SP branch-aware</span>
      <span class="n">Rectangle for an action, ellipse for a state, dashed for
        an annotation. Checked on every run.</span></div>
    <div class="fact"><span class="k">Pagination</span>
      <span class="v">Long-graph pagination: automatic</span>
      <span class="n">Split only at causal state boundaries, so no page loses
        a dependency.</span></div>
    <div class="fact"><span class="k">Print floor</span>
      <span class="v">8.0 pt at 250 mm placement</span>
      <span class="n">A page too wide to meet it is reported, not silently
        shipped.</span></div>
  </div>
</div>

<!-- One form, rendered once. It is open before a run and collapsed to a single
     summary line afterwards, so the figure gets the vertical space without a
     second code path that could drift from this one. -->
<details class="runwrap" {% if not images %}open{% endif %}>
  <summary>
    {% if images %}
    <span class="seg"><span class="k">Rules</span><b>{{ selected_ruleset }}</b></span>
    <span class="seg"><span class="k">Layout</span><b>AGVS-SP</b></span>
    <span class="seg"><span class="k">Pages</span><b>{{ images|length }}</b></span>
    {% else %}
    <span class="seg"><b>01 &nbsp;Run configuration</b></span>
    {% endif %}
    <span class="toggle">Change and re-run</span>
  </summary>
  <div class="panel-action">
  <form method="post" action="/generate" enctype="multipart/form-data">
    <div class="fields">
      <div class="field">
        <label for="report">Report</label>
        <input id="report" type="file" name="report" accept=".pdf,.txt,.md" required>
        <p class="hint">PDF, TXT or Markdown &middot; max 25 MB</p>
      </div>
      <div class="field">
        <label for="provider">Provider</label>
        <select name="provider" id="provider" onchange="syncModels()">
          <option value="anthropic">Claude API (hosted, richer)</option>
          <option value="ollama">Ollama (local, private)</option>
          <option value="mock">Mock (offline test)</option>
        </select>
        <p class="hint">hosted, local or offline</p>
      </div>
      <div class="field" id="model_wrap">
        <label id="model_label" for="model">Claude model</label>
        <select name="model" id="model"></select>
        <p class="hint">blank uses the default</p>
      </div>
      <div class="field">
        <label for="ruleset">Rules</label>
        <select name="ruleset" id="ruleset">
          {% for r in rulesets %}
          <option value="{{ r }}" {% if r == selected_ruleset %}selected{% endif %}>
            {{ r }}{% if r == default_ruleset %} (current){% elif r == baseline %} (frozen baseline){% else %} (experimental){% endif %}
          </option>
          {% endfor %}
        </select>
        <p class="hint">{{ baseline }} is the frozen comparison baseline</p>
      </div>
      <div class="field">
        <label for="fresh_sample">Sampling</label>
        <label><input id="fresh_sample" type="checkbox"
          name="fresh_sample" value="1"> Generate an independent sample</label>
        <p class="hint">Unchecked: replay the validated graph for identical
          source, rules, model, catalogue and extraction code.</p>
      </div>
      <!-- The layout and pagination lines used to sit here as two disabled
           fields. They are not inputs, they are properties of the tool, so
           they moved to the opening panel above where they read as facts
           rather than as controls somebody forgot to enable. -->
      <!-- The semantic draft pipeline's checkbox was here. It is an
           explored alternative that is kept, tested and reachable from
           `extract_attack_graph_semantic`, but it is no longer offered in
           the interface, because a figure it produces cannot be compared
           with any other figure this project reports:

             - it refuses v1.6 outright, and v1.6 is what the work is about;
             - it takes no rule set, so it cannot appear on either side of
               the v1.4/v1.6 comparison that is the research method;
             - `measure_runs.py` does not read it, so nothing measures it;
             - it draws through its own renderer, so it has none of the
               visual-syntax key, the page-width budget or the vector
               output that every other figure now carries.

           Leaving one click between a user and a figure that matches
           nothing in the write-up is the trap; deleting 2,600 tested lines
           nine days before the draft is the other one. -->
    </div>
    <div class="actions">
      <button type="submit">Generate attack graph</button>
      <p class="note">The report is saved to reports/. Each graph is saved to
        outputs/ with its rule set, model, and a sequential run number, so prior
        generations are retained.</p>
    </div>
  </form>
  </div>
</details>

{% if error %}
<div class="sec"><h2>Error</h2><div class="line"></div></div>
<div class="panel-fail"><h3>Generation did not complete</h3><p>{{ error }}</p></div>
{% endif %}

{% if tactics %}
<div class="sec"><span class="num">02</span><h2>Tactics this graph reaches</h2><div class="line"></div>
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
    <span class="sub">{% if metrics.pages is none %}not rendered{% else %}lossless split{% endif %}</span></div>
  <div class="metric"><span class="k">Nodes</span>
    <span class="v">{% if metrics.nodes is none %}&mdash;{% else %}{{ metrics.nodes }}{% endif %}</span>
    <span class="sub">{% if metrics.nodes is none %}not rendered{% else %}{{ metrics.states }} states / {{ metrics.actions }} actions{% endif %}</span></div>
  <div class="metric {{ metrics.width_state }}"><span class="k">Widest page</span>
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

{% if reproducibility %}
<div class="panel-note neutral">
  <h3>Reproducibility &middot; {{ reproducibility.label }}</h3>
  <p class="tail">{{ reproducibility.message }} Cache key:
    <code>{{ reproducibility.cache_key }}</code>. The complete run identity is
    saved as <code>{{ reproducibility.manifest }}</code>.</p>
</div>
{% endif %}

{% if images %}
<!-- Rendered whether or not anything was flagged. An absent section reads as
     a gap in the numbering; a section saying nothing was flagged is the
     result of a check, which is what a reviewer needs to know. -->
<div class="sec"><span class="num">04</span><h2>Needs your review</h2><div class="line"></div>
  {% if layout_warnings %}<span class="count">{{ layout_warnings|length }}</span>
  {% else %}<span class="count clear">nothing flagged</span>{% endif %}</div>
{% if layout_warnings %}
<div class="panel-note">
  <h3>The graph was saved, but these pages miss an acceptance limit</h3>
  <ul class="checklist">{% for w in layout_warnings %}<li>{{ w }}</li>{% endfor %}</ul>
  <p class="tail">Reported rather than withheld: a reviewer still needs to see the
    page. Full metrics are in the run's <code>.layout-quality.json</code> file.</p>
</div>
{% else %}
<div class="panel-note neutral">
  <h3>Every page met the acceptance limits</h3>
  <p class="tail">No extraction note, and no page outside the width budget or
    below the print floor. Full metrics are in the run's
    <code>.layout-quality.json</code> file.</p>
</div>
{% endif %}
{% endif %}

{% if images %}
<div class="sec"><span class="num">05</span><h2>Result</h2><div class="line"></div></div>
<div class="panel-state">
  <div class="figtitle"><h3>{{ title }}</h3>
    <span class="meta">{{ n_pre }} preconditions &middot; {{ n_ev }} events</span></div>
  {% for im in images %}
  <div class="figframe"><img src="/outputs/{{ im }}" alt="attack graph, page {{ loop.index }} of {{ images|length }}"></div>
  {% endfor %}
  {% if vectors %}
  <p class="vector">Vector copies of the same pages, for a document that will be
    printed: {% for v in vectors %}<a href="/outputs/{{ v }}">{{ v }}</a>{% if not
    loop.last %}, {% endif %}{% endfor %}</p>
  {% endif %}
</div>
{% endif %}
</div>

<script>
  const CLAUDE = {{ claude_models|tojson }};
  const OLLAMA = {{ ollama_models|tojson }};
  function fill(sel, items, withDefault) {
    sel.innerHTML = "";
    if (withDefault) {
      const o = document.createElement("option");
      o.value = ""; o.textContent = "Default"; sel.appendChild(o);
    }
    items.forEach(function(m) {
      const o = document.createElement("option");
      o.value = m; o.textContent = m; sel.appendChild(o);
    });
  }
  function syncModels() {
    const p = document.getElementById("provider").value;
    const wrap = document.getElementById("model_wrap");
    const label = document.getElementById("model_label");
    const sel = document.getElementById("model");
    if (p === "mock") { wrap.style.display = "none"; return; }
    wrap.style.display = "";
    if (p === "ollama") { label.textContent = "Local model:"; fill(sel, OLLAMA, false); }
    else { label.textContent = "Claude model:"; fill(sel, CLAUDE, true); }
  }
  syncModels();
</script>
</body>
</html>
"""


def _page_context(**overrides) -> dict:
    """Defaults every render of the page needs, so no branch can omit one."""
    context = {
        "images": None,
        "vectors": None,
        "error": None,
        "usage": None,
        "metrics": None,
        "tactics": None,
        "title": None,
        "n_pre": None,
        "n_ev": None,
        "layout_warnings": None,
        "claude_models": CLAUDE_MODELS,
        "ollama_models": OLLAMA_MODELS,
        "rulesets": RULESETS,
        "baseline": COMPARISON_BASELINE,
        "default_ruleset": DEFAULT_RULESET,
        "selected_ruleset": DEFAULT_RULESET,
        "reproducibility": None,
    }
    context.update(overrides)
    return context


@app.route("/")
def index():
    return render_template_string(PAGE, **_page_context())


@app.route("/generate", methods=["POST"])
def generate():
    f = request.files.get("report")
    if not f or not f.filename:
        return render_template_string(
            PAGE, **_page_context(error="No file uploaded."))
    provider = request.form.get("provider", "mock")
    model = request.form.get("model") or None
    # Only a rule set that exists on disk is accepted; anything else falls back
    # to the frozen baseline rather than reaching load_ruleset as a path.
    ruleset = _selected_ruleset(request.form.get("ruleset"))
    # No control in the page sets this any more (see the note in PAGE). The
    # read stays so the pipeline can still be exercised deliberately, by a test
    # or by restoring the control, rather than being deleted along with the
    # only way to reach it.
    semantic_mode = request.form.get("semantic_mode") == "1"
    independent_sample = request.form.get("fresh_sample") == "1"

    if provider not in {"anthropic", "ollama", "mock"}:
        return render_template_string(
            PAGE, **_page_context(
                error=f"Unsupported provider: {provider}",
                selected_ruleset=ruleset)), 400
    report_name = Path(f.filename).name
    if Path(report_name).suffix.lower() not in ALLOWED_REPORT_SUFFIXES:
        return render_template_string(
            PAGE, **_page_context(
                error="Upload a PDF, TXT, or Markdown report.",
                selected_ruleset=ruleset)), 400

    effective_model = resolve_model(provider, model)
    report_path = REPORTS_DIR / report_name
    f.save(str(report_path))
    # fold the rule set version into the name so iterations do not overwrite
    layout_tag = "__semantic-draft-v1" if semantic_mode else ""
    stem = f"{report_path.stem}__rules-{ruleset}{layout_tag}"
    filename_model = None if provider == "mock" else effective_model
    out_path = tagged_output_path(
        OUTPUTS_DIR, stem, provider, filename_model)

    usage = None
    graph_audit_path = None
    graph = None
    reproducibility = None
    spec = None
    cache_dir = None
    cache_hit = False
    try:
        text = ingest(report_path)
        if semantic_mode and is_construct_ruleset(ruleset):
            raise ValueError(
                "the semantic draft pipeline cannot express the v1.6 "
                "constructs (external resources, annotations, dotted "
                "branches). Untick the semantic checkbox to use v1.6, or "
                "choose v1.4 or v1.5 to use the semantic pipeline."
            )
        if semantic_mode:
            semantic_result = extract_attack_graph_semantic(
                text,
                provider=provider,
                model=effective_model,
            )
            graph = semantic_result.graph
        else:
            semantic_result = None
            spec = build_reproducibility_spec(
                ROOT, text, ruleset, provider, effective_model,
            )
            cache_dir = OUTPUTS_DIR / ".reproducibility-cache"
            graph = (
                None
                if independent_sample
                else load_validated_graph(cache_dir, spec)
            )
            cache_hit = graph is not None
            if graph is None:
                graph = extract_attack_graph(
                    text,
                    provider=provider,
                    model=effective_model,
                    ruleset=ruleset,
                )
                usage = get_last_api_usage()
            else:
                # A replay does not call the provider.  Do not display usage
                # left in a worker context by an earlier request.
                usage = zero_api_usage()
        if semantic_mode:
            usage = get_last_api_usage()
        graph_audit_path = out_path.with_suffix(
            ".semantic.json" if semantic_mode else ".json")
        graph_audit_path.write_text(
            (
                semantic_result.model_dump_json(indent=2)
                if semantic_result is not None
                else graph.model_dump_json(indent=2)
            ),
            encoding="utf-8",
        )
        paths = (
            render_semantic_layout(
                graph,
                semantic_result.draft,
                str(out_path),
                dpi=170,
            )
            if semantic_result is not None
            else render_split(graph, str(out_path), dpi=170)
        )
        images = [Path(p).name for p in paths]
        vectors = (
            [Path(p).name for p in
             render_split(graph, str(out_path.with_suffix(".svg")), fmt="svg")]
            if semantic_result is None else None
        )
        layout_warnings = _extraction_notes() + _layout_warnings(out_path)
        if not semantic_mode:
            # Freeze only a graph that has passed both the semantic contract
            # and the renderer.  A structurally valid but unrenderable graph
            # must never become the replay reference.
            if not independent_sample and not cache_hit:
                store_validated_graph(cache_dir, spec, graph)
            manifest = write_run_manifest(
                out_path,
                ROOT,
                spec,
                graph,
                cache_hit=cache_hit,
                independent_sample=independent_sample,
                pages=len(images),
            )
            if independent_sample:
                label = "independent sample"
                message = (
                    "The validated replay cache was bypassed and was not "
                    "replaced; this run may differ from another model sample."
                )
            elif cache_hit:
                label = "validated replay"
                message = (
                    "The exact previously validated graph was reused, so no "
                    "model request or new API cost was incurred."
                )
            else:
                label = "new frozen reference"
                message = (
                    "A new validated graph was generated and frozen for exact "
                    "replay by subsequent identical runs."
                )
            reproducibility = {
                "label": label,
                "message": message,
                "cache_key": spec.cache_key[:12],
                "manifest": manifest.name,
            }
    except Exception as e:
        app.logger.exception("Attack-graph generation failed")
        if graph_audit_path is not None and graph_audit_path.exists():
            app.logger.error(
                "Validated graph preserved for offline rendering: %s",
                graph_audit_path,
            )
        if usage is None:
            usage = get_last_api_usage()
        error = _friendly_error(e, provider)
        if graph_audit_path is not None and graph_audit_path.exists():
            error += (
                " The validated model output was preserved as "
                f"outputs/{graph_audit_path.name}; no new API extraction is "
                "needed to reproduce this rendering failure."
            )
        return render_template_string(
            PAGE, **_page_context(
                error=error, usage=usage, selected_ruleset=ruleset,
                reproducibility=reproducibility,
                metrics=run_metrics(graph, None, None, usage),
                tactics=tactic_progression(graph) if graph else None))

    return render_template_string(
        PAGE, **_page_context(
            images=images, vectors=vectors, title=graph.title,
            n_pre=len(graph.preconditions), n_ev=len(graph.events),
            usage=usage, layout_warnings=layout_warnings,
            reproducibility=reproducibility,
            selected_ruleset=ruleset,
            metrics=run_metrics(graph, quality_report_path(str(out_path)),
                                len(images), usage),
            tactics=tactic_progression(graph)))


@app.route("/outputs/<path:name>")
def outputs(name):
    return send_from_directory(str(OUTPUTS_DIR), name)


if __name__ == "__main__":
    app.run(debug=os.environ.get("AGVS_DEBUG") == "1", port=5000)
