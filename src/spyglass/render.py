"""Pure renderer: Audit Report envelope -> self-contained HTML string."""

from __future__ import annotations

import html
import json

from .models import (
    AuditReport,
    AzureRoleAssignment,
    CredentialRecord,
    DirectoryRoleRecord,
    ServicePrincipalRecord,
)

_STYLE = """
:root {
  --bg: #f6f7f9; --fg: #1f2933; --muted: #62707d; --accent: #0b6bcb;
  --border: #d8dee6; --card: #ffffff; --chip: #e3ecf7; --chip-fg: #0b3d75;
  --ok: #1a7f37; --ok-bg: #e6f4ea; --warn: #9a6700; --warn-bg: #fff8e1;
  --bad: #b3261e; --bad-bg: #fce8e6; --mg-bg: #efe7fb; --mg-fg: #5b2a86;
  --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
  Roboto, Arial, sans-serif; background: var(--bg); color: var(--fg);
  line-height: 1.45; }
header { position: sticky; top: 0; z-index: 10; background: var(--card);
  border-bottom: 1px solid var(--border); padding: 14px 24px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
header h1 { margin: 0 0 8px; font-size: 18px; }
.meta { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 12px;
  color: var(--muted); margin-bottom: 10px; }
.meta .label, .sp-ids .label { font-weight: 600; color: var(--fg);
  margin-right: 4px; }
.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
#search { flex: 1; min-width: 260px; padding: 8px 12px; font-size: 14px;
  border: 1px solid var(--border); border-radius: 6px; outline: none; }
#search:focus { border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(11,107,203,0.15); }
#count, .hint { color: var(--muted); font-size: 12px; }
.hint kbd { background: var(--bg); border: 1px solid var(--border);
  border-bottom-width: 2px; border-radius: 4px; padding: 0 6px;
  font-family: var(--mono); font-size: 11px; }
main { padding: 8px 24px 40px; }
.sp { background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; margin: 16px 0; padding: 16px 18px; }
.sp-name { margin: 0 0 4px; font-size: 16px; }
.sp-ids { font-family: var(--mono); font-size: 12px; color: var(--muted);
  display: flex; flex-wrap: wrap; gap: 4px 16px; word-break: break-all; }
.section-title { font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--muted); margin: 16px 0 6px;
  border-top: 1px solid var(--border); padding-top: 10px; }
.empty { color: var(--muted); font-style: italic; margin: 4px 0; }
ul.creds, ul.drs, ul.ras { list-style: none; margin: 0; padding: 0; }
.cred, .dr, .ra { display: flex; flex-wrap: wrap; gap: 6px 10px;
  align-items: baseline; padding: 5px 0; border-top: 1px dashed var(--border);
  font-size: 13px; }
.cred:first-child, .dr:first-child, .ra:first-child { border-top: none; }
.cred-status, .dr-type { font-size: 11px; font-weight: 700; padding: 1px 8px;
  border-radius: 10px; text-transform: uppercase; letter-spacing: 0.03em; }
.status-active .cred-status { background: var(--ok-bg); color: var(--ok); }
.status-expired .cred-status { background: var(--bad-bg); color: var(--bad); }
.status-not-yet-valid .cred-status { background: var(--warn-bg); color: var(--warn); }
.status-expired { background: var(--bad-bg); border-radius: 6px;
  padding-left: 8px; padding-right: 8px; }
.cred-type, .cred-owner, .dr-source, .ra-scope-type { font-size: 11px;
  color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
.cred-name, .dr-role, .ra-role { font-weight: 600; }
.cred-dates, .ra-scope { font-family: var(--mono); font-size: 12px;
  color: var(--muted); word-break: break-all; }
.dr-type { background: var(--chip); color: var(--chip-fg); }
.scope-bucket { margin: 8px 0; border: 1px solid var(--border);
  border-radius: 6px; padding: 8px 12px; }
.scope-bucket-management-group { background: var(--mg-bg);
  border-color: #d3c2ee; }
.scope-bucket-management-group .bucket-kind { color: var(--mg-fg); }
.bucket-head { font-size: 13px; margin-bottom: 6px; }
.bucket-kind { font-size: 11px; text-transform: uppercase; font-weight: 700;
  letter-spacing: 0.04em; margin-right: 8px; }
.bucket-name { font-weight: 600; }
.raw-sections { margin-top: 4px; }
details { border: 1px solid var(--border); border-radius: 6px;
  margin: 6px 0; background: var(--bg); }
summary { cursor: pointer; padding: 6px 12px; font-size: 13px;
  font-weight: 600; }
pre.raw-json { margin: 0; padding: 12px; overflow-x: auto; font-family: var(--mono);
  font-size: 12px; background: #0f172a; color: #e2e8f0; border-radius: 0 0 6px 6px; }
.errors { background: var(--bad-bg); border: 1px solid #f3b9b4;
  border-radius: 6px; padding: 8px 12px; margin: 10px 0; font-size: 13px; }
.errors ul { margin: 4px 0 0; padding-left: 18px; }
.run-error, .sp-error { color: var(--bad); }
.hidden { display: none !important; }
"""


_FILTER_JS = """
(function () {
  const search = document.getElementById('search');
  const countEl = document.getElementById('count');
  const sps = Array.from(document.querySelectorAll('.sp'));

  // Case-insensitive multi-token match: each whitespace-separated token must
  // appear as a substring of the name, in order. "infra app" matches
  // "infra-terraform-app".
  function nameMatches(query, candidate) {
    const tokens = (query || '').toLowerCase().split(/\\s+/).filter(Boolean);
    if (tokens.length === 0) return true;
    const c = (candidate || '').toLowerCase();
    let pos = 0;
    for (const t of tokens) {
      const found = c.indexOf(t, pos);
      if (found === -1) return false;
      pos = found + t.length;
    }
    return true;
  }

  function updateCount() {
    const visible = sps.filter((el) => !el.classList.contains('hidden')).length;
    countEl.textContent = visible === sps.length
      ? sps.length + ' service principal' + (sps.length === 1 ? '' : 's')
      : visible + ' / ' + sps.length + ' shown';
  }

  function applyFilter() {
    const q = search.value.trim();
    for (const el of sps) {
      const name = el.getAttribute('data-name') || '';
      el.classList.toggle('hidden', !nameMatches(q, name));
    }
    updateCount();
  }

  search.addEventListener('input', applyFilter);
  search.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { search.value = ''; applyFilter(); search.blur(); }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== search) {
      const tag = (document.activeElement && document.activeElement.tagName) || '';
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      e.preventDefault();
      search.focus();
      search.select();
    }
  });

  updateCount();
})();
"""


def _esc(value: object) -> str:
    """HTML-escape any value for safe inclusion as text or in an attribute."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _render_credentials(credentials: list[CredentialRecord]) -> str:
    """Render the Credentials block, flagging non-active status distinctly."""
    if not credentials:
        return '<p class="empty">No credentials.</p>'
    rows: list[str] = []
    for cred in credentials:
        status = cred["status"]
        label = {
            "active": "active",
            "expired": "EXPIRED",
            "not-yet-valid": "not yet valid",
        }.get(status, status)
        cred_name = _esc(cred["displayName"] or cred["keyId"])
        rows.append(
            f'<li class="cred status-{_esc(status)}">'
            f'<span class="cred-status">{_esc(label)}</span> '
            f'<span class="cred-type">{_esc(cred["credentialType"])}</span> '
            f'<span class="cred-owner">{_esc(cred["owner"])}</span> '
            f'<span class="cred-name">{cred_name}</span> '
            f'<span class="cred-dates">{_esc(cred["startDateTime"])}'
            f" → {_esc(cred['endDateTime'])}</span>"
            "</li>"
        )
    return f'<ul class="creds">{"".join(rows)}</ul>'


def _render_directory_roles(roles: list[DirectoryRoleRecord]) -> str:
    """Render Directory Roles with assignment type and via-group source."""
    if not roles:
        return '<p class="empty">No directory roles.</p>'
    rows: list[str] = []
    for role in roles:
        source = role["source"]
        source_html = (
            '<span class="dr-source dr-source-direct">direct</span>'
            if source == "direct"
            else f'<span class="dr-source">via {_esc(source)}</span>'
        )
        rows.append(
            f'<li class="dr assignment-{_esc(role["assignmentType"])}">'
            f'<span class="dr-role">{_esc(role["roleName"])}</span> '
            f'<span class="dr-type">{_esc(role["assignmentType"])}</span> '
            f"{source_html}</li>"
        )
    return f'<ul class="drs">{"".join(rows)}</ul>'


def _render_azure_rbac(assignments: list[AzureRoleAssignment]) -> str:
    """Render Azure Role Assignments, bucketing Management Group scopes apart.

    Management-Group-scoped assignments get their own bucket keyed on the parsed
    `managementGroupId`; everything else is grouped by subscription so MG-level
    grants are never folded under a subscription heading.
    """
    if not assignments:
        return '<p class="empty">No Azure role assignments.</p>'

    mg_buckets: dict[str, list[AzureRoleAssignment]] = {}
    sub_buckets: dict[str, list[AzureRoleAssignment]] = {}
    sub_names: dict[str, str] = {}
    for ra in assignments:
        if ra["scopeType"] == "Management Group":
            key = ra["managementGroupId"] or ra["scope"]
            mg_buckets.setdefault(key, []).append(ra)
        else:
            key = ra["subscriptionId"] or ra["subscriptionName"] or "(no subscription)"
            sub_buckets.setdefault(key, []).append(ra)
            sub_names[key] = ra["subscriptionName"] or ra["subscriptionId"] or key

    def _rows(items: list[AzureRoleAssignment]) -> str:
        out: list[str] = []
        for ra in sorted(items, key=lambda r: (r["roleName"], r["scope"])):
            out.append(
                '<li class="ra">'
                f'<span class="ra-role">{_esc(ra["roleName"])}</span> '
                f'<span class="ra-scope-type">{_esc(ra["scopeType"])}</span> '
                f'<span class="ra-scope">{_esc(ra["scope"])}</span>'
                "</li>"
            )
        return f'<ul class="ras">{"".join(out)}</ul>'

    def _bucket(
        suffix: str, kind: str, name: str, items: list[AzureRoleAssignment]
    ) -> str:
        return (
            f'<div class="scope-bucket scope-bucket-{suffix}">'
            f'<div class="bucket-head"><span class="bucket-kind">{kind}</span> '
            f'<span class="bucket-name">{_esc(name)}</span></div>'
            f"{_rows(items)}</div>"
        )

    parts: list[str] = []
    for key in sorted(mg_buckets):
        parts.append(
            _bucket("management-group", "Management Group", key, mg_buckets[key])
        )
    for key in sorted(sub_buckets, key=lambda k: sub_names[k].lower()):
        parts.append(
            _bucket("subscription", "Subscription", sub_names[key], sub_buckets[key])
        )
    return "".join(parts)


def _render_errors(errors: list[str], css_class: str, heading: str) -> str:
    """Render an error list (run-wide or per-SP), or nothing when empty."""
    if not errors:
        return ""
    items = "".join(f'<li class="{css_class}">{_esc(e)}</li>' for e in errors)
    return f'<div class="errors"><strong>{_esc(heading)}</strong><ul>{items}</ul></div>'


def _render_raw_json(label: str, data: object) -> str:
    """Render a long-tail section as collapsible, escaped raw JSON.

    The JSON is embedded as escaped text in a `<pre>`, so a literal
    `</script>` (or any markup) in a field can never break out of the page.
    """
    dumped = json.dumps(data, indent=2, ensure_ascii=False)
    return (
        f"<details><summary>{_esc(label)}</summary>"
        f'<pre class="raw-json">{_esc(dumped)}</pre></details>'
    )


def _render_sp(sp: ServicePrincipalRecord) -> str:
    name = sp["displayName"] or "(unnamed service principal)"
    parts: list[str] = [
        f'<section class="sp" data-name="{_esc((sp["displayName"] or "").lower())}">',
        f'<h2 class="sp-name">{_esc(name)}</h2>',
        '<div class="sp-ids">'
        '<span class="id"><span class="label">objectId</span> '
        f"{_esc(sp['objectId'])}</span>"
        '<span class="id"><span class="label">appId</span> '
        f"{_esc(sp['appId'])}</span>"
        "</div>",
        _render_errors(sp["errors"], "sp-error", "Gaps for this service principal"),
        '<h3 class="section-title">Directory Roles</h3>',
        _render_directory_roles(sp["directoryRoles"]),
        '<h3 class="section-title">Credentials</h3>',
        _render_credentials(sp["credentials"]),
        '<h3 class="section-title">Azure Role Assignments</h3>',
        _render_azure_rbac(sp["azureRoleAssignments"]),
        '<h3 class="section-title">Details</h3>',
        '<div class="raw-sections">',
        _render_raw_json(
            f"Group memberships ({len(sp['groupMemberships'])})",
            sp["groupMemberships"],
        ),
        _render_raw_json(
            f"Application permissions ({len(sp['applicationPermissions'])})",
            sp["applicationPermissions"],
        ),
        _render_raw_json(
            f"Delegated permissions ({len(sp['delegatedPermissions'])})",
            sp["delegatedPermissions"],
        ),
        _render_raw_json(f"Owners ({len(sp['owners'])})", sp["owners"]),
        _render_raw_json(
            "Identity & application",
            {
                "objectId": sp["objectId"],
                "appId": sp["appId"],
                "displayName": sp["displayName"],
                "tags": sp["tags"],
                "application": sp["application"],
            },
        ),
        "</div>",
        "</section>",
    ]
    return "".join(parts)


def render(report: AuditReport) -> str:
    """Return a complete self-contained HTML document for the Audit Report."""
    meta = report["meta"]
    sps = report["servicePrincipals"]
    selection = meta["selection"]
    tag = selection.get("tag")
    selection_desc = (
        f'tag "{_esc(tag)}"' if tag else f"{len(selection['objectIds'])} object id(s)"
    )
    meta_items = [
        ("Tenant", _esc(meta["tenantId"])),
        ("Generated", _esc(meta["generatedAt"])),
        ("Tool", _esc(meta["toolVersion"])),
        ("Selection", selection_desc),
        ("Service principals", str(len(sps))),
    ]
    meta_header = '<div class="meta">{}</div>'.format(
        "".join(
            f'<span class="meta-item"><span class="label">{label}</span> {value}</span>'
            for label, value in meta_items
        )
    )
    run_errors = _render_errors(meta["runErrors"], "run-error", "Run errors")
    body_parts = [_render_sp(sp) for sp in sps]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Spyglass — Service Principal Audit Report</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
<h1>Spyglass — Service Principal Audit Report</h1>
{meta_header}
<div class="toolbar">
<input id="search" type="search" autocomplete="off" spellcheck="false"
  placeholder="Filter by display name (space-separated tokens, in order)…">
<span id="count"></span>
<span class="hint">Press <kbd>/</kbd> to focus, <kbd>Esc</kbd> to clear</span>
</div>
{run_errors}
</header>
<main id="report">
{"".join(body_parts)}
</main>
<script>{_FILTER_JS}</script>
</body>
</html>
"""
