"""Interactive packet browser HTML panel."""

from __future__ import annotations

import json

from secintel_core.report import PanelSpec

from pcap_investigation_studio.models import PacketRecord


def build_browser_panel(packets: list[PacketRecord], *, highlight_indices: set[int] | None = None) -> PanelSpec:
    """Build filterable packet table panel."""
    highlights = highlight_indices or set()
    rows = []
    for pkt in packets[:5000]:
        row = pkt.to_row()
        row["highlight"] = pkt.index in highlights
        rows.append(row)
    payload = json.dumps(rows, separators=(",", ":"))

    html = """
<div class="toolbar" id="pcap-toolbar">
  <input type="text" id="pcap-filter" placeholder="Filter: proto=TCP port=443 tag=dns or free text" style="flex:1;min-width:200px"/>
  <select id="pcap-proto"><option value="">All protocols</option></select>
  <button id="pcap-apply">Apply</button>
  <button id="pcap-reset">Reset</button>
  <span id="pcap-count" class="muted"></span>
</div>
<div style="overflow:auto;max-height:480px;border:1px solid var(--border);border-radius:8px;">
  <table id="pcap-table" style="width:100%;border-collapse:collapse;font-size:0.8rem;">
    <thead><tr>
      <th>#</th><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th>
      <th>Sport</th><th>Dport</th><th>Len</th><th>Flags</th><th>Info</th>
    </tr></thead>
    <tbody></tbody>
  </table>
</div>
"""

    js = f"""
(function() {{
  const allRows = {payload};
  const tbody = document.querySelector('#pcap-table tbody');
  const countEl = document.getElementById('pcap-count');
  const protoSel = document.getElementById('pcap-proto');
  const protos = [...new Set(allRows.map(r => r.proto))].sort();
  protos.forEach(p => {{
    const o = document.createElement('option');
    o.value = p; o.textContent = p;
    protoSel.appendChild(o);
  }});

  function render(rows) {{
    tbody.innerHTML = rows.map(r => {{
      const cls = r.highlight ? 'severity-high' : '';
      return `<tr class="${{cls}}">
        <td>${{r.index}}</td><td>${{r.time}}</td>
        <td>${{r.src}}</td><td>${{r.dst}}</td><td>${{r.proto}}</td>
        <td>${{r.sport}}</td><td>${{r.dport}}</td><td>${{r.len}}</td>
        <td>${{r.flags}}</td><td>${{r.info}}</td></tr>`;
    }}).join('');
    countEl.textContent = rows.length + ' / ' + allRows.length + ' packets';
  }}

  function applyFilter() {{
    const expr = (document.getElementById('pcap-filter').value || '').trim().toLowerCase();
    const proto = protoSel.value;
    let rows = allRows;
    if (proto) rows = rows.filter(r => r.proto === proto);
    if (expr) {{
      const parts = expr.split(/\\s+/);
      parts.forEach(tok => {{
        if (tok.startsWith('proto=')) rows = rows.filter(r => r.proto === tok.slice(6).toUpperCase());
        else if (tok.startsWith('port=')) {{
          const p = tok.slice(5);
          rows = rows.filter(r => String(r.sport) === p || String(r.dport) === p);
        }} else if (tok.startsWith('tag=')) {{
          const t = tok.slice(4);
          rows = rows.filter(r => (r.tags || '').includes(t));
        }} else {{
          rows = rows.filter(r =>
            JSON.stringify(r).toLowerCase().includes(tok));
        }}
      }});
    }}
    render(rows);
  }}

  document.getElementById('pcap-apply').onclick = applyFilter;
  document.getElementById('pcap-reset').onclick = () => {{
    document.getElementById('pcap-filter').value = '';
    protoSel.value = '';
    render(allRows);
  }};
  document.getElementById('pcap-filter').onkeydown = e => {{ if (e.key === 'Enter') applyFilter(); }};
  render(allRows);
}})();
"""

    return PanelSpec(id="packet-browser", title="Packet Investigation Browser", html=html, js=js)
