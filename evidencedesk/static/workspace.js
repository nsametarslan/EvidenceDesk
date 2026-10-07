'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="csrf-token"]').content;
let state = {findings: [], imports: []}, selected = null;
const text = (tag, value, className) => { const node = document.createElement(tag); node.textContent = value; if (className) node.className = className; return node; };
function message(value, failed = false) { $('message').textContent = value; $('message').className = failed ? 'error' : ''; }
async function api(url, options = {}) {
  options.headers = {...options.headers, 'X-CSRF-Token': token};
  const response = await fetch(url, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || 'The request could not be completed.');
  return body;
}
function drawFindings() {
  const list = $('findings'); list.replaceChildren();
  const query = $('search').value.trim().toLowerCase(), status = $('status-filter').value;
  const matches = state.findings.filter(f => (!status || f.status === status) && `${f.title} ${f.user} ${f.host} ${f.source_ip}`.toLowerCase().includes(query));
  $('empty').hidden = matches.length > 0;
  $('empty').textContent = state.findings.length ? 'No candidates match these filters.' : 'No candidates yet. Load the synthetic demo or import evidence.';
  for (const f of matches) {
    const button = text('button', '', 'finding' + (selected === f.id ? ' selected' : ''));
    button.setAttribute('aria-label', `Review ${f.title} · ${f.user}`);
    button.setAttribute('aria-pressed', String(selected === f.id));
    const top = text('div', '', 'finding-top'); top.append(text('span', f.severity.toUpperCase(), `severity ${f.severity}`), text('span', f.status + (f.historical ? ' · saved snapshot' : ''), 'case-state'));
    button.append(top, text('h3', f.title), text('p', `${f.user} · ${f.host}`), text('div', `${f.source_ip}  /  ${f.evidence.length} events`, 'mono'));
    button.addEventListener('click', () => openFinding(f.id).catch(e => message(e.message, true)));
    list.append(button);
  }
}
async function refresh() {
  state = await api('/api/workspace');
  for (const key of ['events', 'failures', 'findings', 'sources']) $(`metric-${key}`).textContent = state.summary[key].toLocaleString();
  drawFindings();
  $('imports').replaceChildren();
  if (!state.imports.length) $('imports').append(text('p', 'No evidence files imported.'));
  for (const source of state.imports) {
    const row = text('div', '', 'source-row');
    const info = text('div', '', 'source-info'); info.append(text('b', source.filename), text('small', `${source.rows} records · ${source.added} new events`));
    row.append(info, text('code', source.hash)); $('imports').append(row);
  }
  if (selected) await openFinding(selected);
}
async function openFinding(id) {
  const detail = await api(`/api/findings/${id}`), f = detail.finding;
  selected = id; drawFindings(); $('case-empty').hidden = true; $('case').hidden = false;
  $('case-id').textContent = `CASE ${id.slice(0, 12).toUpperCase()}`;
  $('case-title').textContent = f.title; $('case-severity').textContent = f.severity.toUpperCase();
  $('case-description').textContent = f.description + (f.historical ? ' Saved review snapshot: new evidence changed the current grouping; the original review is preserved.' : ''); $('case-alternative').textContent = f.alternative;
  $('case-status').value = f.status; $('case-note').value = f.note; $('export').href = `/api/findings/${id}/export`;
  $('timeline').replaceChildren();
  for (const e of detail.evidence) {
    const item = text('li', '', e.outcome);
    item.append(text('time', e.timestamp.replace('T', ' ').replace('.000000Z', 'Z')),
      text('b', `${e.outcome} · ${e.user}`), text('span', `${e.source_ip} → ${e.host}`),
      text('code', `event ${e.id.slice(0, 16)}…`));
    const provenance = text('details', ''); provenance.append(text('summary', 'Source fingerprints'));
    provenance.append(text('code', `Event SHA-256: ${e.id}`));
    for (const source of e.source_files) provenance.append(text('p', source.filename), text('code', source.hash));
    item.append(provenance); $('timeline').append(item);
  }
}
async function ingest(url, options = {}) {
  const buttons = [$('demo'), $('upload')]; buttons.forEach(b => b.disabled = true);
  try {
    const result = await api(url, {method: 'POST', ...options});
    await refresh(); message(`${result.added} events added; ${result.duplicates} duplicates skipped.${url === '/api/demo' ? ' Synthetic learning data loaded.' : ''}`);
  } catch (error) { message(error.message, true); }
  finally { buttons.forEach(b => b.disabled = false); }
}
$('demo').addEventListener('click', () => ingest('/api/demo'));
$('upload').addEventListener('change', () => { if ($('upload').files[0]) { const form = new FormData(); form.append('file', $('upload').files[0]); ingest('/api/import', {body: form}); $('upload').value = ''; } });
$('search').addEventListener('input', drawFindings);
$('status-filter').addEventListener('change', drawFindings);
$('save').addEventListener('click', async () => {
  if (!selected) return;
  $('save').disabled = true;
  try { await api(`/api/findings/${selected}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: $('case-status').value, note: $('case-note').value})}); await refresh(); message('Review saved locally.'); }
  catch (error) { message(error.message, true); }
  finally { $('save').disabled = false; }
});
refresh().catch(error => message(error.message, true));
