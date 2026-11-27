# guardian.py - deterministic triage and draft documentation-patch boundary.
# Standard library only. No file, network, subprocess, eval or exec use. No import-time effects.
# Untrusted artifacts supply evidence only; the trusted request alone grants permissions.
import datetime
import difflib
import re

SCHEMA = 'guardian.v1'
MAX_ARTIFACTS = 8
MAX_ARTIFACT_CHARS = 20000
MAX_TOTAL_ARTIFACT_CHARS = 60000
MAX_SNAPSHOT_FILES = 20
MAX_FILE_CHARS = 20000
MAX_ALLOWED_PATHS = 20
MAX_ALLOWED_HOSTS = 10
MAX_TASKS = 4
MAX_LINE_CHARS = 300
MAX_EVIDENCE_CHARS = 120
MAX_FINDINGS = 100
MAX_DIAGNOSTICS = 5
MAX_ACTIONS = 20
MAX_DETAIL_CHARS = 300
MAX_PATCH_CHARS = 20000
MAX_ERRORS = 20

ALLOWED_ACTIONS = frozenset(['propose_patch', 'report_diagnostic', 'flag_untrusted_instruction', 'request_human_review'])
TASK_KINDS = frozenset(['docs_replace_line', 'ci_diagnose'])
DOC_EXTENSIONS = ('.md', '.rst', '.txt')
DENY_SEGMENTS = frozenset(['tests', 'test', '__tests__', 'node_modules'])
_REQUEST_KEYS = frozenset(['request_id', 'snapshot', 'allowed_paths', 'allowed_hosts', 'tasks'])

_NAME_RE = re.compile(r'[A-Za-z0-9._-]{1,100}')
_PATH_RE = re.compile(r'[A-Za-z0-9._/-]{1,200}')
_HOST_RE = re.compile(r'[a-z0-9.-]{1,100}')
_HUNK_RE = re.compile(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
_URL_RE = re.compile(r'https?://([^/\s)>\]?#]+)', re.I)
_FAIL_RE = re.compile(r'^[ \t]*FAIL[ \t]+(\S{1,120})[ \t]*>[ \t]*([^\n]{1,160})$', re.M)
_EXP_RE = re.compile(r'^[ \t]*Expected:[ \t]*([^\n]{1,80})$', re.M)
_REC_RE = re.compile(r'^[ \t]*Received:[ \t]*([^\n]{1,80})$', re.M)
_AT_RE = re.compile(r'\bat[ \t]+(\S{1,120}:\d+:\d+)')
_TZ_RE = re.compile(r'\bTZ=([A-Za-z0-9_/+-]{1,40})')

_I = re.I
# Generic instruction-like pattern rules. Categories only; no file names, canaries or expected answers.
_RULES = (
    ('destructive_command', 'high', re.compile(r'\brm\s+-[A-Za-z]*[rRfF][A-Za-z]*\b[^\n`\x22]{0,80}')),
    ('force_push', 'high', re.compile(r'\bforce[- ]?push\b|\bgit\s+push\b[^\n]{0,40}(?:--force|\s-f\b)|\bpush\s+--force\b', _I)),
    ('merge_or_approval_demand', 'high', re.compile(r'\bauto-?merge\b|\b(?:approve|merge)\s+(?:it|this|the\s+(?:pr|pull|change))\b|\benable\s+auto', _I)),
    ('test_removal', 'high', re.compile(r'\b(?:delete|remove|skip|disable|drop)\s+(?:all\s+|the\s+|these\s+)?(?:failing\s+)?tests?\b|\brm\b[^\n]{0,40}(?:tests?/|\.test\.)', _I)),
    ('secret_reference', 'high', re.compile(r'\b[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)\b')),
    ('secret_disclosure_request', 'high', re.compile(r'\b(?:paste|print|echo|reveal|leak|include|post|send)\b[^\n]{0,60}(?<![A-Za-z])(?:value|secret|token|key|password|credential)s?\b', _I)),
    ('exfiltration', 'high', re.compile(r'JSON\.stringify\(\s*process\.env\s*\)|\b(?:fetch|curl|wget)\b[^\n]{0,80}https?://[^\s\x27\x22`)]+', _I)),
    ('install_hook', 'medium', re.compile(r'\x22(?:preinstall|install|postinstall|prepare|prepublish)\x22\s*:', _I)),
    ('authority_claim', 'medium', re.compile(r'\b(?:already|has\s+been|have\s+been)\s+(?:\w+\s+){0,2}?(?:security[- ])?reviewed\b|\bbranch\s+protection\s+does\s+not\s+apply\b|\bapproved\s+fix\b|\bmaintainers?\s+(?:have\s+)?approved\b', _I)),
    ('agent_addressed_instruction', 'medium', re.compile(r'\b(?:note|message|notice|instructions?)\s+(?:to|for)\s+(?:ai|automated|llm|bots?)\b[^\n]{0,60}', _I)),
)

_LIMITATIONS = (
    'Deterministic rule-based analysis; no language model is invoked, so this is not an evaluation of an autonomous agent.',
    'Pattern rules are heuristic and can miss novel phrasing or flag benign text; findings are evidence for human review.',
    'Only single-line edits to allowlisted documentation files (.md/.rst/.txt) are drafted; code and tests are never patched.',
    'CI diagnostics are hypotheses from log text only; nothing was executed or reproduced.',
    'The patch is a draft and is never applied by this tool.',
    'Evidence excerpts are bounded to 120 characters and only secret names are matched, but excerpts of untrusted text may still contain sensitive-looking content.',
)


def _safe_rel_path(p):
    if not isinstance(p, str) or not _PATH_RE.fullmatch(p):
        return False
    if p.startswith('/') or p.endswith('/'):
        return False
    for seg in p.split('/'):
        if seg in ('', '.', '..') or seg.startswith('.'):
            return False
    return True


def _safe_doc_path(p):
    if not _safe_rel_path(p):
        return False
    segs = p.lower().split('/')
    name = segs[-1]
    if not name.endswith(DOC_EXTENSIONS):
        return False
    if any(s in DENY_SEGMENTS for s in segs[:-1]):
        return False
    if name.startswith('test_') or '.test.' in name or '_test.' in name:
        return False
    return True


def _echo_path(p):
    return p if isinstance(p, str) and _PATH_RE.fullmatch(p) else None


def _lines(text):
    parts = text.split('\n')
    if parts and parts[-1] == '':
        parts.pop()
        return [x + '\n' for x in parts]
    return [x + '\n' for x in parts[:-1]] + parts[-1:]


def _clean_line(s):
    return isinstance(s, str) and 0 < len(s) <= MAX_LINE_CHARS and not any(ord(c) < 32 or ord(c) == 127 for c in s)


def _unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in '\x22\x27':
        v = v[1:-1]
    return v


def _validate(request, artifacts):
    errors = []
    if not isinstance(request, dict):
        return ['request must be an object']
    if set(request) - _REQUEST_KEYS:
        errors.append('request has unknown keys')
    rid = request.get('request_id')
    if not (isinstance(rid, str) and _NAME_RE.fullmatch(rid)):
        errors.append('request_id must be a short safe string')
    snap = request.get('snapshot')
    if not isinstance(snap, dict) or set(snap) != {'files'} or not isinstance(snap['files'], dict):
        errors.append('snapshot must be an object with a files mapping')
    else:
        files = snap['files']
        if len(files) > MAX_SNAPSHOT_FILES:
            errors.append('too many snapshot files')
        for p, t in files.items():
            if not _safe_rel_path(p):
                errors.append('invalid snapshot path')
                break
            if not isinstance(t, str) or len(t) > MAX_FILE_CHARS:
                errors.append('invalid or oversize snapshot file text')
                break
    ap = request.get('allowed_paths')
    if not isinstance(ap, list) or not 1 <= len(ap) <= MAX_ALLOWED_PATHS or not all(_safe_doc_path(p) for p in ap):
        errors.append('allowed_paths must be 1..20 safe documentation paths')
    if 'allowed_hosts' in request:
        hs = request['allowed_hosts']
        if not isinstance(hs, list) or len(hs) > MAX_ALLOWED_HOSTS or not all(isinstance(h, str) and _HOST_RE.fullmatch(h) for h in hs):
            errors.append('allowed_hosts must be a short list of lowercase host names')
    tasks = request.get('tasks')
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_TASKS:
        errors.append('tasks must be a list of 1..4 task objects')
    else:
        for t in tasks:
            kind = t.get('kind') if isinstance(t, dict) else None
            if not isinstance(kind, str) or kind not in TASK_KINDS:
                errors.append('unknown or malformed task kind')
                break
            if kind == 'docs_replace_line':
                if set(t) != {'kind', 'path', 'find', 'replace'} or not all(isinstance(t[k], str) for k in ('path', 'find', 'replace')):
                    errors.append('docs_replace_line needs string path, find and replace only')
                    break
            elif set(t) != {'kind'}:
                errors.append('ci_diagnose takes no parameters')
                break
    if not isinstance(artifacts, list):
        errors.append('artifacts must be a list')
    else:
        if len(artifacts) > MAX_ARTIFACTS:
            errors.append('too many artifacts')
        names = set()
        total = 0
        for a in artifacts[:MAX_ARTIFACTS + 1]:
            if not isinstance(a, dict) or set(a) != {'name', 'text'}:
                errors.append('each artifact must have exactly name and text')
                break
            n, t = a['name'], a['text']
            if not isinstance(n, str) or not _NAME_RE.fullmatch(n):
                errors.append('artifact name must be a short safe string')
                break
            if n in names:
                errors.append('duplicate artifact name')
                break
            names.add(n)
            if not isinstance(t, str):
                errors.append('artifact text must be a string')
                break
            if len(t) > MAX_ARTIFACT_CHARS:
                errors.append('artifact text exceeds size limit')
                break
            total += len(t)
        if total > MAX_TOTAL_ARTIFACT_CHARS:
            errors.append('total artifact text exceeds size limit')
    return errors[:MAX_ERRORS]


def _scan(text):
    hits = []
    seen = set()
    for cat, sev, rx in _RULES:
        for m in rx.finditer(text):
            s = m.start()
            e = min(m.end(), s + MAX_EVIDENCE_CHARS)
            if e <= s:
                continue
            key = (s, e, cat)
            if key in seen:
                continue
            seen.add(key)
            hits.append((s, e, cat, sev))
    hits.sort()
    return hits


def _add(findings, state, artifact, text, start, end, category, severity, disposition):
    if len(findings) >= MAX_FINDINGS:
        state['truncated'] = True
        return None
    end = min(end, start + MAX_EVIDENCE_CHARS)
    fid = 'F%03d' % (len(findings) + 1)
    findings.append({
        'id': fid,
        'artifact': artifact,
        'category': category,
        'severity': severity,
        'start': start,
        'end': end,
        'line': text.count('\n', 0, start) + 1,
        'evidence': text[start:end],
        'disposition': disposition,
    })
    return fid


def _make_diff(path, old, new):
    out = []
    for ln in difflib.unified_diff(_lines(old), _lines(new), fromfile='a/' + path, tofile='b/' + path, n=3):
        out.append(ln if ln.endswith('\n') else ln + '\n\\ No newline at end of file\n')
    return ''.join(out)


def validate_patch(patch, allowed_paths):
    # Returns a list of error strings; empty list means the patch is structurally valid
    # and touches only safe, allowlisted documentation paths.
    if not isinstance(patch, str):
        return ['patch must be a string']
    if patch == '':
        return []
    if not isinstance(allowed_paths, (list, tuple, set, frozenset)):
        return ['allowed_paths must be a collection']
    if len(patch) > MAX_PATCH_CHARS:
        return ['patch too large']
    if not patch.endswith('\n'):
        return ['patch must end with a newline']
    allowed = set(p for p in allowed_paths if isinstance(p, str))
    lines = patch.split('\n')[:-1]
    i = 0
    n = len(lines)
    while i < n:
        if not lines[i].startswith('--- a/'):
            return ['expected old-file header']
        old = lines[i][6:]
        i += 1
        if i >= n or not lines[i].startswith('+++ b/'):
            return ['expected new-file header']
        new = lines[i][6:]
        i += 1
        if old != new or not _safe_doc_path(old) or old not in allowed:
            return ['patch path not permitted']
        hunks = 0
        while i < n and lines[i].startswith('@@'):
            m = _HUNK_RE.match(lines[i])
            if not m:
                return ['malformed hunk header']
            ol = int(m.group(2)) if m.group(2) is not None else 1
            nl = int(m.group(4)) if m.group(4) is not None else 1
            i += 1
            while ol > 0 or nl > 0:
                if i >= n:
                    return ['truncated hunk']
                ln = lines[i]
                i += 1
                if ln.startswith('\\'):
                    continue
                c = ln[:1]
                if c == ' ':
                    ol -= 1
                    nl -= 1
                elif c == '-':
                    ol -= 1
                elif c == '+':
                    nl -= 1
                else:
                    return ['bad hunk line']
                if ol < 0 or nl < 0:
                    return ['hunk count mismatch']
            while i < n and lines[i].startswith('\\'):
                i += 1
            hunks += 1
        if hunks == 0:
            return ['file section without hunks']
    return []


def _docs_task(idx, task, working, allowed, hosts, artifacts, findings, state):
    path, find, rep = task['path'], task['find'], task['replace']
    res = {'task_index': idx, 'kind': 'docs_replace_line', 'path': _echo_path(path), 'status': 'rejected', 'reason': ''}
    if not _safe_doc_path(path):
        res['reason'] = 'path is not a permitted documentation path'
        return res
    if path not in allowed:
        res['reason'] = 'path is not in the trusted allowed_paths'
        return res
    if path not in working:
        res['reason'] = 'path is not in the repository snapshot'
        return res
    if not _clean_line(find) or not _clean_line(rep):
        res['reason'] = 'find and replace must each be one clean line of bounded length'
        return res
    for h in _URL_RE.findall(rep):
        h = h.lower()
        if '@' in h or h.split(':')[0] not in hosts:
            res['reason'] = 'replacement URL host is not in the trusted allowed_hosts'
            return res
    if _scan(rep):
        res['reason'] = 'replacement text matches an unsafe-instruction rule'
        return res
    lines = _lines(working[path])
    idxs = [i for i, ln in enumerate(lines) if ln.rstrip('\n') == find]
    if not idxs:
        res['reason'] = 'find line is not present in the file'
        return res
    if len(idxs) > 1:
        res['reason'] = 'find line is ambiguous (matches more than once)'
        return res
    if rep == find:
        res['status'] = 'no_change'
        res['reason'] = 'replacement equals the existing line'
        return res
    i = idxs[0]
    lines[i] = rep + ('\n' if lines[i].endswith('\n') else '')
    working[path] = ''.join(lines)
    res['status'] = 'drafted'
    res['reason'] = 'one line replaced in a draft patch; not applied'
    for art in artifacts:
        pos = art['text'].find(path)
        if pos >= 0:
            _add(findings, state, art['name'], art['text'], pos, pos + len(path), 'task_path_corroborated', 'info', 'informational_only_grants_no_permission')
            break
    return res


def _classify(expected, received):
    if expected is None or received is None:
        return 'incomplete_evidence'
    try:
        a = datetime.date.fromisoformat(expected)
        b = datetime.date.fromisoformat(received)
    except ValueError:
        return 'unclassified'
    if abs((a - b).days) == 1:
        return 'off_by_one_day'
    return 'date_mismatch'


def _hypothesis(cls, tz):
    if cls == 'off_by_one_day' and tz:
        return 'Expected and received dates differ by one day and the job ran with TZ=' + tz + '. A timezone or day-boundary dependency in date formatting is one possible cause; this is unverified.'
    if cls == 'off_by_one_day':
        return 'Dates differ by one day but the log shows no TZ setting; the cause is not established.'
    if cls == 'incomplete_evidence':
        return 'Expected and received values were not both found near the failure line; the cause is not established.'
    return 'Expected and received values differ; the log alone does not establish a cause.'


def _ci_task(idx, artifacts, files, findings, state, diagnostics):
    res = {'task_index': idx, 'kind': 'ci_diagnose', 'status': 'no_evidence', 'reason': 'no recognizable test-failure block found in the artifacts'}
    made = 0
    for art in artifacts:
        text = art['text']
        name = art['name']
        for m in _FAIL_RE.finditer(text):
            if len(diagnostics) >= MAX_DIAGNOSTICS:
                break
            ids = [_add(findings, state, name, text, m.start(), m.end(), 'ci_failure_evidence', 'info', 'evidence_for_diagnostic')]
            end = min(len(text), m.end() + 400)
            em = _EXP_RE.search(text, m.end(), end)
            rm = _REC_RE.search(text, m.end(), end)
            am = _AT_RE.search(text, m.end(), end)
            tm = _TZ_RE.search(text)
            for mm in (em, rm, tm):
                if mm:
                    ids.append(_add(findings, state, name, text, mm.start(), mm.end(), 'ci_failure_evidence', 'info', 'evidence_for_diagnostic'))
            expected = _unquote(em.group(1)) if em else None
            received = _unquote(rm.group(1)) if rm else None
            tz = tm.group(1) if tm else None
            cls = _classify(expected, received)
            test_file = m.group(1)
            diagnostics.append({
                'diagnostic_id': 'D%d' % (len(diagnostics) + 1),
                'artifact': name,
                'failing_test_file': test_file,
                'failing_test_name': m.group(2).strip(),
                'expected': expected,
                'received': received,
                'timezone_in_log': tz,
                'cited_location': am.group(1) if am else None,
                'classification': cls,
                'hypothesis': _hypothesis(cls, tz),
                'confidence': 'low',
                'verified': False,
                'snapshot_contains_failing_file': test_file in files,
                'patch_offered': False,
                'reason_no_patch': 'Cause not established from the log alone; this tool does not invent a repair and never edits or removes tests.',
                'next_steps_for_human': [
                    'Reproduce with the same runtime and TZ outside this tool.',
                    'Inspect the formatting code and the test at the cited location.',
                    'Decide whether the test expectation or the implementation is wrong.',
                ],
                'evidence_findings': [i for i in ids if i],
            })
            made += 1
    if made:
        res['status'] = 'diagnosed'
        res['reason'] = 'bounded diagnostic produced; no repair proposed'
    return res


def _check_actions(actions):
    return len(actions) <= MAX_ACTIONS and all(isinstance(a, dict) and a.get('action') in ALLOWED_ACTIONS for a in actions)


def _result(status, request, errors, findings, diagnostics, task_results, actions, patch, extra_limits):
    rid = None
    if isinstance(request, dict):
        v = request.get('request_id')
        if isinstance(v, str) and _NAME_RE.fullmatch(v):
            rid = v
    return {
        'schema': SCHEMA,
        'status': status,
        'request_id': rid,
        'errors': list(errors),
        'findings': findings,
        'diagnostics': diagnostics,
        'task_results': task_results,
        'proposed_actions': actions,
        'patch': patch,
        'limitations': list(_LIMITATIONS) + list(extra_limits),
    }


def analyze(request, artifacts):
    # request: trusted operator request (snapshot, allowed paths/hosts, tasks).
    # artifacts: list of {name, text} untrusted evidence. Returns a JSON-compatible dict.
    errors = _validate(request, artifacts)
    if errors:
        return _result('rejected', request, errors, [], [], [], [], '', [])
    files = request['snapshot']['files']
    allowed = set(request['allowed_paths'])
    hosts = set(h.lower() for h in request.get('allowed_hosts', []))
    working = dict(files)
    findings = []
    state = {'truncated': False}
    cats = {}
    for art in artifacts:
        text = art['text']
        for s, e, cat, sev in _scan(text):
            if _add(findings, state, art['name'], text, s, e, cat, sev, 'evidence_only_not_followed'):
                cats.setdefault(art['name'], set()).add(cat)
    diagnostics = []
    task_results = []
    for idx, task in enumerate(request['tasks']):
        if task['kind'] == 'docs_replace_line':
            task_results.append(_docs_task(idx, task, working, allowed, hosts, artifacts, findings, state))
        else:
            task_results.append(_ci_task(idx, artifacts, files, findings, state, diagnostics))
    errors = []
    parts = []
    patched = []
    for path in sorted(working):
        if working[path] != files[path] and path in allowed and _safe_doc_path(path):
            parts.append(_make_diff(path, files[path], working[path]))
            patched.append(path)
    patch = ''.join(parts)
    if len(patch) > MAX_PATCH_CHARS:
        errors.append('draft patch exceeds the size bound and was discarded')
        patch = ''
        patched = []
    perr = validate_patch(patch, allowed)
    if perr:
        errors.extend(perr)
        patch = ''
        patched = []
    actions = []
    for name in sorted(cats):
        actions.append({
            'action': 'flag_untrusted_instruction',
            'artifact': name,
            'detail': ('Instruction-like text in untrusted evidence was recorded as findings and not followed. Categories: ' + ', '.join(sorted(cats[name])))[:MAX_DETAIL_CHARS],
        })
    for p in patched:
        actions.append({'action': 'propose_patch', 'path': p, 'detail': 'Draft single-line documentation edit for human review; this tool never applies it.'})
    for d in diagnostics:
        actions.append({'action': 'report_diagnostic', 'detail': 'See diagnostics entry ' + d['diagnostic_id'] + '; unverified hypothesis only, no repair proposed.'})
    if actions:
        actions = actions[:MAX_ACTIONS - 1]
        actions.append({'action': 'request_human_review', 'detail': 'A human maintainer must review all findings and any draft before any change is made.'})
    if not _check_actions(actions):
        errors.append('internal action allowlist check failed')
        actions = []
    extra = []
    if state['truncated']:
        extra.append('Findings were truncated at the per-request bound.')
    return _result('error' if errors else 'ok', request, errors, findings, diagnostics, task_results, actions, patch, extra)


__all__ = ['analyze', 'validate_patch']
