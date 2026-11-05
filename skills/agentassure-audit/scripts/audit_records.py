#!/usr/bin/env python3
"""Create and check audit records. This tool does not establish security truth."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid

COLLECTIONS = ('evidence', 'coverage', 'findings', 'prevention', 'visual_elements')
ID = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,79}$')
SHA = re.compile(r'^[a-f0-9]{64}$')
MAX_BYTES = 16 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text_field(item, field):
    value = item.get(field)
    require(isinstance(value, str) and bool(value.strip()), f'Missing text: {field}')
    return value


def timestamp(value):
    require(isinstance(value, str), 'Missing timestamp.')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'Timestamp needs a time zone.')


def load(path):
    require(path.stat().st_size <= MAX_BYTES, 'Record file exceeds the size limit.')
    return json.loads(path.read_text(encoding='utf-8'))


def source_hash(root, relative):
    path = Path(relative)
    require(not path.is_absolute() and bool(path.parts) and '..' not in path.parts,
            'Source path must stay inside the target.')
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), 'Source evidence must not follow a symlink.')
    info = current.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_BYTES,
            'Source evidence must be a bounded regular file.')
    with current.open('rb') as handle:
        data = handle.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, 'Source evidence exceeds the size limit.')
    return hashlib.sha256(data).hexdigest()


def validate(data, target=None, diagram=None):
    require(isinstance(data, dict) and data.get('schema_version') == 1, 'Unknown record format.')
    run = data.get('run')
    require(isinstance(run, dict), 'Missing run.')
    for field in ('id', 'target', 'revision', 'snapshot_id'):
        text_field(run, field)
    require(SHA.fullmatch(run['snapshot_id']), 'snapshot_id must be a SHA-256 digest.')
    timestamp(run.get('created_at'))
    require(run.get('status') in ('in_progress', 'complete', 'partial'), 'Invalid run status.')
    require(isinstance(run.get('scope_paths'), list) and bool(run['scope_paths']), 'Missing scope paths.')
    require(all(isinstance(x, str) and x for x in run['scope_paths']), 'Invalid scope path.')
    require(isinstance(run.get('gaps'), list), 'Missing gaps array.')
    if target is not None:
        target = target.resolve()
        require(target == Path(run['target']).resolve(), 'Target differs from the recorded target.')
    tables = {}
    seen = set()
    for collection in COLLECTIONS:
        items = data.get(collection)
        require(isinstance(items, list), f'Missing array: {collection}')
        tables[collection] = {}
        for item in items:
            require(isinstance(item, dict), f'Invalid record in {collection}')
            ident = text_field(item, 'id')
            require(ID.fullmatch(ident) and ident not in seen, 'Invalid or duplicate record ID.')
            seen.add(ident)
            tables[collection][ident] = item

    def refs(item, field, collection, minimum=0):
        values = item.get(field)
        require(isinstance(values, list) and len(values) >= minimum, f'Missing references: {field}')
        require(all(isinstance(v, str) for v in values), f'Invalid references: {field}')
        require(len(values) == len(set(values)), f'Duplicate references: {field}')
        require(all(v in tables[collection] for v in values), f'Broken references: {field}')
        return [tables[collection][v] for v in values]

    for item in data['evidence']:
        text_field(item, 'summary')
        timestamp(item.get('observed_at'))
        require(item.get('snapshot_id') == run['snapshot_id'], 'Stale evidence snapshot.')
        require(item.get('kind') in ('source', 'observation', 'advisory'), 'Invalid evidence kind.')
        if item['kind'] == 'source':
            path = text_field(item, 'path')
            require(SHA.fullmatch(text_field(item, 'sha256')), 'Invalid source hash.')
            if target is not None:
                require(source_hash(target, path) == item['sha256'], 'Stale source evidence: ' + item['id'])
        elif item['kind'] == 'advisory':
            text_field(item, 'url')
            require(item.get('source_status') in ('complete', 'partial', 'failed', 'not_checked'),
                    'Invalid advisory source status.')
        else:
            text_field(item, 'method')
            text_field(item, 'result')
            text_field(item, 'limitations')

    for item in data['coverage']:
        for field in ('surface', 'boundary', 'attack_class'):
            text_field(item, field)
        require(item.get('state') in ('planned', 'checked', 'candidate', 'blocked', 'out_of_scope'),
                'Invalid coverage state.')
        refs(item, 'evidence_refs', 'evidence', 1 if item['state'] in ('checked', 'candidate') else 0)
        if item['state'] in ('blocked', 'out_of_scope'):
            text_field(item, 'reason')

    for item in data['findings']:
        for field in ('claim', 'hunter_id', 'reason'):
            text_field(item, field)
        require(item.get('snapshot_id') == run['snapshot_id'], 'Stale finding snapshot.')
        require(item.get('verdict') in ('confirmed', 'needs_validation', 'rejected'), 'Invalid verdict.')
        evidence = refs(item, 'evidence_refs', 'evidence', 1)
        refs(item, 'coverage_refs', 'coverage', 1)
        if item['verdict'] == 'confirmed':
            require(text_field(item, 'verifier_id') != item['hunter_id'], 'Verifier must be independent.')
            text_field(item, 'trace')
            text_field(item, 'observed_result')
            text_field(item, 'counterevidence')
            require(any(x['kind'] == 'source' for x in evidence), 'Confirmation needs source evidence.')
            require(any(x['kind'] == 'observation' for x in evidence), 'Confirmation needs an observation.')
            require(item.get('severity') in ('critical', 'high', 'medium', 'low'), 'Invalid finding severity.')
        else:
            require(item.get('severity') is None, 'Unconfirmed findings have no application severity.')
            if item['verdict'] == 'needs_validation':
                text_field(item, 'next_test')

    for item in data['prevention']:
        for field in ('rule', 'control', 'regression_test', 'ci_check', 'retest_condition'):
            text_field(item, field)
        require(item.get('status') in ('proposed', 'implemented', 'verified'), 'Invalid prevention status.')
        linked = refs(item, 'finding_refs', 'findings') + refs(item, 'coverage_refs', 'coverage')
        require(linked, 'Prevention needs a finding or coverage unit.')
        evidence = refs(item, 'evidence_refs', 'evidence', 0 if item['status'] == 'proposed' else 1)
        if item['status'] == 'verified':
            require(any(x['kind'] == 'observation' for x in evidence), 'Verified control needs an observation.')

    for item in data['visual_elements']:
        require(item.get('kind') in ('node', 'edge'), 'Invalid visual element kind.')
        require(item.get('status') in ('observed', 'inferred', 'untested', 'proposed'), 'Invalid visual status.')
        refs(item, 'evidence_refs', 'evidence', 1 if item['status'] == 'observed' else 0)
        refs(item, 'finding_refs', 'findings')
        refs(item, 'prevention_refs', 'prevention')
    if diagram is not None:
        shapes = {'architecture': ('components', 'connections'), 'workflow': ('nodes', 'edges')}
        require(diagram.get('diagram_type') in shapes, 'Unsupported diagram type.')
        node_key, edge_key = shapes[diagram['diagram_type']]
        require(isinstance(diagram.get(node_key), list) and bool(diagram[node_key]), 'Missing diagram nodes.')
        require(isinstance(diagram.get(edge_key), list), 'Missing diagram edges.')
        items = [('node', x) for x in diagram[node_key]] + [('edge', x) for x in diagram[edge_key]]
        diagram_ids = [(kind, x.get('id')) for kind, x in items]
        require(all(isinstance(ident, str) for _, ident in diagram_ids), 'Every visual element needs an ID.')
        require(len(diagram_ids) == len(set(ident for _, ident in diagram_ids)), 'Duplicate diagram ID.')
        mapped = {(x['kind'], x['id']) for x in data['visual_elements']}
        require(mapped == set(diagram_ids), 'Diagram and evidence map differ.')
    gaps = [x for x in data['coverage'] if x['state'] in ('blocked', 'planned', 'candidate')]
    failures = [x for x in data['evidence'] if x['kind'] == 'advisory' and x['source_status'] != 'complete']
    pending = [x for x in data['findings'] if x['verdict'] == 'needs_validation']
    if run['status'] == 'complete':
        require(data['coverage'], 'A complete run needs coverage records.')
        require(not (gaps or failures or pending or run['gaps']), 'A run with unresolved gaps must be partial.')
    return {'ok': True, 'run_id': run['id'], 'status': run['status'],
            'source_hashes_checked': target is not None, 'diagram_checked': diagram is not None,
            'counts': {k: len(data[k]) for k in COLLECTIONS}}


def encode(data):
    return (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()


def create(path, data):
    with path.open('xb') as handle:
        os.chmod(path, 0o600)
        handle.write(encode(data))
        handle.flush()
        os.fsync(handle.fileno())


def checkpoint(path, data):
    validate(data, Path(data['run']['target']))
    require(not path.is_symlink(), 'Checkpoint must not replace a symlink.')
    if path.exists():
        old = load(path)
        first_pin = old['run'].get('snapshot_id') == '' and all(not old[name] for name in COLLECTIONS)
        identity_keys = ('id', 'target', 'revision') if first_pin else ('id', 'target', 'revision', 'snapshot_id')
        require(all(old['run'][key] == data['run'][key] for key in identity_keys),
                'A changed source identity needs a new run.')
        for name in COLLECTIONS:
            new = {item['id']: item for item in data[name]}
            for item in old[name]:
                require(item['id'] in new, 'Checkpoint cannot erase prior records.')
                if name == 'evidence' or (name == 'findings' and item.get('verdict') in ('confirmed', 'rejected')):
                    require(new[item['id']] == item, 'Final records are immutable. Use a linked new record or run.')
        digest = hashlib.sha256(encode(old)).hexdigest()
        history = path.parent / (path.name + '.history')
        history.mkdir(mode=0o700, exist_ok=True)
        require(not history.is_symlink(), 'History directory must not be a symlink.')
        archive = history / (digest + '.json')
        if archive.exists():
            require(not archive.is_symlink() and archive.read_bytes() == encode(old), 'Invalid history file.')
        else:
            create(archive, old)
    fd, temp = tempfile.mkstemp(prefix='.audit-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(encode(data))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('--target', type=Path, required=True)
    init.add_argument('--revision', required=True)
    init.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('validate')
    check.add_argument('input', type=Path)
    check.add_argument('--target', type=Path)
    check.add_argument('--map', type=Path)
    save = sub.add_parser('checkpoint')
    save.add_argument('input', type=Path)
    save.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'init':
            require(args.target.is_dir(), 'Target is not a directory.')
            data = {'schema_version': 1, 'run': {'id': 'run-' + uuid.uuid4().hex,
                    'target': str(args.target.resolve()), 'revision': args.revision, 'snapshot_id': '',
                    'created_at': now(), 'status': 'in_progress', 'scope_paths': [], 'gaps': []},
                    **{key: [] for key in COLLECTIONS}}
            create(args.output, data)
            print(json.dumps({'created': str(args.output), 'next': 'Set scope_paths and snapshot_id.'}))
        elif args.command == 'validate':
            print(json.dumps(validate(load(args.input), args.target, load(args.map) if args.map else None)))
        else:
            checkpoint(args.output, load(args.input))
            print(json.dumps({'saved': str(args.output)}))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Record check failed: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
