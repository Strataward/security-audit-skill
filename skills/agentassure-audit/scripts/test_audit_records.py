"""Check evidence integrity and checkpoint behavior."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import audit_records as module


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = self.root / 'target'
        self.target.mkdir()
        (self.target / 'app.txt').write_text('fixture\n')
        self.sha = hashlib.sha256(b'fixture\n').hexdigest()
        self.data = {'schema_version': 1, 'run': {'id': 'run-fixture', 'target': str(self.target),
            'revision': 'fixture-commit', 'snapshot_id': self.sha, 'created_at': '2026-11-05T00:00:00Z',
            'status': 'in_progress', 'scope_paths': ['app.txt'], 'gaps': []},
            'evidence': [{'id': 'ev-source', 'kind': 'source', 'summary': 'Fixture source.',
                'snapshot_id': self.sha, 'observed_at': '2026-11-05T00:00:00Z', 'path': 'app.txt', 'sha256': self.sha}],
            'coverage': [{'id': 'unit-one', 'surface': 'fixture', 'boundary': 'caller',
                'attack_class': 'authorization', 'state': 'checked', 'evidence_refs': ['ev-source']}],
            'findings': [], 'prevention': [], 'visual_elements': []}

    def test_valid_source(self):
        self.assertTrue(module.validate(self.data, self.target)['source_hashes_checked'])

    def test_first_checkpoint_pins_initial_snapshot(self):
        initial = copy.deepcopy(self.data)
        initial['run']['snapshot_id'] = ''
        initial['run']['scope_paths'] = []
        for name in module.COLLECTIONS:
            initial[name] = []
        output = self.root / 'audit.json'
        module.create(output, initial)
        module.checkpoint(output, self.data)
        self.assertEqual(module.load(output)['run']['snapshot_id'], self.sha)

    def test_stale_source(self):
        (self.target / 'app.txt').write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'Stale source'):
            module.validate(self.data, self.target)

    def test_broken_reference(self):
        self.data['coverage'][0]['evidence_refs'] = ['missing']
        with self.assertRaisesRegex(ValueError, 'Broken references'):
            module.validate(self.data)

    def test_duplicate_id(self):
        self.data['coverage'][0]['id'] = 'ev-source'
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            module.validate(self.data)

    def test_stale_snapshot(self):
        self.data['evidence'][0]['snapshot_id'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Stale evidence'):
            module.validate(self.data)

    def test_failed_advisory_prevents_complete(self):
        self.data['run']['status'] = 'complete'
        self.data['evidence'].append({'id': 'ev-advisory', 'kind': 'advisory', 'summary': 'Source failed.',
            'snapshot_id': self.sha, 'observed_at': '2026-11-05T00:00:00Z',
            'url': 'https://example.invalid', 'source_status': 'failed'})
        with self.assertRaisesRegex(ValueError, 'unresolved gaps'):
            module.validate(self.data)

    def finding(self):
        return {'id': 'finding-one', 'claim': 'Fixture claim.', 'verdict': 'confirmed',
            'snapshot_id': self.sha, 'hunter_id': 'hunter', 'verifier_id': 'verifier',
            'reason': 'Fixture reason.', 'trace': 'Fixture trace.', 'observed_result': 'Fixture observation.',
            'counterevidence': 'Fixture guard checked.', 'evidence_refs': ['ev-source'],
            'coverage_refs': ['unit-one'], 'severity': 'high'}

    def test_source_only_cannot_confirm(self):
        self.data['findings'] = [self.finding()]
        with self.assertRaisesRegex(ValueError, 'needs an observation'):
            module.validate(self.data)

    def test_same_agent_cannot_confirm(self):
        finding = self.finding()
        finding['verifier_id'] = 'hunter'
        self.data['findings'] = [finding]
        with self.assertRaisesRegex(ValueError, 'independent'):
            module.validate(self.data)

    def test_unverified_prevention(self):
        self.data['prevention'] = [{'id': 'control-one', 'status': 'verified', 'rule': 'Deny access.',
            'control': 'Check owner.', 'regression_test': 'Use two owners.', 'ci_check': 'Run test.',
            'retest_condition': 'Changed source.', 'finding_refs': [], 'coverage_refs': ['unit-one'],
            'evidence_refs': ['ev-source']}]
        with self.assertRaisesRegex(ValueError, 'needs an observation'):
            module.validate(self.data)

    def test_resume_preserves_rejected_and_history(self):
        finding = self.finding()
        finding.update(verdict='rejected', severity=None)
        self.data['findings'] = [finding]
        output = self.root / 'audit.json'
        module.checkpoint(output, self.data)
        changed = copy.deepcopy(self.data)
        changed['run']['gaps'] = ['A later check is unavailable.']
        module.checkpoint(output, changed)
        self.assertEqual(module.load(output)['findings'], [finding])
        self.assertEqual(len(list((self.root / 'audit.json.history').glob('*.json'))), 1)
        changed['findings'] = []
        with self.assertRaisesRegex(ValueError, 'cannot erase'):
            module.checkpoint(output, changed)
        self.assertEqual(module.load(output)['findings'], [finding])

    def test_new_snapshot_needs_new_run(self):
        output = self.root / 'audit.json'
        module.checkpoint(output, self.data)
        changed = copy.deepcopy(self.data)
        changed['run']['snapshot_id'] = '0' * 64
        changed['evidence'][0]['snapshot_id'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'new run'):
            module.checkpoint(output, changed)

    def test_map_missing_element(self):
        with self.assertRaisesRegex(ValueError, 'map differ'):
            module.validate(self.data, diagram={'diagram_type': 'workflow', 'nodes': [{'id': 'api'}], 'edges': []})

    def test_architecture_map_requires_evidence_mapping(self):
        diagram = {'diagram_type': 'architecture', 'components': [{'id': 'api'}], 'connections': []}
        with self.assertRaisesRegex(ValueError, 'map differ'):
            module.validate(self.data, diagram=diagram)
        self.data['visual_elements'] = [{'id': 'api', 'kind': 'node', 'status': 'observed',
            'evidence_refs': ['ev-source'], 'finding_refs': [], 'prevention_refs': []}]
        self.assertTrue(module.validate(self.data, diagram=diagram)['diagram_checked'])

    def test_unsupported_map_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported diagram'):
            module.validate(self.data, diagram={'components': [], 'connections': []})

    def test_orphan_candidate_prevents_complete(self):
        self.data['coverage'][0]['state'] = 'candidate'
        self.data['run']['status'] = 'complete'
        with self.assertRaisesRegex(ValueError, 'unresolved gaps'):
            module.validate(self.data)

    def test_source_path_escape(self):
        self.data['evidence'][0]['path'] = '../other.txt'
        with self.assertRaisesRegex(ValueError, 'inside the target'):
            module.validate(self.data, self.target)

    def test_source_symlink(self):
        (self.target / 'alias.txt').symlink_to('app.txt')
        self.data['evidence'][0]['path'] = 'alias.txt'
        with self.assertRaisesRegex(ValueError, 'symlink'):
            module.validate(self.data, self.target)


if __name__ == '__main__':
    unittest.main()
