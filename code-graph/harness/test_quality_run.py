"""Quota checkpoint checks without database, credentials or provider calls.

Run from the repository root: python3 -m unittest discover -s code-graph/harness
"""

import json
import tempfile
import unittest
from pathlib import Path

from quality_run import citation_ranges, resume_report


class QualityCheckpointTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'results.json'
        self.report = {'requests_sha256': 'corpus', 'model_config': {'id': 'connection'},
                       'budget': 8, 'spent': 10, 'calls': [
                           {'id': 'done', 'status': 'completed', 'tokens': 6},
                           {'id': 'retry', 'status': 'failed', 'reason': 'token_limit', 'tokens': 4}]}

    def save(self):
        self.path.write_text(json.dumps(self.report))

    def test_resume_preserves_failed_usage_and_completed_results(self):
        self.save()
        original = self.path.read_bytes()
        result = resume_report(self.path, 'corpus', 'connection', 20)
        self.assertEqual((result['spent'], result['budget_history'], result['budget']), (10, [8], 20))
        self.assertEqual(result['calls'], self.report['calls'])
        self.assertEqual(self.path.read_bytes(), original)

    def test_rejects_changed_identity_budget_and_accounting(self):
        self.save()
        for corpus, connection, budget in [('changed', 'connection', 20),
                                            ('corpus', 'changed', 20), ('corpus', 'connection', 10)]:
            with self.subTest(corpus=corpus, connection=connection, budget=budget), self.assertRaises(ValueError):
                resume_report(self.path, corpus, connection, budget)
        self.report['spent'] = 9
        self.save()
        with self.assertRaises(ValueError):
            resume_report(self.path, 'corpus', 'connection', 20)

    def test_rejects_unknown_or_non_budget_failure(self):
        for tokens, status, reason in [(None, 'failed', 'token_limit'),
                                        (True, 'completed', None), (-1, 'completed', None),
                                        (4, 'dispatched', None), (4, 'failed', 'authentication')]:
            self.report['calls'][1].update(tokens=tokens, status=status, reason=reason)
            self.save()
            with self.subTest(tokens=tokens, status=status, reason=reason), self.assertRaises(ValueError):
                resume_report(self.path, 'corpus', 'connection', 20)

    def test_citation_bounds_do_not_establish_semantic_accuracy(self):
        prompt = json.dumps({'sources': [{'source_id': 'assigned', 'path': 'a.py',
                                         'start_line': 10, 'end_line': 20}]})
        result = {'evidence': [{'source_id': 'assigned', 'start_line': 10, 'end_line': 20},
                               {'source_id': 'missing', 'start_line': 10, 'end_line': 20},
                               {'source_id': 'assigned', 'start_line': 9, 'end_line': 20}]}
        self.assertEqual(citation_ranges(result, prompt), {'valid': 1, 'total': 3, 'source_paths': ['a.py']})


if __name__ == '__main__':
    unittest.main()
