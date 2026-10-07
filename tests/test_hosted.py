"""Stateless hosted behavior across independent requests and visitors."""
import json
import unittest
from api.index import defaults, dispatch, validate_settings
from core import Problem


class HostedTests(unittest.TestCase):
    def test_public_state_has_fixture(self):
        value = dispatch('GET', '/api/state', {}, defaults())
        self.assertEqual(value['overview']['totals']['events'], 2400)
        self.assertIsNone(value['evaluation'])

    def test_policy_and_replay_survive_request_reconstruction(self):
        settings = defaults()
        rules = dict(settings['rules'], department_boundary=False)
        saved = dispatch('POST', '/api/policy', {'rules': rules}, settings)
        self.assertEqual(saved['version'], 2)
        result = dispatch('POST', '/api/evaluate', {}, saved['_demo'])
        self.assertGreater(result['candidate']['false_allow'], 529)
        state = dispatch('GET', '/api/state', {}, result['_demo'])
        self.assertEqual(state['evaluation']['candidate']['false_allow'], result['candidate']['false_allow'])
        self.assertEqual(state['evaluation']['run_id'], 1)
        report = dispatch('GET', '/api/report', {}, result['_demo'])
        self.assertIn('Run 1; policy v2', report['markdown'])

    def test_visitors_do_not_share_policy(self):
        changed = defaults()
        changed['rules']['department_boundary'] = False
        first = dispatch('POST', '/api/evaluate', {}, changed)
        second = dispatch('POST', '/api/evaluate', {}, defaults())
        self.assertGreater(first['candidate']['false_allow'], 0)
        self.assertEqual(second['candidate']['false_allow'], 0)

    def test_last_replay_retains_its_policy_after_edit(self):
        initial = dispatch('POST', '/api/evaluate', {}, defaults())
        rules = dict(initial['_demo']['rules'], department_boundary=False)
        changed = dispatch('POST', '/api/policy', {'rules': rules}, initial['_demo'])
        state = dispatch('GET', '/api/state', {}, changed['_demo'])
        self.assertEqual(state['policy']['version'], 2)
        self.assertEqual(state['evaluation']['version'], 1)
        self.assertEqual(state['evaluation']['candidate']['false_allow'], 0)

    def test_untrusted_state_rejects_invalid_shapes(self):
        for value in ([], {'rules': {}}, dict(defaults(), version=True), dict(defaults(), runs=10001), dict(defaults(), last={'version': 2, 'rules': defaults()['rules']})):
            with self.assertRaises(Problem):
                validate_settings(value)

    def test_rule_validation_and_unknown_route(self):
        with self.assertRaises(Problem):
            dispatch('POST', '/api/policy', {'rules': {'arbitrary': True}}, defaults())
        with self.assertRaises(Problem):
            dispatch('GET', '/api/login', {}, defaults())

    def test_csv_and_reset(self):
        export = dispatch('GET', '/api/export', {}, defaults())
        self.assertEqual(len(export['csv'].splitlines()), 2401)
        reset = dispatch('POST', '/api/reset', {}, defaults())
        self.assertEqual(reset['_demo'], defaults())


if __name__ == '__main__':
    unittest.main()
