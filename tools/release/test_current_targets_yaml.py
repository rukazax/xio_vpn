"""Parse actual YAML and execute its actual final acceptance script on bounded job states."""
from pathlib import Path
import copy
import os
import shutil
import subprocess
import tempfile
import unittest
try:
    import yaml
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parents[2]


def policy(document):
    if document.get('permissions') != {'contents': 'read'}:
        raise RuntimeError('Workflow must not gain publication permissions')
    jobs = document['jobs']
    candidates = jobs['candidates']
    for fragment in ["github.event_name == 'workflow_dispatch'", 'inputs.signed_candidates',
                     'github.actor == github.repository_owner']:
        if fragment not in candidates['if']:
            raise RuntimeError('Owner/manual signed-job gate missing')
    if candidates.get('environment') != 'xio-release-candidates':
        raise RuntimeError('Explicit candidate environment required')
    for name in ['compile', 'candidates']:
        rows = jobs[name]['strategy']['matrix']['include']
        if {row['target'] for row in rows} != {'android', 'ubuntu', 'windows'} or len(rows) != 3:
            raise RuntimeError('Missing/extra current compile target')
    if set(jobs['result']['needs']) != {'workflow-lint', 'gates', 'compile', 'candidates'} or jobs['result']['if'] != 'always()':
        raise RuntimeError('Final result must evaluate all required job states')
    for job in jobs.values():
        for item in [job, *job.get('steps', [])]:
            if 'continue-on-error' in item:
                raise RuntimeError('Cannot downgrade a required gate failure')
        for step in job.get('steps', []):
            if 'uses' in step and 'actions/upload-artifact@' in step['uses']:
                if step['with'].get('if-no-files-found') != 'error':
                    raise RuntimeError('Missing artifact upload must fail')
    for job_name in ['compile', 'candidates']:
        steps = jobs[job_name]['steps']
        guards = [i for i, step in enumerate(steps) if 'receipt-check' in step.get('run', '')]
        upload = next(i for i, step in enumerate(steps) if 'upload-artifact@' in step.get('uses', ''))
        if len(guards) != 1 or guards[0] >= upload:
            raise RuntimeError('Mandatory complete-receipt guard must precede upload')
    steps = candidates['steps']
    material = next(i for i, step in enumerate(steps) if 'ci_signing_material.py create' in step.get('run', ''))
    build = next(i for i, step in enumerate(steps) if step.get('name') == 'Build exact reviewed Android release matrix')
    if material >= build or set(steps[material]['env']) != {
        'XIO_ANDROID_KEYSTORE_BASE64', 'XIO_ANDROID_STORE_PASSWORD', 'XIO_ANDROID_KEY_ALIAS', 'XIO_ANDROID_KEY_PASSWORD'}:
        raise RuntimeError('All named signing inputs must precede Android release compilation')


@unittest.skipIf(yaml is None, 'PyYAML absent; actual actionlint/YAML validation also runs separately')
class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.document = yaml.load((ROOT/'.github/workflows/current-targets.yml').read_text(), Loader=yaml.BaseLoader)

    def test_actual_workflow_policy(self):
        policy(self.document)
        self.assertIn('workflow_dispatch', self.document['on'])
        for job in self.document['jobs'].values():
            for step in job.get('steps', []):
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')

    def test_dangerous_or_incomplete_structured_mutations_rejected(self):
        for change in ['permissions', 'owner', 'target', 'upload', 'continue', 'needs', 'receipt']:
            document = copy.deepcopy(self.document)
            if change == 'permissions':
                document['permissions']['contents'] = 'write'
            elif change == 'owner':
                document['jobs']['candidates']['if'] = 'always()'
            elif change == 'target':
                document['jobs']['compile']['strategy']['matrix']['include'].pop()
            elif change == 'upload':
                upload = next(step for step in document['jobs']['compile']['steps'] if 'upload-artifact@' in step.get('uses', ''))
                upload['with']['if-no-files-found'] = 'warn'
            elif change == 'continue':
                document['jobs']['candidates']['continue-on-error'] = 'true'
            elif change == 'needs':
                document['jobs']['result']['needs'].remove('compile')
            else:
                steps = document['jobs']['candidates']['steps']
                steps[:] = [step for step in steps if 'receipt-check' not in step.get('run', '')]
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                policy(document)

    @unittest.skipUnless(os.name != 'nt' and shutil.which('bash'), 'Parse production bash scripts on Linux')
    def test_actual_bash_steps_parse_without_running_builds(self):
        for name, job in self.document['jobs'].items():
            for step in job.get('steps', []):
                if 'run' in step and step.get('shell') != 'pwsh':
                    result = subprocess.run(['bash', '-n'], input=step['run'], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, (name, step.get('name'), result.stderr))

    @unittest.skipUnless(os.name != 'nt' and shutil.which('bash'), 'Execute production bash final gate on Linux')
    def test_actual_final_gate_does_not_turn_missing_or_skipped_builds_green(self):
        script = self.document['jobs']['result']['steps'][0]['run']
        cases = [('success','success','skipped','false',0), ('success','success','success','true',0),
                 ('success','success','skipped','true',1), ('success','success','failure','true',1),
                 ('success','failure','success','true',1), ('cancelled','success','success','false',1),
                 ('success','skipped','skipped','false',1)]
        with tempfile.TemporaryDirectory() as directory:
            for gates, compile_result, candidates, requested, code in cases:
                env = dict(os.environ, LINT_RESULT='success', GATES_RESULT=gates, COMPILE_RESULT=compile_result, CANDIDATE_RESULT=candidates,
                           CANDIDATES_REQUESTED=requested, GITHUB_STEP_SUMMARY=str(Path(directory)/'summary'))
                result = subprocess.run(['bash','-c',script], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, code, (gates, compile_result, candidates, requested, result.stderr))


if __name__ == '__main__':
    unittest.main()
