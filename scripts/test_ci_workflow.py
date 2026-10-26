"""Rules the continuous-integration workflow must keep.

.github/workflows/ci.yml is the release gate of docs/VALIDATION.md. These
tests read it as text, so they need no YAML library; the reader below accepts
only the layout the workflow uses and fails on anything else rather than
guessing. They check that:

- every action is pinned to a full commit, and every toolchain and installed
  tool to an exact version, so a moved tag or branch cannot change what runs;
- every Windows step that PowerShell runs holds one command, because
  PowerShell decides a step by its last command's exit code only;
- each check is its own step and still runs after another check failed;
- the browser cryptography bundle is rebuilt from its lockfile;
- one Rust pass and the fuzzers run with debug assertions;
- the Rust test steps of the test jobs report failing tests as annotations,
  through scripts/ci_annotate.sh or .ps1, which mirror the command's output
  and exit code;
- a pushed release tag or release branch runs the full gate on its commit;
- every standalone test program and launcher test is run by a job, or only
  wraps programs that are.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github' / 'workflows' / 'ci.yml'
NETWORK_SUITES = ROOT / 'scripts' / 'ci_network_suites.sh'
ANNOTATE = ROOT / 'scripts' / 'ci_annotate.sh'


def indentation(line):
    return len(line) - len(line.lstrip(' '))


class Step:
    """One step of a job: its own keys, with a block `run: |` joined."""

    def __init__(self, lines):
        self.lines = lines
        self.keys = {}
        self.env = {}
        first = lines[0]
        assert first.startswith('      - '), first
        body = ['        ' + first[len('      - '):]] + lines[1:]
        index = 0
        while index < len(body):
            line = body[index]
            index += 1
            if not line.strip() or line.strip().startswith('#'):
                continue
            assert indentation(line) >= 8, f'unexpected step layout: {line!r}'
            if indentation(line) > 8:
                continue
            key, _, value = line.strip().partition(':')
            value = value.strip()
            if value in ('|', '>'):
                block = []
                while index < len(body) and (not body[index].strip() or indentation(body[index]) > 8):
                    block.append(body[index].strip())
                    index += 1
                value = '\n'.join(block).strip()
            elif not value:
                nested = {}
                while index < len(body) and (not body[index].strip() or indentation(body[index]) > 8):
                    inner = body[index].strip()
                    index += 1
                    if inner and not inner.startswith('#'):
                        name, _, setting = inner.partition(':')
                        nested[name.strip()] = setting.strip()
                if key == 'env':
                    self.env = nested
                value = nested
            self.keys[key] = value

    @property
    def name(self):
        return self.keys.get('name') or self.keys.get('uses') or self.keys.get('run', '')[:40]

    def commands(self):
        """The command lines of `run`, without blank lines and comments."""
        run = self.keys.get('run', '')
        return [line for line in run.splitlines() if line.strip() and not line.strip().startswith('#')]


class Job:
    def __init__(self, name, lines):
        self.name = name
        self.lines = lines
        self.steps = []
        self.env = {}
        self.text = '\n'.join(lines)
        index = 0
        while index < len(lines):
            line = lines[index]
            if line == '    env:':
                index += 1
                while index < len(lines) and indentation(lines[index]) > 4:
                    inner = lines[index].strip()
                    if inner and not inner.startswith('#'):
                        key, _, value = inner.partition(':')
                        self.env[key.strip()] = value.strip().strip("'\"")
                    index += 1
                continue
            if line == '    steps:':
                step = []
                for inner in lines[index + 1:]:
                    if inner.startswith('      - '):
                        if step:
                            self.steps.append(Step(step))
                        step = [inner]
                    elif step and (not inner.strip() or indentation(inner) > 6 or inner.strip().startswith('#')):
                        step.append(inner)
                    elif inner.strip():
                        raise AssertionError(f'{name}: unexpected line after the steps: {inner!r}')
                if step:
                    self.steps.append(Step(step))
                break
            index += 1

    def runs_on(self):
        match = re.search(r'^    runs-on: (\S+)$', self.text, re.M)
        return match.group(1) if match else ''

    def default_shell(self):
        match = re.search(r'^    defaults:\n      run:\n        shell: (\S+)$', self.text, re.M)
        return match.group(1) if match else ''


def read_workflow():
    text = WORKFLOW.read_text(encoding='utf-8')
    lines = text.splitlines()
    assert 'jobs:' in lines, 'no jobs section'
    start = lines.index('jobs:') + 1
    jobs, name, body = {}, None, []
    for line in lines[start:]:
        match = re.fullmatch(r'  ([A-Za-z0-9_-]+):', line)
        if match:
            if name:
                jobs[name] = Job(name, body)
            name, body = match.group(1), []
        elif name:
            body.append(line)
        elif line.strip() and not line.strip().startswith('#'):
            raise AssertionError(f'unexpected line before the first job: {line!r}')
    if name:
        jobs[name] = Job(name, body)
    header = lines[:start]
    environment = {}
    if 'env:' in header:
        for line in header[header.index('env:') + 1:]:
            if not line.startswith('  '):
                break
            inner = line.strip()
            if inner and not inner.startswith('#'):
                key, _, value = inner.partition(':')
                environment[key.strip()] = value.strip().strip("'\"")
    return text, environment, jobs


def test_programs():
    """Standalone programs: scripts/test_*.py with no unittest test case,
    which unittest discovery imports without running anything."""
    return [path.name for path in sorted((ROOT / 'scripts').glob('test_*.py'))
            if not re.search(r'\bTestCase\b', path.read_text(encoding='utf-8'))]


class WorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.environment, cls.jobs = read_workflow()

    def steps(self):
        for job in self.jobs.values():
            for step in job.steps:
                yield job, step

    def test_every_action_is_pinned_to_a_full_commit(self):
        uses = re.findall(r'^\s*(?:- )?uses: (\S+)(.*)$', self.text, re.M)
        self.assertTrue(uses)
        for action, comment in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$',
                                 'pin each action to a full commit SHA')
                self.assertRegex(comment, r'^ # \S+', 'name the release a pinned commit belongs to')

    def test_toolchains_and_tools_are_exact(self):
        self.assertRegex(self.environment.get('RUST_TOOLCHAIN', ''), r'^\d+\.\d+\.\d+$')
        self.assertRegex(self.environment.get('FUZZ_TOOLCHAIN', ''), r'^nightly-\d{4}-\d{2}-\d{2}$',
                         'the fuzz job needs a dated nightly')
        self.assertRegex(self.environment.get('CARGO_FUZZ_VERSION', ''), r'^\d+\.\d+\.\d+$')
        # A major or minor version alone takes the newest release of that
        # line, and with Node.js the corepack that checks the pnpm hash.
        for name in ('NODE_VERSION', 'PYTHON_VERSION'):
            with self.subTest(variable=name):
                self.assertRegex(self.environment.get(name, ''), r'^\d+\.\d+\.\d+$')
        pinned = {
            'toolchain': ('${{ env.RUST_TOOLCHAIN }}', '${{ env.FUZZ_TOOLCHAIN }}'),
            'node-version': ('${{ env.NODE_VERSION }}',),
            'python-version': ('${{ env.PYTHON_VERSION }}',),
        }
        installers = {'actions/setup-node': 'node-version', 'actions/setup-python': 'python-version'}
        for job, step in self.steps():
            settings = step.keys.get('with') if isinstance(step.keys.get('with'), dict) else {}
            action = step.keys.get('uses', '').partition('@')[0]
            with self.subTest(job=job.name, step=step.name):
                if action in installers:
                    self.assertIn(installers[action], settings, 'name the version an installer sets up')
                for key, allowed in pinned.items():
                    if key in settings:
                        self.assertIn(settings[key], allowed)
        self.assertNotRegex(self.text, r'\+nightly\b', 'name the dated fuzz toolchain, not a moving nightly')
        installs = re.findall(r'^.*cargo .*install .*$', self.text, re.M)
        self.assertTrue(installs)
        for line in installs:
            with self.subTest(line=line.strip()):
                self.assertIn('--version ${{ env.CARGO_FUZZ_VERSION }}', line)
                self.assertIn('--locked', line)

    def test_powershell_steps_hold_one_command(self):
        windows = [job for job in self.jobs.values() if job.runs_on().startswith('windows')]
        self.assertTrue(windows)
        for job in windows:
            for step in job.steps:
                if 'run' not in step.keys:
                    continue
                shell = step.keys.get('shell') or job.default_shell() or 'pwsh'
                if shell.startswith('bash'):
                    continue
                with self.subTest(job=job.name, step=step.name):
                    self.assertEqual(len(step.commands()), 1,
                                     "PowerShell takes a step's result from its last command only")

    def test_each_check_is_its_own_step_and_runs_after_a_failure(self):
        for name in ('linux', 'windows', 'debug-assertions'):
            job = self.jobs[name]
            checks = [step for step in job.steps if 'run' in step.keys]
            build = checks[0]
            self.assertEqual(build.keys.get('id'), 'build', f'{name}: the first command builds')
            for step in checks[1:]:
                with self.subTest(job=name, step=step.name):
                    condition = step.keys.get('if', '')
                    self.assertTrue('!cancelled()' in condition or 'always()' in condition,
                                    'a check also runs after an earlier check failed')
                    programs = re.findall(r'scripts/test_\w+\.(?:py|ps1|cjs)', step.keys['run'].replace('\\', '/'))
                    self.assertLessEqual(len(programs), 1, 'one test program per step')

    def test_browser_cryptography_is_rebuilt_from_the_lockfile(self):
        rebuilds = [step for _, step in self.steps() if 'pnpm run check' in step.keys.get('run', '')]
        self.assertEqual(len(rebuilds), 1)
        step = rebuilds[0]
        self.assertEqual(step.keys.get('working-directory'), 'scripts/browser-crypto')
        self.assertIn('corepack pnpm install --frozen-lockfile', step.keys['run'])
        self.assertIn('corepack pnpm run check', step.keys['run'])

    def test_debug_assertions_run_somewhere(self):
        job = self.jobs['debug-assertions']
        self.assertEqual(job.env.get('CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS'), 'true')
        self.assertTrue(any('cargo test --release --all-targets --locked --features test-fixtures' in step.keys.get('run', '')
                            for step in job.steps))
        fuzz = self.jobs['fuzz']
        self.assertEqual(fuzz.env.get('CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS'), 'true')
        commands = re.findall(r'\$fuzz (build|run|cmin)\b([^\n]*)', fuzz.text)
        self.assertEqual(sorted({command for command, _ in commands}), ['build', 'cmin', 'run'])
        for command, arguments in commands:
            with self.subTest(command=command):
                self.assertIn('--release --debug-assertions', arguments)

    def test_rust_test_steps_report_failures_as_annotations(self):
        wrappers = {'linux': 'bash scripts/ci_annotate.sh -- ', 'debug-assertions': 'bash scripts/ci_annotate.sh -- ',
                    'windows': './scripts/ci_annotate.ps1 -- '}
        for name, wrapper in wrappers.items():
            tests = [step for step in self.jobs[name].steps if 'cargo test' in step.keys.get('run', '')]
            self.assertTrue(tests, f'{name}: no Rust test step')
            for step in tests:
                with self.subTest(job=name, step=step.name):
                    self.assertEqual(len(step.commands()), 1)
                    self.assertTrue(step.commands()[0].startswith(wrapper + 'cargo test '),
                                    'run the Rust tests through the annotation wrapper')

    def test_release_refs_run_the_full_gate(self):
        # Nightly and manual runs start only from the default branch, so a
        # pushed release tag or branch is how the release commit itself gets
        # per-target fuzzing and the network suites.
        self.assertRegex(self.text, r'(?m)^on:\n  push:\n  pull_request:\n',
                         'every pushed branch and tag runs the workflow')
        release = ("startsWith(github.ref, 'refs/tags/v')", "startsWith(github.ref, 'refs/heads/release/')")
        network = re.search(r'(?m)^    if: (.*)$', self.jobs['network'].text)
        self.assertTrue(network, 'the network suites run only in the full gate')
        fuzz = self.jobs['fuzz'].text
        matrix = re.search(r'(?m)^\s*target: \$\{\{ fromJSON\((.*)$', fuzz)
        seconds = re.search(r'(?m)^\s*FUZZ_SECONDS: (.*)$', fuzz)
        for where, text in (('network suites', network.group(1)), ('fuzz matrix', matrix.group(1)),
                            ('fuzz time', seconds.group(1))):
            for ref in release:
                with self.subTest(where=where, ref=ref):
                    self.assertIn(ref, text)

    def test_every_program_and_launcher_test_runs(self):
        network = NETWORK_SUITES.read_text(encoding='utf-8')
        default = re.search(r'\|\| suites=\(([^)]*)\)$', network, re.M).group(1).split()
        ran = set(re.findall(r'scripts[/\\](test_\w+\.(?:py|ps1))', self.text))
        ran |= {name + '.py' for name in default}
        ran |= {name + '.py' for name in re.findall(r'ci_network_suites\.sh \S+ \S+ \S+ (test_\w+)', self.text)}
        launchers = sorted(path.name for path in (ROOT / 'scripts').glob('test_*.ps1'))
        self.assertTrue(launchers)
        for name in test_programs() + launchers:
            if name in ran:
                continue
            with self.subTest(program=name):
                # Otherwise it must only wrap test programs that a job runs.
                source = (ROOT / 'scripts' / name).read_text(encoding='utf-8')
                wrapped = set(re.findall(r"'(test_\w+)'", source))
                self.assertTrue(wrapped, f'{name} runs in no job')
                for inner in wrapped:
                    suffix = '.ps1' if name.endswith('.ps1') else '.py'
                    self.assertIn(inner + suffix, ran, f'{name} wraps {inner}, which no job runs')


@unittest.skipIf(sys.platform == 'win32' or not shutil.which('bash'), 'needs bash on a POSIX system')
class AnnotateScriptTest(unittest.TestCase):
    def run_wrapped(self, script):
        return subprocess.run(['bash', str(ANNOTATE), '--', 'bash', '-c', script],
                              capture_output=True, text=True, timeout=60)

    def annotations(self, output):
        return [line for line in output.splitlines() if line.startswith('::error ')]

    def test_success_mirrors_the_output_and_adds_nothing(self):
        result = self.run_wrapped('echo out; echo err >&2; echo "---- x stdout ----"')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), ['out', 'err', '---- x stdout ----'])
        self.assertEqual(self.annotations(result.stdout), [])

    def test_failing_tests_and_compile_errors_become_annotations(self):
        script = r"""
            printf 'running 2 tests\n\nfailures:\n\n'
            printf -- '---- tests::a_b stdout ----\n'
            printf "thread 'tests::a_b' (7) panicked at src/x.rs:3:5:\n"
            printf 'left: 1, right: 2 (100%%)\n\nnote: run with `RUST_BACKTRACE=1`\n'
            printf '\033[1m\033[91merror[E0425]\033[0m: cannot find value\n'
            exit 101
        """
        result = self.run_wrapped(script)
        self.assertEqual(result.returncode, 101)
        self.assertIn('---- tests::a_b stdout ----', result.stdout.splitlines())
        self.assertEqual(self.annotations(result.stdout), [
            '::error title=tests%3A%3Aa_b::---- tests::a_b stdout ----%0A'
            "thread 'tests::a_b' (7) panicked at src/x.rs:3:5:%0A"
            'left: 1, right: 2 (100%25)%0Aerror[E0425]: cannot find value',
            '::error title=compile error::error[E0425]: cannot find value',
        ])

    def test_cargo_names_the_failed_test_target(self):
        result = self.run_wrapped("printf '\\033[1m\\033[91merror\\033[0m: test failed, to rerun pass `--lib`\\n'; exit 101")
        self.assertEqual(result.returncode, 101)
        self.assertEqual(self.annotations(result.stdout),
                         ['::error title=tests failed::error: test failed, to rerun pass `--lib`'])

    def test_annotations_are_at_most_ten(self):
        result = self.run_wrapped('for i in $(seq 12); do echo "---- t$i stdout ----"; done; exit 1')
        self.assertEqual(result.returncode, 1)
        titles = [line.split('::')[1] for line in self.annotations(result.stdout)]
        self.assertEqual(titles, [f'error title=t{i}' for i in range(1, 11)])

    def test_another_failure_reports_the_last_lines(self):
        result = self.run_wrapped('seq 20; exit 3')
        self.assertEqual(result.returncode, 3)
        self.assertEqual(self.annotations(result.stdout),
                         ['::error title=bash failed (3)::' + '%0A'.join(str(i) for i in range(6, 21))])


if __name__ == '__main__':
    unittest.main()
