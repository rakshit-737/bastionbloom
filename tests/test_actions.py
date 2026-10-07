"""Exercise privileged PR workflows and safe alternatives, including YAML edge cases."""

import pytest
import yaml

from bastionbloom.rules.actions import scan_actions
from bastionbloom.yaml_support import load_document


def workflow(text):
    return scan_actions(".github/workflows/build.yml", load_document(text))


def test_privileged_pr_checkout_injection_and_self_hosted_runner():
    findings = workflow("""on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
""")
    assert {finding.rule.id for finding in findings} == {
        "ACT001", "ACT002", "ACT003", "ACT004", "ACT005",
    }
    injection = next(f for f in findings if f.rule.id == "ACT003")
    assert injection.line == 10
    assert "echo" not in injection.evidence


def test_pinned_read_only_pr_job_with_environment_input_is_clean():
    findings = workflow("""on: [push, pull_request]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "$PR_TITLE"
      - uses: ./local-action
""")
    assert findings == []


def test_privileged_metadata_only_workflow_is_not_untrusted_checkout():
    findings = workflow("""on:
  pull_request_target:
    types: [opened]
permissions: {}
jobs:
  metadata:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
""")
    assert findings == []


def test_job_scoped_writes_and_reusable_workflow_are_inspected():
    findings = workflow("""on: push
permissions: {}
jobs:
  deploy:
    permissions: {contents: write}
    uses: org/repo/.github/workflows/deploy.yml@main
""")
    assert {finding.rule.id for finding in findings} == {"ACT001", "ACT002"}


def test_identity_and_repository_write_scopes_are_inspected():
    findings = workflow("""on: push
permissions: {id-token: write}
jobs:
  release:
    permissions: {pull-requests: write}
""")
    assert [finding.rule.id for finding in findings] == ["ACT001", "ACT001"]


def test_sarif_upload_permission_is_allowed_but_unrelated_writes_are_not():
    permitted = workflow("""on: push
permissions: {}
jobs:
  report:
    permissions: {security-events: write}
    steps:
      - uses: github/codeql-action/upload-sarif@1190a975f95ce23525efb6a3fc21ea29567c1b52
        with: {sarif_file: results.sarif}
""")
    mixed = workflow("""on: push
permissions: {}
jobs:
  report:
    permissions: {contents: write, security-events: write}
    steps:
      - uses: github/codeql-action/upload-sarif@1190a975f95ce23525efb6a3fc21ea29567c1b52
""")
    assert permitted == []
    assert [finding.rule.id for finding in mixed] == ["ACT001"]


def test_yaml_on_key_and_boolean_values_are_preserved():
    document = load_document("on: pull_request_target\nprivileged: true\nname: yes\n")
    assert document.data["on"] == "pull_request_target"
    assert document.data["privileged"] is True
    assert document.data["name"] == "yes"


def test_yaml_anchors_merge_without_losing_configuration():
    document = load_document("defaults: &base {privileged: true}\nservice: {<<: *base}\n")
    assert document.data["service"]["privileged"] is True


@pytest.mark.parametrize("text", [
    "!!python/object/apply:os.system ['do-not-execute']",
    "a: " + "[" * 100 + "0" + "]" * 100,
    "a: &base [1]\nb: [" + ",".join(["*base"] * 110) + "]",
    "[not, a, mapping]",
])
def test_unsafe_or_overly_complex_yaml_is_rejected(text):
    with pytest.raises(yaml.YAMLError):
        load_document(text)
