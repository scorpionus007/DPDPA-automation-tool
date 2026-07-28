import pytest

from dpdp_scanner.config import load_config
from dpdp_scanner.extractor import extract
from dpdp_scanner.rule_engine import run_rules


def _repo_file(path: str, content: str, language: str) -> dict:
    return {"path": path, "display_path": path, "content": content, "language": language}


GOLDEN_REPOS = [
    {
        "name": "documenso_like",
        "files": [
            _repo_file("package.json", '{"dependencies":{"@remix-run/react":"1","hono":"1","@prisma/client":"1","posthog-js":"1"}}', "json"),
            _repo_file("README.md", "Self-hosted document signing platform", "markdown"),
            _repo_file(
                "prisma/schema.prisma",
                "model DocumentAuditLog { id String @id email String recipientEmail String senderEmail String phone String fullName String }\n"
                "model Document { id String @id recipientEmail String senderEmail String phone String address String fullName String }",
                "prisma",
            ),
            _repo_file("apps/remix/app/routes/signin.tsx", 'export async function loader(){ return null }\nexport default function SignIn(){ return <form><input name="email" /><input name="phone" /></form> }', "typescript"),
            _repo_file("packages/lib/server-only/telemetry/telemetry-client.ts", "posthog.capture('boot')", "typescript"),
        ],
        "expected_rules_present": {"AUDIT_TRAIL_PRESENT"},
        "expected_rules_absent": {"AUDIT_TRAIL_PARTIAL", "NO_ERROR_HANDLING_IN_AUTH"},
    },
    {
        "name": "flask_library_like",
        "files": [
            _repo_file("pyproject.toml", "[project]\nname='flask-like'", "toml"),
            _repo_file("src/flask_like/__init__.py", "from .app import App", "python"),
            _repo_file("src/flask_like/app.py", "class App:\n    pass", "python"),
        ],
        "expected_library": True,
    },
    {
        "name": "fastapi_like",
        "files": [
            _repo_file("pyproject.toml", "[project]\ndependencies=['fastapi','uvicorn','sqlalchemy']", "toml"),
            _repo_file("app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/signup')\ndef signup(email:str):\n    return {'email': email}", "python"),
            _repo_file("app/models.py", "class User(BaseModel):\n    email: str\n    name: str", "python"),
        ],
        "min_findings": 1,
    },
    {
        "name": "next_saas_like",
        "files": [
            _repo_file("package.json", '{"dependencies":{"next":"14","react":"18","stripe":"1"}}', "json"),
            _repo_file("app/api/signup/route.ts", "export async function POST(req: Request){ const body = await req.json(); return Response.json(body); }", "typescript"),
            _repo_file("app/page.tsx", "export default function Page(){ return <form><input name='email' /></form> }", "typescript"),
        ],
        "expected_deployment_class": "saas",
    },
    {
        "name": "self_hosted_oss_like",
        "files": [
            _repo_file("Dockerfile", "FROM python:3.12", "dockerfile"),
            _repo_file("LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE", "text"),
            _repo_file("README.md", "You can self-host this application.", "markdown"),
            _repo_file("app/routes/account.ts", "export async function loader(){ return null }", "typescript"),
        ],
        "expected_deployment_class": "self_hosted_oss",
    },
    {
        "name": "job_logger_like",
        "files": [
            _repo_file("package.json", '{"dependencies":{"pino":"1"}}', "json"),
            _repo_file("jobs/process-reminder.handler.ts", "io.logger.info(`email ${recipient.email}`)", "typescript"),
            _repo_file("models/recipient.ts", "export const recipient = { email: 'x' }", "typescript"),
        ],
        "expected_rule_severity": {"PLAINTEXT_PII_IN_LOGS": "MEDIUM"},
    },
]


@pytest.mark.golden_repos
@pytest.mark.parametrize("case", GOLDEN_REPOS, ids=[c["name"] for c in GOLDEN_REPOS])
def test_synthetic_golden_repos(case):
    extracted = extract(case["files"])
    findings, score, _ = run_rules(extracted, load_config(None), quiet=True)
    rules = {f["rule"] for f in findings}

    for rule in case.get("expected_rules_present", set()):
        assert rule in rules
    for rule in case.get("expected_rules_absent", set()):
        assert rule not in rules
    if "expected_library" in case:
        assert extracted["is_framework_library"] is case["expected_library"]
    if "expected_deployment_class" in case:
        assert extracted["deployment_class"] == case["expected_deployment_class"]
    if "min_findings" in case:
        assert len(findings) >= case["min_findings"]
    if "expected_rule_severity" in case:
        sev_by_rule = {f["rule"]: f["severity"] for f in findings}
        for rule, severity in case["expected_rule_severity"].items():
            assert sev_by_rule.get(rule) == severity
    assert score.get("score") is None or 0 <= score["score"] <= 100
