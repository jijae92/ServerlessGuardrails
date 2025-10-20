# Serverless Guardrails — Lambda 안전벨트

Serverless Guardrails is a monorepo that bundles a static analysis scanner, demo Lambda functions, infrastructure templates, and CI/CD automation for enforcing secure AWS Lambda deployments.

## Architecture Overview
- **Scanner (`scanner/`)** – Python 3.11 package with pluggable rules (`env_secret`, `iam_leastpriv`, `vpc_egress`) and a CLI entry point (`python -m scanner`).
- **Functions (`functions/`)** – Demo Lambda code highlighting insecure (`vulnerable/`) versus remediated (`safe/`) configurations.
- **Infrastructure (`templates/`, `pipeline/`)** – SAM application template plus a SAM-based pipeline stack that provisions CodePipeline → CodeBuild → Manual Approval → SAM deployment.
- **Tests (`tests/`)** – Pytest suites covering the core rules.
- **Docs (`docs/`)** – Architecture notes and a scripted demo (`DEMO.md`).

## Getting Started
1. Create a virtual environment with Python 3.11.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the scanner locally against the default SAM template (recommended before every deployment):
   ```bash
   python -m scanner --template templates/app-sam.yaml \
     --source functions/vulnerable \
     --format json \
     --out artifacts/scan.json
   ```
   The command prints a console severity table and writes a JSON report to `artifacts/scan.json`. Review the findings and remediate before pushing pipeline changes.
4. Execute unit tests:
   ```bash
   pytest --cov=scanner --cov-report=term-missing --cov-fail-under=80
   ```

## Definition of Done
- pytest 전용 테스트 성공률 ≥90% (CI에서 실패 테스트 없음) 및 기본 라인 커버리지 ≥80% 유지 (`pytest --cov ... --cov-fail-under=80`).
- `scan.json`에 CRITICAL/HIGH 심각도 항목이 존재하면 머지/배포 금지 (`FAIL_ON` 정책으로 강제).
- README 및 `docs/DEMO.md`의 워크플로와 아키텍처 설명이 최신 상태인지 PR에서 확인.
- `.guardrails-allow.json` 예외가 필요한 경우 [docs/GUARDRAILS_ALLOW.md](docs/GUARDRAILS_ALLOW.md)를 참고해 만료일과 근거를 포함.

## CI / Branch Policies
- `main` 브랜치는 보호되며, 배포 파이프라인은 Pull Request를 통해서만 실행합니다.
- `.github/workflows/ci.yml`이 PR 생성 시 자동으로 `pytest` + 스캐너를 실행하고, 요약 코멘트(Top 10 findings + 가이드 링크)를 남깁니다.
- CodePipeline 빌드 스테이지에서는 `pytest --cov ... --cov-fail-under=80`과 스캐너 실행이 필수이며, Pre/Post Deploy Hook이 결과를 다시 검증합니다.
- `.guardrails-allow.json`에 등록된 예외는 CI가 감지하고 문서화된 승인 절차에 따라 만료일을 주기적으로 검토해야 합니다.

## Local Reproduction Checklist
1. **가상환경 구성**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **취약 버전 스캔 (실패 예상)**
   ```bash
   python -m scanner --template templates/app-sam.yaml \
     --source functions/vulnerable \
     --format json \
     --out artifacts/scan.json
   echo $?
   ```
   종료 코드가 `2`(HIGH/CRITICAL)인지 확인합니다.
3. **안전 버전 스캔 (통과)**
   ```bash
   python -m scanner --template templates/app-sam.yaml \
     --source functions/safe \
     --format json \
     --out artifacts/scan.json
   echo $?
   ```
   종료 코드가 `0`이면 통과입니다.
4. **SAM 배포(선택)**
   ```bash
   sam build
   sam deploy --guided --stack-name serverless-guardrails-demo
   ```
5. **정리**
   ```bash
   sam delete --stack-name serverless-guardrails-demo
   ```

## Scanner Behavior
- Output format is JSON:
  ```json
  {
    "summary": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 1},
    "findings": [...],
    "passed": false
  }
  ```
- Exit codes:
  - `2` if at least one CRITICAL or HIGH finding exists.
  - `1` if medium findings exist but no critical/high.
  - `0` if only low/info findings remain.

## CI/CD Integration
- CodeBuild executes `python -m scanner` using `pipeline/buildspec.yml` and uploads `build/findings.json` as a pipeline artifact.
- CodePipeline stages:
  1. **Source** – pull CodeCommit (parameterised repo/branch).
  2. **Build/Scan** – run CodeBuild with pytest + scanner and publish approval summary.
  3. **PreDeploy Hook** – Lambda가 `scan.json`을 재검증.
  4. **Manual Approval** – 보안 리뷰어가 `approval_message.txt` 확인 후 승인.
  5. **Deploy** – CloudFormation이 ChangeSet을 적용.
  6. **PostDeploy Hook** – 배포된 리소스를 Describe API로 확인.
- Deploy the pipeline stack with the SAM CLI (see `pipeline/sam-pipeline/README.md`).

## Local Demo Workflow
Follow `docs/DEMO.md` for a scripted run that demonstrates the scanner blocking the vulnerable Lambda and passing the safe version after remediation.
