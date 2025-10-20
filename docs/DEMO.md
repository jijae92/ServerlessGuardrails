```mermaid
flowchart LR
    Dev[(Developer Laptop)] -->|git push| Repo[(GitHub/CodeCommit)]
    Repo -->|Source Stage| CP[CodePipeline]
    CP -->|Build| CB[CodeBuild Scanner]
    CB -->|artifacts/scan.json| CP
    CP -->|PreDeploy Lambda| PreHook[
        PreDeploy Hook
        (re-validate scan)
    ]
    CP -->|Manual Approval| Gate[Security Reviewer]
    Gate -->|Approve| CP
    CP -->|Deploy| CFN[CloudFormation]
    CFN -->|Stack Outputs| PostHook[
        PostDeploy Hook
        (describe resources)
    ]
    PostHook -->|Status| CP
    CP -->|Notifications| SNS[(Email/Chat)]
```

# Demo: Failing → Fixing the Serverless Guardrails Pipeline

## 1. Architecture Overview
- **Source:** GitHub 또는 CodeCommit 리포지터리가 CodePipeline을 트리거합니다.
- **Build:** CodeBuild가 `pipeline/buildspec.yml`을 실행해 `pytest`와 `python -m scanner`를 수행하고 `artifacts/scan.json` 및 `artifacts/approval_message.txt`를 생성합니다.
- **Hooks:** PreDeploy/PostDeploy Lambda가 배포 전·후에 scanner 결과와 실환경 구성을 검증하여 우회 시도를 차단합니다.
- **Gate:** Manual Approval 단계에서 보안 담당자가 하이라이트와 가이드 링크를 확인한 뒤 배포를 승인합니다.
- **Deploy:** CloudFormation이 `serverless-guardrails-demo` 스택을 업데이트합니다.

## 2. 로컬 스캔 (실패 예시)
```bash
python -m scanner \
  --template templates/app-sam.yaml \
  --source functions/vulnerable \
  --format json \
  --out artifacts/scan.json
```
예상 출력(요약):
```
Scan Summary
CRITICAL: 0  HIGH: 2  MEDIUM: 1  LOW: 1  INFO: 1
Status    : FAIL (exit code 2)
Top Findings: ENV001 Hardcoded secret ..., IAM001 Wildcard IAM ..., VPC001 Public subnet ...
```

## 3. 파이프라인 트리거 – 취약 버전 (실패 경로)
1. `functions/vulnerable/` 및 `templates/app-sam.yaml` 의 초기 상태를 `main` 또는 `demo` 브랜치에 푸시합니다.
2. CodePipeline 소스 단계가 변경을 감지하여 Build 단계를 실행합니다.
3. **Build 단계 실패:** CodeBuild 로그에 scanner 실패와 `artifacts/approval_message.txt` 요약이 남고, `FAIL_ON=MEDIUM` 정책 때문에 파이프라인이 PreDeploy 단계 이전에 중단됩니다.
4. Manual Approval 단계는 “대기” 상태로 남으나, PreDeploy Hook이 `scan.json`의 `passed=false` 를 재검증하여 JobFailure를 반환하고 Gate가 열리지 않습니다.

## 4. 수정 커밋 – 안전 버전 (성공 경로)
1. 다음 변경사항을 커밋하고 푸시합니다.
   - `functions/safe/app.py`에서 Secrets Manager 호출 사용.
   - `templates/app-sam.yaml`에 최소권한 IAM 정책, 제한된 SG, VPC 엔드포인트 구성.
2. CodeBuild가 다시 실행되어 `pytest` + scanner를 통과하고 `artifacts/scan.json`에서 `passed=true`로 표시됩니다.
3. PreDeploy Hook이 성공을 기록하면 Manual Approval 단계가 “대기” 상태로 전환되고, `artifacts/approval_message.txt`의 하이라이트와 가이드 링크를 검토합니다.
4. 보안 담당자가 승인하면 CloudFormation이 `serverless-guardrails-demo` 스택을 업데이트합니다.
5. PostDeploy Hook이 배포된 SecurityGroup/네트워크 구성을 Describe API로 확인하여 `0.0.0.0/0` egress 등의 위험이 제거되었는지 검증하고 성공을 기록합니다.

## 5. scan.json 비교 예시
- **실패 버전:**
  ```json
  {
    "summary": {"critical": 0, "high": 2, "medium": 1, "low": 1, "info": 1},
    "passed": false,
    "findings": [
      {"id": "ENV001", "severity": "HIGH", "resource": "AWS::Serverless::Function VulnerableFunction", ...},
      {"id": "IAM001", "severity": "CRITICAL", "resource": "AWS::IAM::Role VulnerableFunctionRole", ...}
    ]
  }
  ```
- **성공 버전:**
  ```json
  {
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 1},
    "passed": true,
    "findings": [
      {"id": "ENV001", "severity": "LOW", "resource": "PythonSource functions/safe/app.py", ...}
    ]
  }
  ```

## 6. 보안 통제 매핑
| 표준 | 통제 항목 | 구현 요소 |
|------|-----------|-----------|
| NIST SP 800-53 | AC-6 (최소 권한) | IAM rule이 와일드카드 정책을 차단, SafeFunction에 최소 로그 권한만 허용 |
| | SC-7 (경계 보호) | VPC egress rule이 퍼블릭 서브넷/SG를 탐지, Restricted SG + VPC 엔드포인트로 제어 |
| | SA-11 (정적 분석) | CodeBuild에서 정적 스캐너와 pytest 실행 |
| | CM-3 (변경 관리) | Pre/Post Hook, Manual Approval, scan.json 아티팩트 기록 |
| ISO/IEC 27001 | A.9 접근 통제 | Secrets Manager 사용 및 IAM 최소 권한 정책 |
| | A.12.6 기술적 취약점 관리 | 정적 분석 룰과 pipeline 차단 |
| | A.14 시스템 보안 요구 | 배포 전 안전성 검증 및 승인 절차 |
| AWS Well-Architected (보안) | IAM | IAM 최소 권한 및 `FAIL_ON` 정책 |
| | 데이터 보호 | Secrets Manager/SSM 권장, 하드코딩 비밀 제거 |
| | 네트워크 보안 | SG egress 제한, VPC 엔드포인트 필수화 |
| | 변경 관리 | Pre/Post Hook + Manual Approval으로 변경 추적 |

## 7. 제한사항
- 정적 분석 특성상 False Positive/False Negative가 발생할 수 있으며, 동적 런타임 조건을 100% 판별할 수 없습니다.
- IaC 그래프 상관관계를 최소 구현만 포함하므로, 복잡한 다중 계층 네트워크 경로는 추가 도구(예: AWS Config, CloudGraph)가 필요합니다.
- Secrets Manager 참조나 IAM 정책이 템플릿 외부에서 주입되는 경우, 스캐너는 값을 추론하지 못합니다.

## 8. 향후 확장 아이디어
- Bandit, cfn-nag, Semgrep 같은 추가 정적 분석기 연동
- SARIF 출력 및 GitHub/GitLab PR 코멘트봇으로 피드백 자동화
- OPA/Conftest를 이용한 조직 정책 준수 검증
- Organizations 계정 전반에 `FAIL_ON` 정책 일관 적용, GuardDuty/Config 룰과 연계
- ChangeSet Diff를 PreDeploy Hook에서 더 정교하게 분석(예: 삭제/Privilege Escalation 감지)

## 부록: 빠른 실행 요약
1. `pip install -r requirements.txt`
2. `sam deploy --template-file pipeline/sam-pipeline/template.yaml ...`
3. 취약 버전 푸시 → 실패 확인
4. 안전 버전 수정 → 성공 → 승인 → 배포 완료
