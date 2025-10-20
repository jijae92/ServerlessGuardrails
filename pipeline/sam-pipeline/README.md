# Pipeline Stack

This folder contains an AWS SAM template that provisions the delivery pipeline used by the project:

1. **Source** – tracks the CodeCommit repository (parameterised via `SourceRepo`/`SourceBranch`).
2. **Scan** – runs the static scanner inside CodeBuild with Python 3.11.
3. **Approval** – enforces a manual gate before infrastructure updates.
4. **Deploy** – deploys the SAM application stack using CloudFormation.

Deploy the pipeline with the AWS SAM CLI:

```bash
sam deploy \
  --template-file pipeline/sam-pipeline/template.yaml \
  --stack-name serverless-guardrails-pipeline \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    SourceRepo=ServerlessGuardrails \
    SourceBranch=main \
    PipelineArtifactBucketName=<artifact-bucket>
```

Update the `PipelineArtifactBucketName` parameter to point at an existing, versioned S3 bucket within the target account.
