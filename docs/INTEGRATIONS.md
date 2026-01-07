# Beyond GitHub Integrations

OccamO is CLI-first and works in any CI/CD system. Use standard outputs
(`--json`, `--sarif`, `--html`, `--md`, `--snippets`) and archive them as
artifacts.

## GitLab CI

```yaml
stages: [analyze]

occamo:
  stage: analyze
  image: python:3.12
  script:
    - pip install occamo
    - occamo analyze . --changed-only --compare-base \
        --base-ref origin/main \
        --json out/occamo.json \
        --md out/occamo.md \
        --sarif out/occamo.sarif \
        --snippets out/occamo.snippets.md
  artifacts:
    when: always
    paths:
      - out/occamo.json
      - out/occamo.md
      - out/occamo.sarif
      - out/occamo.snippets.md
```

If your CI provides a merge-request base branch variable, pass it to
`--base-ref` for accurate diffs.

## Jenkins (Declarative Pipeline)

```groovy
pipeline {
  agent any
  stages {
    stage('OccamO') {
      steps {
        sh 'pip install occamo'
        sh '''
          occamo analyze . --changed-only --compare-base \
            --base-ref origin/main \
            --json out/occamo.json \
            --md out/occamo.md \
            --sarif out/occamo.sarif \
            --snippets out/occamo.snippets.md
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'out/*', fingerprint: true
        }
      }
    }
  }
}
```

## Azure DevOps Pipelines

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: |
      pip install occamo
      occamo analyze . --changed-only --compare-base \
        --base-ref origin/main \
        --json out/occamo.json \
        --md out/occamo.md \
        --sarif out/occamo.sarif \
        --snippets out/occamo.snippets.md
    displayName: 'Run OccamO'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: 'out'
      ArtifactName: 'occamo'
```

## Baseline caching outside GitHub

If you cannot rely on git history in CI, store a baseline JSON artifact on
main and reuse it in PRs:

```bash
# on main
occamo baseline . --json out/occamo.json

# on PR
occamo analyze . --baseline-json out/occamo.json --compare-base
```

## Notes

- SARIF can be ingested by many security/reporting tools; otherwise, archive it.
- JSON is best for dashboards and custom automation.
- Markdown/HTML are best for human review.
