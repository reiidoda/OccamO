# Privacy and Data Handling

OccamO runs locally in your CI or developer machine. It does not upload
source code or analysis results to any external service by default.

## What Leaves the Runner

- Nothing, unless you explicitly upload artifacts or SARIF via your CI.
- Optional baseline download uses the GitHub API to fetch artifacts from your
  own repository (when `baseline_auto` is enabled in the action).
- Slack/Teams outputs are JSON files only; sending them is up to your CI.

## Logs and Outputs

OccamO writes reports to paths you specify (examples use `out/`). Logs include
file paths and summary metrics; they do not include file contents.

## Dynamic Verification

Dynamic verification executes repo code in a subprocess. It does not send
results off the runner, but it runs code and should only be enabled in trusted
CI environments.

## Telemetry

OccamO does not include telemetry. If telemetry is added in the future, it
will be opt-in and documented here before release.
