//! Fail-closed command inspection, independent of approval policy and its cache.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::hooks::{HookDecision, HookInput};

use super::runtime::ToolError;

pub(super) fn from_env() -> Option<Arc<Vec<String>>> {
    std::env::var_os("BUT_COMMAND_GUARD").map(|raw| {
        // Invalid configuration stays enabled and fails closed at execution time.
        Arc::new(
            raw.to_str()
                .and_then(|value| serde_json::from_str(value).ok())
                .unwrap_or_default(),
        )
    })
}

pub(super) async fn inspect(command: &[String], input: HookInput) -> Result<(), ToolError> {
    let denied = || ToolError::Rejected("Command blocked by pre-execution guard.".into());
    let program = command
        .first()
        .filter(|program| !program.is_empty())
        .ok_or_else(denied)?;
    let payload = serde_json::to_vec(&input).map_err(|_| denied())?;
    let mut child = Command::new(program)
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| denied())?;

    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stdin = child.stdin.take().ok_or_else(denied)?;
        stdin.write_all(&payload).await.map_err(|_| denied())?;
        drop(stdin);

        let mut output = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(denied)?
            .take(8 * 1024 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| denied())?;
        if output.len() > 8 * 1024 || !child.wait().await.map_err(|_| denied())?.success() {
            return Err(denied());
        }
        let decision: HookDecision = serde_json::from_slice(&output).map_err(|_| denied())?;
        if decision.r#continue != Some(true) {
            return Err(denied());
        }
        Ok(())
    })
    .await
    .map_err(|_| denied())?
}

#[cfg(all(test, unix))]
mod tests {
    use super::inspect;
    use crate::hooks::{HookEvent, HookInput};

    #[tokio::test]
    async fn command_guard_requires_a_successful_explicit_allow_decision() {
        for script in [
            "cat >/dev/null; printf '{\"continue\":true}'; exit 1",
            "cat >/dev/null; printf '{}'",
            "cat >/dev/null; printf '{\"continue\":\"true\"}'",
            "cat >/dev/null; printf 'not json'",
            "cat >/dev/null; head -c 8193 /dev/zero",
        ] {
            let result = inspect(
                &["sh".into(), "-c".into(), script.into()],
                HookInput::new(HookEvent::PreToolUse),
            )
            .await;
            assert!(result.is_err(), "checker must fail closed: {script}");
        }
        for command in [
            vec![],
            vec!["/nonexistent/browser-use-command-guard".into()],
        ] {
            assert!(inspect(&command, HookInput::new(HookEvent::PreToolUse))
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn command_guard_times_out_without_allowing_execution() {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(7),
            inspect(
                &[
                    "sh".into(),
                    "-c".into(),
                    "cat >/dev/null; exec sleep 30".into(),
                ],
                HookInput::new(HookEvent::PreToolUse),
            ),
        )
        .await
        .expect("checker must honor the five-second timeout");
        assert!(result.is_err());
    }
}
