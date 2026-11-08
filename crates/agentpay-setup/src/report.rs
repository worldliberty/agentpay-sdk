//! Step reporting: quiet, numbered, aligned human output or a single JSON document.
//!
//! Human output looks like:
//!
//! ```text
//! AgentPay setup · install for alice
//!
//!    1  ✓  Source binaries       /Users/alice/.agentpay/bin
//!    2  ✓  Service account       _agentpay (uid 301), created
//!    3  ✗  Daemon socket         not accepting connections after 15s
//!
//! Next: Check the daemon log: sudo tail -n 50 /var/log/agentpay/com.agentpay.daemon.err.log
//! ```
//!
//! With `--json` nothing is printed until the end, then exactly one JSON object.

use std::io::{self, Write};

use serde::Serialize;
use serde_json::{json, Value};

/// Width the step titles are padded to so details line up.
const TITLE_WIDTH: usize = 22;

/// Outcome of a successful step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    /// Short detail shown after the title.
    pub detail: String,
    /// Whether the step changed the machine.
    pub changed: bool,
}

impl Done {
    /// The step modified the machine.
    pub fn changed(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            changed: true,
        }
    }

    /// The step found everything already in place.
    pub fn unchanged(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            changed: false,
        }
    }
}

/// An error that carries the single next action the user should take.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Actionable {
    /// What went wrong.
    pub message: String,
    /// The one thing to do next.
    pub next: String,
}

/// Builds an [`Actionable`] error.
pub fn actionable(message: impl Into<String>, next: impl Into<String>) -> anyhow::Error {
    Actionable {
        message: message.into(),
        next: next.into(),
    }
    .into()
}

/// A failed step, ready to be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Title of the failing step.
    pub step: String,
    /// Error message (full anyhow context chain).
    pub message: String,
    /// The next action for the user.
    pub next: String,
}

/// One rendered step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepRecord {
    /// 1-based position.
    pub number: usize,
    /// Step title.
    pub title: String,
    /// Whether it succeeded.
    pub ok: bool,
    /// Whether it changed the machine.
    pub changed: bool,
    /// Detail or error message.
    pub detail: String,
}

/// Collects and prints steps for one command.
pub struct Reporter<'a> {
    out: &'a mut dyn Write,
    json: bool,
    command: &'static str,
    default_next: String,
    steps: Vec<StepRecord>,
}

impl<'a> Reporter<'a> {
    /// Starts a report. `default_next` is the next action for failures without a specific one.
    pub fn new(
        out: &'a mut dyn Write,
        json: bool,
        command: &'static str,
        heading: &str,
        default_next: impl Into<String>,
    ) -> Self {
        if !json {
            let _ = writeln!(out, "{heading}\n");
        }
        Self {
            out,
            json,
            command,
            default_next: default_next.into(),
            steps: Vec::new(),
        }
    }

    /// Steps recorded so far.
    pub fn steps(&self) -> &[StepRecord] {
        &self.steps
    }

    /// Runs one step and records its outcome.
    pub fn step<T>(
        &mut self,
        title: &str,
        run: impl FnOnce() -> anyhow::Result<(T, Done)>,
    ) -> Result<T, Failure> {
        let number = self.steps.len() + 1;
        match run() {
            Ok((value, done)) => {
                self.record(StepRecord {
                    number,
                    title: title.into(),
                    ok: true,
                    changed: done.changed,
                    detail: done.detail,
                });
                Ok(value)
            }
            Err(error) => {
                let next = error
                    .downcast_ref::<Actionable>()
                    .map(|actionable| actionable.next.clone())
                    .unwrap_or_else(|| self.default_next.clone());
                let message = format!("{error:#}");
                self.record(StepRecord {
                    number,
                    title: title.into(),
                    ok: false,
                    changed: false,
                    detail: message.clone(),
                });
                Err(Failure {
                    step: title.into(),
                    message,
                    next,
                })
            }
        }
    }

    /// Records a read-only check that does not stop the report when it fails.
    pub fn check(&mut self, title: &str, ok: bool, detail: impl Into<String>) {
        let number = self.steps.len() + 1;
        self.record(StepRecord {
            number,
            title: title.into(),
            ok,
            changed: false,
            detail: detail.into(),
        });
    }

    fn record(&mut self, step: StepRecord) {
        if !self.json {
            let mark = if step.ok { "✓" } else { "✗" };
            let _ = writeln!(
                self.out,
                "  {:>2}  {mark}  {:<TITLE_WIDTH$} {}",
                step.number, step.title, step.detail
            );
            let _ = self.out.flush();
        }
        self.steps.push(step);
    }

    /// Prints the closing line (human) or the JSON document for a successful run.
    pub fn finish_ok(self, message: &str, result: Value) -> io::Result<()> {
        if self.json {
            let document = json!({
                "ok": true,
                "command": self.command,
                "steps": self.steps,
                "result": result,
                "error": null,
                "next_action": null,
            });
            writeln!(self.out, "{}", serde_json::to_string_pretty(&document)?)
        } else {
            writeln!(self.out, "\n{message}")
        }
    }

    /// Prints the failure and its single next action. `result` is included in JSON output
    /// (use `Value::Null` when there is nothing to report).
    pub fn finish_err(self, failure: &Failure, result: Value) -> io::Result<()> {
        if self.json {
            let document = json!({
                "ok": false,
                "command": self.command,
                "steps": self.steps,
                "result": result,
                "error": failure.message,
                "next_action": failure.next,
            });
            writeln!(self.out, "{}", serde_json::to_string_pretty(&document)?)
        } else {
            writeln!(self.out, "\nNext: {}", failure.next)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(json: bool, fail: bool) -> String {
        let mut buffer = Vec::new();
        {
            let mut reporter = Reporter::new(&mut buffer, json, "install", "Heading", "rerun");
            reporter
                .step("First", || Ok(((), Done::changed("did it"))))
                .unwrap();
            if fail {
                let failure = reporter
                    .step("Second", || -> anyhow::Result<((), Done)> {
                        Err(actionable("boom", "do the thing"))
                    })
                    .unwrap_err();
                reporter.finish_err(&failure, Value::Null).unwrap();
            } else {
                reporter.finish_ok("All good.", json!({"k": 1})).unwrap();
            }
        }
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn human_output_is_numbered_and_aligned() {
        let text = render(false, true);
        assert!(text.starts_with("Heading\n\n"));
        assert!(text.contains(&format!("   1  ✓  {:<22} did it\n", "First")));
        assert!(text.contains(&format!("   2  ✗  {:<22} boom\n", "Second")));
        assert!(text.ends_with("\nNext: do the thing\n"));
    }

    #[test]
    fn json_output_is_a_single_document() {
        let value: Value = serde_json::from_str(&render(true, false)).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["steps"][0]["title"], "First");
        assert_eq!(value["result"]["k"], 1);
        let value: Value = serde_json::from_str(&render(true, true)).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["next_action"], "do the thing");
        assert_eq!(value["error"], "boom");
    }

    #[test]
    fn errors_without_a_hint_use_the_default_next_action() {
        let mut sink = Vec::new();
        let mut reporter = Reporter::new(&mut sink, true, "install", "", "rerun");
        let failure = reporter
            .step("X", || -> anyhow::Result<((), Done)> {
                Err(anyhow::anyhow!("plain"))
            })
            .unwrap_err();
        assert_eq!(failure.next, "rerun");
    }
}
