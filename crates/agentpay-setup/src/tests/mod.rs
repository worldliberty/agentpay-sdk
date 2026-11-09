//! End-to-end flow tests against [`FakeSystem`].

mod flows;
mod lifecycle;
mod payments;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::install::{install, InstallOptions};
use crate::layout::{Layout, Platform, KEYCHAIN_HELPER_BIN, LEGACY_KEYCHAIN_SERVICE};
use crate::report::{Failure, Reporter};
use crate::system::fake::FakeSystem;

/// Where the fake "downloaded" binaries live.
const SOURCE_DIR: &str = "/Users/alice/.agentpay/bin";

/// A fake machine plus its layout, with source binaries in place.
struct Machine {
    sys: FakeSystem,
    layout: Layout,
}

/// Result of one install run.
struct Run {
    outcome: Result<Value, Failure>,
    output: String,
}

impl Run {
    fn ok(&self) -> &Value {
        match &self.outcome {
            Ok(value) => value,
            Err(failure) => panic!("install failed: {failure:?}\n{}", self.output),
        }
    }

    fn failure(&self) -> &Failure {
        self.outcome.as_ref().expect_err("install should fail")
    }
}

impl Machine {
    fn new(platform: Platform) -> Self {
        let sys = match platform {
            Platform::Macos => FakeSystem::macos(),
            Platform::Linux => FakeSystem::linux(),
        };
        let layout = Layout::for_platform(platform);
        let machine = Self { sys, layout };
        for binary in &machine.layout.binaries {
            machine.put_source(binary.name, b"v1");
        }
        machine
    }

    fn macos() -> Self {
        Self::new(Platform::Macos)
    }

    fn linux() -> Self {
        Self::new(Platform::Linux)
    }

    fn put_source(&self, name: &str, contents: &[u8]) {
        self.sys
            .put_file(Path::new(SOURCE_DIR).join(name), contents, 501, 0o755);
    }

    fn install(&self) -> Run {
        self.install_with_legacy_helper(None)
    }

    fn install_with_legacy_helper(&self, legacy_helper: Option<&str>) -> Run {
        let options = InstallOptions {
            user: "alice".into(),
            source_dir: PathBuf::from(SOURCE_DIR),
            legacy_helper: legacy_helper.map(PathBuf::from),
            socket_timeout: Duration::from_secs(2),
        };
        let mut buffer = Vec::new();
        let outcome = {
            let mut reporter = Reporter::new(&mut buffer, false, "install", "test", "rerun");
            install(&self.sys, &self.layout, &options, &mut reporter)
        };
        Run {
            outcome,
            output: String::from_utf8(buffer).expect("utf8 output"),
        }
    }

    /// The stored machine secret, read straight from the fake store.
    fn stored_secret(&self) -> Option<String> {
        match self.layout.platform {
            Platform::Macos => self
                .sys
                .state
                .borrow()
                .keychain
                .get(&("agentpay-daemon-secret".into(), "agentpay".into()))
                .cloned(),
            Platform::Linux => self.sys.file_text("/var/lib/agentpay/daemon-secret"),
        }
    }

    /// Simulates an install made by an older release that used a vault password.
    fn seed_legacy_install(&self, with_state: bool) {
        match self.layout.platform {
            Platform::Macos => {
                let key = (LEGACY_KEYCHAIN_SERVICE.to_string(), "alice".to_string());
                let mut state = self.sys.state.borrow_mut();
                state.keychain.insert(key.clone(), "legacy vault pw".into());
                // Only the release's own helper build can read the item back.
                state.keychain_acl.insert(key, b"old-helper".to_vec());
                drop(state);
                let helper = self.layout.managed(KEYCHAIN_HELPER_BIN);
                self.sys.put_file(helper, b"old-helper", 0, 0o700);
            }
            Platform::Linux => {
                let path = "/var/lib/agentpay/daemon-password";
                self.sys.put_file(path, b"legacy vault pw", 0, 0o600);
            }
        }
        if with_state {
            self.seed_state();
        }
        let mut state = self.sys.state.borrow_mut();
        state.service_loaded = true;
        state.service_running = true;
    }

    fn seed_state(&self) {
        self.sys
            .put_file(&self.layout.state_file, b"encrypted", 0, 0o600);
    }

    fn assert_secret_hidden(&self, run: &Run, secret: &str) {
        self.sys.assert_secret_never_leaked(secret);
        assert!(!run.output.contains(secret), "secret printed to output");
        if let Ok(result) = &run.outcome {
            assert!(
                !result.to_string().contains(secret),
                "secret in JSON result"
            );
        }
    }

    fn mutating_commands(&self) -> Vec<String> {
        self.sys
            .command_lines()
            .into_iter()
            .filter(|line| {
                !(line.starts_with("launchctl print")
                    || line.starts_with("security find-generic-password")
                    || line.starts_with("systemctl is-")
                    || line.contains("read-generic-password"))
            })
            .collect()
    }
}
