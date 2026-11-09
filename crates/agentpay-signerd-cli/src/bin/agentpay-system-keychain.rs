// The System Keychain exists only on macOS. Elsewhere every command just says so, which leaves
// the shared parsing and stdin helpers unused there (they stay compiled and tested everywhere).
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroize;

const MAX_SECRET_STDIN_BYTES: usize = 16 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "agentpay-system-keychain",
    about = "Read and replace AgentPay generic-password items in a specific macOS keychain"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ReadGenericPassword {
        #[arg(long, value_name = "PATH")]
        keychain: PathBuf,
        #[arg(long, value_name = "NAME")]
        service: String,
        #[arg(long, value_name = "NAME")]
        account: String,
    },
    ReplaceGenericPassword {
        #[arg(long, value_name = "PATH")]
        keychain: PathBuf,
        #[arg(long, value_name = "NAME")]
        service: String,
        #[arg(long, value_name = "NAME")]
        account: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Read the replacement password from stdin"
        )]
        password_stdin: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ReadGenericPassword {
            keychain,
            service,
            account,
        } => read_generic_password(keychain, service, account),
        Command::ReplaceGenericPassword {
            keychain,
            service,
            account,
            password_stdin,
        } => replace_generic_password(keychain, service, account, password_stdin),
    }
}

fn required_trimmed(value: String, label: &str) -> Result<String> {
    let normalized = value.trim().to_owned();
    if normalized.is_empty() {
        bail!("{label} is required");
    }
    if normalized.chars().any(|character| character.is_control()) {
        bail!("{label} must not contain control characters");
    }
    Ok(normalized)
}

fn read_secret_from_stdin(label: &str) -> Result<String> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .with_context(|| format!("failed to read {label} from stdin"))?;

    if raw.len() > MAX_SECRET_STDIN_BYTES {
        raw.zeroize();
        bail!("{label} must not exceed {MAX_SECRET_STDIN_BYTES} bytes");
    }

    let trimmed = raw.trim_end_matches(['\r', '\n']).to_owned();
    raw.zeroize();

    if trimmed.trim().is_empty() {
        bail!("{label} must not be empty or whitespace");
    }

    Ok(trimmed)
}

#[cfg(target_os = "macos")]
fn read_generic_password(keychain: PathBuf, service: String, account: String) -> Result<()> {
    use security_framework::os::macos::keychain::SecKeychain;

    let service = required_trimmed(service, "service")?;
    let account = required_trimmed(account, "account")?;
    let _interaction_guard =
        SecKeychain::disable_user_interaction().context("failed to disable keychain UI")?;
    let keychain = SecKeychain::open(&keychain)
        .with_context(|| format!("failed to open keychain {}", keychain.display()))?;
    let (password, _) = keychain
        .find_generic_password(&service, &account)
        .with_context(|| {
            format!(
                "failed to read generic password for service '{}' and account '{}'",
                service, account
            )
        })?;
    let mut secret = String::from_utf8(password.as_ref().to_vec())
        .context("generic password data is not valid UTF-8")?;
    std::io::stdout()
        .write_all(secret.as_bytes())
        .context("failed to write generic password to stdout")?;
    std::io::stdout()
        .write_all(b"\n")
        .context("failed to terminate stdout output")?;
    secret.zeroize();
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn read_generic_password(_keychain: PathBuf, _service: String, _account: String) -> Result<()> {
    bail!("agentpay-system-keychain is available only on macOS");
}

#[cfg(target_os = "macos")]
fn replace_generic_password(
    keychain: PathBuf,
    service: String,
    account: String,
    password_stdin: bool,
) -> Result<()> {
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework_sys::base::{errSecAuthFailed, errSecItemNotFound};

    if !password_stdin {
        bail!("replace-generic-password requires --password-stdin");
    }

    let service = required_trimmed(service, "service")?;
    let account = required_trimmed(account, "account")?;
    let mut password = read_secret_from_stdin("password")?;

    let result = (|| {
        let _interaction_guard =
            SecKeychain::disable_user_interaction().context("failed to disable keychain UI")?;
        let keychain = SecKeychain::open(&keychain)
            .with_context(|| format!("failed to open keychain {}", keychain.display()))?;

        match keychain.find_generic_password(&service, &account) {
            Ok((_existing_password, item)) => item.delete(),
            Err(error) if error.code() == errSecItemNotFound => {}
            Err(error) if error.code() == errSecAuthFailed => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect existing generic password for service '{}' and account '{}'",
                        service, account
                    )
                });
            }
        }

        add_generic_password_restricted_to_creator(
            &keychain,
            &service,
            &account,
            password.as_bytes(),
        )
        .with_context(|| {
            format!(
                "failed to store generic password for service '{}' and account '{}'",
                service, account
            )
        })?;
        Ok(())
    })();

    password.zeroize();
    result
}

#[cfg(target_os = "macos")]
fn add_generic_password_restricted_to_creator(
    keychain: &security_framework::os::macos::keychain::SecKeychain,
    service: &str,
    account: &str,
    password: &[u8],
) -> Result<()> {
    use core_foundation::array::{CFArray, CFArrayRef};
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::string::CFString;
    use security_framework::base::Error as SecurityError;
    use security_framework::os::macos::access::SecAccess;
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework_sys::base::{
        SecAccessRef, SecKeychainAttribute, SecKeychainAttributeList, SecKeychainItemRef,
    };

    const K_SEC_GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
    const K_SEC_SERVICE_ITEM_ATTR: u32 = u32::from_be_bytes(*b"svce");
    const K_SEC_ACCOUNT_ITEM_ATTR: u32 = u32::from_be_bytes(*b"acct");

    unsafe extern "C" {
        fn SecAccessCreate(
            descriptor: core_foundation::string::CFStringRef,
            trustedlist: CFArrayRef,
            access_ref: *mut SecAccessRef,
        ) -> core_foundation::base::OSStatus;

        fn SecKeychainItemCreateFromContent(
            item_class: u32,
            attr_list: *mut SecKeychainAttributeList,
            length: u32,
            data: *const libc::c_void,
            keychain_ref: security_framework_sys::base::SecKeychainRef,
            initial_access: SecAccessRef,
            item_ref: *mut SecKeychainItemRef,
        ) -> core_foundation::base::OSStatus;

        fn SecTrustedApplicationCreateFromPath(
            path: *const libc::c_char,
            app: *mut *mut libc::c_void,
        ) -> core_foundation::base::OSStatus;
    }

    let descriptor = CFString::from("agentpay-system-keychain");
    let mut trusted_app_ref: *mut libc::c_void = std::ptr::null_mut();
    let trusted_app_status =
        unsafe { SecTrustedApplicationCreateFromPath(std::ptr::null(), &mut trusted_app_ref) };
    if trusted_app_status != 0 {
        return Err(SecurityError::from_code(trusted_app_status))
            .context("failed to create trusted-application ACL entry for helper");
    }
    let trusted_app = unsafe { CFType::wrap_under_create_rule(trusted_app_ref.cast()) };
    let trusted_apps = CFArray::from_CFTypes(&[trusted_app]);

    let mut access_ref: SecAccessRef = std::ptr::null_mut();
    let access_status = unsafe {
        SecAccessCreate(
            descriptor.as_concrete_TypeRef(),
            trusted_apps.as_concrete_TypeRef(),
            &mut access_ref,
        )
    };
    if access_status != 0 {
        return Err(SecurityError::from_code(access_status))
            .context("failed to create keychain item access rules");
    }
    let access = unsafe { SecAccess::wrap_under_create_rule(access_ref) };

    let mut service_bytes = service.as_bytes().to_vec();
    let mut account_bytes = account.as_bytes().to_vec();
    let mut attributes = [
        SecKeychainAttribute {
            tag: K_SEC_SERVICE_ITEM_ATTR,
            length: service_bytes.len() as u32,
            data: service_bytes.as_mut_ptr().cast(),
        },
        SecKeychainAttribute {
            tag: K_SEC_ACCOUNT_ITEM_ATTR,
            length: account_bytes.len() as u32,
            data: account_bytes.as_mut_ptr().cast(),
        },
    ];
    let mut attribute_list = SecKeychainAttributeList {
        count: attributes.len() as u32,
        attr: attributes.as_mut_ptr(),
    };
    let mut item_ref: SecKeychainItemRef = std::ptr::null_mut();

    let create_status = unsafe {
        SecKeychainItemCreateFromContent(
            K_SEC_GENERIC_PASSWORD_ITEM_CLASS,
            &mut attribute_list,
            password.len() as u32,
            password.as_ptr().cast(),
            keychain.as_CFTypeRef() as security_framework_sys::base::SecKeychainRef,
            access.as_concrete_TypeRef(),
            &mut item_ref,
        )
    };
    let _item =
        (!item_ref.is_null()).then(|| unsafe { SecKeychainItem::wrap_under_create_rule(item_ref) });
    if create_status != 0 {
        return Err(SecurityError::from_code(create_status))
            .context("failed to create restricted generic password item");
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn replace_generic_password(
    _keychain: PathBuf,
    _service: String,
    _account: String,
    _password_stdin: bool,
) -> Result<()> {
    bail!("agentpay-system-keychain is available only on macOS");
}

#[cfg(test)]
mod tests {
    use super::required_trimmed;

    #[test]
    fn required_trimmed_accepts_spaces_inside_identifiers() {
        let value = required_trimmed("Jane Doe".to_string(), "account").unwrap();
        assert_eq!(value, "Jane Doe");
    }

    #[test]
    fn required_trimmed_rejects_blank_identifiers() {
        let error = required_trimmed("   ".to_string(), "service").unwrap_err();
        assert!(error.to_string().contains("service is required"));
    }

    #[test]
    fn required_trimmed_rejects_control_characters() {
        let error = required_trimmed("bad\naccount".to_string(), "account").unwrap_err();
        assert!(error
            .to_string()
            .contains("account must not contain control characters"));
    }
}
