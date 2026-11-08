use serde::{Deserialize, Serialize};

/// Which environment variables to collect.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvPolicy {
    #[default]
    None,
    Allowlist(Vec<String>),
    All,
}

/// Decides from the variable name whether the value is redacted.
pub type IsSecretFn = dyn Fn(&str) -> bool + Send + Sync;

/// Produces the redacted value from the name and the value.
pub type RedactFn = dyn Fn(&str, &str) -> String + Send + Sync;

/// The pair of functions that redact environment values.
pub struct Redaction {
    pub is_secret: Box<IsSecretFn>,
    pub redact: Box<RedactFn>,
}

impl Default for Redaction {
    fn default() -> Self {
        Self {
            is_secret: Box::new(default_is_secret),
            redact: Box::new(default_redact),
        }
    }
}

/// Words whose presence anywhere in a variable name marks its value secret, compared ignoring case. Chosen after existing lists such as Rails' `filter_parameters` and Sentry's default scrubbing. `PWD` also matches the working-directory variable, whose value the `cwd` item carries anyway.
const SECRET_NAME_WORDS: [&str; 13] = [
    "TOKEN", "SECRET", "PASS", "KEY", "CRED", "AUTH", "COOKIE", "SESSION", "PRIVATE", "CERT",
    "SALT", "PWD", "OTP",
];

/// What `default_redact` puts in place of a value.
const REDACTED: &str = "[redacted]";

/// Default secret-name predicate: the name contains one of `SECRET_NAME_WORDS`, ignoring case.
pub fn default_is_secret(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    SECRET_NAME_WORDS.iter().any(|word| name.contains(word))
}

/// Default redaction: keeps the name, hides the value behind a fixed marker that tells nothing about it (not even its length).
pub fn default_redact(_name: &str, _value: &str) -> String {
    REDACTED.to_owned()
}

#[cfg(test)]
mod tests {
    use super::{default_is_secret, default_redact};

    // 名前の判定は大文字小文字を区別しない。`api_token` も `Api_Token` も、`API_TOKEN` と同じく秘密として伏せる (小文字の名前で伏せ字を逃れられないように)。
    #[test]
    fn secret_words_match_ignoring_case() {
        for name in ["API_TOKEN", "api_token", "Api_Token"] {
            assert!(default_is_secret(name), "{name}");
        }
    }

    // 語は名前のどこに含まれても当たる (部分一致)。前置・後置・語の途中のどれでも伏せる。`PASSWORD` は `PASS` を、`SSH_AUTH_SOCK` は `AUTH` を含むので伏せる。
    #[test]
    fn secret_words_match_anywhere_in_the_name() {
        for name in [
            "GITHUB_TOKEN",
            "TOKEN_FILE",
            "DB_PASSWORD",
            "SSH_AUTH_SOCK",
            "AWS_SECRET_ACCESS_KEY",
            "MYCREDENTIALS",
            "SESSIONID",
            "TLS_CERT_PATH",
            "OTP_SEED",
            "COOKIE_JAR",
            "PRIVATE_DIR",
            "SALT",
        ] {
            assert!(default_is_secret(name), "{name}");
        }
    }

    // `PWD` は作業ディレクトリの変数 (`PWD`、`OLDPWD`) も巻き込んで伏せる。パスワードの略として使う名前を逃さないための既定で、作業ディレクトリは cwd の項目で取れるので困らない。
    #[test]
    fn pwd_is_a_secret_word() {
        assert!(default_is_secret("PWD"));
        assert!(default_is_secret("OLDPWD"));
        assert!(default_is_secret("MYSQL_PWD"));
    }

    // どの語も含まない名前は伏せない (全部を伏せると env を集める意味がなくなる)。
    #[test]
    fn other_names_are_kept() {
        for name in ["PATH", "HOME", "LANG", "TERM", "SHELL", "EDITOR"] {
            assert!(!default_is_secret(name), "{name}");
        }
    }

    // 伏せた値は固定の印で、元の値の長さも中身も残さない。
    #[test]
    fn redaction_hides_the_value_entirely() {
        assert_eq!(default_redact("API_TOKEN", "abc"), "[redacted]");
        assert_eq!(default_redact("API_TOKEN", &"x".repeat(100)), "[redacted]");
        assert_eq!(default_redact("API_TOKEN", ""), "[redacted]");
    }
}
