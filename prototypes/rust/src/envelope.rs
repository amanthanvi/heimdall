//! Result envelope (contract §1, schemas/g02/result.schema.json).

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Succeeded,
    Failed,
    Cancelled,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Succeeded => "succeeded",
            State::Failed => "failed",
            State::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    ProfileOk,
    AgentOk,
    VersionOk,
    ChildExited,
    ChildLaunchFailed,
    UsageError,
    SchemaInvalid,
    InputTooLarge,
    AgentUnavailable,
    AgentProtocolError,
    AgentRefused,
    Cancelled,
    Internal,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::ProfileOk => "PROFILE_OK",
            Code::AgentOk => "AGENT_OK",
            Code::VersionOk => "VERSION_OK",
            Code::ChildExited => "CHILD_EXITED",
            Code::ChildLaunchFailed => "CHILD_LAUNCH_FAILED",
            Code::UsageError => "USAGE_ERROR",
            Code::SchemaInvalid => "SCHEMA_INVALID",
            Code::InputTooLarge => "INPUT_TOO_LARGE",
            Code::AgentUnavailable => "AGENT_UNAVAILABLE",
            Code::AgentProtocolError => "AGENT_PROTOCOL_ERROR",
            Code::AgentRefused => "AGENT_REFUSED",
            Code::Cancelled => "CANCELLED",
            Code::Internal => "INTERNAL",
        }
    }

    /// Process exit code for this result code (contract §1 table). `run` does not
    /// use this mapping for child results (contract §4).
    pub fn exit_code(self) -> i32 {
        match self {
            Code::ProfileOk | Code::AgentOk | Code::VersionOk => 0,
            Code::UsageError | Code::SchemaInvalid | Code::InputTooLarge => 2,
            Code::AgentUnavailable | Code::AgentProtocolError | Code::AgentRefused => 5,
            Code::Cancelled => 130,
            Code::Internal => 1,
            // Not used for process exit; `run` exits with the child's status.
            Code::ChildExited => 0,
            Code::ChildLaunchFailed => 127,
        }
    }
}

/// A complete result document.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub state: State,
    pub code: Code,
    pub data: Value,
    pub warnings: Vec<String>,
}

impl Envelope {
    pub fn success(code: Code, data: Value) -> Self {
        Envelope {
            state: State::Succeeded,
            code,
            data,
            warnings: Vec::new(),
        }
    }

    /// Failure with the contract's error data shape:
    /// `{"error":{"key_path":<string|null>,"message":<string>}}`.
    pub fn failure(code: Code, key_path: Option<String>, message: impl Into<String>) -> Self {
        Envelope {
            state: State::Failed,
            code,
            data: json!({"error": {"key_path": key_path, "message": message.into()}}),
            warnings: Vec::new(),
        }
    }

    pub fn cancelled() -> Self {
        Envelope {
            state: State::Cancelled,
            code: Code::Cancelled,
            data: Value::Null,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("schema_version".into(), json!("1"));
        m.insert("state".into(), json!(self.state.as_str()));
        m.insert("code".into(), json!(self.code.as_str()));
        m.insert("data".into(), self.data.clone());
        m.insert("warnings".into(), json!(self.warnings));
        m.insert("next".into(), Value::Null);
        Value::Object(m)
    }

    /// Exactly one JSON document followed by `\n`.
    pub fn to_line(&self) -> String {
        let mut s =
            serde_json::to_string(&self.to_value()).expect("serializing a Value cannot fail");
        s.push('\n');
        s
    }

    pub fn exit_code(&self) -> i32 {
        self.code.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_shape() {
        let e = Envelope::failure(Code::SchemaInvalid, Some("name".into()), "bad");
        let v = e.to_value();
        let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "schema_version",
                "state",
                "code",
                "data",
                "warnings",
                "next"
            ]
        );
        assert_eq!(v["data"]["error"]["key_path"], "name");
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_line().ends_with("}\n"));
        assert_eq!(Envelope::cancelled().exit_code(), 130);
        assert_eq!(Code::AgentRefused.exit_code(), 5);
        assert_eq!(Code::Internal.exit_code(), 1);
    }
}
