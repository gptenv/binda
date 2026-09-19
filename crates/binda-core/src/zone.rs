//! Zone files: the same information a BIND9 zone file carries (SOA,
//! records), represented as TOML instead of BIND's own text format.

use serde::{Deserialize, Serialize};

/// The Start-of-Authority parameters for a zone, mirroring a BIND9 `SOA`
/// record's fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartOfAuthority {
    pub primary_nameserver: String,
    pub admin_email: String,
    pub serial: u32,
    pub refresh_secs: u32,
    pub retry_secs: u32,
    pub expire_secs: u32,
    pub minimum_ttl_secs: u32,
}

/// A single resource record within a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub ttl_secs: u32,
    pub value: String,
}

/// The record types BINDA resolves, matching the classic DNS set that
/// matters for basic name resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
}

/// A full zone: SOA plus records, TOML-serializable.
///
/// ```toml
/// [soa]
/// primary_nameserver = "ns1.example.binda"
/// admin_email = "admin.example.binda"
/// serial = 1
/// refresh_secs = 3600
/// retry_secs = 600
/// expire_secs = 604800
/// minimum_ttl_secs = 300
///
/// [[record]]
/// name = "@"
/// type = "A"
/// ttl_secs = 300
/// value = "203.0.113.10"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneFile {
    pub soa: StartOfAuthority,
    #[serde(default, rename = "record")]
    pub records: Vec<Record>,
}

/// Errors parsing or emitting a [`ZoneFile`].
#[derive(Debug, thiserror::Error)]
pub enum ZoneFileError {
    #[error("failed to parse TOML zone file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("failed to serialize zone file to TOML: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl ZoneFile {
    pub fn from_toml(input: &str) -> Result<Self, ZoneFileError> {
        Ok(toml::from_str(input)?)
    }

    pub fn to_toml(&self) -> Result<String, ZoneFileError> {
        Ok(toml::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let zone = ZoneFile {
            soa: StartOfAuthority {
                primary_nameserver: "ns1.example.binda".into(),
                admin_email: "admin.example.binda".into(),
                serial: 1,
                refresh_secs: 3600,
                retry_secs: 600,
                expire_secs: 604800,
                minimum_ttl_secs: 300,
            },
            records: vec![Record {
                name: "@".into(),
                record_type: RecordType::A,
                ttl_secs: 300,
                value: "203.0.113.10".into(),
            }],
        };
        let toml_str = zone.to_toml().unwrap();
        let parsed = ZoneFile::from_toml(&toml_str).unwrap();
        assert_eq!(zone, parsed);
    }

    #[test]
    fn defaults_records_to_empty_when_omitted() {
        let toml_str = r#"
            [soa]
            primary_nameserver = "ns1.example.binda"
            admin_email = "admin.example.binda"
            serial = 1
            refresh_secs = 3600
            retry_secs = 600
            expire_secs = 604800
            minimum_ttl_secs = 300
        "#;
        let zone = ZoneFile::from_toml(toml_str).unwrap();
        assert!(zone.records.is_empty());
    }

    #[test]
    fn rejects_malformed_toml() {
        let result = ZoneFile::from_toml("this is not valid toml {{{");
        assert!(matches!(result, Err(ZoneFileError::Parse(_))));
    }

    #[test]
    fn rejects_missing_required_field() {
        let result = ZoneFile::from_toml("[soa]\nprimary_nameserver = \"ns1.example.binda\"");
        assert!(matches!(result, Err(ZoneFileError::Parse(_))));
    }

    #[test]
    fn error_messages_are_human_readable() {
        let err = ZoneFile::from_toml("not toml {{{").unwrap_err();
        assert!(err
            .to_string()
            .starts_with("failed to parse TOML zone file"));
    }
}
