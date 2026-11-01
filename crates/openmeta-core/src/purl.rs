use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Purl {
    package_type: String,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

impl Purl {
    pub fn package_type(&self) -> &str {
        &self.package_type
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn without_version(&self) -> Purl {
        Purl {
            version: None,
            ..self.clone()
        }
    }
}

fn is_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+')
}

fn is_version_char(c: char) -> bool {
    is_segment_char(c) || c == ':'
}

impl FromStr for Purl {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let fail = |reason| Error::InvalidPurl {
            input: input.to_string(),
            reason,
        };
        let rest = input
            .strip_prefix("pkg:")
            .ok_or_else(|| fail("must start with `pkg:`"))?;
        if rest.contains(['?', '#']) {
            return Err(fail("qualifiers and subpaths are not supported"));
        }
        let (package_type, path) = rest
            .split_once('/')
            .ok_or_else(|| fail("missing package type"))?;
        let package_type = package_type.to_ascii_lowercase();
        if package_type.is_empty()
            || !package_type
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
            || package_type.starts_with(|c: char| c.is_ascii_digit())
        {
            return Err(fail("invalid package type"));
        }

        let (path, version) = match path.rsplit_once('@') {
            Some((path, version)) => {
                if version.is_empty() || !version.chars().all(is_version_char) {
                    return Err(fail("invalid version"));
                }
                (path, Some(version.to_string()))
            }
            None => (path, None),
        };

        let segments: Vec<&str> = path.split('/').collect();
        if segments
            .iter()
            .any(|s| s.is_empty() || !s.chars().all(is_segment_char))
        {
            return Err(fail("invalid namespace or name"));
        }
        let (name, namespace) = segments.split_last().ok_or_else(|| fail("missing name"))?;
        let namespace = (!namespace.is_empty()).then(|| namespace.join("/"));

        Ok(Purl {
            package_type,
            namespace,
            name: name.to_string(),
            version,
        })
    }
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg:{}/", self.package_type)?;
        if let Some(namespace) = &self.namespace {
            write!(f, "{namespace}/")?;
        }
        f.write_str(&self.name)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

impl Serialize for Purl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Purl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_namespaced_purl() {
        let purl: Purl = "pkg:NPM/scope/left-pad@1.3.0".parse().unwrap();
        assert_eq!(purl.package_type(), "npm");
        assert_eq!(purl.namespace(), Some("scope"));
        assert_eq!(purl.name(), "left-pad");
        assert_eq!(purl.version(), Some("1.3.0"));
        assert_eq!(purl.to_string().parse::<Purl>().unwrap(), purl);
    }

    #[test]
    fn display_is_canonical() {
        let purl: Purl = "pkg:Cargo/examplelib@1.0.0".parse().unwrap();
        assert_eq!(purl.to_string(), "pkg:cargo/examplelib@1.0.0");
        assert_eq!(purl.without_version().to_string(), "pkg:cargo/examplelib");
    }

    #[test]
    fn parses_maven_namespace() {
        let purl: Purl = "pkg:maven/org.example/core-lib@2.1.0".parse().unwrap();
        assert_eq!(purl.namespace(), Some("org.example"));
        assert_eq!(purl.name(), "core-lib");
    }

    #[test]
    fn rejects_malformed_purls() {
        for bad in [
            "cargo/examplelib@1.0.0",
            "pkg:cargo",
            "pkg:/examplelib",
            "pkg:cargo/@1.0",
            "pkg:cargo/example lib@1.0",
            "pkg:cargo/examplelib@",
            "pkg:cargo/examplelib@1.0?arch=x86",
            "pkg:cargo//examplelib",
        ] {
            assert!(bad.parse::<Purl>().is_err(), "{bad} should be rejected");
        }
    }
}
