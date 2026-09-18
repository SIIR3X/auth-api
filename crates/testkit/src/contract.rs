//! The OpenAPI document as an executable contract.
//!
//! Every [`TestApp`](crate::TestApp) routes its responses through [`record`],
//! which checks them against the document generated from the handlers
//! (`auth_api::openapi::ApiDoc`): the status must be documented for the
//! operation, and a JSON body must match the documented schema. Every
//! integration and security test is thereby a contract test as well.
//!
//! A response outside the contract fails the test when its app is dropped
//! (`TEST_CONTRACT=strict`, the default). `TEST_CONTRACT=report` appends the
//! violations to `target/contract-report/` instead, to survey a change;
//! `TEST_CONTRACT=off` disables the check.

use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::header::CONTENT_TYPE,
    middleware::Next,
    response::Response,
};
use serde_json::{Value, json};
use utoipa::OpenApi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Strict,
    Report,
    Off,
}

pub fn mode() -> Mode {
    match std::env::var("TEST_CONTRACT").as_deref() {
        Ok("report") => Mode::Report,
        Ok("off") => Mode::Off,
        _ => Mode::Strict,
    }
}

pub struct Contract {
    operations: Vec<Operation>,
}

struct Operation {
    method: String,
    template: String,
    segments: Vec<Segment>,
    responses: BTreeMap<String, ResponseSpec>,
}

enum Segment {
    Literal(String),
    Parameter,
}

struct ResponseSpec {
    /// Validator of the `application/json` body, when one is documented.
    json: Option<jsonschema::Validator>,
    /// Whether any content is documented at all.
    has_content: bool,
}

/// The contract of the code under test, built once per process.
pub fn contract() -> &'static Contract {
    static CONTRACT: OnceLock<Contract> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        let document =
            serde_json::to_value(auth_api::openapi::ApiDoc::openapi()).expect("document to JSON");
        Contract::from_document(&document)
    })
}

impl Contract {
    pub fn from_document(document: &Value) -> Self {
        let components = document.get("components").cloned().unwrap_or(json!({}));
        let mut operations = Vec::new();

        for (template, item) in document["paths"].as_object().expect("paths") {
            for method in ["get", "post", "put", "patch", "delete"] {
                let Some(operation) = item.get(method) else {
                    continue;
                };
                let responses = operation["responses"]
                    .as_object()
                    .map(|responses| {
                        responses
                            .iter()
                            .map(|(status, response)| {
                                (status.clone(), response_spec(response, &components))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                operations.push(Operation {
                    method: method.to_ascii_uppercase(),
                    template: template.clone(),
                    segments: segments(template),
                    responses,
                });
            }
        }

        // Literal segments win over parameters (`/oauth/device/verify` before
        // `/oauth/device/{user_code}`).
        operations.sort_by_key(|op| {
            std::cmp::Reverse(
                op.segments
                    .iter()
                    .filter(|s| matches!(s, Segment::Literal(_)))
                    .count(),
            )
        });
        Self { operations }
    }

    /// Operation template of `method path`, if the document describes one.
    pub fn template(&self, method: &str, path: &str) -> Option<&str> {
        self.find(method, path).map(|op| op.template.as_str())
    }

    fn find(&self, method: &str, path: &str) -> Option<&Operation> {
        let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
        self.operations.iter().find(|op| {
            op.method.eq_ignore_ascii_case(method)
                && op.segments.len() == parts.len()
                && op
                    .segments
                    .iter()
                    .zip(&parts)
                    .all(|(segment, part)| match segment {
                        Segment::Literal(literal) => literal == part,
                        Segment::Parameter => !part.is_empty(),
                    })
        })
    }

    /// Check one response. Requests to paths the document does not describe
    /// are not the contract's business and pass.
    pub fn check(
        &self,
        method: &str,
        path: &str,
        status: u16,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<(), String> {
        let Some(operation) = self.find(method, path) else {
            return Ok(());
        };
        let context = format!("{method} {} -> {status}", operation.template);

        let Some(spec) = operation
            .responses
            .get(&status.to_string())
            .or_else(|| operation.responses.get("default"))
        else {
            return Err(format!("{context}: status not documented"));
        };

        match &spec.json {
            Some(validator) => {
                let is_json = content_type.is_some_and(|ct| ct.starts_with("application/json"));
                if !is_json {
                    return Err(format!(
                        "{context}: documented as application/json, got {} ({})",
                        content_type.unwrap_or("no content type"),
                        String::from_utf8_lossy(&body[..body.len().min(80)])
                    ));
                }
                let instance: Value = serde_json::from_slice(body)
                    .map_err(|e| format!("{context}: body is not JSON: {e}"))?;
                let errors: Vec<String> = validator
                    .iter_errors(&instance)
                    .take(5)
                    .map(|error| format!("at `{}`: {error}", error.instance_path()))
                    .collect();
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(format!(
                        "{context}: body does not match the schema: {}; body: {instance}",
                        errors.join("; ")
                    ))
                }
            }
            None if !spec.has_content && !body.is_empty() => Err(format!(
                "{context}: no body documented, got {} ({})",
                content_type.unwrap_or("no content type"),
                String::from_utf8_lossy(&body[..body.len().min(80)])
            )),
            None => Ok(()),
        }
    }
}

fn segments(template: &str) -> Vec<Segment> {
    template
        .trim_end_matches('/')
        .split('/')
        .map(|part| {
            if part.starts_with('{') && part.ends_with('}') {
                Segment::Parameter
            } else {
                Segment::Literal(part.to_owned())
            }
        })
        .collect()
}

fn response_spec(response: &Value, components: &Value) -> ResponseSpec {
    let content = response.get("content").and_then(Value::as_object);
    let json = content
        .and_then(|content| content.get("application/json"))
        .and_then(|media| media.get("schema"))
        .map(|schema| {
            // `#/components/...` references resolve against this root.
            let root = json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "components": components,
                "allOf": [schema],
            });
            jsonschema::options()
                .should_validate_formats(true)
                .build(&root)
                .unwrap_or_else(|e| panic!("invalid schema in the OpenAPI document: {e}"))
        });
    ResponseSpec {
        json,
        has_content: content.is_some_and(|content| !content.is_empty()),
    }
}

/// Violations seen by one app.
#[derive(Clone, Default)]
pub struct Recorder {
    violations: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.violations.lock().unwrap())
    }

    fn push(&self, violation: String) {
        self.violations.lock().unwrap().push(violation);
    }
}

/// Middleware checking every response of the app against the contract.
pub async fn record(State(recorder): State<Recorder>, request: Request, next: Next) -> Response {
    if mode() == Mode::Off {
        return next.run(request).await;
    }
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();

    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("buffer the response body");
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());

    if let Err(violation) =
        contract().check(&method, &path, parts.status.as_u16(), content_type, &bytes)
    {
        recorder.push(violation);
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Act on the violations of an app being dropped.
pub fn settle(recorder: &Recorder) {
    let violations = recorder.take();
    if violations.is_empty() {
        return;
    }
    match mode() {
        Mode::Strict if !std::thread::panicking() => panic!(
            "responses outside the OpenAPI contract (docs/dev/api/openapi.yaml):\n  {}",
            violations.join("\n  ")
        ),
        Mode::Report => {
            let dir = crate::workspace_path("target/contract-report");
            let _ = std::fs::create_dir_all(&dir);
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(format!("{}.txt", std::process::id())))
            {
                let test = std::thread::current()
                    .name()
                    .unwrap_or("unnamed test")
                    .to_owned();
                for violation in violations {
                    let _ = writeln!(file, "{test}\t{violation}");
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Contract {
        Contract::from_document(&json!({
            "paths": {
                "/items/{id}": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}
                            },
                            "204": {"description": "empty"}
                        }
                    }
                },
                "/items/special": {
                    "get": {"responses": {"418": {"description": "teapot"}}}
                }
            },
            "components": {
                "schemas": {
                    "Item": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {"id": {"type": "string", "format": "uuid"}}
                    }
                }
            }
        }))
    }

    const JSON: Option<&str> = Some("application/json");

    #[test]
    fn a_conforming_response_passes() {
        let body = br#"{"id":"6f1c1a3e-7d5b-4b8e-9a51-3e0b1f7f3c2a"}"#;
        assert_eq!(sample().check("GET", "/items/1", 200, JSON, body), Ok(()));
        assert_eq!(sample().check("GET", "/items/1", 204, None, b""), Ok(()));
    }

    #[test]
    fn undocumented_statuses_and_bodies_are_violations() {
        let contract = sample();
        assert!(contract.check("GET", "/items/1", 500, JSON, b"{}").is_err());
        assert!(
            contract
                .check("GET", "/items/1", 204, Some("text/plain"), b"x")
                .is_err()
        );
        assert!(
            contract
                .check("GET", "/items/1", 200, Some("text/plain"), b"{}")
                .is_err()
        );
    }

    #[test]
    fn schemas_are_enforced_through_references() {
        let contract = sample();
        assert!(contract.check("GET", "/items/1", 200, JSON, b"{}").is_err());
        assert!(
            contract
                .check("GET", "/items/1", 200, JSON, br#"{"id":"not-a-uuid"}"#)
                .is_err()
        );
    }

    #[test]
    fn literal_segments_win_and_unknown_paths_pass() {
        let contract = sample();
        assert_eq!(
            contract.template("GET", "/items/special"),
            Some("/items/special")
        );
        assert_eq!(contract.template("GET", "/items/42"), Some("/items/{id}"));
        assert_eq!(contract.check("GET", "/nowhere", 404, None, b""), Ok(()));
        assert_eq!(contract.check("POST", "/items/1", 405, None, b""), Ok(()));
    }

    #[test]
    fn the_service_document_builds_a_contract() {
        let contract = contract();
        assert_eq!(contract.template("GET", "/users/me"), Some("/users/me"));
        assert_eq!(
            contract.template("GET", "/oauth/device/ABCD-2345"),
            Some("/oauth/device/{user_code}")
        );
    }
}
