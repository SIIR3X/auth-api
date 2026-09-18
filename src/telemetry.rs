//! OpenTelemetry traces, exported over OTLP/HTTP when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
//!
//! Every request runs in a span named after its route template, continuing the
//! caller's trace when it sends a W3C `traceparent`. The spans of the code it
//! reaches (the event relay, webhook deliveries) nest under it or start their
//! own trace. No identifier from the URL, header value or body is recorded.

use std::time::Duration;

use opentelemetry::{KeyValue, propagation::TextMapPropagator, trace::TracerProvider as _};
use opentelemetry_http::{Bytes, HeaderExtractor, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracerProvider},
};

use crate::config::TelemetryConfig;

/// The tracer provider, when exporting is configured. Keep it for the life of
/// the process and call [`SdkTracerProvider::shutdown`] before exiting, so the
/// last spans are flushed.
pub fn tracer_provider(config: &TelemetryConfig) -> anyhow::Result<Option<SdkTracerProvider>> {
    let Some(endpoint) = config.otlp_endpoint.as_deref() else {
        return Ok(None);
    };
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{endpoint}/v1/traces"))
        .with_timeout(Duration::from_secs(10))
        .with_http_client(TokioHttpClient {
            client: reqwest::Client::new(),
            runtime: tokio::runtime::Handle::current(),
        })
        .build()?;
    Ok(Some(
        SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                config.sample_ratio,
            ))))
            .with_resource(
                Resource::builder()
                    .with_service_name(config.service_name.clone())
                    .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
                    .build(),
            )
            .build(),
    ))
}

/// The `tracing` layer turning spans into OpenTelemetry spans.
pub fn layer<S>(
    provider: &SdkTracerProvider,
) -> tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    tracing_opentelemetry::layer().with_tracer(provider.tracer("auth-api"))
}

/// The span of an incoming request: named after its route template, child of
/// the caller's span when the request carries a `traceparent`.
pub fn request_span(
    method: &axum::http::Method,
    route: &str,
    headers: &axum::http::HeaderMap,
) -> tracing::Span {
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let span = tracing::info_span!(
        "request",
        otel.name = %format!("{method} {route}"),
        otel.kind = "server",
        http.request.method = %method,
        http.route = route,
        http.response.status_code = tracing::field::Empty,
    );
    let parent = TraceContextPropagator::new().extract(&HeaderExtractor(headers));
    // Without an OpenTelemetry layer there is nothing to attach the parent to.
    let _ = span.set_parent(parent);
    span
}

/// The batch exporter runs on its own thread, outside the Tokio runtime: each
/// export is spawned on the runtime and awaited from there.
#[derive(Debug)]
struct TokioHttpClient {
    client: reqwest::Client,
    runtime: tokio::runtime::Handle,
}

#[async_trait::async_trait]
impl HttpClient for TokioHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let client = self.client.clone();
        let (parts, body) = request.into_parts();
        let exported = self.runtime.spawn(async move {
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await?;
            let status = response.status();
            let headers = response.headers().clone();
            Ok::<_, reqwest::Error>((status, headers, response.bytes().await?))
        });
        let (status, headers, body) = exported.await??;
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::Request as HttpRequest, middleware, routing::get};
    use opentelemetry::trace::TraceId;
    use opentelemetry_sdk::trace::InMemorySpanExporter;
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[tokio::test]
    async fn a_request_span_continues_the_callers_trace_under_its_route_template() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(layer(&provider));
        let _guard = tracing::subscriber::set_default(subscriber);

        let app = Router::new()
            .route("/users/{id}", get(|| async { "ok" }))
            .layer(middleware::from_fn(crate::middleware::access_log::layer));
        let response = app
            .oneshot(
                HttpRequest::get("/users/0f8fad5b-d9cb-469f-a165-70867728950e")
                    .header(
                        "traceparent",
                        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|s| s.name == "GET /users/{id}")
            .unwrap_or_else(|| panic!("no request span in {spans:?}"));
        assert_eq!(
            span.span_context.trace_id(),
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
        );
        assert!(
            span.attributes
                .iter()
                .any(|kv| kv.key.as_str() == "http.response.status_code"
                    && kv.value.as_str() == "200")
        );
        assert!(
            !format!("{span:?}").contains("0f8fad5b"),
            "an identifier from the path reached the trace"
        );
    }

    #[test]
    fn no_endpoint_means_no_exporter() {
        let config = TelemetryConfig {
            otlp_endpoint: None,
            service_name: "auth-api".into(),
            sample_ratio: 1.0,
        };
        assert!(tracer_provider(&config).unwrap().is_none());
    }
}
