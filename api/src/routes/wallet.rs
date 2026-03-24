use axum::{routing::post, Json, Router};
use serde::Deserialize;

use crate::error::ApiError;
use crate::preflight::{preflight_scan, ScanReport, ScanTarget, UtxoInput};

pub fn router() -> Router {
    Router::new().route("/scan", post(scan_post))
}

#[derive(Debug, Deserialize)]
struct ScanRequestBody {
    #[serde(default)]
    descriptor: Option<String>,
    #[serde(default)]
    descriptors: Option<Vec<String>>,
    #[serde(default)]
    utxos: Option<Vec<UtxoInput>>,
}

async fn scan_post(Json(body): Json<ScanRequestBody>) -> Result<Json<ScanReport>, ApiError> {
    run_scan(body.into_scan_target()?)
}

fn run_scan(target: ScanTarget) -> Result<Json<ScanReport>, ApiError> {
    preflight_scan(target).map(Json).map_err(ApiError::from)
}

impl ScanRequestBody {
    fn into_scan_target(self) -> Result<ScanTarget, ApiError> {
        let mut selected_sources = 0usize;
        if self.descriptor.is_some() {
            selected_sources += 1;
        }
        if self.descriptors.is_some() {
            selected_sources += 1;
        }
        if self.utxos.is_some() {
            selected_sources += 1;
        }

        if selected_sources == 0 {
            return Err(ApiError::bad_request(
                "one input source is required: descriptor, descriptors, or utxos",
            ));
        }
        if selected_sources > 1 {
            return Err(ApiError::bad_request(
                "descriptor, descriptors, and utxos are mutually exclusive",
            ));
        }

        if let Some(descriptor) = self.descriptor {
            return Ok(ScanTarget::Descriptor(descriptor));
        }
        if let Some(descriptors) = self.descriptors {
            return Ok(ScanTarget::Descriptors(descriptors));
        }
        if let Some(utxos) = self.utxos {
            return Ok(ScanTarget::Utxos(utxos));
        }

        Err(ApiError::bad_request("invalid scan request body"))
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use crate::app;

    #[tokio::test]
    async fn get_scan_is_not_allowed() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn post_scan_with_descriptor_list_returns_report() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "descriptors": [
                                "wpkh(xpub.../0/*)",
                                "wpkh(xpub.../1/*)"
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["stats"]["addresses_derived"], 2);
    }

    #[tokio::test]
    async fn post_scan_with_utxos_returns_report() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "utxos": [
                                {
                                    "txid": "9f8adf8adf8adf8adf8adf8adf8adf8adf8adf8adf8adf8adf8adf8adf8adf8a",
                                    "vout": 1,
                                    "value_sats": 25000
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["stats"]["utxos_current"], 1);
    }

    #[tokio::test]
    async fn post_scan_with_single_descriptor_returns_report() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "descriptor": "wpkh(xpub.../0/*)"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["stats"]["addresses_derived"], 1);
    }

    #[tokio::test]
    async fn post_scan_requires_one_input_source() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn post_scan_rejects_multiple_sources() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "descriptor": "wpkh(xpub.../0/*)",
                            "utxos": [
                                {
                                    "txid": "txid",
                                    "vout": 0
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
