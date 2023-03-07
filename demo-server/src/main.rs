use axum::{routing::get, Json, Router};
use josekit::jwk::{
    alg::{ec::EcCurve, ec::EcKeyPair, ed::EdKeyPair, rsa::RsaKeyPair},
    Jwk,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use jwt_authorizer::{error::InitError, AuthError, JwtAuthorizer, JwtClaims, Refresh, RefreshStrategy};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{net::SocketAddr, thread, time::Duration};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Object representing claims
/// (a subset of deserialized claims)
#[derive(Debug, Deserialize, Clone)]
struct User {
    sub: String,
}

const SERVER_URI: &str = "http://localhost:3000";

#[tokio::main]
async fn main() -> Result<(), InitError> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,jwt_authorizer=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // claims checker function
    fn claim_checker(u: &User) -> bool {
        info!("checking claims: {} -> {}", u.sub, u.sub.contains('@'));

        u.sub.contains('@') // must be an email
    }

    let iodc_router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/tokens", get(tokens));

    let mut app_router = Router::new()
        // public endpoint
        .route("/public", get(public_handler))
        .nest("/", iodc_router);

    // starting oidc provider (discovery is needed by from_oidc())

    // First let's create an authorizer builder from a Oidc Discovery
    // User is a struct deserializable from JWT claims representing the authorized user
    // let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc("https://accounts.google.com/")
    let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::from_jwks_url("http://localhost:3000/jwks")
        // .no_refresh()
        .refresh(Refresh {
            strategy: RefreshStrategy::Interval,
            ..Default::default()
        })
        .check(claim_checker);

    // actual router demo
    let auth_router = Router::new()
        .route("/protected", get(protected))
        .layer(jwt_auth.layer().await?);

    // protected APIs
    app_router = app_router.nest("/api", auth_router).layer(TraceLayer::new_for_http());

    // start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr).serve(app_router.into_make_service()).await.unwrap();

    Ok(())
}

/// handler with injected claims object
async fn protected(JwtClaims(user): JwtClaims<User>) -> Result<String, AuthError> {
    // Send the protected data to the user
    Ok(format!("Welcome: {}", user.sub))
}

// public url handler
async fn public_handler() -> &'static str {
    "Public URL!"
}

/// OpenId Connect discovery (simplified for test purposes)
#[derive(Serialize, Clone)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// discovery url handler
async fn discovery() -> Json<Value> {
    let d = OidcDiscovery {
        issuer: SERVER_URI.to_owned(),
        jwks_uri: format!("{SERVER_URI}/jwks"),
    };
    Json(json!(d))
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// jwk set endpoint handler
async fn jwks() -> Json<Value> {
    let mut kset = JwkSet { keys: Vec::<Jwk>::new() };

    let keypair = RsaKeyPair::from_pem(include_bytes!("../../config/rsa-private1.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("rsa01");
    pk.set_algorithm("RS256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = RsaKeyPair::from_pem(include_bytes!("../../config/rsa-private2.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("rsa02");
    pk.set_algorithm("RS256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EcKeyPair::from_pem(include_bytes!("../../config/ecdsa-private1.pem"), Some(EcCurve::P256)).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ec01");
    pk.set_algorithm("ES256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EcKeyPair::from_pem(include_bytes!("../../config/ecdsa-private2.pem"), Some(EcCurve::P256)).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ec02");
    pk.set_algorithm("ES256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EdKeyPair::from_pem(include_bytes!("../../config/ed25519-private1.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ed01");
    pk.set_algorithm("EdDSA");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EdKeyPair::from_pem(include_bytes!("../../config/ed25519-private2.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ed02");
    pk.set_algorithm("EdDSA");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    Json(json!(kset))
}

/// build a minimal JWT header
fn build_header(alg: Algorithm, kid: &str) -> Header {
    Header {
        typ: Some("JWT".to_string()),
        alg,
        kid: Some(kid.to_owned()),
        cty: None,
        jku: None,
        jwk: None,
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    }
}

/// token claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: &'static str,
    sub: &'static str,
    aud: &'static str,
    exp: usize,
    nbf: usize,
}

/// handler issuing test tokens (this is not a standard endpoint)
pub async fn tokens() -> Json<Value> {
    let claims = Claims {
        iss: SERVER_URI,
        sub: "b@b.com",
        aud: "aud1",
        exp: 2000000000, // May 2033
        nbf: 1516239022, // Jan 2018
    };

    let rsa1_key = EncodingKey::from_rsa_pem(include_bytes!("../../config/rsa-private1.pem")).unwrap();
    let rsa2_key = EncodingKey::from_rsa_pem(include_bytes!("../../config/rsa-private2.pem")).unwrap();
    let ec1_key = EncodingKey::from_ec_pem(include_bytes!("../../config/ecdsa-private1.pem")).unwrap();
    let ec2_key = EncodingKey::from_ec_pem(include_bytes!("../../config/ecdsa-private2.pem")).unwrap();
    let ed1_key = EncodingKey::from_ed_pem(include_bytes!("../../config/ed25519-private1.pem")).unwrap();
    let ed2_key = EncodingKey::from_ed_pem(include_bytes!("../../config/ed25519-private2.pem")).unwrap();

    let rsa1_token = encode(&build_header(Algorithm::RS256, "rsa01"), &claims, &rsa1_key).unwrap();
    let rsa2_token = encode(&build_header(Algorithm::RS256, "rsa02"), &claims, &rsa2_key).unwrap();
    let ec1_token = encode(&build_header(Algorithm::ES256, "ec01"), &claims, &ec1_key).unwrap();
    let ec2_token = encode(&build_header(Algorithm::ES256, "ec02"), &claims, &ec2_key).unwrap();
    let ed1_token = encode(&build_header(Algorithm::EdDSA, "ed01"), &claims, &ed1_key).unwrap();
    let ed2_token = encode(&build_header(Algorithm::EdDSA, "ed02"), &claims, &ed2_key).unwrap();

    Json(json!({
        "rsa01": rsa1_token,
        "rsa02": rsa2_token,
        "ec01": ec1_token,
        "ec02": ec2_token,
        "ed01": ed1_token,
        "ed02": ed2_token,
    }))
}
