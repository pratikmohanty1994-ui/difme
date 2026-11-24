//! difme-notary: env NOTARY_NAME (default "notary"); the key: NOTARY_KBS_URL (attested key release, the cluster way:
//! NOTARY_TEE_SVN, first start NOTARY_BOOTSTRAP_OPENBAO + NOTARY_BOOTSTRAP_ROLE/JWT) or NOTARY_KEY_FILE (32-byte seed,
//! base64 or hex: local runs and tests only),
//! NOTARY_LOG (append-only JSON-lines file; optional), NOTARY_ADDR (default 0.0.0.0:8080), NOTARY_INDEX (default 65536).

use difme_notary::{Notary, read_seed, router};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let seed = match std::env::var("NOTARY_KBS_URL") {
        Ok(kbs) if !kbs.is_empty() => {
            let openbao = std::env::var("NOTARY_BOOTSTRAP_OPENBAO").ok().filter(|v| !v.is_empty());
            let (svn, role, jwt) = (env("NOTARY_TEE_SVN", "1"), env("NOTARY_BOOTSTRAP_ROLE", "notary-bootstrap"),
                env("NOTARY_BOOTSTRAP_JWT", "/var/run/secrets/openbao/token"));
            tokio::task::spawn_blocking(move || difme_notary::keyrelease::notary_seed(&kbs, &svn, openbao.as_deref(), &role, &jwt))
                .await.expect("key release task").expect("attested key release")
        }
        _ => {
            let key_file = std::env::var("NOTARY_KEY_FILE").expect("NOTARY_KBS_URL (cluster) or NOTARY_KEY_FILE (local) is required");
            eprintln!("notary: seed from NOTARY_KEY_FILE (local runs only; clusters use attested key release)");
            read_seed(&std::fs::read_to_string(&key_file).expect("cannot read NOTARY_KEY_FILE")).expect("bad seed")
        }
    };
    let log = match std::env::var("NOTARY_LOG") {
        Ok(p) if !p.is_empty() => Some(
            tokio::fs::OpenOptions::new().create(true).append(true).open(&p).await.expect("cannot open NOTARY_LOG"),
        ),
        _ => None,
    };
    let cap = env("NOTARY_INDEX", "65536").parse().unwrap_or(65_536);
    let n = Notary::new(env("NOTARY_NAME", "notary"), seed, cap, log);
    let addr = env("NOTARY_ADDR", "0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("notary {} listening on {addr}", env("NOTARY_NAME", "notary"));
    axum::serve(listener, router(n))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("serve");
}
