use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use serde::Deserialize;
use sha2::Sha256;
use std::process::Command;
use warp::hyper::body::Bytes;
use warp::{Filter, Rejection, Reply};

lazy_static! {
    ///  GitHub webhook secret
    static ref SECRET: String = std::env::var("GITHUB_HOOK_SECRET").expect("SECRET must be set");
    static ref PORT:u16 = std::env::var("HOOK_PORT").unwrap_or("33275".to_string()).parse().unwrap();
}
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct GitHubEvent {
    #[serde(rename = "ref")]
    r#ref: String,
    repository: Repository,
}
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Repository {
    clone_url: String,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    dotenv::dotenv().ok();
    let webhook_route = warp::path("webhook")
        .and(warp::post())
        .and(warp::header::<String>("X-Hub-Singature-256"))
        .and(warp::body::bytes())
        .and_then(handle_webhook);
    let ping_route = warp::path("ping").and(warp::get()).and_then(handle_ping);

    println!("🚀 Server running on port {}", *PORT);

    warp::serve(webhook_route.or(ping_route))
        .run(([0, 0, 0, 0], *PORT))
        .await;
}

async fn handle_webhook(singature: String, body: Bytes) -> Result<impl Reply, Rejection> {
    if !verify_signature(&SECRET, &body, &singature) {
        return Ok(warp::reply::with_status(
            "Invaild signature".to_string(),
            warp::http::StatusCode::UNAUTHORIZED,
        ));
    }

    let event: GitHubEvent = match serde_json::from_slice(&body) {
        Ok(event) => event,
        Err(_why) => {
            return Ok(warp::reply::with_status(
                "Invaild Json:".to_string(),
                warp::http::StatusCode::BAD_REQUEST,
            ));
        }
    };

    if !event.r#ref.ends_with("/master") {
        return Ok(warp::reply::with_status(
            "Ignoring non-master branch".to_string(),
            warp::http::StatusCode::OK,
        ));
    };

    // run
    tokio::spawn(async {
        if let Err(why) = deploy().await {
            eprintln!("Deployment failed :{:?}", why);
        }
    });

    Ok(warp::reply::with_status(
        "Deployment started".to_string(),
        warp::http::StatusCode::OK,
    ))
}
async fn handle_ping() -> Result<impl Reply, Rejection> {
    Ok(warp::reply::with_status(
        "Pong".to_string(),
        warp::http::StatusCode::OK,
    ))
}
fn verify_signature(secret: &str, body: &[u8], signature: &str) -> bool {
    let signature = signature.trim_start_matches("sha256=");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC initalization failed");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    hex::encode(result) == signature
}

async fn deploy() -> Result<(), Box<dyn std::error::Error>> {
    // 更新目标目录的代码
    run_command("git", &["pull"], "/home/ubuntu/discord_hub_bot")?;
    // 开始构建
    run_command("docker-compose", &["build"], "/home/ubuntu/discord_hub_bot")?;
    // 重启容器
    run_command(
        "docker-compose",
        &["up", "-d"],
        "/home/ubuntu/discord_hub_bot",
    )?;
    println!("✅ Deployment successful");
    Ok(())
}

fn run_command(cmd: &str, args: &[&str], cwd: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(cmd).args(args).current_dir(cwd).output()?;

    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed: {}", msg).into());
    }
    Ok(())
}
