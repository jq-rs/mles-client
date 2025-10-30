use crate::dupdet::{MessageTracker, hash_binary_message};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use siphasher::sip::SipHasher;
use std::env;
use std::hash::Hasher;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    connect_async, tungstenite::client::IntoClientRequest, tungstenite::protocol::Message,
};

pub async fn run_proxy(
    server1: String,
    server2: String,
    channel: String,
    uid: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Add counters for messages and message tracker
    let messages_s1_to_s2 = Arc::new(AtomicU64::new(0));
    let messages_s2_to_s1 = Arc::new(AtomicU64::new(0));
    let message_tracker = Arc::new(Mutex::new(MessageTracker::new()));

    // Connect to first server
    let mut request1 = server1.clone().into_client_request()?;
    request1
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "mles-websocket".parse().unwrap());
    let (ws_stream1, _) = connect_async(request1).await?;
    let (write1, mut read1) = ws_stream1.split();
    let write1 = Arc::new(Mutex::new(write1));

    // Connect to second server
    let mut request2 = server2.clone().into_client_request()?;
    request2
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "mles-websocket".parse().unwrap());
    let (ws_stream2, _) = connect_async(request2).await?;
    let (write2, mut read2) = ws_stream2.split();
    let write2 = Arc::new(Mutex::new(write2));

    // Prepare authentication messages
    let auth_message = {
        let mut hasher = SipHasher::new();
        hasher.write(uid.as_bytes());
        hasher.write(channel.as_bytes());
        if let Ok(mles_key) = env::var("MLES_KEY") {
            hasher.write(mles_key.as_bytes());
        }
        let hash = hasher.finish();
        json!({
            "uid": uid,
            "channel": channel,
            "auth": format!("{:016x}", hash)
        })
        .to_string()
    };

    // Send auth messages to both servers
    write1
        .lock()
        .await
        .send(Message::Text(auth_message.clone().into()))
        .await?;
    write2
        .lock()
        .await
        .send(Message::Text(auth_message.into()))
        .await?;

    let write1_clone = Arc::clone(&write1);
    let write2_clone = Arc::clone(&write2);

    println!("Proxy established between {} and {}", server1, server2);

    let messages_s1_to_s2_clone = Arc::clone(&messages_s1_to_s2);
    let message_tracker_clone1 = Arc::clone(&message_tracker);
    // Forward messages from server1 to server2
    let task1 = tokio::spawn(async move {
        while let Some(Ok(msg)) = read1.next().await {
            if let Message::Binary(data) = msg {
                let msg_hash = hash_binary_message(&data);
                let mut tracker = message_tracker_clone1.lock().await;
                if !tracker.is_duplicate(msg_hash) {
                    let mut write2 = write2_clone.lock().await;
                    messages_s1_to_s2_clone.fetch_add(1, Ordering::Relaxed);
                    let _ = write2.send(Message::Binary(data)).await;
                }
            }
        }
    });

    let messages_s2_to_s1_clone = Arc::clone(&messages_s2_to_s1);
    let message_tracker_clone2 = Arc::clone(&message_tracker);
    // Forward messages from server2 to server1
    let task2 = tokio::spawn(async move {
        while let Some(Ok(msg)) = read2.next().await {
            if let Message::Binary(data) = msg {
                let msg_hash = hash_binary_message(&data);
                let mut tracker = message_tracker_clone2.lock().await;
                if !tracker.is_duplicate(msg_hash) {
                    let mut write1 = write1_clone.lock().await;
                    messages_s2_to_s1_clone.fetch_add(1, Ordering::Relaxed);
                    let _ = write1.send(Message::Binary(data)).await;
                }
            }
        }
    });

    // Start statistics display task
    let stats_task = tokio::spawn(async move {
        loop {
            print!(
                "\rProxy stats - Messages: {} → {}: {} | {} → {}: {}",
                server1,
                server2,
                messages_s1_to_s2.load(Ordering::Relaxed),
                server2,
                server1,
                messages_s2_to_s1.load(Ordering::Relaxed),
            );
            std::io::stdout().flush().unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Wait for either task to complete or Ctrl+C
    tokio::select! {
        _ = task1 => println!("Connection to server1 closed"),
        _ = task2 => println!("Connection to server2 closed"),
        _ = stats_task => println!("\nStats task ended"),
        _ = tokio::signal::ctrl_c() => println!("Received Ctrl+C"),
    }

    Ok(())
}
