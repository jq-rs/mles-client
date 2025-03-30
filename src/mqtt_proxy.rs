use futures_util::{SinkExt, StreamExt};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
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
use url::Url;

use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
struct ProxyError(String);

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for ProxyError {}

pub async fn run_mqtt_proxy(
    server: String,
    mqtt_server: String,
    channel: String,
    uid: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let messages_mles_to_mqtt = Arc::new(AtomicU64::new(0));
    let messages_mqtt_to_mles = Arc::new(AtomicU64::new(0));

    // Create clones for the stats task
    let messages_mles_to_mqtt_stats = Arc::clone(&messages_mles_to_mqtt);
    let messages_mqtt_to_mles_stats = Arc::clone(&messages_mqtt_to_mles);
    let server_stats = server.clone();

    // Connect to Mles server
    let mut request = server.clone().into_client_request()?;
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "mles-websocket".parse().unwrap());
    let (ws_stream, _) = connect_async(request).await?;
    let (write, mut read) = ws_stream.split();
    let write = Arc::new(Mutex::new(write));

    // Setup MQTT connection
    println!("Connecting to MQTT broker {}...", mqtt_server);
    let mqtt_url = Url::parse(&mqtt_server)?;
    let host = mqtt_url
        .host_str()
        .ok_or_else(|| ProxyError("No host in MQTT URL".to_string()))?;
    let port = mqtt_url.port().unwrap_or(1883);
    println!("Resolved MQTT broker address: {}:{}", host, port);

    let mut mqttoptions = MqttOptions::new("mles-mqtt-proxy", host, port);
    mqttoptions.set_keep_alive(Duration::from_secs(60));
    mqttoptions.set_clean_session(true);
    mqttoptions.set_max_packet_size(100 * 1024, 100 * 1024);
    mqttoptions.set_pending_throttle(Duration::from_millis(10));

    let (mqtt_client, mut eventloop) = AsyncClient::new(mqttoptions, 100);

    // Wait for connection acknowledgment before proceeding
    println!("Waiting for MQTT connection...");
    let mut connection_attempts = 0;
    const MAX_ATTEMPTS: u32 = 3;

    while connection_attempts < MAX_ATTEMPTS {
        match eventloop.poll().await {
            Ok(notification) => {
                if let Event::Incoming(Packet::ConnAck(_)) = notification {
                    println!("MQTT connection established");
                    break;
                }
            }
            Err(e) => {
                connection_attempts += 1;
                println!("Connection attempt {} failed: {:?}", connection_attempts, e);
                if connection_attempts < MAX_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                } else {
                    return Err(Box::new(ProxyError(
                        "Failed to establish MQTT connection".to_string(),
                    )));
                }
            }
        }
    }

    println!("Subscribing to MQTT topic '{}'", channel);
    match mqtt_client.subscribe(&channel, QoS::AtLeastOnce).await {
        Ok(_) => println!("Successfully subscribed to topic"),
        Err(e) => {
            println!("Failed to subscribe: {}", e);
            return Err(Box::new(ProxyError(format!(
                "MQTT subscription failed: {}",
                e
            ))));
        }
    }

    // Prepare authentication message
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

    write.lock().await.send(Message::Text(auth_message)).await?;

    let write_clone = Arc::clone(&write);
    println!(
        "MQTT proxy established between {} and {}",
        server, mqtt_server
    );

    // Start statistics display task
    let stats_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            // Clear the current line before printing
            print!("\r\x1B[K"); // \r moves to start of line, \x1B[K clears to end of line
            print!(
                "Proxy stats - Messages: {} to MQTT: {} | MQTT to {}: {}",
                server_stats,
                messages_mles_to_mqtt_stats.load(Ordering::Relaxed),
                server_stats,
                messages_mqtt_to_mles_stats.load(Ordering::Relaxed),
            );
            std::io::stdout().flush().unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let mqtt_client_clone = mqtt_client.clone();
    let messages_mles_to_mqtt_clone = Arc::clone(&messages_mles_to_mqtt);
    let channel_clone = channel.clone();
    let mles_to_mqtt = tokio::spawn(async move {
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Binary(data) = msg {
                mqtt_client_clone
                    .publish(&channel_clone, QoS::AtLeastOnce, false, data)
                    .await
                    .map_err(|e| ProxyError(e.to_string()))?;
                messages_mles_to_mqtt_clone.fetch_add(1, Ordering::Relaxed);
            }
        }
        println!("\nMles to MQTT forwarding ended");
        Ok::<(), ProxyError>(())
    });

    let write_clone2 = Arc::clone(&write_clone);
    let messages_mqtt_to_mles_clone = Arc::clone(&messages_mqtt_to_mles);
    let mqtt_to_mles = tokio::spawn(async move {
        let result: Result<(), ProxyError> = async {
            loop {
                match eventloop.poll().await {
                    Ok(notification) => {
                        match notification {
                            Event::Incoming(Packet::Publish(msg)) => {
                                let mut write = write_clone2.lock().await;
                                write
                                    .send(Message::Binary(msg.payload.to_vec()))
                                    .await
                                    .map_err(|e| ProxyError(e.to_string()))?;
                                messages_mqtt_to_mles_clone.fetch_add(1, Ordering::Relaxed);
                            }
                            Event::Incoming(Packet::Disconnect) => {
                                println!("\nMQTT broker disconnected, attempting reconnect...");
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                            evt => {
                                // Only log significant non-standard events
                                match evt {
                                    Event::Incoming(Packet::PingResp)
                                    | Event::Outgoing(rumqttc::Outgoing::PingReq)
                                    | Event::Outgoing(rumqttc::Outgoing::Subscribe(_))
                                    | Event::Outgoing(rumqttc::Outgoing::Publish(_))
                                    | Event::Outgoing(rumqttc::Outgoing::PubAck(_))
                                    | Event::Incoming(Packet::ConnAck(_))
                                    | Event::Incoming(Packet::SubAck(_))
                                    | Event::Incoming(Packet::PubAck(_)) => {}
                                    _ => println!("\nOther MQTT event: {:?}", evt),
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("\nMQTT poll error: {:?}, attempting reconnect...", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        .await;
        result
    });

    // Add a ping task to keep the connection alive
    let mqtt_client_ping = mqtt_client.clone();
    let ping_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if let Err(e) = mqtt_client_ping
                .publish("$SYS/ping", QoS::AtLeastOnce, false, vec![])
                .await
            {
                println!("\nPing failed: {:?}", e);
            }
        }
    });

    tokio::select! {
        result = mles_to_mqtt => {
            if let Err(e) = result {
                println!("\nMles to MQTT error: {:?}", e);
            } else {
                println!("\nMles to MQTT connection closed");
            }
        },
        result = mqtt_to_mles => {
            if let Err(e) = result {
                println!("\nMQTT to Mles error: {:?}", e);
            } else {
                println!("\nMQTT to Mles connection closed");
            }
        },
        _ = ping_task => println!("\nPing task ended"),
        _ = stats_task => println!("\nStats task ended"),
        _ = tokio::signal::ctrl_c() => println!("\nReceived Ctrl+C"),
    }

    Ok(())
}
