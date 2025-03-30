use chrono::{DateTime, Local, Utc};
use clap::Parser;
use crossterm::{
    cursor, execute,
    style::{Color, SetBackgroundColor, SetForegroundColor},
    terminal::{Clear, ClearType, size},
};
use futures_util::{SinkExt, StreamExt};
use rand::seq::SliceRandom;
use rpassword::read_password;
use serde_json::json;
use siphasher::sip::SipHasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::hash::Hasher;
use std::io::{self, Write};
use std::process;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::{
    connect_async, tungstenite::client::IntoClientRequest, tungstenite::protocol::Message,
};

mod message;
mod mqtt_proxy;
mod proxy;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// WebSocket server URL
    #[arg(short, long, default_value = "wss://mles.io")]
    server: String,

    /// Channel name
    #[arg(short, long)]
    channel: Option<String>,

    /// User ID
    #[arg(short, long)]
    uid: Option<String>,

    /// Second server URL for proxy mode
    #[arg(long)]
    proxy_server: Option<String>,

    /// MQTT broker URL for MQTT proxy mode
    #[arg(long)]
    mqtt_broker: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(mqtt_broker) = args.mqtt_broker {
        // Get necessary information
        let uid = args.uid.unwrap_or_else(|| {
            print!("UID: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        let channel = args.channel.unwrap_or_else(|| {
            print!("Channel: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        // Run in MQTT proxy mode
        if let Err(e) = mqtt_proxy::run_mqtt_proxy(args.server, mqtt_broker, channel, uid).await {
            eprintln!("MQTT Proxy error: {}", e);
            process::exit(1);
        }
    } else if args.proxy_server.is_some() {
        let proxy_server = args.proxy_server.unwrap();
        // Get necessary information
        let uid = args.uid.unwrap_or_else(|| {
            print!("UID: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        let channel = args.channel.unwrap_or_else(|| {
            print!("Channel: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        // Run in proxy mode
        if let Err(e) = proxy::run_proxy(args.server, proxy_server, channel, uid).await {
            eprintln!("Proxy {}", e);
            process::exit(1);
        }
    } else {
        let seen_messages = Arc::new(Mutex::new(HashSet::new())); // Add this
        let seen_messages_clone = Arc::clone(&seen_messages);
        let url = args.server;
        let mut request = url.into_client_request().expect("Invalid request");
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", "mles-websocket".parse().unwrap());

        // Try to connect and exit on failure
        let (ws_stream, _) = connect_async(request).await.unwrap_or_else(|e| {
            eprintln!("Failed to connect: {}", e);
            process::exit(1);
        });
        let (write, mut read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write)); // Share write between tasks
        let write_clone = Arc::clone(&write);
        let messages = Arc::new(Mutex::new(Vec::new()));
        let messages_clone = Arc::clone(&messages);
        let user_colors = Arc::new(Mutex::new(HashMap::new()));

        // Ask for UID and Channel
        let mut uid = String::new();
        let mut channel = String::new();
        let mut stdout = io::stdout();

        if let Some(arg_uid) = args.uid {
            uid = arg_uid;
        } else {
            print!("UID: ");
            stdout.flush().unwrap();
            io::stdin().read_line(&mut uid).unwrap();
        }

        if let Some(arg_channel) = args.channel {
            channel = arg_channel;
        } else {
            print!("Channel: ");
            stdout.flush().unwrap();
            io::stdin().read_line(&mut channel).unwrap();
        }
        print!("Shared key: ");
        stdout.flush().unwrap();
        let key = read_password().unwrap();
        let uid = uid.trim().to_string();
        let channel = channel.trim().to_string();
        let encryption_key = message::derive_key(&key, &channel);

        let first_message = {
            let mut hasher = SipHasher::new();
            hasher.write(uid.as_bytes());
            hasher.write(channel.as_bytes());

            // If MLES_KEY exists, include it in the hash
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
        // Send first message
        {
            let mut write_guard = write.lock().await;
            write_guard
                .send(Message::Text(first_message))
                .await
                .unwrap();
        }

        // Create a channel to signal program termination
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        let shutdown_tx_clone = shutdown_tx.clone();

        // Spawn a task to receive messages
        let uid_clone = uid.clone();
        let channel_clone = channel.clone();
        let user_colors_clone = Arc::clone(&user_colors);
        let message_handler = tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                if let Message::Binary(data) = msg {
                    if let Some(decrypted) = message::decrypt_message(&encryption_key, &data) {
                        let mut seen = seen_messages_clone.lock().await;
                        if seen.insert(decrypted.clone()) {
                            let mut msgs = messages_clone.lock().await;
                            let mut colors = user_colors_clone.lock().await;
                            // Only process the message if we haven't seen it before

                            if let Ok(parsed) =
                                serde_json::from_str::<serde_json::Value>(&decrypted)
                            {
                                if let Some(join_uid) = parsed.get("uid").and_then(|v| v.as_str()) {
                                    if join_uid != uid_clone {
                                        assign_color(&mut colors, join_uid);
                                        msgs.push(format!("{} joined.", join_uid));
                                    }
                                }
                            } else {
                                let parts: Vec<&str> = decrypted.splitn(2, ' ').collect(); // Split first space to get timestamp
                                if parts.len() == 2 {
                                    let timestamp = parts[0];
                                    let rest = parts[1];

                                    // Split the rest at the first colon
                                    if let Some((sender, message)) = rest.split_once(':') {
                                        if sender != uid_clone {
                                            assign_color(&mut colors, sender);
                                            msgs.push(format!(
                                                "{} {}: {}",
                                                timestamp, sender, message
                                            ));
                                        } else {
                                            msgs.push(format!("{} {}", timestamp, message));
                                        }
                                    }
                                }
                            }
                            print_ui(&msgs, &colors, &uid_clone, &channel_clone);
                        }
                    }
                }
            }
            // Connection closed
            let _ = shutdown_tx.send(()).await;
        });

        // Input handling in a separate task
        let input_handler = tokio::spawn(async move {
            let mut input = String::new();

            loop {
                input.clear();
                {
                    let msgs = messages.lock().await;
                    let colors = user_colors.lock().await;
                    print_ui(&*msgs, &*colors, &uid, &channel); // Dereference the MutexGuards
                } // Guards are dropped here
                print!("\r> ");
                io::stdout().flush().unwrap();

                // Use tokio's stdin to make it cancellable
                let mut line = String::new();
                if let Ok(_) = tokio::io::AsyncBufReadExt::read_line(
                    &mut tokio::io::BufReader::new(tokio::io::stdin()),
                    &mut line,
                )
                .await
                {
                    let input = line.trim();
                    if !input.is_empty() {
                        let timestamp = get_timestamp();
                        let formatted_message = format!("{} {}:{}", timestamp, uid, input);
                        let mut msgs = messages.lock().await;
                        msgs.push(format!("{} {}", timestamp, input));
                        drop(msgs);

                        let mut write_guard = write.lock().await;
                        if let Err(e) = write_guard
                            .send(Message::Binary(message::encrypt_message(
                                &encryption_key,
                                &formatted_message,
                            )))
                            .await
                        {
                            eprintln!("\nFailed to send message: {}", e);
                            let _ = shutdown_tx_clone.send(()).await;
                            break;
                        }
                    }
                }
            }
        });

        // Wait for either task to finish
        tokio::select! {
            _ = shutdown_rx.recv() => {
            }
            _ = tokio::signal::ctrl_c() => {
                // Send close frame
                            let mut write_guard = write_clone.lock().await;
                            let _ = write_guard.send(Message::Close(Some(CloseFrame {
                                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                                reason: "Client shutdown".into(),
                            }))).await;
            }
        }
        // Abort the tasks before cleanup
        message_handler.abort();
        input_handler.abort();

        // Wait for tasks to finish
        let _ = tokio::join!(message_handler, input_handler);

        // Clean up and exit
        execute!(
            io::stdout(),
            Clear(ClearType::All),
            cursor::MoveTo(0, 0),
            SetBackgroundColor(Color::Reset),
            SetForegroundColor(Color::Reset)
        )
        .unwrap();

        process::exit(0);
    }
}

fn get_timestamp() -> String {
    let now = Utc::now();
    now.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn format_timestamp(timestamp_str: &str) -> String {
    // Parse ISO8601/RFC3339 UTC timestamp
    if let Ok(utc_time) = DateTime::parse_from_rfc3339(timestamp_str) {
        // Convert UTC to local time
        let local_time: DateTime<Local> = DateTime::from(utc_time);
        let today = Local::now().date_naive();

        if local_time.date_naive() == today {
            // If message is from today, only show local time
            local_time.format("%H:%M").to_string()
        } else {
            // If message is from another day, show local date and time
            local_time.format("%Y-%m-%d %H:%M").to_string()
        }
    } else {
        // If parsing fails, return original timestamp
        timestamp_str.to_string()
    }
}

fn assign_color(colors: &mut HashMap<String, Color>, uid: &str) {
    if !colors.contains_key(uid) {
        let color_choices = [
            Color::Blue,
            Color::Green,
            Color::Yellow,
            Color::Cyan,
            Color::Magenta,
            Color::Red,
            Color::White,
        ];
        let chosen_color = *color_choices.choose(&mut rand::thread_rng()).unwrap();
        colors.insert(uid.to_string(), chosen_color);
    }
}

fn print_ui(messages: &Vec<String>, colors: &HashMap<String, Color>, _uid: &str, _channel: &str) {
    let (_cols, rows) = size().unwrap_or((80, 24));
    let message_area = rows as usize - 2; // Reserve 2 lines for status and input

    execute!(
        io::stdout(),
        Clear(ClearType::All),
        cursor::MoveTo(0, 0),
        SetBackgroundColor(Color::Black),
        SetForegroundColor(Color::White)
    )
    .unwrap();

    // Print messages
    let start_index = if messages.len() > message_area {
        messages.len() - message_area
    } else {
        0
    };

    for msg in &messages[start_index..] {
        if let Some((timestamp_str, rest)) = msg.split_once(' ') {
            let timestamp = format_timestamp(timestamp_str);

            if rest.contains(':') {
                if let Some((sender, message)) = rest.split_once(':') {
                    let sender = sender.trim();
                    let message = message.trim();
                    // Only show username if it's not a system message and sender isn't empty
                    if !sender.is_empty() {
                        if let Some(color) = colors.get(sender) {
                            execute!(io::stdout(), SetForegroundColor(*color)).unwrap();
                            print!("{} {}: ", timestamp, sender);
                            execute!(io::stdout(), SetForegroundColor(Color::White)).unwrap();
                            println!("{}", message);
                        } else {
                            println!("{} {}: {}", timestamp, sender, message);
                        }
                    }
                }
            } else {
                // For your own messages and system messages
                println!("{} {}", timestamp, rest);
            }
        } else {
            println!("{}", msg);
        }
    }

    // Move cursor to input line
    execute!(io::stdout(), cursor::MoveTo(0, rows - 1)).unwrap();
    print!("\r> ");

    io::stdout().flush().unwrap();
}
