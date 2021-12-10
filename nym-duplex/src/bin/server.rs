use futures::sink::SinkExt;
use futures::stream::StreamExt;
use nym_duplex::socks::SocksRequest;
use nym_duplex::transport::{ConnectionId, Packet, Payload};
use nym_sphinx::anonymous_replies::ReplySurb;
use nym_websocket::responses::ServerResponse;
use std::collections::BTreeMap;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::MissedTickBehavior;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::EnvFilter;

#[derive(StructOpt)]
struct Options {
    #[structopt(
        short,
        long,
        default_value = "ws://127.0.0.1:1977",
        help = "Nym native client websocket address"
    )]
    websocket: String,
}

#[tokio::main]
async fn main() {
    // Start logging service (specify log level using RUST_LOG env, default=info)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Read command line arguments
    let options: Options = Options::from_args();

    // Connect to Nym native client
    debug!("Connecting to websocket at {}", &options.websocket);
    let (mut ws, _) = connect_async(&options.websocket)
        .await
        .expect("Couldn't connect to nym websocket");

    debug!("Requesting own identity from nym client");
    ws.send(build_identity_request())
        .await
        .expect("failed to send identity request");

    // Prepare communication channels between the main task and client connection tasks
    let (outgoing_sender, mut outgoing_receiver) =
        tokio::sync::mpsc::channel::<(Packet, ReplySurb)>(4);
    let mut connections = BTreeMap::<ConnectionId, Sender<(Packet, ReplySurb)>>::new();

    loop {
        // Process events from the Nym connection and the client connections
        select! {
            ws_packet_res = ws.next() => {
                // Receive Nym packets from the websocket, decode them and forward to the
                // appropriate client connection task. Other than the client we also need to extract
                // and forward the SURBs sent with the packet.
                let ws_packet = ws_packet_res.and_then(Result::ok).expect("Web socket stream died");
                let nym_bytes = match ws_packet {
                    Message::Binary(bin) => bin,
                    _ => {
                        warn!("Received non-binary packet from websocket");
                        continue;
                    },
                };

                let (bytes, surb) = match ServerResponse::deserialize(&nym_bytes) {
                    Ok(ServerResponse::Received(msg)) => {
                        let surb = match msg.reply_surb {
                            Some(surb) => surb,
                            None => {
                                warn!("Packet did not contain SURB, ignoring");
                                continue;
                            }
                        };

                        (msg.message, surb)
                    },
                    Ok(ServerResponse::SelfAddress(address)) => {
                        info!("Our nym address: {}", address);
                        continue;
                    }
                    _ => {
                        warn!("Received unexpected packet from websocket");
                        continue;
                    }
                };

                let packet: Packet = match bincode::deserialize(&bytes) {
                    Ok(packet) => packet,
                    Err(_) => {
                        warn!("Received malformed packet from websocket");
                        continue;
                    }
                };

                // If we receive a new establish packet we spawn a task for the client connection
                if let Payload::Establish(req) = &packet.payload {
                    if connections.get(&packet.stream).is_none() {
                        info!("Connection {:?} started, connecting to {:?}", packet.stream, req);
                        let (incoming_sender, incoming_receiver) = tokio::sync::mpsc::channel::<(Packet, ReplySurb)>(4);
                        connections.insert(packet.stream, incoming_sender);
                        tokio::spawn(handle_connection(
                            packet.stream,
                            req.clone(),
                            outgoing_sender.clone(),
                            incoming_receiver
                        ));
                    }
                }

                // Find the appropriate channel to the client task and forward the packet
                let stream = packet.stream;
                let stream_sender = match connections.get_mut(&stream) {
                    Some(stream_sender) => stream_sender,
                    None => {
                        warn!("Received packet for unknown stream {:?}", stream);
                        continue;
                    }
                };
                if stream_sender.send((packet, surb)).await.is_err() {
                    connections.remove(&stream);
                }
            }
            outgoing_res = outgoing_receiver.recv() => {
                // Receive packets from client connection tasks, encode them and send them via Nym
                let (packet, reply_surb) = outgoing_res.expect("Outgoing channel closed, this should not happen!");

                let nym_packet = nym_websocket::requests::ClientRequest::Reply {
                    message: bincode::serialize(&packet).expect("serialization can't fail"),
                    reply_surb
                };

                ws.send(Message::Binary(nym_packet.serialize()))
                    .await
                    .expect("couldn't send websocket packet");
            }
        }
    }
}

fn build_identity_request() -> Message {
    let nym_message = nym_websocket::requests::ClientRequest::SelfAddress;
    Message::Binary(nym_message.serialize())
}

async fn handle_connection(
    connection_id: ConnectionId,
    target: SocksRequest,
    outgoing_sender: Sender<(Packet, ReplySurb)>,
    mut incoming_receiver: Receiver<(Packet, ReplySurb)>,
) {
    // Resolve the target hostname. Unfortunately connect does not do this anymore.
    let dst = match target {
        SocksRequest::Fqdn { fqdn, port } => {
            match tokio::net::lookup_host((fqdn.clone(), port))
                .await
                .map(|mut iter| iter.next())
            {
                Ok(Some(host)) => host,
                Ok(None) => {
                    warn!("DNS lookup for {}:{} didn't return a result", fqdn, port);
                    return;
                }
                Err(e) => {
                    warn!("DNS lookup for {}:{} failed: {}", fqdn, port, e);
                    return;
                }
            }
        }
        SocksRequest::Ip(dst) => dst,
    };

    // Connect to the destination requested by the client
    let mut socket = match TcpStream::connect(dst).await {
        Ok(socket) => socket,
        Err(e) => {
            warn!("Outgoing connection to {} failed: {}", dst, e);
            return;
        }
    };

    // Initialize reliable transport with SURBs
    let mut last_sent_idx = 0;
    let mut last_received_idx = 0;
    let mut last_sent_unack: Option<Packet> = None;
    let mut next_surb: Option<ReplySurb> = None;
    let mut resend_timer = tokio::time::interval(tokio::time::Duration::from_secs(1));
    resend_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // The buffer used to receive data from the socket. Its size defines the maximum data size sent
    // in one packet. Thus it should be tuned such that its size plus the other overhead from the
    // packet struct are equal to the maximum data size in one nym SURB reply since these can not be
    // fragmented and larger payloads would lead to errors.
    // TODO: tune to right size
    let mut buffer = [0u8; 500];
    loop {
        select! {
            _ = resend_timer.tick(), if next_surb.is_some() && last_sent_unack.is_some() => {
                // If we have a packet that didn't receive an ACK yet we resend it (if we have a
                // SURB for that).
                let unack = last_sent_unack.as_ref().unwrap();
                trace!("Resending message {}", unack.get_idx().unwrap());
                outgoing_sender.send((unack.clone(), next_surb.take().unwrap()))
                    .await
                    .expect("Outgoing channel failed");
            }
            incoming_res = incoming_receiver.recv() => {
                let (packet, surb): (Packet, ReplySurb) = incoming_res.expect("Incoming stream died");

                // If the received ACK is for our last-sent message we can forget it
                if last_sent_unack.as_ref().map(|unack| unack.get_idx().unwrap() == packet.ack).unwrap_or(false) {
                    last_sent_unack = None;
                }

                match packet.payload {
                    Payload::Data { idx, data } => {
                        // If we received the expected data packet we write the data to our
                        // socket. Otherwise it is dropped since it wouldn't fit into the data
                        // stream.
                        let expected_idx = last_received_idx + 1;
                        if idx == expected_idx {
                            if socket.write_all(&data).await.is_err() {
                                warn!("Connection closed");
                                return;
                            }
                            last_received_idx = idx;
                        } else {
                            warn!("Received unexpected message {}, expected {}", idx, expected_idx);
                        }
                    },
                    // Establish is handled by the main thread, SURB messages don't need further
                    // handling
                    Payload::Establish { .. } | Payload::SURB => {}
                }

                // If we did not use the last SURB burn it on a useless SURB message back to the
                // client. This is meant to avoid incoming traffic fingerprinting that might be
                // possible if the server accumulated a lot of SURBs and sent them in a burst.
                // If this mitigation is enough against this kind of problem is an open research
                // question, caveat emptor.
                if let Some(old_surb) = next_surb.replace(surb) {
                    outgoing_sender.send((
                        Packet {
                            stream: connection_id,
                            ack: last_received_idx,
                            payload: Payload::SURB,
                        },
                        old_surb
                    ))
                    .await
                    .expect("Outgoing channel died");
                }
            }
            read_res = socket.read(&mut buffer), if last_sent_unack.is_none() && next_surb.is_some() => {
                // Read from our socket if we are ready to send a new packet. For that we need to
                // have a SURB available and the last packet has to have been ACKed.
                let read = match read_res {
                    Ok(read) => read,
                    Err(_) => {
                        warn!("Connection closed");
                        return;
                    }
                };

                // If we read 0 bytes, ignore
                if read == 0 {
                    continue;
                }

                let packet = Packet {
                    stream: connection_id,
                    ack: last_received_idx,
                    payload: Payload::Data {
                        idx: last_sent_idx + 1,
                        data: buffer[0..read].to_vec()
                    }
                };
                last_sent_idx += 1;

                outgoing_sender.send((packet.clone(), next_surb.take().unwrap()))
                    .await
                    .expect("Outgoing channel died");

                last_sent_unack = Some(packet)
            }
        }
    }
}
