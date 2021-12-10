use futures::sink::SinkExt;
use futures::stream::StreamExt;
use nym_addressing::clients::Recipient;
use nym_duplex::socks::receive_request;
use nym_duplex::transport::{ConnectionId, Packet, Payload};
use nym_websocket::responses::ServerResponse;
use rand::Rng;
use std::collections::BTreeMap;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, trace, warn};
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
    #[structopt(
        long,
        parse(try_from_str = Recipient::try_from_base58_string),
        help = "Exit node address",
    )]
    service_provider: Recipient,
    #[structopt(
        long,
        default_value = "127.0.0.1:1080",
        help = "Address the socks server should listen on"
    )]
    socks_bind_addr: String,
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
    let opts: Options = StructOpt::from_args();

    // Connect to Nym native client
    let (mut ws, _) = connect_async(&opts.websocket)
        .await
        .expect("Couldn't connect to nym websocket");

    // Listen for incoming SOCKS connections
    let listener = TcpListener::bind(&opts.socks_bind_addr).await.unwrap();

    // Prepare communication channels between the main task and SOCKS connection tasks
    let (outgoing_sender, mut outgoing_receiver) = tokio::sync::mpsc::channel::<Packet>(4);
    let mut connections = BTreeMap::<ConnectionId, Sender<Packet>>::new();

    loop {
        // Process events from the Nym connection, SOCKS connections and the listening socket
        select! {
            connection_res = listener.accept() => {
                // Accept new connection and start a task to handle it
                let (socket, _) = connection_res.expect("Listener died");

                let connection_id: ConnectionId = rand::thread_rng().gen();
                let (incoming_sender, incoming_receiver) = tokio::sync::mpsc::channel::<Packet>(4);
                connections.insert(connection_id, incoming_sender);
                tokio::spawn(handle_connection(socket, connection_id, outgoing_sender.clone(), incoming_receiver));
            },
            ws_packet_res = ws.next() => {
                // Receive Nym packets from the websocket, decode them and forward to the
                // appropriate SOCKS connection task
                let ws_packet = ws_packet_res.and_then(Result::ok).expect("Web socket stream died");
                let nym_bytes = match ws_packet {
                    Message::Binary(bin) => bin,
                    _ => {
                        warn!("Received non-binary packet from websocket");
                        continue;
                    },
                };

                let bytes = match ServerResponse::deserialize(&nym_bytes) {
                    Ok(ServerResponse::Received(msg)) => msg.message,
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

                // Look up channel of the SOCKS connection task the packet is destined for
                let stream = packet.stream;
                let stream_sender = match connections.get_mut(&stream) {
                    Some(stream_sender) => stream_sender,
                    None => {
                        warn!("Received packet for unknown stream {:?}", stream);
                        continue;
                    }
                };
                if stream_sender.send(packet).await.is_err() {
                    connections.remove(&stream);
                }
            }
            outgoing_res = outgoing_receiver.recv() => {
                // Receive outgoing packets, encode them and send them over Nym
                let outgoing = outgoing_res.expect("Outgoing channel closed, this should not happen!");
                let nym_packet = nym_websocket::requests::ClientRequest::Send {
                    recipient: opts.service_provider,
                    message: bincode::serialize(&outgoing).expect("serialization can't fail"),
                    with_reply_surb: true,
                };

                ws.send(Message::Binary(nym_packet.serialize()))
                    .await
                    .expect("couldn't send websocket packet");
            }
        }
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    connection_id: ConnectionId,
    outgoing_sender: Sender<Packet>,
    mut incoming_receiver: Receiver<Packet>,
) {
    // Receive the sock "header" that specifies where to open a connection to
    let socks_reqest = match receive_request(&mut socket).await {
        Ok(request) => request,
        Err(e) => {
            error!("Socks connection error: {:?}", e);
            return;
        }
    };

    info!("Received request for {:?}", socks_reqest);
    // Initialize reliable transport
    let mut last_received_idx = 0;
    let mut last_sent_idx = 0;
    let mut resend_timer = tokio::time::interval(tokio::time::Duration::from_secs(1));

    // Since the resend timer will tick as soon as it is polled the first time we can save the
    // establish message as the last message for which we did not receive an ACK. It will be sent as
    // soon as we enter the event loop.
    //
    // The Establish message type tells the server where to open a connection to and initializes
    // the connection between client and server.
    let mut last_sent_unack = Some(Packet {
        stream: connection_id,
        ack: last_received_idx,
        payload: Payload::Establish(socks_reqest),
    });

    // The buffer used to receive data from the socket. Its size defines the maximum data size sent
    // in one packet. Thus it should be tuned such that its size plus the other overhead from the
    // packet struct are equal to the maximum data size in one nym packet to avoid fragmentation.
    // TODO: tune to right size
    let mut buffer = [0u8; 500];
    loop {
        select! {
            _ = resend_timer.tick() => {
                if let Some(last_sent_unack) = &last_sent_unack {
                    // If we have a packet that didn't receive an ACK yet we resend it, maybe it
                    // went missing in the mixnet.
                    trace!("Resending message {}", last_sent_unack.get_idx().unwrap());
                    outgoing_sender.send(last_sent_unack.clone())
                        .await
                        .expect("Outgoing channel failed");
                } else {
                    // If there is nothing to send we still want to give the server a new SURB in
                    // case too many of its replies got dropped and it ran out. The SURB message
                    // type, like any other, also transports ACKs for received packets but carries
                    // no other useful data.
                    trace!("Sending SURB");
                    let packet = Packet {
                        stream: connection_id,
                        ack: last_received_idx,
                        payload: Payload::SURB,
                    };
                    outgoing_sender.send(packet)
                        .await
                        .expect("Outgoing channel failed");
                }
            }
            incoming_res = incoming_receiver.recv() => {
                // Handle incoming packets from the server
                let incoming = incoming_res.expect("Incoming channel died, this should not happen.");

                // If the received ACK is for our last-sent message we can forget it, no need to
                // resend it anymore.
                if last_sent_unack.as_ref().map(|unack| unack.get_idx().unwrap() == incoming.ack).unwrap_or(false) {
                    last_sent_unack = None;
                }

                match incoming.payload {
                    Payload::Establish {..} => {
                        error!("We received an establish from the exit node, closing the connection.");
                        return;
                    },
                    Payload::Data { idx, data } => {
                        // If we received the expected data packet we write the data to our SOCKS
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

                        // We also send a SURB packet to ACK the received packet asap
                        let packet = Packet {
                            stream: connection_id,
                            ack: last_received_idx,
                            payload: Payload::SURB,
                        };
                        outgoing_sender.send(packet)
                            .await
                            .expect("Outgoing channel failed");
                    },
                    Payload::SURB => {
                        // If the server has too many SURBs it needs to safely dispose of them. So
                        // it just sends them back. See the server for a more in-depth explanation.
                        trace!("Ignoring empty SURB answer");
                    }
                }
            }
            read_res = socket.read(&mut buffer), if last_sent_unack.is_none() => {
                // If we are ready to send (aka all our previous packets were ACKed) we try to read
                // from the SOCKS socket.
                let read = match read_res {
                    Ok(read) => read,
                    Err(e) => {
                        error!("Socks connection error: {:?}", e);
                        return;
                    }
                };

                // We read 0 bytes, ignore
                if read == 0 {
                    continue;
                }

                // Send the read data to the server
                last_sent_idx += 1;
                let packet = Packet {
                    stream: connection_id,
                    ack: last_received_idx,
                    payload: Payload::Data {
                        idx: last_sent_idx,
                        data: buffer[0..read].to_vec()
                    },
                };
                outgoing_sender.send(packet.clone())
                    .await
                    .expect("Outgoing channel failed");
                last_sent_unack = Some(packet);
            }
        }
    }
}
