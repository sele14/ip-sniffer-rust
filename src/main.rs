/*
Based on: https://www.youtube.com/watch?v=-Jp7sabBCp4&list=PLJbE2Yu2zumDD5vy2BuSHvFZU0a6RDmgb&index=1

Usage:
ip_sniffer.exe -h // help flag
ip_sniffer.exe -j <ip-adr> // num of threads to use
ip_sniffer.exe <ip-adr> // scan this IP
*/
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::{env, net::IpAddr, net::TcpStream, process, thread};
const MAX: u16 = 65535;
use std::io::{self, Write};

struct Arguments {
    flag: String,
    ipaddr: IpAddr,
    threads: u16,
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments");
        } else if args.len() > 4 {
            return Err("too many arguments");
        } else {
            // proceed if args OK
            let f = args[1].clone();
            if let Ok(ipaddr) = IpAddr::from_str(&f) {
                return Ok(Arguments {
                    flag: String::from(""),
                    ipaddr,
                    threads: 4,
                });
            // handle if receive more flags
            } else {
                let flag = args[1].clone();
                if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                    println!(
                        "Usage: -j to select how many threads you want 
                            \r\n -h or help to show this help message"
                    );
                    return Err("help");
                } else if flag.contains("-h") || flag.contains("-help") {
                    return Err("too many arguments");
                } else if flag.contains("-j") {
                    let ipaddr = match IpAddr::from_str(&args[3]) {
                        Ok(s) => s,
                        Err(_) => return Err("not a valid IPADDR; must be IPv4 or IPv6"),
                    };
                    let threads = match args[2].parse::<u16>() {
                        Ok(s) => s,
                        Err(_) => return Err("Failed to parse thread number"),
                    };
                    return Ok(Arguments {
                        threads,
                        flag,
                        ipaddr,
                    });
                } else {
                    return Err("invalid syntax");
                }
            }
        }
    }
}

fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16) {
    /*
    # Arguments
    * `tx` - sender
    * `start_port` - a number from 0 to thread number
    * `addr` - ip address
    * `num_threads` - number of threads we are currently using in our program
    */
    let mut port: u16 = start_port + 1;
    loop {
        match TcpStream::connect((addr, port)) {
            Ok(_) => {
                print!(".");
                // sends print statement
                io::stdout().flush().unwrap();
                // send the open port number
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if (MAX - port) <= num_threads {
            break;
        }
        port += num_threads;
    }
}

fn main() {
    // store arguments passed to the program
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let arguments = Arguments::new(&args).unwrap_or_else(|err| {
        if err.contains("help") {
            process::exit(0);
        } else {
            eprintln!("{} problem missing arguments: {}", program, err);
            process::exit(0);
        }
    });
    let num_threads = arguments.threads;
    let (tx, rx) = channel();
    for i in 0..num_threads {
        let tx = tx.clone();
        // spawn thread
        thread::spawn(move || {
            scan(tx, i, arguments.ipaddr, num_threads);
        });
    }
    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p);
    }

    println!("");
    out.sort();

    for v in out {
        println!("{} is open", v);
    }
}
