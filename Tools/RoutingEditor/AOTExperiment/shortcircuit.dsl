on same:tcp.syn {
    if port.server == 443 && ip.server_address in prefix("10.0.0.0/8") {
        ip.dscp = 16;
    } else {
        if port.server == 443 && ip.server_address in prefix("192.0.2.0/24") {
            drop();
        }
    }
}
