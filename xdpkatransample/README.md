# Katran like loadbalancer


This is a poor man's version of how katran works by encapsulating the packet into an IPIP tunnel
and leveraging direct server return.

This example uses the following layout provided by docker compose:

```none
              10.111.220.0                     10.111.222.0/24

┌──────────────────┐       ┌───────────────────┐        ┌───────────────────┐
│                  │       │                   │        │                   │
│                  │ ◄─────┼───────────────────┼────────┤                   │
│                  │       │                   │        │                   │
│    Client        ├──────►│  Gateway          │        │    Real           │
│                  │       │             ┌─────┼───────►│                   │
│                  │       │             │     │        │                   │
│                  │       │             │     │        │                   │
└──────────────────┘       └──────┬──────┴─────┘        └───────────────────┘
                                  │      ▲
                                  │      │
                                  │      │  10.111.221.0/24
                                  ▼      │
                            ┌────────────┴─────┐
                            │                  │
                            │                  │
                            │                  │
                            │     Katran       │
                            │                  │
                            │                  │
                            └──────────────────┘

```

The gateway container mimics a router. The `real` container mimics a katran endpoint, with an ipip interface
and the VIP associated to `lo`.

The `katran` container is instructed with the mac address of the `gateway` interface on the `10.111.221.0/24`
network, and whenever it receives a packet directed to the VIP it encapsulate it into a packet with `dst_mac=gateway mac`
and `dst_ip=real ip`.

## To setup

Build the binary and copy it under [./repro/setup]([./repro/setup]):

```bash
go generate && go build && mv xdplb repro/setup/xdplb
```

Under the [./repro](./repro/) folder, run `docker-compose up`.

Then, by doing `docker-compose exec client bash` and `docker-compose exec real bash` you will be able to open sessions against the
client and real container.

## Note

The `rp_filter` check must be disabled, by running `echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter`.
Once the setup is ready, `nc` can be used on both the client and the server (the client must use the `192.168.10.1` VIP).