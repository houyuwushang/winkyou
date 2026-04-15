# coturn Deployment for WinkYou

This directory contains the default coturn TURN relay deployment for WinkYou.

## Why coturn?

coturn is the production-grade TURN relay server used by WinkYou's default deployment path. It's battle-tested, widely deployed, and handles NAT traversal reliably in real-world scenarios.

The embedded `wink-relay` binary remains in the repository for development and testing, but **coturn is the recommended relay for production deployments**.

## Quick Start

### Prerequisites

- Linux server with public IP
- Docker and docker-compose installed
- Firewall rules configured (see below)

### Firewall Configuration

**Critical**: Open these ports on your server:

```bash
# TURN signaling
sudo ufw allow 3478/udp

# Relay data ports (MUST be open for relay to work)
sudo ufw allow 49152:65535/udp
```

Without the relay port range open, clients will see `ConnectionType: relay` but WireGuard handshake will fail.

### Deployment Steps

1. **Edit `turnserver.conf`**

   Replace `<EXTERNAL_IP>` with your server's public IP:

   ```bash
   sed -i 's/<EXTERNAL_IP>/203.0.113.10/g' turnserver.conf
   ```

2. **Start coturn**

   ```bash
   docker-compose up -d
   ```

3. **Verify it's running**

   ```bash
   docker-compose logs -f coturn
   ```

   You should see:
   ```
   0: : Listener address to use: 0.0.0.0:3478
   0: : Relay address to use: 203.0.113.10
   ```

4. **Update client configs**

   In your `wink` client config (e.g., `deploy/quickstart/windows-client.yaml`):

   ```yaml
   nat:
     turn_servers:
       - url: "turn:203.0.113.10:3478"
         username: "winkdemo"
         password: "winkdemo-pass"
   ```

## Configuration

### Change Credentials

Edit `turnserver.conf`:

```
user=myuser:mypassword
```

Then restart:

```bash
docker-compose restart
```

### Change Port Range

Edit `turnserver.conf`:

```
min-port=50000
max-port=60000
```

Update firewall rules accordingly, then restart.

## Troubleshooting

### Relay selected but no handshake

**Symptom**: `wink peers` shows `Conn Type: relay` but `Last Handshake: never`

**Diagnosis**:
1. Check if relay port range is open:
   ```bash
   sudo ufw status | grep 49152:65535
   ```

2. Check coturn logs:
   ```bash
   docker-compose logs coturn | grep -i allocation
   ```

3. Verify external-ip is correct:
   ```bash
   grep external-ip turnserver.conf
   ```

**Fix**: Ensure UDP ports 49152-65535 are open in your firewall.

### Connection refused on 3478

**Symptom**: Client can't reach TURN server

**Fix**:
```bash
sudo ufw allow 3478/udp
docker-compose restart
```

### Logs show "Cannot allocate relay endpoint"

**Symptom**: coturn can't bind relay ports

**Fix**: Check if another process is using the port range:
```bash
sudo netstat -tulpn | grep -E '(49152|65535)'
```

## Production Hardening

For production deployments:

1. **Change default credentials** in `turnserver.conf`
2. **Enable TLS** (add cert/key paths)
3. **Set up log rotation** for `/var/log/coturn/turnserver.log`
4. **Monitor allocation count** via coturn admin interface
5. **Consider rate limiting** via `max-bps` and `bps-capacity`

## Switching from wink-relay

If you were using the embedded `wink-relay`:

1. Stop `wink-relay`
2. Deploy coturn using this directory
3. Update client configs to point to coturn
4. Restart clients

No code changes needed - both use the standard TURN protocol.
