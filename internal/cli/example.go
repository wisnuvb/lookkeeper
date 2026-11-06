package cli

// ExampleConfig is written by `lockkeeper init`. It contains no credentials:
// every secret is a reference to an environment variable or a file.
const ExampleConfig = `# Lockkeeper configuration. See docs/SPEC.md for every option.
#
# Secrets are never written here. Each one is a reference:
#   { env: NAME }       read from an environment variable
#   { file: /path }     read from a file that only you can read (chmod 600)
#   { prompt: true }    ask on the terminal (interactive commands only)
version: 1

databases:
  # The name is yours to choose. A database has no fixed "source" or "target" role.
  rds-main:
    engine: postgres
    host: your-db.xxxxxxxx.eu-west-1.rds.amazonaws.com
    port: 5432
    database: postgres
    # Use a dedicated least-privilege role, not an admin account:
    #   CREATE ROLE lockkeeper LOGIN PASSWORD '...';
    #   GRANT pg_monitor TO lockkeeper;
    # Lockkeeper warns if the role is a superuser or can replicate.
    user: lockkeeper
    password: { env: LK_RDS_MAIN_PASSWORD }
    tls:
      mode: verify-full                      # the default; checks the server certificate and name
      ca_file: /etc/lockkeeper/rds-ca-bundle.pem   # the RDS CA bundle for your region
    read_only: true                          # sessions are always read-only
    # Optional, lets WAL thresholds be judged against disk size:
    # disk_total_gb: 500

monitor:
  interval: 30s
  retention: 14d
  # targets: [rds-main]                      # default: every database above
  # Dead-man switch: ping a URL while Lockkeeper is healthy, so an external
  # service (for example Healthchecks.io) alerts you if Lockkeeper itself stops.
  # heartbeat:
  #   url: { env: LK_HEARTBEAT_URL }
  #   interval: 1m

alerts:
  channels:
    telegram:
      bot_token: { env: LK_TELEGRAM_TOKEN }
      chat_id: "123456789"
    # slack:
    #   webhook_url: { env: LK_SLACK_WEBHOOK }
    # SMTP email. The server certificate is always verified (use ca_file for a
    # private CA). tls: starttls (port 587, default), tls (implicit, port 465)
    # or none (only for a local relay; refused for remote hosts unless you also
    # set allow_insecure: true, and credentials are never sent unencrypted).
    # email:
    #   host: smtp.example.com
    #   port: 587
    #   tls: starttls
    #   username: alerts@example.com
    #   password: { env: LK_SMTP_PASSWORD }
    #   from: Lockkeeper <alerts@example.com>
    #   to: [ops@example.com]
    #   # ca_file: /etc/lockkeeper/smtp-ca.pem
  # With no routes, every alert goes to every channel.
  # routes:
  #   - match: { severity: [critical] }
  #     to: [telegram]
  # Override a default threshold (sizes accept KiB, MiB, GiB):
  # rules:
  #   pg.slot.retained_wal_bytes:
  #     warning: 5GiB
  #     critical: 20GiB

store:
  path: ~/.local/state/lockkeeper/lockkeeper.db   # created with mode 600
`
