# Attacker container for Deception SOC lab demo (12 §infrastructure, 13 §demo).
# Targets ONLY lab decoys on the isolated decoy_net network.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    nmap \
    curl \
    jq \
    sshpass \
    python3 \
    unzip \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy attack script so image can run standalone if not volume-mounted
COPY scripts/attack.sh /scripts/attack.sh
RUN chmod +x /scripts/attack.sh

ENTRYPOINT ["/scripts/attack.sh"]
