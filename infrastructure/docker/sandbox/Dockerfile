FROM alpine:latest

RUN apk add --no-cache bash nano curl coreutils openssh-server sudo util-linux procps socat iproute2

# Configure sshd
RUN ssh-keygen -A &&     sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config &&     sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config &&     echo "Port 22222" >> /etc/ssh/sshd_config &&     echo "ClientAliveInterval 30" >> /etc/ssh/sshd_config

# Create deploy user
RUN adduser -D -s /bin/bash deploy &&     echo "deploy:HalSummer2023!" | chpasswd &&     echo "root:HalSummer2023!" | chpasswd &&     echo "deploy ALL=(ALL) ALL" >> /etc/sudoers

# Create hostname & environment
RUN echo "hal-app-01" > /etc/hostname &&     echo "export PS1='deploy@hal-app-01:\w\$ '" >> /home/deploy/.bashrc &&     mkdir -p /home/deploy/.aws /opt/deploy /home/deploy/.ssh

# Plant honeyfiles
RUN echo -e "[default]\naws_access_key_id = AKIA3EXNNKIAOP2SNCD5\naws_secret_access_key = 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\nregion = ap-south-1" > /home/deploy/.aws/credentials &&     echo -e "Host: hal-app-01\nUser: deploy\nAuth: deploy_id_ed25519\nNote: Automated migration sync key. Do not share outside deployment engineering." > /home/deploy/notes.txt &&     echo -e "ls -la\ncd /opt/deploy\ncurl -s http://s3.harborline-logistics.internal:8088/t/15ede59d03ec5dbf -o status.json\nexit" > /home/deploy/.bash_history &&     echo -e "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: prod-cluster\ncontexts:\n- context:\n    cluster: prod-cluster\n    user: deploy-sa\n  name: prod\ncurrent-context: prod\nkind: Config\nusers:\n- name: deploy-sa\n  user:\n    token: neaUPVW4RYGJViL9C8iUHxNtr8HULVBeiJKsY0Eg9Lq9GhMv" > /opt/deploy/kubeconfig &&     chown -R deploy:deploy /home/deploy /opt/deploy &&     chmod 600 /home/deploy/.aws/credentials /opt/deploy/kubeconfig

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22222

ENTRYPOINT ["/entrypoint.sh"]
