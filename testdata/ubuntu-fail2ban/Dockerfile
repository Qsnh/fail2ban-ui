# An Ubuntu server with sshd, sudo and fail2ban, for end-to-end tests of
# RuleLens. Run it with NET_ADMIN so that fail2ban can ban with nftables:
#   docker build -t rulelens-ubuntu testdata/ubuntu-fail2ban
#   docker run -d --cap-add NET_ADMIN -p 2222:22 --name rulelens-ubuntu rulelens-ubuntu
#
# APT_MIRROR replaces Ubuntu's archive, e.g.
#   --build-arg APT_MIRROR=http://mirrors.aliyun.com
# UBUNTU picks the release: 24.04 has fail2ban 1.0.2 banning with nftables,
# 22.04 has 0.11.2 banning with iptables.
ARG UBUNTU=24.04
FROM ubuntu:${UBUNTU}
ARG APT_MIRROR=
RUN if [ -n "$APT_MIRROR" ]; then \
      for f in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do \
        if [ -f "$f" ]; then sed -i -E "s#http://(archive|ports|security).ubuntu.com#$APT_MIRROR#g" "$f"; fi; \
      done; \
    fi \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo fail2ban nftables iptables rsyslog \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /run/fail2ban \
 && sed -i '/imklog/s/^/#/' /etc/rsyslog.conf \
 && useradd -m -s /bin/bash ops \
 && echo 'ops:rulelens' | chpasswd \
 && usermod -aG sudo ops \
 && sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# The container has no journal: the jails read the logs rsyslog writes.
COPY jail.local /etc/fail2ban/jail.local
EXPOSE 22
CMD ["/bin/sh", "-c", "touch /var/log/auth.log /var/log/fail2ban.log && rsyslogd && fail2ban-client start && exec /usr/sbin/sshd -D"]
