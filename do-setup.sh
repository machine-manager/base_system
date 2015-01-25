#!/bin/bash

set -e
set -u

HUMAN_ADMIN_NEEDS="htop dstat tmux git tig wget nano mtr"

. funcs.sh

install-config /etc/timezone
dpkg-reconfigure --frontend noninteractive tzdata

apt-get update
# Upgrade apt and OpenSSL early in case there were security holes
upgrade-y apt libssl1.0.0

aginir-y git
aginir-y etckeeper

if grep -Fxq 'VCS="bzr"' /etc/etckeeper/etckeeper.conf; then
	sed -i -r 's,^VCS="bzr",#VCS="bzr",g' /etc/etckeeper/etckeeper.conf
	sed -i -r 's,^#VCS="git",VCS="git",g' /etc/etckeeper/etckeeper.conf
fi

etckeeper init || echo "Could not etckeeper init; maybe already initialized?"

# ntpdate can slightly mess up on the time on boot
remove-purge-y ntpdate

# remove other time managers in case they were installed
remove-purge-y ntpd
remove-purge-y adjtimex
remove-purge-y chrony

# resolvconf = put garbage in my /etc/resolv.conf
remove-purge-y resolvconf

chattr -i /etc/resolv.conf
install-config /etc/resolv.conf
# Prevent Ubuntu's networking scripts from overwriting it
chattr +i /etc/resolv.conf
etckeeper commit "Use Google DNS resolvers" || true

dist-upgrade-y
aginir-y openssh-server openntpd unattended-upgrades pollinate molly-guard psmisc zsh $HUMAN_ADMIN_NEEDS
autoremove-purge-y
apt-get clean

chsh -s /bin/zsh

install-config /etc/openntpd/ntpd.conf
etckeeper commit "Use more time servers" || true
service openntpd restart

if ! grep -Pxq 'AllowUsers .*' /etc/ssh/sshd_config; then
	echo "AllowUsers root" >> /etc/ssh/sshd_config
fi
if ! grep -Pxq 'MaxSessions .*' /etc/ssh/sshd_config; then
	echo "MaxSessions 60" >> /etc/ssh/sshd_config
fi
service ssh restart

install-config /etc/apt/apt.conf.d/20auto-upgrades

install-config /etc/zsh/zshrc-cont
if ! grep -Fxq 'source /etc/zsh/zshrc-cont' /etc/zsh/zshrc; then
	echo >> /etc/zsh/zshrc
	echo 'source /etc/zsh/zshrc-cont' >> /etc/zsh/zshrc
fi

echo
echo "If anything was upgraded (esp. the kernel), you should reboot now."
