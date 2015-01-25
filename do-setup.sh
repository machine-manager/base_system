#!/bin/bash

set -e
set -u

HUMAN_ADMIN_NEEDS="htop dstat tmux git tig wget nano mtr"

. funcs.sh

### UTC timezone

install-config /etc/timezone
dpkg-reconfigure --frontend noninteractive tzdata

### update package listings and apt

apt-get update
# Upgrade apt and OpenSSL early in case there were security holes
upgrade-y apt libssl1.0.0

### etckeeper

aginir-y git
aginir-y etckeeper

if grep -Fxq 'VCS="bzr"' /etc/etckeeper/etckeeper.conf; then
	sed -i -r 's,^VCS="bzr",#VCS="bzr",g' /etc/etckeeper/etckeeper.conf
	sed -i -r 's,^#VCS="git",VCS="git",g' /etc/etckeeper/etckeeper.conf
fi

etckeeper init || echo "Could not etckeeper init; maybe already initialized?"

### non-ntp time managers

# ntpdate can slightly mess up on the time on boot
remove-purge-y ntpdate

# remove other time managers in case they were installed
remove-purge-y ntpd
remove-purge-y adjtimex
remove-purge-y chrony

### /etc/resolv.conf

# resolvconf = put garbage in my /etc/resolv.conf
remove-purge-y resolvconf

chattr -i /etc/resolv.conf
install-config /etc/resolv.conf
# Prevent Ubuntu's networking scripts from overwriting it
chattr +i /etc/resolv.conf
etckeeper commit "Use Google DNS resolvers" || true

### upgrade and install packages

dist-upgrade-y
aginir-y openssh-server openntpd unattended-upgrades pollinate molly-guard psmisc zsh $HUMAN_ADMIN_NEEDS
autoremove-purge-y
apt-get clean

### zsh

chsh -s /bin/zsh

install-config /etc/zsh/zshrc-cont
if ! grep -Fxq 'source /etc/zsh/zshrc-cont' /etc/zsh/zshrc; then
	echo >> /etc/zsh/zshrc
	echo 'source /etc/zsh/zshrc-cont' >> /etc/zsh/zshrc
fi
# Create empty ~/.zshrc to prevent zsh from prompting on first run
if [ ! -f ~/.zshrc ]; then
	touch ~/.zshrc
fi

# Set up zsh for first Ubuntu user as well
FIRST_USER="$(cat /etc/passwd | grep -P "^[^:]+:x:1000:1000:" | cut -f 1 -d ":")"
if [ -n "$FIRST_USER" ]; then
	chsh -s /bin/zsh "$FIRST_USER"
	su "$FIRST_USER" -c "if [ ! -f ~/.zshrc ]; then touch ~/.zshrc; fi"
fi

### ntpd

install-config /etc/openntpd/ntpd.conf
etckeeper commit "Use more time servers" || true
service openntpd restart

### ssh

if ! grep -Pxq 'AllowUsers .*' /etc/ssh/sshd_config; then
	echo "AllowUsers root" >> /etc/ssh/sshd_config
fi
if ! grep -Pxq 'MaxSessions .*' /etc/ssh/sshd_config; then
	echo "MaxSessions 60" >> /etc/ssh/sshd_config
fi
service ssh restart

### automatic security updates

install-config /etc/apt/apt.conf.d/20auto-upgrades

###

echo
echo "If anything was upgraded (esp. the kernel), you should reboot now."
