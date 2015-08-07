#!/bin/bash

set -e
set -u

HUMAN_ADMIN_NEEDS="htop dstat tmux git tig wget nano mtr nethogs iftop lsof software-properties-common rsync"

. funcs.sh

### UTC timezone

install-config /etc/timezone
dpkg-reconfigure --frontend noninteractive tzdata

### locales

# Needed because some servers (e.g. Ubuntu 14.04 OVH Classic VPS)
# come with a broken locale setup

locale-gen en_US.UTF-8
dpkg-reconfigure locales

### update package listings and apt

apt-get update
# Upgrade apt and OpenSSL early in case there were security holes
upgrade-y apt libssl1.0.0

### etckeeper

aginir-y git

git config --global user.email "root@$HOSTNAME"
git config --global user.name "root"

aginir-y etckeeper

if grep -Fxq 'VCS="bzr"' /etc/etckeeper/etckeeper.conf; then
	sed -i -r 's,^VCS="bzr",#VCS="bzr",g' /etc/etckeeper/etckeeper.conf
	sed -i -r 's,^#VCS="git",VCS="git",g' /etc/etckeeper/etckeeper.conf
fi

etckeeper init || echo "Could not etckeeper init; maybe already initialized?"

### don't get stuck on grub screen forever if last boot failed
### (e.g. power outage during boot process)

if [ -f /etc/default/grub ]; then
	if ! grep -Pxq 'GRUB_RECORDFAIL_TIMEOUT=.*' /etc/default/grub; then
		sed -i -r 's,^GRUB_TIMEOUT=(.*),GRUB_TIMEOUT=\1\nGRUB_RECORDFAIL_TIMEOUT=\1,g' /etc/default/grub
	fi

	# Disable quiet and splash for easier debugging of early boot problems
	# Enable noautogroup to make 'nice' actually work
	if grep -Pxq 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"' /etc/default/grub; then
		sed -i -r 's,GRUB_CMDLINE_LINUX_DEFAULT="quiet splash",GRUB_CMDLINE_LINUX_DEFAULT="noautogroup",g' /etc/default/grub
	fi

	update-grub
fi

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

chattr -i /etc/resolv.conf || rm -f /etc/resolv.conf
install-config /etc/resolv.conf
# Prevent Ubuntu's networking scripts from overwriting it
chattr +i /etc/resolv.conf || true
etckeeper commit "Use Google DNS resolvers" || true

### disable sudo credential caching ###

install-config /etc/sudoers.d/no_cred_caching
etckeeper commit "Don't let sudo cache credentials" || true

### upgrade and install packages

# TODO: no openntpd if in OpenVZ environment (check for /proc/user_beancounters)

dist-upgrade-y
aginir-y openssh-server openntpd unattended-upgrades pollinate molly-guard psmisc acl zsh $HUMAN_ADMIN_NEEDS
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

# Set zsh as default shell for new users
sed -i -r 's,^DSHELL=/bin/bash$,DSHELL=/bin/zsh,g' /etc/adduser.conf
if [ ! -f /etc/skel/.zshrc ]; then
	touch /etc/skel/.zshrc
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

### utilities

mkdir -p /opt

cd /root && clone-or-pull https://github.com/ludios/anonssh-git anonssh-git
cd /opt && clone-or-pull /root/anonssh-git anonssh-git && chmod -R a+rX /opt/anonssh-git

PATH="$PATH:/opt/anonssh-git"

install-anonssh-config
alias git=anonssh-git

# Now that we have anonssh-git set up, we can switch to the non-https://
# origin for conformatter and anonssh-git
cd /root/conformatter && git remote set-url origin git@github.com:ludios/conformatter.git
cd /root/anonssh-git && git remote set-url origin git@github.com:ludios/anonssh-git.git

cd /root && clone-or-pull https://github.com/ludios/ubuntils ubuntils
cd /opt && clone-or-pull /root/ubuntils ubuntils && chmod -R a+rX /opt/ubuntils

cd /root && clone-or-pull https://github.com/ludios/quickmunge quickmunge
cd /opt && clone-or-pull /root/quickmunge quickmunge && chmod -R a+rX /opt/quickmunge

if ! grep -Fxq 'alias git=anonssh-git' /etc/zsh/zshrc-cont; then
	echo 'PATH="$PATH:/opt/anonssh-git:/opt/ubuntils/bin:/opt/quickmunge/bin"' >> /etc/zsh/zshrc-cont
	echo "alias git=anonssh-git" >> /etc/zsh/zshrc-cont
fi

if ! grep -Fxq 'alias r=tmux-resume' /etc/zsh/zshrc-cont; then
	echo "alias r=tmux-resume" >> /etc/zsh/zshrc-cont
fi

if [ -n "$FIRST_USER" ]; then
	su "$FIRST_USER" -c /opt/anonssh-git/install-anonssh-config
fi

###

echo
echo "If anything was upgraded (esp. the kernel), you should reboot now."
