#!/bin/bash

install-y() {
	DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@"
}

upgrade-y() {
	DEBIAN_FRONTEND=noninteractive apt-get install --upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@"
}

dist-upgrade-y() {
	DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@"
}

autoremove-purge-y() {
	DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y "$@"
}

remove-purge-y() {
	DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "$@" || echo "Could not remove package(s)"
}

aginir-y() {
	install-y --no-install-recommends "$@"
}

install-config() {
	cp -a "files/$1" "$1"
	# Needed in case the system has a restrictive umask that makes
	# files unreadable by other by default
	chmod a+r "$1"
}

clone-or-pull() {
	local url=$1
	local dir=$2
	if [ -e "$dir" ]; then
		cd "$dir"
		git pull
	else
		git clone "$url" "$dir"
	fi
}
