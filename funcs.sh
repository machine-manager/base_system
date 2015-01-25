#!/bin/bash

install-y() {
	DEBIAN_FRONTEND=noninteractive apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@"
}

upgrade-y() {
	DEBIAN_FRONTEND=noninteractive apt-get install --upgrade -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@"
}

dist-upgrade-y() {
	DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@"
}

autoremove-purge-y() {
	DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -q -y "$@"
}

remove-purge-y() {
	DEBIAN_FRONTEND=noninteractive apt-get remove --purge -q -y "$@" || echo "Could not remove package(s)"
}

aginir-y() {
	install-y --no-install-recommends "$@"
}

install-config() {
	cp -a "files/$1" "$1"
}
