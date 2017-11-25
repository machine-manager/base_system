alias Converge.{
	All,
	BeforeMeet,
	Context,
	DanglingPackagesPurged,
	DirectoryEmpty,
	DirectoryPresent,
	EtcCommitted,
	EtcSystemdUnitFiles,
	Fallback,
	FileMissing,
	FilePresent,
	Fstab,
	FstabEntry,
	GPGKeybox,
	GPGSimpleKeyring,
	Grub,
	MetaPackageInstalled,
	NoPackagesNewerThanInSource,
	NoPackagesUnavailableInSource,
	PackagePurged,
	PackageRoots,
	RedoAfterMeet,
	RegularUsersPresent,
	Runner,
	SymlinkPresent,
	Sysctl,
	Sysfs,
	SystemdUnitDisabled,
	SystemdUnitEnabled,
	SystemdUnitStarted,
	SystemdUnitStopped,
	TerminalReporter,
	Unit,
	UnitError,
	User,
	UserPresent,
	Util
}
alias Gears.TableFormatter

defmodule BaseSystem.Configure do
	# Keep in sync with the units above; this list is queried to determine which
	# packages need to be installed before converging the giant All unit below.
	@unit_modules [
		All,
		BeforeMeet,
		DanglingPackagesPurged,
		DirectoryEmpty,
		DirectoryPresent,
		EtcCommitted,
		EtcSystemdUnitFiles,
		Fallback,
		FileMissing,
		FilePresent,
		Fstab,
		GPGKeybox,
		GPGSimpleKeyring,
		Grub,
		MetaPackageInstalled,
		NoPackagesNewerThanInSource,
		NoPackagesUnavailableInSource,
		PackagePurged,
		PackageRoots,
		RedoAfterMeet,
		RegularUsersPresent,
		SymlinkPresent,
		Sysctl,
		Sysfs,
		SystemdUnitDisabled,
		SystemdUnitEnabled,
		SystemdUnitStarted,
		SystemdUnitStopped,
		UserPresent,
	]

	require Util
	import Util, only: [content: 1, path_expand_content: 1, conf_file: 1, conf_file: 3, conf_dir: 1, conf_dir: 2, marker: 1]
	Util.declare_external_resources("files")

	@allowed_descriptor_keys MapSet.new([
		:desired_packages,
		:desired_early_packages,
		:undesired_packages,
		:apt_pins,
		:apt_keys,
		:apt_sources,
		:etc_systemd_unit_files,
		:sysctl_parameters,
		:sysfs_variables,
		:boot_time_kernel_modules,
		:regular_users,
		:ssh_allow_users,
		:hosts,
		:pre_install_unit,
		:post_install_unit,
		:implied_roles,
		:ferm_input_chain,
		:ferm_output_chain,
		:ferm_forward_chain,
		:ferm_postrouting_chain,
		:udev_rules,
		:security_limits,
	])

	@spec configure_with_roles([String.t], [module]) :: nil
	def configure_with_roles(tags, role_modules) do
		if tags == [] do
			raise("Refusing to configure with 0 tags because this is probably a mistake; pass a dummy tag if not")
		end

		role_modules                 = get_all_role_modules(tags, role_modules |> MapSet.new)
		role_modules_and_descriptors = role_modules |> Enum.map(fn mod -> {mod, apply(mod, :role, [tags])} end)
		descriptors                  = for {module, desc} <- role_modules_and_descriptors do
			descriptor_keys  = desc |> Map.keys |> MapSet.new
			unsupported_keys = MapSet.difference(descriptor_keys, @allowed_descriptor_keys)
			if MapSet.size(unsupported_keys) > 0 do
				raise("Descriptor for #{inspect module} has unsupported keys #{inspect(unsupported_keys |> MapSet.to_list)}")
			end
			desc
		end
		configure(
			tags,
			extra_desired_packages:         descriptors |> Enum.flat_map(fn desc -> desc[:desired_packages]         || [] end),
			extra_desired_early_packages:   descriptors |> Enum.flat_map(fn desc -> desc[:desired_early_packages]   || [] end),
			extra_undesired_packages:       descriptors |> Enum.flat_map(fn desc -> desc[:undesired_packages]       || [] end),
			extra_apt_pins:                 descriptors |> Enum.flat_map(fn desc -> desc[:apt_pins]                 || [] end),
			extra_apt_keys:                 descriptors |> Enum.flat_map(fn desc -> desc[:apt_keys]                 || [] end),
			extra_apt_sources:              descriptors |> Enum.flat_map(fn desc -> desc[:apt_sources]              || [] end),
			extra_etc_systemd_unit_files:   descriptors |> Enum.flat_map(fn desc -> desc[:etc_systemd_unit_files]   || [] end),
			extra_regular_users:            descriptors |> Enum.flat_map(fn desc -> desc[:regular_users]            || [] end),
			extra_ssh_allow_users:          descriptors |> Enum.flat_map(fn desc -> desc[:ssh_allow_users]          || [] end),
			extra_hosts:                    descriptors |> Enum.flat_map(fn desc -> desc[:hosts]                    || [] end),
			extra_boot_time_kernel_modules: descriptors |> Enum.flat_map(fn desc -> desc[:boot_time_kernel_modules] || [] end),
			extra_udev_rules:               descriptors |> Enum.flat_map(fn desc -> desc[:udev_rules]               || [] end),
			extra_security_limits:          descriptors |> Enum.flat_map(fn desc -> desc[:security_limits]          || [] end),
			extra_pre_install_units:        descriptors |> Enum.map(fn desc -> desc[:pre_install_unit] end)         |> Enum.reject(&is_nil/1),
			extra_post_install_units:       descriptors |> Enum.map(fn desc -> desc[:post_install_unit] end)        |> Enum.reject(&is_nil/1),
			extra_ferm_input_chain:         descriptors |> Enum.map(fn desc -> desc[:ferm_input_chain] end)         |> Enum.reject(&is_nil/1),
			extra_ferm_output_chain:        descriptors |> Enum.map(fn desc -> desc[:ferm_output_chain] end)        |> Enum.reject(&is_nil/1),
			extra_ferm_forward_chain:       descriptors |> Enum.map(fn desc -> desc[:ferm_forward_chain] end)       |> Enum.reject(&is_nil/1),
			extra_ferm_postrouting_chain:   descriptors |> Enum.map(fn desc -> desc[:ferm_postrouting_chain] end)   |> Enum.reject(&is_nil/1),
			extra_sysctl_parameters:        descriptors |> Enum.map(fn desc -> desc[:sysctl_parameters] || %{} end) |> Enum.reduce(%{}, fn(m, acc) -> Map.merge(acc, m) end),
			extra_sysfs_variables:          descriptors |> Enum.map(fn desc -> desc[:sysfs_variables]   || %{} end) |> Enum.reduce(%{}, fn(m, acc) -> Map.merge(acc, m) end)
		)
	end

	defp get_all_role_modules(tags, role_modules) do
		descriptors  = role_modules |> Enum.map(fn mod -> apply(mod, :role, [tags]) end)
		more_modules = descriptors |> Enum.flat_map(fn desc -> desc[:implied_roles] || [] end) |> MapSet.new
		# If we already know about every module we just discovered, we're done;
		# otherwise, recurse with our new list of modules.
		case MapSet.difference(more_modules, role_modules) |> MapSet.size do
			0 -> role_modules
			_ -> get_all_role_modules(tags, MapSet.union(role_modules, more_modules))
		end
	end

	@non_root_username System.get_env()["USER"]

	defmacro check_non_root_username(username) do
		if username == "root" do
			raise(RuntimeError, ~s(USER environmental variable was "root", cannot determine name of non-root user to create))
		end
		if username == nil do
			raise(RuntimeError, "No USER environmental variable, cannot determine name of non-root user to create")
		end
	end

	def configure(tags, opts) do
		extra_desired_packages         = opts[:extra_desired_packages]         || []
		extra_desired_early_packages   = opts[:extra_desired_early_packages]   || []
		extra_undesired_packages       = opts[:extra_undesired_packages]       || []
		extra_apt_pins                 = opts[:extra_apt_pins]                 || []
		extra_apt_keys                 = opts[:extra_apt_keys]                 || []
		extra_apt_sources              = opts[:extra_apt_sources]              || []
		extra_etc_systemd_unit_files   = opts[:extra_etc_systemd_unit_files]   || []
		extra_regular_users            = opts[:extra_regular_users]            || []
		extra_ssh_allow_users          = opts[:extra_ssh_allow_users]          || []
		extra_hosts                    = opts[:extra_hosts]                    || []
		extra_boot_time_kernel_modules = opts[:extra_boot_time_kernel_modules] || []
		extra_pre_install_units        = opts[:extra_pre_install_units]        || []
		extra_post_install_units       = opts[:extra_post_install_units]       || []
		extra_ferm_input_chain         = opts[:extra_ferm_input_chain]         || []
		extra_ferm_output_chain        = opts[:extra_ferm_output_chain]        || []
		extra_ferm_forward_chain       = opts[:extra_ferm_forward_chain]       || []
		extra_ferm_postrouting_chain   = opts[:extra_ferm_postrouting_chain]   || []
		extra_udev_rules               = opts[:extra_udev_rules]               || []
		extra_security_limits          = opts[:extra_security_limits]          || []
		extra_sysctl_parameters        = opts[:extra_sysctl_parameters]        || %{}
		extra_sysfs_variables          = opts[:extra_sysfs_variables]          || %{}
		optimize_for_short_lived_files = "optimize_for_short_lived_files" in tags
		ipv6                           = "ipv6"                           in tags
		release                        = Util.tag_value!(tags, "release") |> String.to_atom()

		base_keys = case release do
			:xenial  -> [content("files/apt_keys/C0B21F32 Ubuntu Archive Automatic Signing Key (2012).gpg")]
			:stretch -> [content("files/apt_keys/debian-archive-keyring.gpg")]
		end
		country      = Util.tag_value!(tags, "country")
		base_sources = case release do
			:xenial -> [
				"deb http://#{country}.archive.ubuntu.com/ubuntu xenial          main restricted universe multiverse",
				"deb http://#{country}.archive.ubuntu.com/ubuntu xenial-updates  main restricted universe multiverse",
				"deb http://security.ubuntu.com/ubuntu           xenial-security main restricted universe multiverse",
			]
			:stretch -> [
				"deb https://mirrors.kernel.org/debian          stretch           main contrib non-free",
				"deb http://security.debian.org/debian-security stretch/updates   main contrib non-free",
				"deb https://mirrors.kernel.org/debian          stretch-updates   main contrib non-free",
				"deb https://mirrors.kernel.org/debian          stretch-backports main",
				"deb https://mirrors.kernel.org/debian          experimental      main",
			]
		end
		apt_keys     = base_keys    ++ extra_apt_keys
		apt_sources  = base_sources ++ extra_apt_sources

		check_non_root_username(@non_root_username)
		base_regular_users = case "no_base_regular_user" in tags do
			true  -> []
			false -> [
				%User{
					name:  @non_root_username,
					home:  "/home/#{@non_root_username}",
					shell: "/bin/zsh",
					authorized_keys: [
						path_expand_content("~/.ssh/id_rsa.pub") |> String.trim_trailing
					]
				}
			]
		end
		root_user = %User{
			name:            "root",
			home:            "/root",
			shell:           "/bin/zsh",
			authorized_keys: case "no_ssh_to_root" in tags do
				true  -> []
				false -> [path_expand_content("~/.ssh/id_rsa.pub") |> String.trim_trailing]
			end
		}
		regular_users   = base_regular_users ++ extra_regular_users
		ssh_allow_users =
			extra_ssh_allow_users ++ (
				[root_user | regular_users]
				|> Enum.filter(fn user -> length(user.authorized_keys) > 0 end)
				|> Enum.map(fn user -> user.name end)
			) |> Enum.uniq

		base_output_chain = [
			"""
			outerface lo {
				# Necessary for chrony to work properly, also for `chronyc tracking`
				daddr 127.0.0.1 proto udp dport 323 {
					mod owner uid-owner (root _chrony) ACCEPT;
				}
			}
			"""
		]

		# Check for transparent_hugepage because it is missing on scaleway kernels
		transparent_hugepage_variables =
			if release == :xenial and File.exists?("/sys/kernel/mm/transparent_hugepage") do
				%{
					# WARNING: removing a variable here will *not* reset it to the
					# Linux default until a reboot.

					# According to https://goo.gl/Ep8iM6 system stalls are not caused by
					# transparent hugepages but by synchronous defrag, so leave THP enabled.
					"kernel/mm/transparent_hugepage/enabled" => "always",

					# Linux 4.4 has default "always", so set to "madvise" to reduce
					# stalls caused by defrag.  Linux 4.6+ has default "madvise"; see
					# https://github.com/torvalds/linux/commit/444eb2a449ef36fe115431ed7b71467c4563c7f1
					"kernel/mm/transparent_hugepage/defrag"  => "madvise",

					# Note: high-memory systems will need a much lower scan_sleep_millisecs
					# to increase hugepage availability.

					# See also https://www.kernel.org/doc/Documentation/vm/transhuge.txt
				}
			else
				%{}
			end

		sysfs_variables = %{}
			|> Map.merge(transparent_hugepage_variables)
			|> Map.merge(extra_sysfs_variables)

		dirty_settings = get_dirty_settings(optimize_for_short_lived_files: optimize_for_short_lived_files)

		# TODO: min_free_kbytes
		# TODO: optimize network stack based on wikimedia-puppet
		base_sysctl_parameters = %{
			# Standard Ubuntu console log level that we want on Debian as well
			"kernel.printk"                      => [4, 4, 1, 7],

			# See https://www.kernel.org/doc/Documentation/sysctl/kernel.txt
			"kernel.kptr_restrict"               => 1,

			# Debian has this off by default but we don't want to disable Chrome
			# namespace sandbox or break `unshare`.
			"kernel.unprivileged_userns_clone"   => 1,

			# Turn on Source Address Verification in all interfaces to
			# prevent some spoofing attacks.
			"net.ipv4.conf.default.rp_filter"    => 1,
			"net.ipv4.conf.all.rp_filter"        => 1,

			# Note that some important settings are already set by the procps package,
			# which creates .conf files in /etc/sysctl.d/.  Anything we set here will
			# override those default settings.  (If that is not the case, check
			# /etc/sysctl.d for a file that sorts after "99-sysctl.conf".)
			#
			# WARNING: removing a variable here will not necessarily restore a default
			# value, until the next reboot!

			# Don't allow non-root users to use dmesg.
			# http://blog.wpkg.org/2013/06/11/lxc-restricting-container-view-of-dmesg/
			"kernel.dmesg_restrict"              => 1,

			# Disable the magic SysRq key completely for improved security on servers
			# not under our physical control.  Magic SysRq is allegedly useful, but
			# I've never run into a situation where I could use it to fix a wedged
			# system.
			"kernel.sysrq"                       => 0,

			# "The perf subsystem has a huge history of privilege escalation vunerabilities"
			# "When kernel.perf_event_open is set to 3 (or greater), disallow all
			# access to performance events by users without CAP_SYS_ADMIN."
			"kernel.perf_event_paranoid"         => 3,

			# Disable IPv6 by default because far too many IPv6 routes announced
			# to our servers are broken.
			"net.ipv6.conf.all.disable_ipv6"     => (if ipv6, do: 0, else: 1),
			"net.ipv6.conf.default.disable_ipv6" => (if ipv6, do: 0, else: 1),

			# Use the canonical IPv6 address instead of using the privacy extensions.
			# Servers generally are expected to use the canonical address.
			# https://bugs.launchpad.net/ubuntu/+source/procps/+bug/1068756
			"net.ipv6.conf.all.use_tempaddr"     => 0,
			"net.ipv6.conf.default.use_tempaddr" => 0,

			# Prefer to retain directory and inode objects.
			# http://www.beegfs.com/wiki/StorageServerTuning
			"vm.vfs_cache_pressure"              => 50,

			"vm.dirty_background_bytes"          => dirty_settings.dirty_background_bytes,
			"vm.dirty_bytes"                     => dirty_settings.dirty_bytes,
			"vm.dirty_expire_centisecs"          => dirty_settings.dirty_expire_centisecs,

			# Ubuntu 16.04 ships with a default of fs.inotify.max_user_watches = 8192,
			# too low for some applications.
			"fs.inotify.max_user_watches"        => inotify_max_user_watches(1/32),

			# Ubuntu 16.04 ships with a default of fs.inotify.max_user_instances = 128,
			# while Sublime Text 3 likes to use > 120 instances and therefore prevent
			# other programs from using inotify at all, unless we raise the limit.
			# https://github.com/SublimeTextIssues/Core/issues/1195
			"fs.inotify.max_user_instances"      => 8192,
		}

		unprivileged_bpf_parameters =
			if File.exists?("/proc/sys/kernel/unprivileged_bpf_disabled") do
				%{
					# CVE-2016-4557 allowed for local privilege escalation using unprivileged BPF.
					#
					# "only used for things like network profiling in userspace [...]; disabling
					# the bpf() does not mean disabling all BPF/eBPF. Netfilter still uses BPF,
					# seccomp still uses BPF, etc. All it means is that userspace network profiling
					# tools and such will not function."
					"kernel.unprivileged_bpf_disabled" => 1,
				}
			else
				%{}
			end

		bbr_parameters = case release do
			:xenial -> %{}
			# BBR congestion control (T147569)
			# https://lwn.net/Articles/701165/
			#
			# The BBR TCP congestion control algorithm is based on Bottleneck
			# Bandwidth, i.e. the estimated bandwidth of the slowest link, and
			# Round-Trip Time to control outgoing traffic. Other algorithms such as
			# CUBIC (default on Linux since 2.6.19) and Reno are instead based on
			# packet loss.
			#
			# To send out data at the proper rate, BBR uses the tc-fq packet scheduler
			# instead of the TCP congestion window.
			:stretch -> %{
				"net.core.default_qdisc"          => "fq",
				"net.ipv4.tcp_congestion_control" => "bbr",
			}
		end

		sysctl_parameters =
			base_sysctl_parameters
			|> Map.merge(unprivileged_bpf_parameters)
			|> Map.merge(bbr_parameters)
			|> Map.merge(extra_sysctl_parameters)

		default_limit_nofile = 128 * 1024
		security_limits = [
			# Enable core dumps for everyone
			["root",             "soft", "core",   "unlimited"],
			["*",                "soft", "core",   "unlimited"],

			# The default limit of 1024 is too low
			["root",             "soft", "nofile", default_limit_nofile],
			["root",             "hard", "nofile", default_limit_nofile],
			["*",                "soft", "nofile", default_limit_nofile],
			["*",                "hard", "nofile", default_limit_nofile],

			# Assume @non_root_username might need to nice down to -11 for Chrome, etc
			[@non_root_username, "-",    "nice",   -11],
		] ++ extra_security_limits

		blacklisted_kernel_modules = [
			# Makes computers emit horrible beeps (note: Ubuntu blacklists this, Debian doesn't)
			"pcspkr",

			# Disable the Intel Management Engine Interface driver, which we do not need
			# and may introduce network attack vectors.
			"mei",
			"mei-me",
			"mei-txe",

			# Disable Firewire, which we do not use and may introduce physical attack vectors.
			"firewire-core",
			"firewire-net",
			"firewire-ohci",
			"firewire-sbp2",

			# Disable DCCP because we don't use it and it may have more bugs following
			# https://ma.ttias.be/linux-kernel-cve-2017-6074-local-privilege-escalation-dccp/
			"dccp",
			"dccp_ipv6",
			"dccp_ipv4",
			"dccp_probe",
			"dccp_diag",

			# CVE-2017-9075 allowed kernel memory corruption
			"sctp",
			"sctp_probe",

			# CVE-2017-2636 allows a reliable local privilege escalation in the n_hdlc tty driver
			"n_hdlc",

			# CVE-2016-3955 allowed out-of-bounds write
			"usbip-core",
			"usbip-host",
			"vhci-hcd",

			# Carries some risk and is obsoleted by overlayfs
			"aufs",

			# We do not use floppies
			"floppy",

			# We do not use these filesystems anywhere
			"btrfs",
			"qnx4",
			"hfs",
			"hfsplus",
			"ufs",
			"jfs",
			"minix",

			# We do not use parallel ports or lp anywhere
			"ppdev",
			"parport",
			"parport_pc",
			"lp",

			# We don't use the FUJITSU Extended Socket network device driver anywhere
			"fjes",

			# CVE-2017-7487 allowed a use-after-free
			"ipx",

			# May have more bugs following "tipc: fix use-after-free"
			# http://kernel.ubuntu.com/git/ubuntu/ubuntu-xenial.git/commit/?id=f08b525e9d9d65021556895399c248d1248842ea
			"tipc",

			# Has had local root exploits in the past
			"overlay",
			"overlayfs",
		] ++ case "bluetooth" in tags do
			true  -> []
			false -> [
				# CVE-2017-1000251 allowed a stack buffer overflow
				"bluetooth",
				"bluetooth_6lowpan",

				# drivers/bluetooth
				"ath3k",
				"bcm203x",
				"bfusb",
				"bluecard_cs",
				"bpa10x",
				"bt3c_cs",
				"btbcm",
				"btintel",
				"btmrvl",
				"btmrvl_sdio",
				"btqca",
				"btrtl",
				"btsdio",
				"btuart_cs",
				"btusb",
				"btwilink",
				"dtl1_cs",
				"hci_uart",
				"hci_vhci",

				# net/bluetooth
				"cmtp",
				"bnep",
				"hidp",
				"rfcomm",
			]
		end

		# Remove from blacklist if a role has the module listed in boot_time_kernel_modules
		blacklisted_kernel_modules = blacklisted_kernel_modules -- extra_boot_time_kernel_modules

		# Packages that we need to install before we can converge the giant All unit below
		unit_packages =
			@unit_modules
			|> Enum.flat_map(fn mod -> Unit.package_dependencies(%{__struct__: mod}, release) end)
			# We use the Grub unit below, but not for all types of machines
			|> Kernel.--(["grub2-common"])

		# Packages not used by the unit implementations themselves but still necessary for base_system
		early_packages = [
			"ferm",              # before we install a bunch of other packages; used by hosts_and_ferm_unit_base
			"chrony",            # because the fallback ferm configuration depends on _chrony user
			"apparmor",          # protect the system early
			"apparmor-profiles", # protect the system early
			# Do not install apparmor-profiles-extra because it includes a broken profile
			# for apt-cacher-ng, which causes the service to fail to start:
			#
			# kernel: audit: type=1400 audit(1509580980.586:74): apparmor="DENIED" operation="sendmsg"
			# profile="/usr/sbin/apt-cacher-ng" name="/run/systemd/notify" pid=2597 comm="apt-cacher-ng"
			# requested_mask="w" denied_mask="w" fsuid=110 ouid=0
			"unbound",           # started before full MetaPackageInstalled
			"locales",           # used by locale-gen below
		] ++ extra_desired_early_packages
		base_packages  = [
			"rsync",             # used by machine_manager to copy files to machine
			"dnsutils",          # for dig, used below to make sure unbound works
			"netbase",
			"ifupdown",
			"isc-dhcp-client",
			"rsyslog",
			"logrotate",
			"cron",
			"net-tools",
			"apt",
			"apt-transport-https",
			"ca-certificates",
			"zsh",               # root's default shell
			"intel-microcode",
			"console-setup",     # needed to change console font and prevent keyboard-configuration from erroring out on boot
			"cryptsetup",
			"util-linux",
			"gdisk",
			"hdparm",
			"sudo",
			"libpam-systemd",    # to make ssh server disconnect clients when it shuts down
			"openssh-server",
			"openssh-client",
			"chrony",
			"psmisc",            # for killall
			"acl",
			"prometheus-node-exporter",
		] ++ (case release do
			:xenial  -> ["pollinate"] # for seeding RNG the very first time
			:stretch -> ["firmware-linux", "firmware-linux-nonfree", "firmware-misc-nonfree"]
		end)
		human_admin_needs = [
			"file",
			"molly-guard",
			"lshw",
			"pciutils",            # for lspci
			"net-tools",           # ifconfig, route, netstat
			"iputils-ping",
			"netcat-openbsd",
			"rlwrap",              # for use with netcat
			"less",
			"strace",
			"htop",
			"iotop",
			"perf-tools-unstable", # for execsnoop, opensnoop, cachestat, kprobe, etc
			"dstat",
			"tmux",
			"git",
			"tig",
			"wget",
			"curl",
			"nano",
			"mtr-tiny",
			"nethogs",
			"iftop",
			"lsof",
			"pv",
			"tree",
			"nmap",
			"whois",
		]
		all_desired_packages =
			kernel_packages(release) ++
			bootloader_packages(Util.tag_value!(tags, "boot")) ++
			unit_packages ++
			early_packages ++
			base_packages ++
			human_admin_needs ++
			extra_desired_packages
		# Packages to be purged, unless listed in all_desired_packages.  Prevents
		# some package from installing an undesired package because converge will
		# detect a conflict.
		undesired_packages = [
			# ureadahead has some very suspect code and spews messages to syslog
			# complaining about relative paths
			"ureadahead",

			# Time managers that would conflict with chrony
			"ntpdate",
			"adjtimex",
			"ntp",
			"openntpd",

			# Superfluous stuff that we would find on a non-minbase install
			"snapd",
			"unattended-upgrades",
			"libnss-mdns",
			"avahi-daemon",
			"popularity-contest",

			# We probably don't have many computers that need thermald because the
			# BIOS and kernel also take actions to keep the CPU cool.
			# https://01.org/linux-thermal-daemon/documentation/introduction-thermal-daemon
			"thermald",

			# https://donncha.is/2016/12/compromising-ubuntu-desktop/
			"apport",
			"apport-gtk",
			"python3-apport",
			"python3-problem-report",

			# Having this installed loads the btrfs kernel module and slows down
			# the boot with a scan for btrfs volumes.
			"btrfs-tools",

			# Container technology that works until it doesn't
			"lxd",
			"lxcfs",
			"lxc-common",

			# Gave us names like em0 and em1 for network devices, but we don't want
			# this anywhere; we want systemd's predictable network interface names.
			"biosdevname",

			# We don't use it, but it's not autoremoved for whatever reason
			"anacron",
		] ++ case release do 
			:xenial  -> ["gnupg"] # apt will use either gnupg or gnupg2, and gnupg2 is less bad
			:stretch -> []        # gnupg is gnupg2 on stretch
		end ++ case release do
			:xenial  -> []
			:stretch -> ["initscripts", "sysv-rc"] # obsolete but retained after xenial -> stretch upgrade
		end ++
		extra_undesired_packages

		packages_to_purge = MapSet.difference(MapSet.new(undesired_packages), MapSet.new(all_desired_packages))

		units = [
			# We need a git config with a name and email for etckeeper to work
			%DirectoryPresent{path: "/root/.config",     mode: 0o700},
			%DirectoryPresent{path: "/root/.config/git", mode: 0o700},
			%FilePresent{
				path:    "/root/.config/git/config",
				content: EEx.eval_string(content("files/root/.config/git/config.eex"), [hostname: Util.get_hostname()]),
				mode:    0o640
			},

			%EtcCommitted{message: "converge (before any converging)"},
			%Sysctl{parameters: sysctl_parameters},

			%FilePresent{
				path:    "/etc/modprobe.d/base_system.conf",
				mode:    0o644,
				content: blacklisted_kernel_modules
				         |> Enum.map(fn module -> "blacklist #{module}\n" end)
				         |> Enum.join
			},

			%RedoAfterMeet{
				marker:  marker("kmod.service"),
				unit:    %FilePresent{
					path:    "/etc/modules",
					mode:    0o644,
					content: extra_boot_time_kernel_modules
					         |> Kernel.++([""])
					         |> Enum.join("\n")
				},
				trigger: fn -> Util.systemd_unit_reload_or_restart_if_active("kmod.service") end
			},

			%FilePresent{
				path:    "/etc/udev/rules.d/99-base_system.rules",
				mode:    0o644,
				content: extra_udev_rules
				         |> Enum.map(fn rule -> "#{rule}\n" end)
				         |> Enum.join
			},

			conf_file("/etc/profile"),

			# Use the nicer colors for text VTs
			%RedoAfterMeet{
				marker:  marker("setvtrgb"),
				unit:    %SymlinkPresent{path: "/etc/vtrgb", target: "/etc/console-setup/vtrgb"},
				trigger: fn -> {_, 0} = System.cmd("setvtrgb", ["/etc/vtrgb"]) end
			},

			# Clean up and unify motd across machines
			%FileMissing{path: "/etc/motd"},
			%FileMissing{path: "/etc/legal"},
			%FileMissing{path: "/etc/update-motd.d/00-header"},
			%FileMissing{path: "/etc/update-motd.d/10-help-text"},
			%FileMissing{path: "/etc/update-motd.d/20-ovh-informations"},
			%FileMissing{path: "/etc/update-motd.d/51-cloudguest"},
			%FilePresent{path: "/etc/update-motd.d/10-uname", mode: 0o755, content: content("files/etc/update-motd.d/10-uname")},

			leftover_files_unit(release),

			%FilePresent{
				path: "/etc/security/limits.conf",
				content:
					security_limits
					|> Enum.map(fn row -> Enum.map(row, &value_to_string/1) end)
					|> TableFormatter.format
					|> IO.iodata_to_binary,
				mode: 0o644
			},

			%RedoAfterMeet{
				marker: marker("systemd"),
				unit: %All{units: [
					%FilePresent{
						path:    "/etc/systemd/system.conf",
						content: EEx.eval_string(content("files/etc/systemd/system.conf.eex"), [default_limit_nofile: default_limit_nofile]),
						mode:    0o644
					},

					# Ignore power key because we don't need it to shut down a machine and it's easy to
					# press accidentally or unintentionally (if you assume a blank-screen laptop is off)
					conf_file("/etc/systemd/logind.conf"),

					# Disable systemd's atrocious "one ctrl-alt-del reboots the system" feature.
					# This does not affect the 7x ctrl-alt-del force reboot feature.
					%SymlinkPresent{path: "/etc/systemd/system/ctrl-alt-del.target", target: "/dev/null"},
				]},
				trigger: fn -> {_, 0} = System.cmd("systemctl", ["daemon-reload"]) end
			},

			# Fix this annoying warning:
			# N: Ignoring file '50unattended-upgrades.ucf-dist' in directory '/etc/apt/apt.conf.d/'
			# as it has an invalid filename extension
			%FileMissing{path: "/etc/apt/apt.conf.d/50unattended-upgrades.ucf-dist"},

			%FileMissing{path: "/etc/apt/sources.list~"},
			%FileMissing{path: "/etc/apt/sources.list.bak"},
			%FileMissing{path: "/etc/apt/sources.list.save"},
			%FileMissing{path: "/etc/apt/sources.list.distUpgrade"},
			%FilePresent{
				path:      "/etc/apt/sources.list",
				content:   apt_sources ++ [""] |> Enum.join("\n"),
				mode:      0o440,
				# Make _apt the user owner because there is no _apt group
				user:      "_apt",
				group:     "root",
				immutable: true
			},

			# Don't let any user read the package cache and other metadata
			%DirectoryPresent{path: "/var/cache/apt",               mode: 0o570, user: "_apt", group: "root"},
			%DirectoryPresent{path: "/var/cache/apt-show-versions", mode: 0o750},
			%DirectoryPresent{path: "/var/cache/apt-xapian-index",  mode: 0o750},
			%DirectoryPresent{path: "/var/cache/debconf",           mode: 0o750},
			%DirectoryPresent{path: "/var/log/apt",                 mode: 0o750},

			# We centralize management of our apt sources in /etc/apt/sources.list,
			# so remove anything that may be in /etc/apt/sources.list.d/
			%DirectoryPresent{path: "/etc/apt/sources.list.d", mode: 0o755, immutable: true},
			%DirectoryEmpty{path: "/etc/apt/sources.list.d"},

			(case release do
				:xenial  -> %GPGSimpleKeyring{path: "/etc/apt/trusted.gpg", keys: apt_keys, mode: 0o644, immutable: true}
				:stretch -> %GPGKeybox{path: "/etc/apt/trusted.gpg", keys: apt_keys, mode: 0o644, immutable: true}
			end),
			%DirectoryPresent{path: "/etc/apt/trusted.gpg.d", mode: 0o755, immutable: true},
			# We centralize management of our apt sources in /etc/apt/trusted.gpg,
			# so remove anything that may be in /etc/apt/trusted.gpg.d/
			%DirectoryEmpty{path: "/etc/apt/trusted.gpg.d"},
			# Leftover backup file?
			%FileMissing{path: "/etc/apt/trusted.gpg~"},

			%FilePresent{path: "/etc/apt/preferences", mode: 0o644, content: make_apt_preferences(extra_apt_pins)},
			%DirectoryPresent{path: "/etc/apt/preferences.d", mode: 0o755, immutable: true},
			# We centralize management of our apt preferences in /etc/apt/preferences,
			# so remove anything that may be in /etc/apt/preferences.d/
			%DirectoryEmpty{path: "/etc/apt/preferences.d"},

			fstab_unit(),

			# UTC timezone everywhere to avoid confusion and timezone-handling bugs
			conf_file("/etc/timezone"),

			# Install default /etc/environment to fix servers that may have an ancient/broken one
			conf_file("/etc/environment"),

			# Prevent sudo from caching credentials, because otherwise programs
			# in the same terminal may be able to unexpectedly `sudo` without asking.
			conf_dir("/etc/sudoers.d"),
			conf_file("/etc/sudoers.d/base_system"),
			# leftovers from old base_system
			%FileMissing{path: "/etc/sudoers.d/no_cred_caching"},
			%FileMissing{path: "/etc/country"},

			%MetaPackageInstalled{
				name:    "converge-desired-packages-early",
				depends: early_packages,
			},
			%EtcCommitted{message: "converge (early)"},

			# Set up locale early to avoid complaints from programs
			%RedoAfterMeet{
				marker:  marker("locale-gen"),
				unit:    conf_file("/etc/locale.gen"),
				trigger: fn -> {_, 0} = System.cmd("locale-gen", []) end
			},
			conf_file("/etc/default/locale"),

			%Sysfs{variables: sysfs_variables},

			# Make sure apparmor is started
			# TODO: for Debian, make sure it's started only after first successful `configure`
			# because we need to update-grub and reboot for it to start
			# %SystemdUnitStarted{name: "apparmor.service"},

			# Do this before ferm config, which may require users already exist
			%RegularUsersPresent{users: base_regular_users ++ extra_regular_users},

			hosts_and_ferm_unit(
				extra_hosts,
				make_ferm_config(
					extra_ferm_input_chain,
					base_output_chain ++ extra_ferm_output_chain,
					extra_ferm_forward_chain,
					extra_ferm_postrouting_chain
				),
				# Because the system may not yet have the packages installed that
				# create the users mentioned in extra_ferm_output_chain, fall back
				# to a ferm configuration that just does ACCEPT; on the output
				# chain.  This configuration is replaced after package installation
				# below.
				make_ferm_config(
					extra_ferm_input_chain,
					["ACCEPT;"],
					extra_ferm_forward_chain,
					extra_ferm_postrouting_chain
				)
			),

			# Prevent non-root users from restarting or shutting down the system using the GUI.
			# This is mostly to prevent accidental restarts; the "Log Out" and "Restart" buttons
			# are right next to each other and "Restart" does not require confirmation.
			# http://askubuntu.com/questions/453479/how-to-disable-shutdown-reboot-from-lightdm-in-14-04/454230#454230
			conf_dir("/etc/polkit-1"),
			conf_dir("/etc/polkit-1/localauthority", 0o700),
			conf_dir("/etc/polkit-1/localauthority/50-local.d"),
			conf_file("/etc/polkit-1/localauthority/50-local.d/restrict-login-powermgmt.pkla"),

			conf_dir("/etc/zsh"),
			conf_file("/etc/zsh/zsh-autosuggestions.zsh"),
			conf_file("/etc/zsh/zshrc-custom"),

			%FilePresent{
				path:    "/etc/zsh/zshrc",
				content: content("files/etc/zsh/zshrc.factory") <> "\n\n" <> "source /etc/zsh/zshrc-custom",
				mode:    0o644
			},

			%RedoAfterMeet{
				marker:  marker("unbound.service"),
				unit:    %All{units: [
					conf_dir("/etc/unbound"),
					conf_file("/etc/unbound/unbound.conf"),
				]},
				trigger: fn -> Util.systemd_unit_reload_or_restart_if_active("unbound.service") end
			},

			%RedoAfterMeet{
				marker: marker("chrony.service"),
				unit:   %All{units: [
					conf_dir("/etc/chrony"),
					%FilePresent{
						path:    "/etc/chrony/chrony.conf",
						content: EEx.eval_string(content("files/etc/chrony/chrony.conf.eex"), [country: country]),
						mode:    0o644
					},
				]},
				trigger: fn -> Util.systemd_unit_reload_or_restart_if_active("chrony.service") end
			},

			%RedoAfterMeet{
				marker: marker("ssh.service"),
				unit: %All{units: [
					conf_dir("/etc/ssh"),
					%FilePresent{
						path:    "/etc/ssh/sshd_config",
						content: EEx.eval_string(content("files/etc/ssh/sshd_config.eex"), [allow_users: ssh_allow_users]),
						mode:    0o644
					},
					# Remove obsolete keys no longer used by config
					%FileMissing{path: "/etc/ssh/ssh_host_dsa_key"},
					%FileMissing{path: "/etc/ssh/ssh_host_dsa_key.pub"},
				]},
				trigger: fn -> Util.systemd_unit_reload_or_restart_if_active("ssh.service") end
			},

			%EtcSystemdUnitFiles{units: extra_etc_systemd_unit_files},

			%All{units: extra_pre_install_units},

			%MetaPackageInstalled{
				name:    "converge-desired-packages",
				depends: ["converge-desired-packages-early"] ++ all_desired_packages
			},
			%PackageRoots{names: ["converge-desired-packages"]},
			# This comes after MetaPackageInstalled because the undesired gnupg
			# must be purged *after* installing gnupg2.
			%All{units: packages_to_purge |> Enum.map(fn name -> %PackagePurged{name: name} end)},
			%DanglingPackagesPurged{},
			# Purging can cause some packages to be set to manually-installed,
			# so repeat the PackageRoots unit, then the DanglingPackagesPurged unit.
			%PackageRoots{names: ["converge-desired-packages"]},
			%DanglingPackagesPurged{},
			# Hopefully it doesn't need to be run a third time...

			%NoPackagesUnavailableInSource{whitelist_regexp: ~r/\A(converge-desired-packages(-early)?|linux-(image|tools|headers)-.*)\z/},
			%NoPackagesNewerThanInSource{whitelist_regexp: ~r/\Alinux-(image|tools|headers)-.*\z/},

			# Make sure this is cleared out after a google-chrome-* install drops a file here
			%DirectoryEmpty{path: "/etc/apt/sources.list.d"},

			# /lib/systemd/system/systemd-timesyncd.service.d/disable-with-time-daemon.conf
			# stops systemd-timesyncd from starting if chrony is installed, but systemd-timesyncd
			# may still be running if the system hasn't been rebooted.
			%SystemdUnitStopped{name: "systemd-timesyncd.service"},

			# util-linux drops a file to do a TRIM every week.  If we have servers
			# with SSDs that benefit from TRIM, we should probably do this some
			# other time.
			%FileMissing{path: "/etc/cron.weekly/fstrim"},

			%SystemdUnitStarted{name: "chrony.service"},
			%SystemdUnitStarted{name: "ssh.service"},

			conf_file("/etc/dhcp/dhclient-enter-hooks.d/base_system"),

			%SystemdUnitStarted{name: "unbound.service"},
			# Set /etc/resolv.conf nameservers to the local unbound server
			%BeforeMeet{
				unit:    conf_file("/etc/resolv.conf", 0o644, immutable: true),
				# Make sure unbound actually works before pointing resolv.conf to localhost
				trigger: fn -> {_, 0} = System.cmd("dig", ["-t", "A", "localhost", "@127.0.0.1"]) end
			},

			%SystemdUnitEnabled{name: "prometheus-node-exporter.service"},
			%SystemdUnitStarted{name: "prometheus-node-exporter.service"},

			# We don't use bash for the interactive shell, so there's no point in
			# dropping these files into every user's $HOME
			%FileMissing{path: "/etc/skel/.bashrc"},
			%FileMissing{path: "/etc/skel/.bash_logout"},
			%FileMissing{path: "/etc/skel/.profile"},

			conf_file("/etc/skel/.zshrc"),
			conf_file("/etc/issue"),
			%FileMissing{path: "/etc/issue.dpkg-dist"},
			%FileMissing{path: "/etc/sysctl.conf.dpkg-dist"},
			conf_file("/etc/tmux.conf"),
			conf_file("/etc/nanorc"),
			conf_dir("/etc/nano.d"),
			conf_file("/etc/nano.d/elixir.nanorc"),
			conf_file("/etc/nano.d/git-commit-msg.nanorc"),

			# Make sure root's shell is zsh
			%BeforeMeet{
				unit: %UserPresent{
					name:            root_user.name,
					home:            root_user.home,
					shell:           root_user.shell,
					authorized_keys: root_user.authorized_keys,
				},
				# Make sure zsh actually works before setting root's shell to zsh
				trigger: fn -> {_, 0} = System.cmd("/bin/zsh", ["-c", "true"]) end
			},

			%All{units: boot_units(release, Util.tag_value!(tags, "boot"), Util.tag_value(tags, "boot_resolution"))},
			%All{units: extra_post_install_units},

			# To stabilize on the first run, this should be near-last, after any possible
			# modifications to /etc/passwd or /etc/group
			hosts_and_ferm_unit(
				extra_hosts,
				make_ferm_config(
					extra_ferm_input_chain,
					base_output_chain ++ extra_ferm_output_chain,
					extra_ferm_forward_chain,
					extra_ferm_postrouting_chain
				)
			),

			%EtcCommitted{message: "converge"},
		]
		install_unit_impl_packages(unit_packages ++ ["apt-transport-https", "ca-certificates"])
		ctx = %Context{run_meet: true, reporter: TerminalReporter.new()}
		Runner.converge(%All{units: units}, ctx)
	end

	defp install_unit_impl_packages(unit_packages) do
		missing_unit_impl_packages =
			unit_packages
			|> Enum.uniq
			|> Enum.reject(&Util.installed?/1)
		if missing_unit_impl_packages != [] do
			try do
				Util.update_package_index()
			rescue
				# If we get an error (because e.g. /etc/apt/sources.list is bad),
				# let's hope the existing package index has the packages we need.
				RuntimeError -> nil
			end
			:ok = IO.puts("Installing packages #{inspect missing_unit_impl_packages} before converging, this could take a few minutes...")
			for package <- missing_unit_impl_packages do
				Util.install_package(package)
			end
		end
	end

	defp leftover_files_unit(:xenial), do: %All{units: []}
	defp leftover_files_unit(:stretch) do
		%All{units: [
			# leftover from xenial; stretch doesn't come with an /etc/lsb-release
			%FileMissing{path: "/etc/lsb-release"},

			# upstart-related leftover from xenial
			%FileMissing{path: "/etc/init/startpar-bridge.conf"},

			# leftovers from xenial
			%FileMissing{path: "/etc/apt/apt.conf.d/00aptitude"},
			%FileMissing{path: "/etc/apt/apt.conf.d/00trustcdrom"},
			%FileMissing{path: "/etc/apt/apt.conf.d/01-vendor-ubuntu"},

			# leftover from a xenial -> stretch upgrade
			%FileMissing{path: "/etc/dpkg/origins/ubuntu"},
			# pointing to the wrong file after a xenial -> stretch upgrade
			%SymlinkPresent{path: "/etc/dpkg/origins/default", target: "debian"},

			# old kernel-package file
			%FileMissing{path: "/etc/kernel-img.conf"},

			# Ubuntu's kmod installs these blacklist conf files; Debian's kmod does not
			%FileMissing{path: "/etc/modprobe.d/blacklist-ath_pci.conf"},
			%FileMissing{path: "/etc/modprobe.d/blacklist-firewire.conf"},
			%FileMissing{path: "/etc/modprobe.d/blacklist-framebuffer.conf"},
			%FileMissing{path: "/etc/modprobe.d/blacklist-rare-network.conf"},
			%FileMissing{path: "/etc/modprobe.d/blacklist-watchdog.conf"},
			%FileMissing{path: "/etc/modprobe.d/blacklist.conf"},
			%FileMissing{path: "/etc/modprobe.d/iwlwifi.conf"},
			%FileMissing{path: "/etc/modprobe.d/mlx4.conf"},

			# rsyslog leftovers from xenial (note: the apparmor profile is disabled by
			# default on xenial via a symlink in /etc/apparmor.d/disable)
			%FileMissing{path: "/etc/rsyslog.d/50-default.conf"},
			%FileMissing{path: "/etc/apparmor.d/usr.sbin.rsyslogd"},
			%FileMissing{path: "/etc/apparmor.d/disable/usr.sbin.rsyslogd"},

			# procps leftovers from xenial
			%FileMissing{path: "/etc/sysctl.d/10-console-messages.conf"},
			%FileMissing{path: "/etc/sysctl.d/10-ipv6-privacy.conf"},
			%FileMissing{path: "/etc/sysctl.d/10-kernel-hardening.conf"},
			%FileMissing{path: "/etc/sysctl.d/10-link-restrictions.conf"},
			%FileMissing{path: "/etc/sysctl.d/10-magic-sysrq.conf"},
			%FileMissing{path: "/etc/sysctl.d/10-network-security.conf"},
			%FileMissing{path: "/etc/sysctl.d/10-ptrace.conf"},
			%FileMissing{path: "/etc/sysctl.d/10-zeropage.conf"},
			%FileMissing{path: "/etc/sysctl.d/README"},

			# grub-common leftovers from xenial
			%FileMissing{path: "/etc/init.d/grub-common"},
			%FileMissing{path: "/etc/pm/sleep.d/10_grub-common"},

			# console-setup-linux leftovers from xenial
			%FileMissing{path: "/etc/alternatives/vtrgb"},
		]}
	end

	defp hosts_and_ferm_unit(extra_hosts, ferm_config, ferm_config_fallback \\ nil) do
		case ferm_config_fallback do
			nil ->
				hosts_and_ferm_unit_base(extra_hosts, ferm_config)
			_   ->
				%Fallback{
					primary:  hosts_and_ferm_unit_base(extra_hosts, ferm_config),
					fallback: hosts_and_ferm_unit_base(extra_hosts, ferm_config_fallback)
				}
		end
	end

	defp hosts_and_ferm_unit_base(extra_hosts, ferm_config) do
		%All{units: [
			%RedoAfterMeet{
				marker: marker("ferm.service"),
				unit:   %All{units: [
					# /etc/hosts must be written before reloading ferm, because ferm
					# configuration may resolve hosts mentioned there.
					%FilePresent{
						path:    "/etc/hosts",
						mode:    0o644,
						content: formatted_hosts(extra_hosts)
					},
					%DirectoryPresent{path: "/etc/ferm",      mode: 0o700},
					%FilePresent{path: "/etc/ferm/ferm.conf", mode: 0o600, content: ferm_config},
					conf_file("/etc/default/ferm"),
				]},
				trigger: fn ->
					case System.cmd("systemctl", ["reload-or-restart", "ferm.service"]) do
						{_, 0}    -> nil
						{_, code} -> raise(UnitError, "`systemctl reload-or-start ferm.service` returned exit code #{code}")
					end
				end
			},
			%SystemdUnitStarted{name: "ferm.service"},
		]}
	end

	defp formatted_hosts(extra_hosts) do
		IO.iodata_to_binary(
			TableFormatter.format(
				preamble_hosts() ++
				[[]] ++
				Poison.decode!(File.read!("/root/.cache/machine_manager/hosts.json")) ++
				[[]] ++
				extra_hosts
			)
		) <>
		case file_content_or_nil("/etc/hosts.unmanaged") do
			nil -> ""
			s   -> "\n" <> s
		end
	end

	defp preamble_hosts() do
		[
			["127.0.0.1", "localhost #{Util.get_hostname()}"],
			["::1",       "localhost ip6-localhost ip6-loopback"],
			["ff02::1",   "ip6-allnodes"],
			["ff02::2",   "ip6-allrouters"],
		]
	end

	defp file_content_or_nil(path) do
		case File.read(path) do
			{:ok, content} -> content
			_              -> nil
		end
	end

	defp kernel_packages(:xenial),  do: ["linux-image-generic"]
	# initramfs-tools trigger requires busybox | busybox-static even though it doesn't list it in Depends!?
	# update-initramfs: Generating /boot/initrd.img-4.9.0-4-amd64
	# E: busybox or busybox-static, version 1:1.22.0-17~ or later, is required but not installed
	defp kernel_packages(:stretch), do: ["linux-image-amd64", "busybox"]

	defp bootloader_packages("uefi"),            do: ["grub-efi-amd64"]
	defp bootloader_packages("uefi_bfq"),        do: ["grub-efi-amd64"]
	# outside = our boot is fully managed by the host, to the point where we don't
	# have to install a Linux kernel and bootloader.  You can use this on scaleway.
	defp bootloader_packages("outside"),         do: ["grub-efi-amd64"]
	defp bootloader_packages("scaleway_kexec"),  do: ["scaleway-ubuntu-kernel"]
	defp bootloader_packages(_),                 do: ["grub-pc"]

	defp boot_units(_release, "outside", _),               do: []
	# disabling kexec.service is "required as Ubuntu will kexec too early and leave a dirty filesystem"
	# https://github.com/stuffo/scaleway-ubuntukernel/tree/28f17d8231ad114034d8bbc684fc5afb9f902758#install
	defp boot_units(_release, "scaleway_kexec", _),        do: [%SystemdUnitDisabled{name: "kexec.service"},
	                                                            %SystemdUnitEnabled{name: "scaleway-ubuntu-kernel.service"}]
	defp boot_units(release, "mbr",      boot_resolution), do: [%Grub{cmdline_normal_only: release_specific_cmdline(release),                     gfxpayload: boot_resolution}]
	defp boot_units(release, "mbr_bfq",  boot_resolution), do: [%Grub{cmdline_normal_only: release_specific_cmdline(release) ++ ["elevator=bfq"], gfxpayload: boot_resolution}]
	defp boot_units(release, "uefi",     boot_resolution), do: [%Grub{cmdline_normal_only: release_specific_cmdline(release),                     gfxpayload: boot_resolution}]
	defp boot_units(release, "uefi_bfq", boot_resolution), do: [%Grub{cmdline_normal_only: release_specific_cmdline(release) ++ ["elevator=bfq"], gfxpayload: boot_resolution}]
	defp boot_units(release, "ovh_vps", _),                do: [%Grub{cmdline_normal_only: release_specific_cmdline(release),                     cmdline_normal_and_recovery: ["console=tty1", "console=ttyS0"]}]
	defp boot_units(release, "do_vps", _),                 do: [%Grub{cmdline_normal_only: release_specific_cmdline(release),                     cmdline_normal_and_recovery: ["console=tty1", "console=ttyS0"]}]
	defp boot_units(release, "do_vps_stretch", _),         do: [%Grub{cmdline_normal_only: release_specific_cmdline(release) ++ ["biosdevname=0", "net.ifnames=0", "console=tty0", "console=ttyS0,115200", "earlyprintk=ttyS0,115200", "systemd.show_status=true"]}]

	defp release_specific_cmdline(:xenial),  do: [
		# Kernels before 4.12 blank the console after a delay
		"consoleblank=0",
	]
	defp release_specific_cmdline(:stretch), do: [
		# Kernels before 4.12 blank the console after a delay
		"consoleblank=0",

		# Debian kernels before 4.13 need apparmor explicitly enabled
		"apparmor=1",
		"security=apparmor",

		# Use blk-mq so that we can use the new bfq scheduler in 4.12+
		"scsi_mod.use_blk_mq=y",
		"dm_mod.use_blk_mq=y",
	]

	defp fstab_unit() do
		fstab_existing_entries = Fstab.get_entries()
			|> Enum.map(fn entry -> {entry.mount_point, entry} end)
			|> Enum.into(%{})
		fstab_entries = [
			fstab_existing_entries["/"],
			fstab_existing_entries["/boot"],
			fstab_existing_entries["/boot/efi"],
			%FstabEntry{
				spec:             "proc",
				mount_point:      "/proc",
				type:             "proc",
				# hidepid=2 prevents users from seeing other users' processes
				options:          "hidepid=2",
				fsck_pass_number: 0
			}
		] |> Enum.reject(&is_nil/1)
		fstab_trigger = fn ->
			{_, 0} = System.cmd("mount", ["-o", "remount", "/proc"])
		end
		%RedoAfterMeet{
			marker:  marker("remount-proc"),
			unit:    %Fstab{entries: fstab_entries},
			trigger: fstab_trigger
		}
	end

	defp get_dirty_settings(opts) do
		optimize_for_short_lived_files = Keyword.get(opts, :optimize_for_short_lived_files)
		mb                             = 1024 * 1024
		gb                             = 1024 * mb
		memtotal                       = Util.get_meminfo()["MemTotal"] # bytes
		threshold                      = 4 * gb
		if optimize_for_short_lived_files do
			# Some servers have a workload where they download files, keep them on
			# disk for a minute or two, upload them, then delete them.  For these
			# servers, optimize for avoiding writes to disk.
			%{
				dirty_background_bytes: round(0.35 * memtotal),
				dirty_bytes:            round(0.70 * memtotal),
				dirty_expire_centisecs: 30000 # 300 seconds = 5 minutes
			}
		else
			# On servers with >= 4GB RAM, try to reduce hangs caused by a large
			# number of dirty pages being written to disk, blocking other reads
			# and writes.
			#
			# These settings might become unnecessary if the "Throttled background
			# buffered writeback" patches make it into the kernel.
			#
			# https://www.kernel.org/doc/Documentation/sysctl/vm.txt
			# https://lonesysadmin.net/2013/12/22/better-linux-disk-caching-performance-vm-dirty_ratio/
			# https://lwn.net/Articles/699806/
			if memtotal >= threshold do
				%{
					dirty_background_bytes: 300 * mb,
					dirty_bytes:            600 * mb,
					dirty_expire_centisecs: 3000, # Linux default of 30 sec
				}
			else
				%{
					dirty_background_bytes: round(0.1 * memtotal),
					dirty_bytes:            round(0.2 * memtotal),
					dirty_expire_centisecs: 3000, # Linux default of 30 sec
				}
			end
		end
	end

	# Return the number of inotify watchers to allow per user, alotting a
	# maximum of RAM * `max_ram_ratio` to each user for inotify watchers.
	defp inotify_max_user_watches(max_ram_ratio) when max_ram_ratio > 0 and max_ram_ratio < 1 do
		memtotal_bytes = Util.get_meminfo()["MemTotal"]
		# https://unix.stackexchange.com/questions/13751/kernel-inotify-watch-limit-reached
		watcher_bytes  = 1024
		round((max_ram_ratio * memtotal_bytes) / watcher_bytes)
	end

	def make_apt_preferences(pins) do
		for pin <- pins do
			"""
			Package: #{pin.package}
			Pin: #{pin.pin}
			Pin-Priority: #{pin.pin_priority}
			"""
		end
		|> Enum.join("\n")
	end

	def make_ferm_config(input_chain, output_chain, forward_chain, postrouting_chain) do
		interface_names     = File.ls!("/sys/class/net")
		# eno, ens, enp, enx, eth: https://www.freedesktop.org/wiki/Software/systemd/PredictableNetworkInterfaceNames/
		ethernet_interfaces = interface_names |> Enum.filter(fn name -> name |> String.starts_with?("e")   end)
		wifi_interfaces     = interface_names |> Enum.filter(fn name -> name |> String.starts_with?("wlo") end)
		"""
		# ferm configuration is dependent on uids and gids, so make sure ferm gets reloaded when users/groups change
		# /etc/passwd sha256sum: #{sha256sum("/etc/passwd")}
		# /etc/group  sha256sum: #{sha256sum("/etc/group")}

		@def $ethernet_interfaces = (#{ethernet_interfaces |> Enum.join(" ")});
		@def $wifi_interfaces     = (#{wifi_interfaces     |> Enum.join(" ")});

		table filter {
			chain INPUT {
				policy DROP;

				mod state state ESTABLISHED ACCEPT;
				mod state state RELATED proto icmp ACCEPT;

				# allow local packet
				interface lo ACCEPT;

				# respond to ping
				proto icmp ACCEPT; 

				# allow SSH connections + 29933 spiped
				proto tcp syn dport (22 29933) ACCEPT;

				# allow WireGuard traffic
				interface ($ethernet_interfaces $wifi_interfaces) {
					proto udp dport 51820 ACCEPT;
				}

				# allow localhost or any wg0 host to reach prometheus-node-exporter
				#
				# TODO: add configuration to lock this down to a few hosts that actually
				# need to see the metrics
				interface (lo wg0) {
					proto tcp syn dport 9100 ACCEPT;
				}

		#{input_chain |> Enum.join("\n") |> indent |> indent}

				#LOG log-prefix "Dropped inbound packet: " log-level debug log-uid;
				#REJECT reject-with icmp-port-unreachable;
			}

			chain OUTPUT {
				policy DROP;

				mod state state ESTABLISHED ACCEPT;
				mod state state RELATED proto icmp ACCEPT;

				outerface lo {
					# Allow anyone to make DNS lookups using local unbound
					proto (tcp udp) dport 53 ACCEPT;

					# Allow root to talk to the unbound control port
					proto tcp dport 8953 {
						mod owner uid-owner root ACCEPT;
					}

					# No `daddr` to allow access to ssh even when using the LAN IP instead of 127.0.0.1
					proto tcp syn dport 22 {
						mod owner uid-owner root ACCEPT;
					}
				}

				outerface wg0 {
					# Allow root to ping anyone over the WireGuard interface
					proto icmp {
						mod owner uid-owner root ACCEPT;
					}
				}

		#{output_chain |> Enum.join("\n") |> indent |> indent}

				# To suppress this rule, add your own with REJECT to the output chain
				outerface ($ethernet_interfaces $wifi_interfaces) {
					ACCEPT;
				}

				LOG log-prefix "Dropped outbound packet: " log-level debug log-uid;
				REJECT reject-with icmp-port-unreachable;
			}

			chain FORWARD {
				policy DROP;

				mod state state ESTABLISHED ACCEPT;
				mod state state RELATED proto icmp ACCEPT;

		#{forward_chain |> Enum.join("\n") |> indent |> indent}

				LOG log-prefix "Dropped forwarded packet: " log-level debug log-uid;
				REJECT reject-with icmp-port-unreachable;
			}
		}

		table nat {
			chain POSTROUTING {
		#{postrouting_chain |> Enum.join("\n") |> indent |> indent}
			}
		}
		"""
	end

	defp sha256sum(path) do
		# Don't use :crypto.hash because that requires erlang-crypto, which may
		# be linked to the wrong version of openssl when configuring a machine
		# from a machine_manager running on a different Debian/Ubuntu release.
		{out, 0} = System.cmd("sha256sum", ["--", path])
		out
		|> String.split(~r/\s/)
		|> Enum.at(0)
	end

	defp indent(s) do
		s
		|> String.split("\n")
		|> Enum.map(fn line -> "\t#{line}" end)
		|> Enum.join("\n")
	end

	defp value_to_string(value) when is_binary(value),  do: value
	defp value_to_string(value) when is_integer(value), do: to_string(value)
end
