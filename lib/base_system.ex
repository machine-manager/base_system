alias Converge.{
	Runner, Context, TerminalReporter, FilePresent, FileMissing, SymlinkPresent,
	DirectoryPresent, DirectoryEmpty, EtcCommitted, MetaPackageInstalled,
	PackageRoots, DanglingPackagesPurged, PackagePurged, Fstab, FstabEntry,
	AfterMeet, BeforeMeet, Sysctl, Sysfs, Util, All, GPGSimpleKeyring,
	SystemdUnitStarted, SystemdUnitStopped, SystemdUnitEnabled, SystemdUnitDisabled,
	UserPresent, Grub
}

defmodule BaseSystem.NoTagsError do
	defexception [:message]
end

defmodule BaseSystem.BadRoleDescriptorError do
	defexception [:message]
end

defmodule BaseSystem.Configure do
	@moduledoc """
	Converts a `debootstrap --variant=minbase` install of Ubuntu LTS into a
	useful Ubuntu system.

	Requires that these packages are already installed:
	`erlang-base-hipe erlang-crypto curl binutils`

	`curl` is needed for `Util.get_country`.

	`binutils`'s `ar` is needed for `MetaPackageInstalled`.
	"""
	alias BaseSystem.{BadRoleDescriptorError, NoTagsError}
	require Util
	import Util, only: [content: 1, conf_file: 1, conf_file: 3, conf_dir: 1, conf_dir: 2]
	Util.declare_external_resources("files")

	@allowed_descriptor_keys MapSet.new([
		:desired_packages,
		:undesired_packages,
		:undesired_upgrades,
		:apt_keys,
		:apt_sources,
		:sysctl_parameters,
		:sysfs_variables,
		:pre_install_unit,
		:post_install_unit,
		:implied_roles,
	])

	@spec configure_with_roles([String.t], [module]) :: nil
	def configure_with_roles(tags, role_modules) do
		if length(tags) == 0 do
			raise(NoTagsError, "Refusing to configure with 0 tags because this is probably a mistake; pass a dummy tag if not")
		end

		role_modules                 = get_all_role_modules(tags, role_modules |> MapSet.new)
		role_modules_and_descriptors = role_modules |> Enum.map(fn mod -> {mod, apply(mod, :role, [tags])} end)

		for {module, desc} <- role_modules_and_descriptors do
			descriptor_keys  = desc |> Map.keys |> MapSet.new
			unsupported_keys = MapSet.difference(descriptor_keys, @allowed_descriptor_keys)
			if unsupported_keys |> MapSet.size > 0 do
				raise(BadRoleDescriptorError,
					"Descriptor for #{inspect module} has unsupported keys #{inspect(unsupported_keys |> MapSet.to_list)}")
			end
		end
		descriptors        = role_modules_and_descriptors |> Enum.map(fn {_module, desc} -> desc end)
		desired_packages   = descriptors |> Enum.flat_map(fn desc -> desc[:desired_packages]   || [] end)
		undesired_packages = descriptors |> Enum.flat_map(fn desc -> desc[:undesired_packages] || [] end)
		undesired_upgrades = descriptors |> Enum.flat_map(fn desc -> desc[:undesired_upgrades] || [] end)
		apt_keys           = descriptors |> Enum.flat_map(fn desc -> desc[:apt_keys]           || [] end)
		apt_sources        = descriptors |> Enum.flat_map(fn desc -> desc[:apt_sources]        || [] end)
		sysctl_parameters  = descriptors |> Enum.map(fn desc -> desc[:sysctl_parameters] || %{} end) |> Enum.reduce(%{}, fn(m, acc) -> Map.merge(acc, m) end)
		sysfs_variables    = descriptors |> Enum.map(fn desc -> desc[:sysfs_variables]   || %{} end) |> Enum.reduce(%{}, fn(m, acc) -> Map.merge(acc, m) end)
		pre_install_units  = descriptors |> Enum.map(fn desc -> desc[:pre_install_unit] end)         |> Enum.reject(&is_nil/1)
		post_install_units = descriptors |> Enum.map(fn desc -> desc[:post_install_unit] end)        |> Enum.reject(&is_nil/1)
		configure(
			tags,
			extra_desired_packages:   desired_packages,
			extra_undesired_packages: undesired_packages,
			extra_undesired_upgrades: undesired_upgrades,
			extra_apt_keys:           apt_keys,
			extra_apt_sources:        apt_sources,
			extra_pre_install_units:  pre_install_units,
			extra_post_install_units: post_install_units,
			extra_sysctl_parameters:  sysctl_parameters,
			extra_sysfs_variables:    sysfs_variables,
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

	def configure(tags, opts) do
		extra_apt_keys                 = opts[:extra_apt_keys]           || []
		extra_apt_sources              = opts[:extra_apt_sources]        || []
		extra_desired_packages         = opts[:extra_desired_packages]   || []
		extra_undesired_packages       = opts[:extra_undesired_packages] || []
		extra_undesired_upgrades       = opts[:extra_undesired_upgrades] || []
		extra_pre_install_units        = opts[:extra_pre_install_units]  || []
		extra_post_install_units       = opts[:extra_post_install_units] || []
		extra_sysctl_parameters        = opts[:extra_sysctl_parameters]  || %{}
		extra_sysfs_variables          = opts[:extra_sysfs_variables]    || %{}
		optimize_for_short_lived_files = "optimize_for_short_lived_files" in tags
		ipv6                           = "ipv6"                           in tags

		base_keys = [
			content("files/apt_keys/C0B21F32 Ubuntu Archive Automatic Signing Key (2012).txt"),
		]
		country      = Util.get_country()
		base_sources = [
			"deb http://#{country}.archive.ubuntu.com/ubuntu xenial          main restricted universe multiverse",
			"deb http://#{country}.archive.ubuntu.com/ubuntu xenial-updates  main restricted universe multiverse",
			"deb http://#{country}.archive.ubuntu.com/ubuntu xenial-security main restricted universe multiverse",
		]
		apt_keys     = base_keys    ++ extra_apt_keys
		apt_sources  = base_sources ++ extra_apt_sources

		# Check for transparent_hugepage because it is missing on scaleway kernels
		transparent_hugepage_variables = case File.exists?("/sys/kernel/mm/transparent_hugepage") do
			true -> %{
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
			false -> %{}
		end

		sysfs_variables = %{}
			|> Map.merge(transparent_hugepage_variables)
			|> Map.merge(extra_sysfs_variables)

		dirty_settings = get_dirty_settings(optimize_for_short_lived_files: optimize_for_short_lived_files)

		# TODO: min_free_kbytes
		# TODO: optimize network stack based on wikimedia-puppet
		base_sysctl_parameters = %{
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
			#
			# TODO: apply grkernsec_perf_harden.patch to our kernels to that setting '3'
			# actually completely disables access to perf for unprivileged users.
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
		}

		unprivileged_bpf_parameters = case File.exists?("/proc/sys/kernel/unprivileged_bpf_disabled") do
			true -> %{
				# CVE-2016-4557 allowed for local privilege escalation using unprivileged BPF.
				#
				# "only used for things like network profiling in userspace [...]; disabling
				# the bpf() does not mean disabling all BPF/eBPF. Netfilter still uses BPF,
				# seccomp still uses BPF, etc. All it means is that userspace network profiling
				# tools and such will not function."
				"kernel.unprivileged_bpf_disabled" => 1,
			}
			false -> %{}
		end

		sysctl_parameters =
			base_sysctl_parameters
			|> Map.merge(unprivileged_bpf_parameters)
			|> Map.merge(extra_sysctl_parameters)

		blacklisted_kernel_modules = [
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

			# TODO: blacklist overlay and overlayfs once we can whitelist it on sbuild
		]

		base_packages = [
			"apt",
			"aptitude",          # used by ObsoletePackagesPurged
			"apt-show-versions", # to be used by a NoPackagesNewerThanInSource
			"intel-microcode",
			"locales",           # needed for locale-gen below
			"console-setup",     # needed to change console font and not make keyboard-configuration error out on boot
			"cryptsetup",
			"util-linux",
			"nocache",
			"gdisk",
			"hdparm",
			"netbase",
			"ifupdown",
			"isc-dhcp-client",
			"rsyslog",
			"logrotate",
			"cron",
			"net-tools",
			"sudo",
			"openssh-server",
			"openssh-client",
			"rsync",
			"libpam-systemd",   # to make ssh server disconnect clients when it shuts down
			"ca-certificates",
			"gnupg2",
			"pollinate",        # for seeding RNG the very first time
			"vim-common",       # https://bugs.launchpad.net/ubuntu/+source/pollinate/+bug/1656484
			"chrony",
			"sysfsutils",       # for Sysfs unit and /sys configuration on boot
			"zsh",              # root's default shell
			"psmisc",           # for killall
			"acl",
			"apparmor",
			"apparmor-profiles",
			"curl",             # for Converge.Util.get_country
			"binutils",         # for ar, required by MetaPackageInstalled
			"pciutils",         # for lspci, (todo) used to determine whether we have an NVIDIA card
			"erlang-base-hipe", # for converge escripts
			"erlang-crypto",    # for converge escripts
		]
		human_admin_needs = [
			"molly-guard",
			"lshw",
			"net-tools",    # ifconfig, route, netstat
			"iputils-ping",
			"netcat-openbsd",
			"rlwrap",       # for use with netcat
			"less",
			"strace",
			"htop",
			"iotop",
			"dstat",
			"tmux",
			"git",
			"tig",
			"wget",
			"nano",
			"mtr-tiny",
			"nethogs",
			"iftop",
			"lsof",
			"pv",
			"tree",
			"dnsutils",     # dig
			"nmap",
			"whois",
		]
		all_desired_packages =
			boot_packages(get_boot_type(tags)) ++
			base_packages ++
			human_admin_needs ++
			extra_desired_packages
		# Packages to be purged, unless listed in all_desired_packages.  None of this
		# should be necessary on a minbase system, but we keep this here
		# 1) in case a package listed here ends up installed by accident or because it is depended-on
		# 2) to make base_system more useful on non-minbase systems
		undesired_packages = [
			# ureadahead has some very suspect code and spews messages to syslog
			# complaining about relative paths
			"ureadahead",

			# Time managers that should be purged because we want just chrony
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

			# apt will use either gnupg or gnupg2, and gnupg2 is less bad
			"gnupg",

			# Container technology that works until it doesn't
			"lxd",
			"lxcfs",
			"lxc-common",

			# Gave us names like em0 and em1 for network devices, but we don't want
			# this anywhere; we want systemd's predictable network interface names.
			"biosdevname",
		] ++ \
		extra_undesired_packages

		packages_to_purge = MapSet.difference(MapSet.new(undesired_packages), MapSet.new(all_desired_packages))

		units = [
			# Set up locale early to avoid complaints from programs
			%AfterMeet{
				unit:    conf_file("/etc/locale.gen"),
				trigger: fn -> {_, 0} = System.cmd("locale-gen", []) end
			},
			conf_file("/etc/default/locale"),

			# We need a git config with a name and email for etckeeper to work
			%DirectoryPresent{path: "/root/.config",     mode: 0o700},
			%DirectoryPresent{path: "/root/.config/git", mode: 0o700},
			%FilePresent{
				path:    "/root/.config/git/config",
				content: EEx.eval_string(content("files/root/.config/git/config.eex"), [hostname: Util.get_hostname()]),
				mode:    0o640
			},

			# Make sure etckeeper is installed, as it is required for the EtcCommitted units here
			%MetaPackageInstalled{name: "converge-desired-packages-early", depends: ["etckeeper"]},
			%EtcCommitted{message: "converge (early)"},

			# Fix this annoying warning:
			# N: Ignoring file '50unattended-upgrades.ucf-dist' in directory '/etc/apt/apt.conf.d/'
			# as it has an invalid filename extension
			%FileMissing{path: "/etc/apt/apt.conf.d/50unattended-upgrades.ucf-dist"},

			%FilePresent{
				path:      "/etc/apt/sources.list",
				content:   apt_sources ++ [""] |> Enum.join("\n"),
				# TODO: after we have _apt in a group, use 0o640 and group: ... to hide the custom-packages password
				mode:      0o644,
				user:      "root",
				#group:     "_apt",
				immutable: true
			},

			# We centralize management of our apt sources in /etc/apt/sources.list,
			# so remove anything that may be in /etc/apt/sources.list.d/
			%DirectoryPresent{path: "/etc/apt/sources.list.d",              mode: 0o755, immutable: true},
			%DirectoryEmpty{path: "/etc/apt/sources.list.d"},

			%GPGSimpleKeyring{path: "/etc/apt/trusted.gpg", keys: apt_keys, mode: 0o644, immutable: true},
			%DirectoryPresent{path: "/etc/apt/trusted.gpg.d",               mode: 0o755, immutable: true},
			# We centralize management of our apt sources in /etc/apt/trusted.gpg,
			# so remove anything that may be in /etc/apt/trusted.gpg.d/
			%DirectoryEmpty{path: "/etc/apt/trusted.gpg.d"},

			%FilePresent{path: "/etc/apt/preferences",        mode: 0o644, content: make_apt_preferences(extra_undesired_upgrades)},
			%DirectoryPresent{path: "/etc/apt/preferences.d", mode: 0o755, immutable: true},
			# We centralize management of our apt preferences in /etc/apt/preferences,
			# so remove anything that may be in /etc/apt/preferences.d/
			%DirectoryEmpty{path: "/etc/apt/preferences.d"},

			fstab_unit(),

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

			# Make sure this is cleared out after a google-chrome-* install drops a file here
			%DirectoryEmpty{path: "/etc/apt/sources.list.d"},

			# /lib/systemd/system/systemd-timesyncd.service.d/disable-with-time-daemon.conf
			# stops systemd-timesyncd from starting if chrony is installed, but systemd-timesyncd
			# may still be running if the system hasn't been rebooted.
			%SystemdUnitStopped{name: "systemd-timesyncd.service"},

			%Sysfs{variables: sysfs_variables},

			# util-linux drops a file to do a TRIM every week.  If we have servers
			# with SSDs that benefit from TRIM, we should probably do this some
			# other time.
			%FileMissing{path: "/etc/cron.weekly/fstrim"},

			%AfterMeet{
				unit:    %All{units: [
					# Use a lower value for DefaultTimeoutStopSec and a higher value for DefaultRestartSec.
					conf_file("/etc/systemd/system.conf"),

					# Disable systemd's atrocious "one ctrl-alt-del reboots the system" feature.
					# This does not affect the 7x ctrl-alt-del force reboot feature.
					%SymlinkPresent{path: "/etc/systemd/system/ctrl-alt-del.target", target: "/dev/null"},
				]},
				trigger: fn -> {_, 0} = System.cmd("systemctl", ["daemon-reload"]) end
			},

			%SystemdUnitStarted{name: "apparmor.service"},
			%AfterMeet{
				# Remove old file we installed
				unit:    %FileMissing{path: "/etc/apparmor.d/bin.tar"},
				trigger: fn -> {_, 0} = System.cmd("service", ["apparmor", "reload"]) end
			},

			%FilePresent{
				path:    "/etc/modprobe.d/base_system.conf",
				mode:    0o644,
				content: blacklisted_kernel_modules
				         |> Enum.map(fn module -> "blacklist #{module}\n" end)
				         |> Enum.join
			},

			# UTC timezone everywhere to avoid confusion and timezone-handling bugs
			conf_file("/etc/timezone"),

			# Install default /etc/environment to fix servers that may have an ancient/broken one
			conf_file("/etc/environment"),

			# Prevent sudo from caching credentials, because otherwise programs
			# in the same terminal may be able to unexpectedly `sudo` without asking.
			conf_file("/etc/sudoers.d/no-cred-caching"),

			# Lock /etc/resolv.conf to Google DNS servers and without any search domain
			conf_file("/etc/resolv.conf", 0o644, immutable: true),

			# Prevent non-root users from restarting or shutting down the system using the GUI.
			# This is mostly to prevent accidental restarts; the "Log Out" and "Restart" buttons
			# are right next to each other and "Restart" does not require confirmation.
			# http://askubuntu.com/questions/453479/how-to-disable-shutdown-reboot-from-lightdm-in-14-04/454230#454230
			conf_dir("/etc/polkit-1"),
			conf_dir("/etc/polkit-1/localauthority", 0o700),
			conf_dir("/etc/polkit-1/localauthority/50-local.d"),
			conf_file("/etc/polkit-1/localauthority/50-local.d/restrict-login-powermgmt.pkla"),

			# We don't use bash for the interactive shell, so there's no point in
			# dropping these files into every user's $HOME
			%FileMissing{path: "/etc/skel/.bashrc"},
			%FileMissing{path: "/etc/skel/.bash_logout"},
			%FileMissing{path: "/etc/skel/.profile"},

			conf_file("/etc/skel/.zshrc"),
			conf_file("/etc/issue"),
			conf_file("/etc/tmux.conf"),
			conf_file("/etc/nanorc"),
			conf_dir("/etc/nano.d"),
			conf_file("/etc/nano.d/elixir.nanorc"),
			conf_file("/etc/nano.d/git-commit-msg.nanorc"),

			conf_file("/etc/zsh/zsh-autosuggestions.zsh"),
			conf_file("/etc/zsh/zshrc-custom"),

			%FilePresent{
				path:    "/etc/zsh/zshrc",
				content: content("files/etc/zsh/zshrc.factory") <> "\n\n" <> "source /etc/zsh/zshrc-custom",
				mode:    0o644
			},

			%AfterMeet{
				unit: %FilePresent{
					path:    "/etc/chrony/chrony.conf",
					content: EEx.eval_string(content("files/etc/chrony/chrony.conf.eex"), [country: Util.get_country()]),
					mode:    0o644
				},
				trigger: fn -> {_, 0} = System.cmd("service", ["chrony", "restart"]) end
			},

			# Make sure root's shell is zsh
			%BeforeMeet{
				unit:    %UserPresent{name: "root", home: "/root", shell: "/bin/zsh"},
				# Make sure zsh actually works before setting root's shell to zsh
				trigger: fn -> {_, 0} = System.cmd("/bin/zsh", ["-c", "true"]) end
			},

			%Sysctl{parameters: sysctl_parameters},
			%All{units: boot_units(get_boot_type(tags), get_boot_resolution(tags))},
			%All{units: extra_post_install_units},
			%EtcCommitted{message: "converge"},
		]
		ctx = %Context{run_meet: true, reporter: TerminalReporter.new()}
		Runner.converge(%All{units: units}, ctx)
	end

	defp boot_packages("uefi"),               do: ["linux-image-generic", "grub-efi-amd64"]
	# outside = our boot is fully managed by the host, to the point where we don't
	# have to install a Linux kernel and bootloader.  You can use this on scaleway.
	defp boot_packages("outside"),            do: []
	defp boot_packages("scaleway_kexec"),     do: ["linux-image-generic", "scaleway-ubuntu-kernel"]
	defp boot_packages(_),                    do: ["linux-image-generic", "grub-pc"]

	defp boot_units("outside", _),            do: []
	# disabling kexec.service is "required as Ubuntu will kexec too early and leave a dirty filesystem"
	# https://github.com/stuffo/scaleway-ubuntukernel/tree/28f17d8231ad114034d8bbc684fc5afb9f902758#install
	defp boot_units("scaleway_kexec", _),     do: [%SystemdUnitDisabled{name: "kexec.service"},
	                                               %SystemdUnitEnabled{name: "scaleway-ubuntu-kernel.service"}]
	defp boot_units("mbr", _),                do: [%Grub{}]
	defp boot_units("uefi", boot_resolution), do: [%Grub{gfxpayload: boot_resolution}]
	# On a 1-core QEMU VM at Ablenet, our default-BFQ kernel hangs early in the boot unless we set the IO scheduler to deadline
	defp boot_units("ablenet_vps", _),        do: [%Grub{cmdline_normal_and_recovery: "elevator=deadline"}]
	defp boot_units("ovh_vps", _),            do: [%Grub{cmdline_normal_and_recovery: "console=tty1 console=ttyS0"}]
	defp boot_units("do_vps", _),             do: [%Grub{cmdline_normal_and_recovery: "console=tty1 console=ttyS0"}]
	defp boot_units("do_vps_2016", _),        do: [%Grub{cmdline_normal_and_recovery: "console=tty1 root=LABEL=DOROOT notsc clocksource=kvm-clock net.ifnames=0"}]

	defp get_boot_type(tags) do
		match = Enum.find(tags, fn tag -> tag |> String.starts_with?("boot:") end)
		[_, boot_type] = String.split(match, ":", parts: 2)
		boot_type
	end

	def get_boot_resolution(tags) do
		match = tags
			|> Enum.find(fn tag -> tag |> String.starts_with?("boot_resolution:") end)
		case match do
			nil -> nil
			res ->
				[_, boot_resolution] = String.split(res, ":", parts: 2)
				boot_resolution
		end
	end

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
		%AfterMeet{
			unit:    %Fstab{entries: fstab_entries},
			trigger: fstab_trigger
		}
	end

	defp get_dirty_settings(opts) do
		optimize_for_short_lived_files = Keyword.get(opts, :optimize_for_short_lived_files)
		gb                             = 1024 * 1024 * 1024
		memtotal                       = Util.get_meminfo()["MemTotal"] # bytes
		threshold                      = 14 * gb # bytes
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
			# On servers with >= 14GB RAM, try to reduce hangs caused by a large
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
					dirty_background_bytes: 1 * gb,
					dirty_bytes:            3 * gb,
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

	def make_apt_preferences(undesired_upgrades) do
		for upgrade <- undesired_upgrades do
			cond do
				upgrade[:version] != nil -> 
					"""
					Package: #{upgrade.name}
					Pin: version #{upgrade.version}
					Pin-Priority: -1
					"""
				upgrade[:distribution_codename] != nil ->
					"""
					Package: #{upgrade.name}
					Pin: release n=#{upgrade.distribution_codename}
					Pin-Priority: -1
					"""
				true ->
					raise(ArgumentError,
						"""
						Undesired upgrade descriptor #{inspect upgrade} had neither \
						a :version or :distribution_codename key.\
						""")
			end
		end
		|> Enum.join("\n")
	end
end
