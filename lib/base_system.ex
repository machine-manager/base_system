alias Gears.StringUtil
alias Converge.{
	Runner, Context, TerminalReporter, FilePresent, FileMissing, SymlinkPresent,
	DirectoryPresent, DirectoryEmpty, EtcCommitted, PackageIndexUpdated,
	MetaPackageInstalled, DanglingPackagesPurged, PackagesMarkedAutoInstalled,
	PackagesMarkedManualInstalled, PackagePurged, Fstab, FstabEntry, AfterMeet,
	BeforeMeet, Sysctl, Sysfs, Util, All, GPGSimpleKeyring, SystemdUnitStarted,
	SystemdUnitStopped, UserPresent
}

defmodule BaseSystem.Configure do
	@moduledoc """
	Converts a `debootstrap --variant=minbase` install of Ubuntu LTS into a
	useful Ubuntu system.

	Requires that these packages are already installed:
	`erlang-base-hipe erlang-crypto curl binutils`

	`curl` is needed for `Util.get_country`.

	`binutils`'s `ar` is needed for `MetaPackageInstalled`.
	"""
	require Util
	Util.declare_external_resources("files")

	defmacrop content(filename) do
		File.read!(filename)
	end

	def main(_args) do
		configure()
	end

	def configure(opts \\ []) do
		apt_keys = %{
			:ubuntu                 => content("files/apt_keys/C0B21F32 Ubuntu Archive Automatic Signing Key (2012).txt"),
			:custom_packages_local  => content("files/apt_keys/2AAA29C8 Custom Packages.txt"),
			:custom_packages_remote => content("files/apt_keys/2AAA29C8 Custom Packages.txt"),
			:google_chrome          => content("files/apt_keys/D38B4796 Google Inc. (Linux Packages Signing Authority).txt"),
			:oracle_virtualbox      => content("files/apt_keys/2980AECF Oracle Corporation (VirtualBox archive signing key).txt"),
			:graphics_drivers_ppa   => content("files/apt_keys/1118213C Launchpad PPA for Graphics Drivers Team.txt"),
			:wine_ppa               => content("files/apt_keys/77C899CB Launchpad PPA for Wine.txt"),
		}

		default_repositories = MapSet.new([
			:custom_packages_remote,
		])

		repositories                   = Keyword.get(opts, :repositories,                   default_repositories)
		tools_for_filesystems          = Keyword.get(opts, :tools_for_filesystems,          [:xfs])
		extra_desired_packages         = Keyword.get(opts, :extra_desired_packages,         [])
		extra_undesired_packages       = Keyword.get(opts, :extra_undesired_packages,       [])
		post_install_units             = Keyword.get(opts, :post_install_units,             [])
		optimize_for_short_lived_files = Keyword.get(opts, :optimize_for_short_lived_files, false)
		extra_sysctl_parameters        = Keyword.get(opts, :extra_sysctl_parameters,        %{})
		# Is our boot fully managed by the host, to the point where we don't have
		# to install a linux kernel and bootloader?  Use `true` for scaleway machines.
		outside_boot                   = Keyword.get(opts, :outside_boot,                   false)

		custom_packages = \
			:custom_packages_local  in repositories or
			:custom_packages_remote in repositories

		apt_trusted_gpg_keys = for repo <- repositories |> MapSet.put(:ubuntu) do
			apt_keys[repo]
		end

		boot_packages = case outside_boot do
			false -> ["linux-image-generic", "grub-pc | grub-efi-amd64"]
			true  -> []
		end
		base_packages = [
			"apt",
			"aptitude",          # used by ObsoletePackagesPurged
			"apt-show-versions", # to be used by a NoPackagesNewerThanInSource
			"intel-microcode",
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
		] ++ \
		case :xfs in tools_for_filesystems do
			true  -> ["xfsprogs", "xfsdump"]
			false -> []
		end ++ \
		case :zfs in tools_for_filesystems do
			true  -> ["zfsutils-linux"]
			false -> []
		end ++ \
		case :ext4 in tools_for_filesystems do
			true  -> ["e2fsprogs"]
			false -> []
		end ++ \
		# If using custom_packages_remote, assume custom-packages-client should be installed
		case :custom_packages_remote in repositories do
			true  -> ["custom-packages-client"]
			false -> []
		end
		human_admin_needs = [
			"molly-guard",
			"lshw",
			"net-tools",    # ifconfig, route, netstat
			"iputils-ping",
			"netcat-openbsd",
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
			"whois",
		] ++ \
		# If custom-packages is available, assume that some additional packages are also desired
		case custom_packages do
			true  -> ["ubuntils", "quickmunge", "pinned-git", "ripgrep"]
			false -> []
		end
		all_desired_packages = boot_packages ++ base_packages ++ human_admin_needs ++ extra_desired_packages
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
		] ++ \
		case outside_boot do
			# linux-zygote creates an install where linux-image-generic and grub-pc
			# are marked manual-installed, so we might need to purge these packages
			# for machines with `outside_boot`
			true  -> ["linux-image-generic", "grub-pc", "grub-efi-amd64"]
			false -> []
		end ++ \
		extra_undesired_packages

		packages_to_purge = MapSet.difference(MapSet.new(undesired_packages), MapSet.new(all_desired_packages))

		dirty_settings = get_dirty_settings(optimize_for_short_lived_files: optimize_for_short_lived_files)

		all = %All{units: [
			# Set up locale early to avoid complaints from programs
			%AfterMeet{
				unit: %FilePresent{
					path:    "/etc/locale.gen",
					content: content("files/etc/locale.gen"),
					mode:    0o644
				},
				trigger: fn -> {_, 0} = System.cmd("locale-gen", []) end
			},

			# We need a git config with a name and email for etckeeper to work
			%DirectoryPresent{path: "/root/.config",     mode: 0o700},
			%DirectoryPresent{path: "/root/.config/git", mode: 0o700},
			%FilePresent{
				path:    "/root/.config/git/config",
				content: EEx.eval_string(content("files/root/.config/git/config.eex"), [hostname: Util.get_hostname()]),
				mode:    0o640
			},

			# Make sure etckeeper is installed, as it is required for the EtcCommitted units here
			%BeforeMeet{
				unit:    %MetaPackageInstalled{name: "converge-desired-packages-early", depends: ["etckeeper"]},
				trigger: fn ctx -> Runner.converge(%PackageIndexUpdated{max_age: 30}, ctx) end
			},
			%PackagesMarkedAutoInstalled{names: ["converge-desired-packages-early"]},
			%EtcCommitted{message: "converge (early)"},

			%AfterMeet{
				unit: %All{units: [
					%FilePresent{
						path:      "/etc/apt/sources.list",
						content:   EEx.eval_string(content("files/etc/apt/sources.list.eex"),
						                           [country:      Util.get_country(),
						                            repositories: repositories])
						           |> StringUtil.remove_empty_lines,
						# TODO: after we have _apt in a group, use 0o640 and group: ...
						mode:      0o644,
						user:      "root",
						#group:     "_apt",
						immutable: true
					},

					# We centralize management of our apt sources in /etc/apt/sources.list,
					# so remove anything that may be in /etc/apt/sources.list.d/
					%DirectoryPresent{path: "/etc/apt/sources.list.d",                          mode: 0o755, immutable: true},
					%DirectoryEmpty{path: "/etc/apt/sources.list.d"},

					%GPGSimpleKeyring{path: "/etc/apt/trusted.gpg", keys: apt_trusted_gpg_keys, mode: 0o644, immutable: true},
					%DirectoryPresent{path: "/etc/apt/trusted.gpg.d",                           mode: 0o755, immutable: true},
					# We centralize management of our apt sources in /etc/apt/trusted.gpg,
					# so remove anything that may be in /etc/apt/trusted.gpg.d/
					%DirectoryEmpty{path: "/etc/apt/trusted.gpg.d"},
				]},
				trigger: fn -> Util.remove_cached_package_index() end
			},

			fstab_unit(),

			# Google Chrome installs symlinks at /etc/cron.daily/google-chrome*;
			# these scripts function as a little configuration manager that re-adds
			# apt keys and apt sources if they are missing (e.g. after an Ubuntu
			# upgrade).  Make these scripts no-ops to prevent them from re-adding
			# the obsolete 7FAC5991 key to apt's trusted keys, and to stop them
			# from mucking with /etc/apt/sources.list.d/
			#
			# Do this before installing Chrome, to prevent the cron.daily scripts
			# from being run at install time.
			%FilePresent{path: "/etc/default/google-chrome",          content: "exit 0\n", mode: 0o644},
			%FilePresent{path: "/etc/default/google-chrome-beta",     content: "exit 0\n", mode: 0o644},
			%FilePresent{path: "/etc/default/google-chrome-unstable", content: "exit 0\n", mode: 0o644},

			%BeforeMeet{
				unit: %MetaPackageInstalled{
					name:    "converge-desired-packages",
					depends: ["converge-desired-packages-early"] ++ all_desired_packages
				},
				trigger: fn ctx -> Runner.converge(%PackageIndexUpdated{max_age: 30}, ctx) end,
			},
			%PackagesMarkedManualInstalled{names: ["converge-desired-packages"]},
			# This comes after MetaPackageInstalled because the undesired gnupg
			# must be purged *after* installing gnupg2.
			%All{units: packages_to_purge |> Enum.map(fn name -> %PackagePurged{name: name} end)},
			%DanglingPackagesPurged{},

			# Make sure this is cleared out after a google-chrome-* install drops a file here
			%DirectoryEmpty{path: "/etc/apt/sources.list.d"},

			# /lib/systemd/system/systemd-timesyncd.service.d/disable-with-time-daemon.conf
			# stops systemd-timesyncd from starting if chrony is installed, but systemd-timesyncd
			# may still be running if the system hasn't been rebooted.
			%SystemdUnitStopped{name: "systemd-timesyncd.service"},

			%Sysfs{variables: %{
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
			}},

			# The scripts in /etc/cron.daily/ are already no-op'ed by the /etc/default/google-chrome-*
			# files, but delete them anyway because we don't need them.  Note that
			# they will re-appear after every Chrome upgrade.  (We can't set them to
			# blank chattr +i'ed files because that breaks upgrades.)
			%FileMissing{path: "/etc/cron.daily/google-chrome"},
			%FileMissing{path: "/etc/cron.daily/google-chrome-beta"},
			%FileMissing{path: "/etc/cron.daily/google-chrome-unstable"},

			# zfsutils-linux drops a file to do a scrub on the second Sunday of every month
			%FileMissing{path: "/etc/cron.d/zfsutils-linux"},

			# util-linux drops a file to do a TRIM every week.  If we have servers
			# with SSDs that benefit from TRIM, we should probably do this some
			# other time.
			%FileMissing{path: "/etc/cron.weekly/fstrim"},

			%AfterMeet{
				unit:    %All{units: [
					# Use a lower value for DefaultTimeoutStopSec and a higher value for DefaultRestartSec.
					%FilePresent{path: "/etc/systemd/system.conf",    content: content("files/etc/systemd/system.conf"),          mode: 0o644},

					# Disable systemd's atrocious "one ctrl-alt-del reboots the system" feature.
					# This does not affect the 7x ctrl-alt-del force reboot feature.
					%SymlinkPresent{path: "/etc/systemd/system/ctrl-alt-del.target", target: "/dev/null"},
				]},
				trigger: fn -> {_, 0} = System.cmd("systemctl", ["daemon-reload"]) end
			},

			%SystemdUnitStarted{name: "apparmor.service"},
			%AfterMeet{
				unit: %FilePresent{
					path:    "/etc/apparmor.d/bin.tar",
					content: content("files/etc/apparmor.d/bin.tar"),
					mode:    0o644
				},
				trigger: fn -> {_, 0} = System.cmd("service", ["apparmor", "reload"]) end
			},

			# Disable the Intel Management Engine Interface driver, which we do not need
			# and may introduce network attack vectors.
			%FilePresent{path: "/etc/modprobe.d/no-mei.conf",       content: content("files/etc/modprobe.d/no-mei.conf"),       mode: 0o644},

			# Disable Firewire, which we do not use and may introduce physical attack vectors.
			%FilePresent{path: "/etc/modprobe.d/no-firewire.conf",  content: content("files/etc/modprobe.d/no-firewire.conf"),  mode: 0o644},

			# UTC timezone everywhere to avoid confusion and timezone-handling bugs
			%FilePresent{path: "/etc/timezone",                     content: content("files/etc/timezone"),                     mode: 0o644},

			# Prevent sudo from caching credentials, because otherwise programs
			# in the same terminal may be able to unexpectedly `sudo` without asking.
			%FilePresent{path: "/etc/sudoers.d/no-cred-caching",    content: content("files/etc/sudoers.d/no-cred-caching"),    mode: 0o644},

			# Lock /etc/resolv.conf to Google DNS servers and without any search domain
			%FilePresent{path: "/etc/resolv.conf",                  content: content("files/etc/resolv.conf"),                  mode: 0o644, immutable: true},

			# Prevent non-root users from restarting or shutting down the system using the GUI.
			# This is mostly to prevent accidental restarts; the "Log Out" and "Restart" buttons
			# are right next to each other and "Restart" does not require confirmation.
			# http://askubuntu.com/questions/453479/how-to-disable-shutdown-reboot-from-lightdm-in-14-04/454230#454230
			%DirectoryPresent{path: "/etc/polkit-1",                                                                            mode: 0o755},
			%DirectoryPresent{path: "/etc/polkit-1/localauthority",                                                             mode: 0o700}, # it ships as 0700
			%DirectoryPresent{path: "/etc/polkit-1/localauthority/50-local.d",                                                  mode: 0o755},
			%FilePresent{
				path:    "/etc/polkit-1/localauthority/50-local.d/restrict-login-powermgmt.pkla",
				content: content("files/etc/polkit-1/localauthority/50-local.d/restrict-login-powermgmt.pkla"),
				mode:    0o644
			},

			# We don't use bash for the interactive shell, so there's no point in
			# dropping these files into every user's $HOME
			%FileMissing{path: "/etc/skel/.bashrc"},
			%FileMissing{path: "/etc/skel/.bash_logout"},
			%FileMissing{path: "/etc/skel/.profile"},

			%FilePresent{path: "/etc/skel/.zshrc",                  content: content("files/etc/skel/.zshrc"),                  mode: 0o644},

			%FilePresent{path: "/etc/issue",                        content: content("files/etc/issue"),                        mode: 0o644},
			%FilePresent{path: "/etc/tmux.conf",                    content: content("files/etc/tmux.conf"),                    mode: 0o644},
			%FilePresent{path: "/etc/nanorc",                       content: content("files/etc/nanorc"),                       mode: 0o644},
			%DirectoryPresent{path: "/etc/nano.d",                                                                              mode: 0o755},
			%FilePresent{path: "/etc/nano.d/elixir.nanorc",         content: content("files/etc/nano.d/elixir.nanorc"),         mode: 0o644},
			%FilePresent{path: "/etc/nano.d/git-commit-msg.nanorc", content: content("files/etc/nano.d/git-commit-msg.nanorc"), mode: 0o644},

			%FilePresent{path: "/etc/zsh/zsh-autosuggestions.zsh",  content: content("files/etc/zsh/zsh-autosuggestions.zsh"),  mode: 0o644},
			%FilePresent{
				path:    "/etc/zsh/zshrc-custom",
				content: EEx.eval_string(content("files/etc/zsh/zshrc-custom.eex"), [custom_packages: custom_packages]),
				mode:    0o644
			},
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

			# TODO: min_free_kbytes
			%Sysctl{parameters: Map.merge(%{
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
			}, extra_sysctl_parameters)},
		] ++ \
			post_install_units ++ \
		[
			%EtcCommitted{message: "converge"}
		]}
		ctx = %Context{run_meet: true, reporter: TerminalReporter.new()}
		Runner.converge(all, ctx)
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
end
