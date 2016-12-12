alias Converge.{
	Runner, Context, TerminalReporter, FilePresent, FileMissing, SymlinkPresent,
	DirectoryPresent, EtcCommitted, PackageIndexUpdated, MetaPackageInstalled,
	DanglingPackagesPurged, PackagesMarkedAutoInstalled,
	PackagesMarkedManualInstalled, PackagePurged, Fstab, FstabEntry, Trigger,
	Assert, All
}

defmodule BaseSystem.Gather do
	@country_file "/etc/country"

	@doc """
	Determines which country this server is located in, returning a lowercase
	two-letter country code.

	Writes the cached country to `/etc/country` so that we don't have to ask
	the Internet again.
	"""
	def get_country() do
		case File.read(@country_file) do
			{:ok, content} -> content |> String.trim_trailing()
			_              ->
				{out, 0} = System.cmd("curl", ["-q", "--silent", "http://freegeoip.net/json/"])
				country =
					Regex.run(~r/"country_code": ?"(..)"/, out, [capture: :all_but_first])
					|> hd
					|> String.downcase
				File.write(@country_file, country)
				File.chmod!(@country_file, 0o644)
				country
		end
	end

	def get_hostname() do
		File.read!("/etc/hostname") |> String.trim_trailing()
	end
end

defmodule BaseSystem.Configure do
	@moduledoc """
	Converts a `debootstrap --variant=minbase` install of Ubuntu LTS into a
	useful Ubuntu system.

	Requires that these packages are already installed: erlang-base-hipe curl
	"""
	import BaseSystem.Gather

	defmacro content(filename) do
		File.read!(filename)
	end

	def main(_args) do
		# Notes:
		# libpam-systemd - to make ssh server disconnect clients when it shuts down
		# psmisc         - for killall
		base_packages = ~w(
			linux-image-generic grub-pc netbase ifupdown isc-dhcp-client rsyslog
			cron net-tools sudo openssh-server libpam-systemd chrony zsh psmisc
			acl apparmor apparmor-profiles)
		human_admin_needs = ~w(
			molly-guard iputils-ping less strace htop dstat tmux git tig wget curl
			nano mtr-tiny nethogs iftop lsof software-properties-common ppa-purge
			rsync pv tree)

		all = %All{units: [
			%FilePresent{
				path:    "/etc/apt/sources.list",
				content: EEx.eval_string(content("files/etc/apt/sources.list.eex"), [country: get_country()]),
				mode:    0o644
			},
			%DirectoryPresent{path: "/var/custom-packages", mode: 0o700},
			%PackageIndexUpdated{},
			%MetaPackageInstalled{name: "converge-desired-packages-early", depends: ["etckeeper"]},
			%PackagesMarkedAutoInstalled{names: ["converge-desired-packages-early"]},

			# We need a git config with a name and email for etckeeper to work
			%DirectoryPresent{path: "/root/.config",     mode: 0o700},
			%DirectoryPresent{path: "/root/.config/git", mode: 0o700},
			%FilePresent{
				path:    "/root/.config/git/config",
				content: EEx.eval_string(content("files/root/.config/git/config.eex"), [hostname: get_hostname()]),
				mode:    0o640
			},
			%EtcCommitted{message: "converge (early)"},

			# ureadahead has some very suspect code and spews messages to syslog
			# complaining about relative paths
			%Assert{unit: %PackagePurged{name: "ureadahead"}},

			# Make sure no time managers besides chrony are installed
			%Assert{unit: %PackagePurged{name: "ntpdate"}},
			%Assert{unit: %PackagePurged{name: "adjtimex"}},
			%Assert{unit: %PackagePurged{name: "ntp"}},
			%Assert{unit: %PackagePurged{name: "openntpd"}},

			# Make sure that we don't have superfluous stuff that we would find
			# on a non-minbase install
			%Assert{unit: %PackagePurged{name: "snapd"}},
			# We probably don't have many computers that need thermald because the
			# BIOS and kernel also take actions to keep the CPU cool.
			# https://01.org/linux-thermal-daemon/documentation/introduction-thermal-daemon
			%Assert{unit: %PackagePurged{name: "thermald"}},
			%Assert{unit: %PackagePurged{name: "unattended-upgrades"}},
			%Assert{unit: %PackagePurged{name: "libnss-mdns"}},
			%Assert{unit: %PackagePurged{name: "avahi-daemon"}},
			# Having this installed loads the btrfs kernel module and slows down
			# the boot with a scan for btrfs volumes.
			%Assert{unit: %PackagePurged{name: "btrfs-tools"}},

			fstab_unit(),

			%MetaPackageInstalled{
				name:    "converge-desired-packages",
				depends: ["converge-desired-packages-early"] ++ base_packages ++ human_admin_needs},
			%PackagesMarkedManualInstalled{names: ["converge-desired-packages"]},
			%DanglingPackagesPurged{},

			# zfsutils-linux drops a file to do a scrub on the second Sunday of every month
			%FileMissing{path: "/etc/cron.d/zfsutils-linux"},

			# util-linux drops a file to do a TRIM every week.  If we have servers
			# with SSDs that benefit from TRIM, we should probably do this some
			# other time.
			%FileMissing{path: "/etc/cron.weekly/fstrim"},

			# Disable systemd's atrocious "one ctrl-alt-del reboots the system" feature.
			# This does not affect the 7x ctrl-alt-del force reboot feature.
			%Trigger{
				unit:    %SymlinkPresent{path: "/etc/systemd/system/ctrl-alt-del.target", target: "/dev/null"},
				trigger: fn -> {_, 0} = System.cmd("systemctl", ["daemon-reload"]) end
			},

			%Trigger{
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

			%FilePresent{path: "/etc/issue",                        content: content("files/etc/issue"),                        mode: 0o644},
			%FilePresent{path: "/etc/tmux.conf",                    content: content("files/etc/tmux.conf"),                    mode: 0o644},
			%FilePresent{path: "/etc/nanorc",                       content: content("files/etc/nanorc"),                       mode: 0o644},
			%DirectoryPresent{path: "/etc/nano.d",                                                                              mode: 0o755},
			%FilePresent{path: "/etc/nano.d/elixir.nanorc",         content: content("files/etc/nano.d/elixir.nanorc"),         mode: 0o644},
			%FilePresent{path: "/etc/nano.d/git-commit-msg.nanorc", content: content("files/etc/nano.d/git-commit-msg.nanorc"), mode: 0o644},

			%FilePresent{path: "/etc/zsh/zshrc-custom",             content: content("files/etc/zsh/zshrc-custom"),             mode: 0o644},
			%FilePresent{path: "/etc/zsh/zsh-autosuggestions.zsh",  content: content("files/etc/zsh/zsh-autosuggestions.zsh"),  mode: 0o644},
			%FilePresent{
				path:    "/etc/zsh/zshrc",
				content: content("files/etc/zsh/zshrc.factory") <> "\n\n" <> "source /etc/zsh/zshrc-custom",
				mode:    0o644
			},

			%Trigger{
				unit: %FilePresent{
					path:    "/etc/chrony/chrony.conf",
					content: EEx.eval_string(content("files/etc/chrony/chrony.conf.eex"), [country: get_country()]),
					mode:    0o644
				},
				trigger: fn -> {_, 0} = System.cmd("service", ["chrony", "restart"]) end
			},

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
				options:          "nodev,noexec,nosuid,hidepid=2",
				fsck_pass_number: 0
			}
		] |> Enum.filter(&(&1 != nil))
		fstab_trigger = fn ->
			{_, 0} = System.cmd("mount", ["-o", "remount", "/proc"])
		end
		%Trigger{
			unit:    %Fstab{entries: fstab_entries},
			trigger: fstab_trigger
		}
	end
end
