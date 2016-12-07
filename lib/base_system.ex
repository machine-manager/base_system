alias Converge.{
	Runner, Context, TerminalReporter, FilePresent, EtcCommitted, MetaPackageInstalled,
	DanglingPackagesPurged, PackagesMarkedAutoInstalled, PackagePurged, Trigger, Assert, All}

defmodule BaseSystem do
	@moduledoc """
	Converts a `debootstrap --variant=minbase` install of Ubuntu LTS into a
	useful Ubuntu system.
	"""

	defmacro content(filename) do
		File.read!(filename)
	end

	def main(_args) do
		base_packages = ~w(
			linux-image-generic grub-pc netbase ifupdown isc-dhcp-client rsyslog
			cron net-tools iputils-ping openssh-server molly-guard chrony less
			strace zsh psmisc acl)
		human_admin_needs = ~w(
			htop dstat tmux git tig wget nano mtr-tiny nethogs iftop lsof
			software-properties-common ppa-purge rsync pv tree)

		all = %All{units: [
			%MetaPackageInstalled{name: "converge-desired-packages-early", depends: ["etckeeper"]},
			%PackagesMarkedAutoInstalled{name: "converge-desired-packages-early"},

			# ureadahead has some very suspect code and spews messages to syslog
			# complaining about relative paths
			%Assert{unit: %PackagePurged{name: "ureadahead"}},

			# Make sure no time managers besides chrony are installed
			%Assert{unit: %PackagePurged{name: "ntpdate"}},
			%Assert{unit: %PackagePurged{name: "adjtimex"}},
			%Assert{unit: %PackagePurged{name: "ntp"}},
			%Assert{unit: %PackagePurged{name: "openntpd"}},

			%MetaPackageInstalled{
				name: "converge-desired-packages",
				depends: ["converge-desired-packages-early"] ++ base_packages ++ human_admin_needs},
			%DanglingPackagesPurged{},

			%FilePresent{path: "/etc/timezone",                     content: content("files/etc/timezone"),                     mode: 0o644},
			%FilePresent{path: "/etc/nanorc",                       content: content("files/etc/nanorc"),                       mode: 0o644},
			%FilePresent{path: "/etc/nano.d/elixir.nanorc",         content: content("files/etc/nano.d/elixir.nanorc"),         mode: 0o644},
			%FilePresent{path: "/etc/nano.d/git-commit-msg.nanorc", content: content("files/etc/nano.d/git-commit-msg.nanorc"), mode: 0o644},
			%Trigger{
				unit:    %FilePresent{path: "/etc/tmux.conf", content: content("files/etc/tmux.conf"), mode: 0o644},
				trigger: fn -> {_, 0} = System.cmd("service", ["cups", "restart"]) end
			},
			%Assert{unit: %PackagePurged{name: "ureadahead"}}
		]}
		ctx = %Context{run_meet: true, reporter: TerminalReporter.new()}
		Runner.converge(all, ctx)
	end
end
