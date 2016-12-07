alias Converge.{
	Runner, Context, TerminalReporter, FilePresent, DirectoryPresent, EtcCommitted, MetaPackageInstalled,
	DanglingPackagesPurged, PackagesMarkedAutoInstalled, PackagePurged, Trigger, Assert, All}

defmodule BaseSystem.Country do
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
end

defmodule BaseSystem.Configure do
	@moduledoc """
	Converts a `debootstrap --variant=minbase` install of Ubuntu LTS into a
	useful Ubuntu system.

	Requires that these packages are already installed: erlang-base-hipe curl
	"""

	defmacro content(filename) do
		File.read!(filename)
	end

	def main(_args) do
		base_packages = ~w(
			linux-image-generic grub-pc netbase ifupdown isc-dhcp-client rsyslog
			cron net-tools iputils-ping openssh-server molly-guard chrony less
			strace zsh psmisc acl apparmor apparmor-profiles)
		human_admin_needs = ~w(
			htop dstat tmux git tig wget curl nano mtr-tiny nethogs iftop lsof
			software-properties-common ppa-purge rsync pv tree)

		all = %All{units: [
			%FilePresent{
				path:    "/etc/apt/sources.list",
				content: EEx.eval_string(content("files/etc/apt/sources.list"), [country: get_country()]),
				mode:    0o644
			},
			%DirectoryExists{path: "/var/custom-packages"},
			%PackageIndexUpdated{},
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
			%FilePresent{path: "/etc/sudoers.d/no_cred_caching",    content: content("files/etc/sudoers.d/no_cred_caching"),    mode: 0o644},
			%FilePresent{path: "/etc/apparmor.d/bin.tar",           content: content("files/etc/apparmor.d/bin.tar"),           mode: 0o644},
			%FilePresent{path: "/etc/resolv.conf",                  content: content("files/etc/resolv.conf"),                  mode: 0o644, immutable: true},
			%FilePresent{path: "/etc/tmux.conf",                    content: content("files/etc/tmux.conf"),                    mode: 0o644},
			%FilePresent{path: "/etc/nanorc",                       content: content("files/etc/nanorc"),                       mode: 0o644},
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
		]}
		ctx = %Context{run_meet: true, reporter: TerminalReporter.new()}
		Runner.converge(all, ctx)
	end
end
