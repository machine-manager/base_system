alias Converge.{Runner, Context, StandardReporter, FilePresent, MetaPackageInstalled, PackagePurged, Trigger, Assert, All}

defmodule BaseSystem do
	defmacro content(filename) do
		File.read!(filename)
	end

	def main(_args) do
		all = %All{units: [
			%FilePresent{path: "/etc/nanorc",    content: content("files/etc/nanorc"),    mode: 0o644},
			%Trigger{
				unit:    %FilePresent{path: "/etc/tmux.conf", content: content("files/etc/tmux.conf"), mode: 0o644},
				trigger: fn -> {_, 0} = System.cmd("service", ["cups", "restart"]) end
			},
			%Assert{unit: %PackagePurged{name: "ureadahead"}}
		]}
		ctx = %Context{run_meet: true, reporter: StandardReporter.new()}
		Runner.converge(all, ctx)
	end
end
