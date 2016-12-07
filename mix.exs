defmodule BaseSystem.Mixfile do
	use Mix.Project

	def project do
		[
			app: :base_system,
			version: "0.1.0",
			elixir: ">= 1.4.0",
			build_embedded: Mix.env == :prod,
			start_permanent: Mix.env == :prod,
			escript: escript(),
			deps: deps()
		]
	end

	def escript do
		[main_module: BaseSystem.Configure]
	end

	defp deps do
		[{:converge, ">= 0.1.0"}]
	end
end
