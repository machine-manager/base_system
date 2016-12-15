defmodule BaseSystem.Mixfile do
	use Mix.Project

	def project do
		[
			app: :base_system,
			version: "0.1.0",
			elixir: ">= 1.4.0",
			build_embedded: Mix.env == :prod,
			start_permanent: Mix.env == :prod,
			elixirc_options: debug_info(Mix.env),
			escript: escript(),
			deps: deps()
		]
	end

	defp debug_info(:prod), do: [debug_info: false]
	defp debug_info(_),     do: [debug_info: true]

	def escript do
		[main_module: BaseSystem.Configure]
	end

	def application do
		[extra_applications: [:eex]]
	end

	defp deps do
		[{:converge, ">= 0.1.0"}]
	end
end
