defmodule BaseSystem.Mixfile do
	use Mix.Project

	def project do
		[
			app:             :base_system,
			version:         "0.1.0",
			elixir:          ">= 1.4.0",
			build_embedded:  Mix.env == :prod,
			start_permanent: Mix.env == :prod,
			deps:            deps()
		]
	end

	def application do
		[extra_applications: [:eex]]
	end

	defp deps do
		[
			{:converge, ">= 0.1.0"},
			{:gears,    ">= 0.1.0"},
			{:poison,   ">= 3.1.0"},
		]
	end
end
