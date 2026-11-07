defmodule EtherNetIP.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/tallakt/yaethernetip"

  def project do
    [
      app: :yaethernetip,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: if(Mix.env() == :test, do: ["lib", "test/support"], else: ["lib"]),
      description:
        "EtherNet/IP in pure Elixir: a scanner for remote I/O such as Beckhoff and Wago " <>
          "couplers, with cyclic I/O connections and explicit CIP messaging, and an adapter " <>
          "that makes the BEAM a device a PLC can scan.",
      package: package(),
      source_url: @source_url,
      docs: docs(),
      test_coverage: [summary: [threshold: 80]],
      dialyzer: [
        # Kept between runs, and between CI jobs by its cache.
        plt_core_path: "priv/plts",
        plt_local_path: "priv/plts",
        flags: [:error_handling, :extra_return, :unmatched_returns]
      ]
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs .formatter.exs README.md CHANGELOG.md LICENSE NOTICE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md", "LICENSE", "NOTICE"],
      source_ref: "v#{@version}"
    ]
  end

  def application do
    [mod: {EtherNetIP.Application, []}, extra_applications: [:logger]]
  end

  defp deps do
    [
      # Only for the fuzz and property tests.
      {:stream_data, "~> 1.1", only: :test},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end
end
