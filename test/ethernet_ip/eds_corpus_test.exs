defmodule EtherNetIP.EDSCorpusTest do
  # Every EDS file under EDS_CORPUS, a folder of vendors' files, which stay out of this repository:
  # each must be read, and the connections it has that the scanner can't open are counted by why.
  #
  #     EDS_CORPUS=~/eds mix test --only eds_corpus
  use ExUnit.Case, async: true

  alias EtherNetIP.EDS

  @moduletag :eds_corpus
  @moduletag timeout: :infinity

  test "every file is read, and its connections given or refused" do
    root = System.fetch_env!("EDS_CORPUS") |> Path.expand()

    files =
      for path <- Path.wildcard(Path.join(root, "**/*")),
          Path.extname(path) =~ ~r/^\.eds$/i,
          do: path

    results = for path <- files, do: {Path.relative_to(path, root), EDS.read(path)}

    unread =
      for {path, {:error, reason}} <- results, do: "#{path}: #{EtherNetIP.describe(reason)}"

    outcomes =
      for {_path, {:ok, eds}} <- results, c <- EDS.connections(eds) do
        case EDS.connection(eds, c.number) do
          {:ok, _options} -> :ok
          {:error, {:unsupported, {kind, _detail}}} -> {:unsupported, kind}
          {:error, {:unsupported, kind}} -> {:unsupported, kind}
          {:error, {kind, _detail}} -> kind
          {:error, kind} -> kind
        end
      end

    tally = outcomes |> Enum.frequencies() |> Enum.sort_by(&(-elem(&1, 1)))

    IO.puts("""

    #{length(files)} files, #{length(files) - length(unread)} read; #{length(outcomes)} connections:
    #{Enum.map_join(tally, "\n", fn {outcome, n} -> "  #{n}\t#{inspect(outcome)}" end)}
    """)

    assert unread == []
  end
end
