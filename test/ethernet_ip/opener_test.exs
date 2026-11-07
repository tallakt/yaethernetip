defmodule EtherNetIP.OpENerTest do
  # Against OpENer's sample application, as a device on another machine at OPENER, the
  # host: a black box, of which these know what its EDS says and what it answers. Its assemblies
  # are 100 for inputs, 150 for outputs and 151 for configuration, of 32, 32 and 10 bytes, and
  # 152 and 153 are the heartbeats of input-only and listen-only connections; it takes RPIs from
  # 20 ms, and scheduled priority only. Its application copies its outputs to its inputs.
  #
  # The tests take turns, as they share the device, and each closes its connections.
  use ExUnit.Case, async: false

  alias EtherNetIP.{Identity, Scanner}

  @moduletag :opener

  @owner [config: 151, output: 150, input: 100, output_size: 32, input_size: 32, rpi: 20_000]
  @input_only [
    config: 151,
    output: 152,
    input: 100,
    output_size: 0,
    input_size: 32,
    output_format: :heartbeat,
    rpi: 20_000
  ]
  @listen_only Keyword.put(@input_only, :output, 153)

  defp scanner(connections, opts \\ []) do
    opts = [host: System.fetch_env!("OPENER"), connections: connections] ++ opts

    start_supervised!(Supervisor.child_spec({Scanner, opts}, id: make_ref(), restart: :temporary))
  end

  defp connection(spec, more), do: Keyword.merge(spec, [subscriber: self()] ++ more)

  defp outputs(first), do: :binary.list_to_bin(Enum.map(0..31, &rem(first + &1, 256)))

  # Inputs of `name` until they are `inputs`, as the device copies the outputs to them.
  defp await_inputs(name, inputs, timeout \\ 2_000) do
    receive do
      {Scanner, ^name, {:inputs, ^inputs}} -> :ok
      {Scanner, ^name, {:inputs, _other}} -> await_inputs(name, inputs, timeout)
    after
      timeout -> flunk("#{name} never had inputs #{inspect(inputs)}")
    end
  end

  test "answers explicit messages" do
    scanner = scanner([])

    assert {:ok, %Identity{} = identity} = Scanner.identity(scanner)
    assert identity.vendor_id == 1
    assert identity.device_type == 12
    assert identity.product_code == 65_001
    assert identity.revision == {2, 3}
    assert identity.product_name == "OpENer PC"

    assert {:ok, <<_::binary-32>>} = Scanner.get_attribute_single(scanner, 4, 100, 3)

    assert {:error, {:cip, _status, _additional}} =
             Scanner.get_attribute_single(scanner, 0x99, 1, 1)
  end

  test "an exclusive owner sends its outputs and takes its inputs" do
    scanner = scanner(owner: connection(@owner, []))
    assert_receive {Scanner, :owner, {:status, :open}}, 2_000

    :ok = Scanner.put(scanner, :owner, outputs(1))
    await_inputs(:owner, outputs(1))
    assert Scanner.get_attribute_single(scanner, 4, 150, 3) == {:ok, outputs(1)}
    assert Scanner.inputs(scanner, :owner) == {:ok, outputs(1)}

    :ok = Scanner.put(scanner, :owner, outputs(2))
    await_inputs(:owner, outputs(2))
  end

  test "multicast inputs go to the owner and to input-only and listen-only connections" do
    scanner =
      scanner(
        owner: connection(@owner, multicast: true),
        input_only: connection(@input_only, multicast: true),
        listen_only: connection(@listen_only, multicast: true)
      )

    for name <- [:owner, :input_only, :listen_only],
        do: assert_receive({Scanner, ^name, {:status, :open}}, 5_000)

    :ok = Scanner.put(scanner, :owner, outputs(3))
    for name <- [:owner, :input_only, :listen_only], do: await_inputs(name, outputs(3))

    # the producer chose one id for all three
    assert Scanner.connections(scanner) == %{owner: :open, input_only: :open, listen_only: :open}
  end

  test "a connection the device can't make is refused, and says why" do
    scanner(owner: connection(@owner, output_size: 30))
    assert_receive {Scanner, :owner, {:status, {:failed, reason}}}, 2_000
    assert reason == {:connection_failure, :invalid_o_t_connection_size, [32 + 6]}
  end

  test "its EDS gives the connections" do
    {:ok, eds} = EtherNetIP.EDS.read(Path.expand("../fixtures/opener.eds", __DIR__))

    connections =
      for {name, which} <- [
            owner: "Exclusive Owner",
            input_only: "Input Only",
            listen_only: "Listen Only"
          ] do
        {:ok, connection} =
          EtherNetIP.EDS.connection(eds, which, multicast: true, subscriber: self())

        {name, connection}
      end

    scanner = scanner(connections)

    for name <- [:owner, :input_only, :listen_only],
        do: assert_receive({Scanner, ^name, {:status, :open}}, 5_000)

    :ok = Scanner.put(scanner, :owner, outputs(4))
    for name <- [:owner, :input_only, :listen_only], do: await_inputs(name, outputs(4))
  end

  # The kill is in the log.
  @tag :capture_log
  test "a scanner that restarts takes back a connection it didn't close" do
    first = scanner(owner: connection(@owner, []))
    assert_receive {Scanner, :owner, {:status, :open}}, 2_000

    # gone without a Forward_Close, as when its node fails
    Process.exit(first, :kill)

    scanner(owner: connection(@owner, []))
    assert_receive {Scanner, :owner, {:status, :open}}, 2_000
  end
end
