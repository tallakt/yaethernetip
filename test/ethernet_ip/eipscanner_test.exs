defmodule EtherNetIP.EIPScannerTest do
  # The adapter against EIPScanner, an open-source scanner in C++, as a black box: the program of
  # test/interop/eipscanner, built against it, is the command EIPSCANNER (over ssh, for one on
  # another machine), given this machine's address and broadcast address. It finds the adapter by
  # broadcast, reads its identity, writes and reads an assembly, has Forward_Opens refused and
  # granted, runs an exclusive owner and an input only connection for 5 s, closes them, opens
  # again and leaves that one to time out, and prints PASS or FAIL for each check. The adapter has
  # OpENer's layout, copies its outputs to its inputs, and takes ports 44818 and 2222, which the
  # program expects.
  use ExUnit.Case, async: false

  alias EtherNetIP.Adapter

  @moduletag :eipscanner
  @moduletag timeout: 120_000

  @adapter [
    identity: [vendor_id: 0xFFFF, product_code: 77, product_name: "yaethernetip peer"],
    inputs: %{100 => 32},
    outputs: %{150 => 32},
    configuration: %{151 => 10},
    input_only: 152,
    listen_only: 153
  ]

  test "EIPScanner finds the adapter, reads and writes it, and runs connections to it" do
    test = self()
    echo = spawn_link(fn -> echo(test) end)
    adapter = start_supervised!({Adapter, [subscriber: echo] ++ @adapter})
    send(echo, {:adapter, adapter})

    {address, broadcast} = local_address()
    [command | args] = String.split(System.fetch_env!("EIPSCANNER"))
    {output, status} = System.cmd(command, args ++ [address, broadcast], stderr_to_stdout: true)

    lines = String.split(output, "\n")
    assert [] == for("FAIL " <> check <- lines, do: check), output
    assert 16 == length(for("PASS " <> check <- lines, do: check)), output
    assert status == 0, output

    assert events() == [
             {:opened, :exclusive_owner},
             {:opened, :input_only},
             {:state, :run},
             {:closed, :exclusive_owner, :closed},
             {:state, :closed},
             {:closed, :input_only, :closed},
             {:opened, :exclusive_owner},
             {:state, :run},
             {:closed, :exclusive_owner, :timed_out},
             {:state, :closed}
           ]
  end

  # Copies the adapter's outputs to its inputs, and passes its other events on to the test.
  defp echo(test) do
    receive do
      {:adapter, adapter} -> echo(adapter, test)
    end
  end

  defp echo(adapter, test) do
    receive do
      {Adapter, {:outputs, 150, data}} -> :ok = Adapter.put(adapter, 100, data)
      {Adapter, event} -> send(test, {:event, event})
    end

    echo(adapter, test)
  end

  # The adapter's events of connections, until none has come for 5 s: the last connection times
  # out after the program has exited.
  defp events do
    receive do
      {:event, {:opened, %{kind: kind}}} -> [{:opened, kind} | events()]
      {:event, {:closed, %{kind: kind}, reason}} -> [{:closed, kind, reason} | events()]
      {:event, {:state, 150, state}} -> [{:state, state} | events()]
    after
      5_000 -> []
    end
  end

  # This machine's address on its default route, and the broadcast address of its interface.
  defp local_address do
    {:ok, socket} = :gen_udp.open(0)
    # TEST-NET-1: connecting a UDP socket only picks the route, and sends nothing.
    :ok = :gen_udp.connect(socket, {192, 0, 2, 1}, 9)
    {:ok, {address, _port}} = :inet.sockname(socket)
    :gen_udp.close(socket)

    {:ok, interfaces} = :inet.getifaddrs()

    broadcast =
      Enum.find_value(interfaces, fn {_name, opts} ->
        case Enum.drop_while(opts, &(&1 != {:addr, address})) do
          [_addr | rest] -> Keyword.get(rest, :broadaddr)
          [] -> nil
        end
      end)

    {to_string(:inet.ntoa(address)), to_string(:inet.ntoa(broadcast))}
  end
end
