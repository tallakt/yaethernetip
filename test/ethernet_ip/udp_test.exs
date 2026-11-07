defmodule EtherNetIP.UDPTest do
  use ExUnit.Case, async: true

  alias EtherNetIP.{IOPacket, UDP}

  setup do
    # A port of its own, free for the test.
    {:ok, probe} = :gen_udp.open(0)
    {:ok, port} = :inet.port(probe)
    :gen_udp.close(probe)
    {:ok, udp} = UDP.ensure(port)
    {:ok, sender} = :gen_udp.open(0, [:binary])
    on_exit(fn -> :gen_udp.close(sender) end)
    %{udp: udp, port: port, sender: sender}
  end

  defp send_packet(ctx, id, sequence) do
    :ok = :gen_udp.send(ctx.sender, {127, 0, 0, 1}, ctx.port, IOPacket.encode(id, sequence, ""))
  end

  # A process that registers `id` from the loopback address `times` times and reports packets.
  defp consumer(ctx, id, times) do
    test = self()

    spawn_link(fn ->
      for _ <- 1..times, do: :ok = UDP.register(ctx.udp, {127, 0, 0, 1}, id)
      send(test, {:registered, self()})
      relay(test)
    end)
    |> tap(fn pid -> assert_receive {:registered, ^pid} end)
  end

  defp relay(test) do
    receive do
      {UDP, id, packet} ->
        {:ok, {^id, sequence, _data}} = IOPacket.decode(packet)
        send(test, {:packet, self(), sequence})

      {:unregister, udp, id} ->
        :ok = UDP.unregister(udp, {127, 0, 0, 1}, id)
        send(test, {:unregistered, self()})
    end

    relay(test)
  end

  test "a connection's packets go to every process that consumes it, once each", ctx do
    a = consumer(ctx, 7, 1)
    b = consumer(ctx, 7, 2)

    send_packet(ctx, 7, 1)
    assert_receive {:packet, ^a, 1}
    assert_receive {:packet, ^b, 1}
    refute_receive {:packet, _, 1}, 50

    # b registered twice, so it takes two to stop
    send(b, {:unregister, ctx.udp, 7})
    assert_receive {:unregistered, ^b}
    send_packet(ctx, 7, 2)
    assert_receive {:packet, ^a, 2}
    assert_receive {:packet, ^b, 2}

    send(b, {:unregister, ctx.udp, 7})
    assert_receive {:unregistered, ^b}
    send_packet(ctx, 7, 3)
    assert_receive {:packet, ^a, 3}
    refute_receive {:packet, ^b, 3}, 50

    # one that exits takes its routes with it
    Process.unlink(a)
    Process.exit(a, :kill)
    send_packet(ctx, 7, 4)
    refute_receive {:packet, _, 4}, 50
  end

  test "other connections, and other senders, are dropped", ctx do
    a = consumer(ctx, 7, 1)
    send_packet(ctx, 8, 1)
    refute_receive {:packet, ^a, _}, 50

    # what another process takes back isn't a's
    :ok = UDP.unregister(ctx.udp, {127, 0, 0, 1}, 7)
    send_packet(ctx, 7, 2)
    assert_receive {:packet, ^a, 2}

    :ok = UDP.register(ctx.udp, {10, 0, 0, 1}, 9)
    send_packet(ctx, 9, 3)
    refute_receive {UDP, 9, _}, 50
  end
end
