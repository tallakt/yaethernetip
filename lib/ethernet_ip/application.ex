defmodule EtherNetIP.Application do
  @moduledoc false
  # Supervises the UDP endpoints of I/O connections, one for each port, started when a scanner
  # or an adapter first needs one.

  use Application

  @impl true
  def start(_type, _args) do
    # What the node's connections are numbered from (EtherNetIP.Scanner.Server): a count, and
    # random starts, new each time the node starts.
    :persistent_term.put({EtherNetIP, :connections}, %{
      count: :atomics.new(1, signed: false),
      serial: :rand.uniform(0x10000) - 1,
      incarnation: :rand.uniform(0xFFFF)
    })

    children = [
      {Registry, keys: :unique, name: EtherNetIP.Registry},
      {DynamicSupervisor, name: EtherNetIP.UDP.Supervisor, strategy: :one_for_one}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: EtherNetIP.Supervisor)
  end

  @doc false
  # A connection's serial number, and a connection id: an incarnation id and a connection number
  # (Volume 2, 3-3.7.1.2). Both are unique among the connections of every scanner and adapter of
  # the node, so that two scanners of one device don't take each other's inputs, and both start
  # anew when the node does, so that it doesn't open what a target still takes for an old
  # connection, nor give an id an originator may still have in use.
  def numbers do
    %{count: count, serial: serial, incarnation: incarnation} =
      :persistent_term.get({EtherNetIP, :connections})

    n = :atomics.add_get(count, 1, 1)
    {Bitwise.band(serial + n, 0xFFFF), Bitwise.bsl(incarnation, 16) + Bitwise.band(n, 0xFFFF)}
  end
end
