defmodule EtherNetIP.UDP do
  @moduledoc false
  # The UDP endpoint of class 0 and 1 I/O connections on one port, 2222 unless told otherwise,
  # shared by every scanner and adapter of the node: multicast data comes to that port whoever it
  # is for, so one socket takes it all. A process that consumes a connection registers the
  # connection id it receives on together with the address it comes from, and gets the packets
  # that match both, as Volume 2, 3-4.2 asks; any other packet is dropped. Several connections
  # may consume one multicast production, under the id its producer chose, and each process
  # that registered it gets its packets, once. A process that consumes unicast data from anyone,
  # as an adapter does before it knows a connection, may register a catch-all for its port.
  #
  # The socket is in a persistent term, so that producers send on it without a call. A call to
  # an endpoint that has stopped gives {:error, :closed}, and doesn't exit the caller, which
  # monitors the endpoint to know.

  use GenServer

  @doc """
  The endpoint on `port`, started if it isn't. `{:error, reason}` when the port can't be opened,
  as when another program has it.
  """
  def ensure(port \\ EtherNetIP.IOPacket.port()) do
    case Registry.lookup(EtherNetIP.Registry, {__MODULE__, port}) do
      [{pid, _}] ->
        {:ok, pid}

      [] ->
        spec = %{
          id: {__MODULE__, port},
          start: {GenServer, :start_link, [__MODULE__, port, [name: via(port)]]},
          restart: :temporary
        }

        case DynamicSupervisor.start_child(EtherNetIP.UDP.Supervisor, spec) do
          {:ok, pid} -> {:ok, pid}
          {:error, {:already_started, pid}} -> {:ok, pid}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp via(port), do: {:via, Registry, {EtherNetIP.Registry, {__MODULE__, port}}}

  @doc """
  Sends the packets of connection `id` from `address` to the calling process, as
  `{EtherNetIP.UDP, id, packet}`, until it has unregistered as many times as it registered, or
  exits. `:any` as the address takes the connection from anywhere.
  """
  def register(udp, address, id), do: call(udp, {:register, self(), address, id})

  @doc "Takes back one registration of connection `id` from `address` by the calling process."
  def unregister(udp, address, id), do: call(udp, {:unregister, self(), address, id})

  @doc """
  Sends the calling process every packet that no connection takes, as
  `{EtherNetIP.UDP, :unmatched, address, packet}`.
  """
  def listen(udp), do: call(udp, {:listen, self()})

  @doc """
  Joins a multicast group on the interface with address `interface`, for as long as some process
  that joined it there is alive and hasn't left it as many times as it joined.
  """
  def join(udp, group, interface), do: call(udp, {:join, self(), {group, interface}})

  @doc "Takes back one join of a multicast group on an interface by the calling process."
  def leave(udp, group, interface), do: call(udp, {:leave, self(), {group, interface}})

  @doc "Sends a packet from the endpoint, from any process."
  def send(udp, address, port, packet) do
    case :persistent_term.get({__MODULE__, udp}, nil) do
      nil -> {:error, :closed}
      socket -> :gen_udp.send(socket, address, port, packet)
    end
  end

  defp call(udp, message) do
    GenServer.call(udp, message)
  catch
    :exit, _reason -> {:error, :closed}
  end

  @impl true
  def init(port) do
    options = [:binary, active: 100, reuseaddr: true, multicast_loop: true]

    case :gen_udp.open(port, options) do
      {:ok, socket} ->
        :persistent_term.put({__MODULE__, self()}, socket)
        {:ok, %{socket: socket, routes: %{}, listener: nil, groups: %{}, monitors: %{}}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  # A route is the processes that registered it, each with how many times.
  def handle_call({:register, pid, address, id}, _from, s) do
    s = monitor(s, pid)

    routes =
      Map.update(s.routes, {address, id}, %{pid => 1}, &Map.update(&1, pid, 1, fn n -> n + 1 end))

    {:reply, :ok, %{s | routes: routes}}
  end

  def handle_call({:unregister, pid, address, id}, _from, s) do
    routes =
      case s.routes do
        %{{^address, ^id} => %{^pid => 1} = pids} when map_size(pids) == 1 ->
          Map.delete(s.routes, {address, id})

        %{{^address, ^id} => %{^pid => 1} = pids} ->
          Map.put(s.routes, {address, id}, Map.delete(pids, pid))

        %{{^address, ^id} => %{^pid => n} = pids} ->
          Map.put(s.routes, {address, id}, %{pids | pid => n - 1})

        _routes ->
          s.routes
      end

    {:reply, :ok, %{s | routes: routes}}
  end

  def handle_call({:listen, pid}, _from, s), do: {:reply, :ok, %{monitor(s, pid) | listener: pid}}

  # A membership, a group on an interface, is the processes that joined it, each with how many
  # times.
  def handle_call({:join, pid, membership}, _from, s) do
    members = Map.get(s.groups, membership, %{})

    result =
      if members == %{},
        do: :inet.setopts(s.socket, add_membership: membership),
        else: :ok

    case result do
      :ok ->
        s = monitor(s, pid)
        members = Map.update(members, pid, 1, &(&1 + 1))
        {:reply, :ok, %{s | groups: Map.put(s.groups, membership, members)}}

      error ->
        {:reply, error, s}
    end
  end

  def handle_call({:leave, pid, membership}, _from, s),
    do: {:reply, :ok, leave_group(s, pid, membership, 1)}

  @impl true
  def handle_info({:udp, socket, address, _port, packet}, %{socket: socket} = s) do
    case packet do
      <<2::little-16, 0x8002::little-16, 8::little-16, id::little-32, _rest::binary>> ->
        route(s, address, id, packet)

      _other ->
        unmatched(s, address, packet)
    end

    {:noreply, s}
  end

  def handle_info({:udp_passive, socket}, %{socket: socket} = s) do
    :ok = :inet.setopts(socket, active: 100)
    {:noreply, s}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, s) do
    routes =
      for {key, pids} <- s.routes,
          pids = Map.delete(pids, pid),
          pids != %{},
          into: %{},
          do: {key, pids}

    listener = if s.listener == pid, do: nil, else: s.listener
    s = Enum.reduce(Map.keys(s.groups), s, &leave_group(&2, pid, &1, :all))
    {:noreply, %{s | routes: routes, listener: listener, monitors: Map.delete(s.monitors, pid)}}
  end

  def handle_info(_message, s), do: {:noreply, s}

  @impl true
  def terminate(_reason, _s), do: :persistent_term.erase({__MODULE__, self()})

  defp route(s, address, id, packet) do
    case Map.get(s.routes, {address, id}) || Map.get(s.routes, {:any, id}) do
      nil -> unmatched(s, address, packet)
      pids -> for {pid, _n} <- pids, do: Kernel.send(pid, {__MODULE__, id, packet})
    end
  end

  defp unmatched(%{listener: nil}, _address, _packet), do: :ok

  defp unmatched(%{listener: pid}, address, packet),
    do: Kernel.send(pid, {__MODULE__, :unmatched, address, packet})

  defp leave_group(s, pid, membership, times) do
    members = Map.get(s.groups, membership, %{})

    members =
      case members do
        %{^pid => n} when times != :all and n > times -> %{members | pid => n - times}
        _members -> Map.delete(members, pid)
      end

    if members == %{} do
      _ = :inet.setopts(s.socket, drop_membership: membership)
      %{s | groups: Map.delete(s.groups, membership)}
    else
      %{s | groups: Map.put(s.groups, membership, members)}
    end
  end

  defp monitor(s, pid) do
    if Map.has_key?(s.monitors, pid),
      do: s,
      else: %{s | monitors: Map.put(s.monitors, pid, Process.monitor(pid))}
  end
end
