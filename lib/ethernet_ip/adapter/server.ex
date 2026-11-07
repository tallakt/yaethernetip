defmodule EtherNetIP.Adapter.Server do
  @moduledoc false
  # The process of an adapter. An acceptor asks it before it hands a client's TCP connection
  # over, and each client has a session process (EtherNetIP.Adapter.Session), which reads its
  # messages and has this process answer the CIP requests in them. This process has every
  # connection: the I/O connections, whose outputs come to it from the shared UDP endpoint and
  # whose inputs it produces every RPI, and the class 3 connections of the sessions.
  #
  # The data of each assembly is in a public table, as are the sizes, so that the application
  # puts inputs and reads outputs without a call; a put that changes inputs tells this process,
  # for connections that produce them by change of state.

  use GenServer

  import Bitwise

  require Logger

  alias EtherNetIP.Adapter.{Objects, Session}
  alias EtherNetIP.{CIP, ConnectionManager, Encapsulation, Identity, IOPacket, Path, UDP}

  @get_attribute_single 0x0E
  @set_attribute_single 0x10
  @multiple_service_packet 0x0A
  @forward_close 0x4E
  @unconnected_send 0x52
  @forward_open 0x54
  @large_forward_open 0x5B

  # Listens in the caller, so that a port that's taken is an error returned rather than an exit,
  # then hands the sockets to the server.
  def start_link(config, name) do
    options = [
      :binary,
      ip: config.address,
      packet: :raw,
      active: false,
      reuseaddr: true,
      nodelay: true,
      keepalive: true,
      send_timeout: 5000,
      send_timeout_close: true,
      backlog: 128
    ]

    with {:ok, socket} <- :gen_tcp.listen(config.port, options),
         {:ok, port} <- :inet.port(socket),
         {:ok, discovery} <- discovery(config, port, socket) do
      config = Map.merge(config, %{socket: socket, port: port, discovery: discovery})
      __MODULE__ |> GenServer.start_link(config, name) |> handed(socket, discovery)
    end
  end

  defp handed({:ok, server}, socket, discovery) do
    :ok = :gen_tcp.controlling_process(socket, server)

    if discovery do
      :ok = :gen_udp.controlling_process(discovery, server)
      :ok = :inet.setopts(discovery, active: 100)
    end

    {:ok, server}
  end

  defp handed(error, socket, discovery) do
    :gen_tcp.close(socket)
    if discovery, do: :gen_udp.close(discovery)
    error
  end

  # ListIdentity and the other commands that may come over UDP, on the same port as TCP.
  defp discovery(%{discovery: false}, _port, _socket), do: {:ok, nil}

  defp discovery(_config, port, socket) do
    options = [:binary, active: false, reuseaddr: true, broadcast: true]

    case :gen_udp.open(port, options) do
      {:ok, udp} ->
        {:ok, udp}

      error ->
        :gen_tcp.close(socket)
        error
    end
  end

  @impl true
  def init(config) do
    Process.flag(:trap_exit, true)
    server = self()
    table = :ets.new(__MODULE__, [:public, :set, read_concurrency: true])
    {:ok, _owner} = Registry.register(EtherNetIP.Registry, {EtherNetIP.Adapter, server}, table)
    :ets.insert(table, {:inactivity, config.inactivity})

    for {instance, {kind, size, data}} <- config.assemblies do
      :ets.insert(table, [{{:assembly, instance}, kind, size}, {{:data, instance}, data}])
      if kind == :output, do: :ets.insert(table, {{:output, instance}, :closed, nil})
    end

    acceptor = spawn_link(fn -> accept(server, config.socket, config.allow) end)

    s =
      Map.merge(config, %{
        table: table,
        acceptor: acceptor,
        sessions: %{},
        connections: %{},
        by_o_t: %{},
        productions: %{},
        udp: nil,
        senders: %{},
        replies: 0,
        configured: false,
        faulted: false
      })

    {:ok, s}
  end

  ## The application's calls

  @impl true
  def handle_call(:port, _from, s), do: {:reply, s.port, s}

  def handle_call(:connections, _from, s),
    do: {:reply, Enum.map(Map.values(s.connections), &info/1), s}

  ## The sessions'

  # A server that's full makes room for a new client by closing a connection; see victim/2.
  def handle_call({:admit, address}, _from, s) do
    s = if map_size(s.sessions) >= s.sessions_max, do: evict(s, address), else: s
    {:ok, pid} = Session.start_link(%{server: self(), table: s.table})
    :ets.insert(s.table, {{:session, pid}, now(), address})
    {:reply, {:ok, pid}, %{s | sessions: Map.put(s.sessions, pid, address)}}
  end

  def handle_call(:identity, _from, s), do: {:reply, identity(s), s}

  def handle_call({:request, request, items, ctx}, _from, s) do
    {reply, items, s} =
      safely(
        request,
        fn -> execute(s, request, Map.put(ctx, :items, items)) end,
        fn -> {CIP.reply(service(request), :vendor_specific_error), [], s} end
      )

    {:reply, {reply, items}, s}
  end

  def handle_call({:connected, id, sequence, request, ctx}, _from, s) do
    {reply, s} =
      safely(
        request,
        fn -> connected(s, id, sequence, request, ctx) end,
        fn -> {:unknown, s} end
      )

    {:reply, reply, s}
  end

  def handle_call({:explicit?, session}, _from, s),
    do: {:reply, Enum.any?(Map.values(s.connections), &(&1.session == session)), s}

  ## I/O, timers and processes

  @impl true
  def handle_info({UDP, id, packet}, s) do
    case Map.fetch(s.by_o_t, id) do
      {:ok, triad} -> {:noreply, consume(s, triad, packet)}
      :error -> {:noreply, s}
    end
  end

  def handle_info({:watchdog, triad, generation}, s) do
    case Map.fetch(s.connections, triad) do
      {:ok, %{generation: ^generation}} -> {:noreply, close(s, triad, :timed_out)}
      _stale -> {:noreply, s}
    end
  end

  def handle_info({:produce, key, tick}, s) do
    case Map.fetch(s.productions, key) do
      {:ok, %{tick: ^tick}} -> {:noreply, produce(s, key)}
      _stale -> {:noreply, s}
    end
  end

  # One message for any number of puts since the last, as put/3 sends one only while there's no
  # mark; the mark goes before the inputs are read, so that a put after it sends another.
  def handle_info({:changed, instance}, s) do
    :ets.delete(s.table, {:changed, instance})
    {:noreply, changed(s, instance)}
  end

  # A host that may not connect isn't answered over UDP either.
  def handle_info({:udp, socket, address, port, packet}, %{discovery: socket} = s) do
    if allowed?(address, s.allow),
      do: {:noreply, discover(s, address, port, packet)},
      else: {:noreply, s}
  end

  def handle_info({:udp_passive, socket}, %{discovery: socket} = s) do
    _ = :inet.setopts(socket, active: 100)
    {:noreply, s}
  end

  def handle_info({:list_identity, address, port, context}, s) do
    _ = :gen_udp.send(s.discovery, address, port, list_identity(s, address, context))
    {:noreply, %{s | replies: s.replies - 1}}
  end

  def handle_info({:reset, type}, s), do: {:noreply, reset(s, type)}

  # The endpoint's routes went with it, and the connections that consumed through it are closed:
  # their originators time out, and open them again.
  def handle_info({:DOWN, _ref, :process, udp, _reason}, s) do
    s =
      Enum.reduce(s.connections, s, fn
        {triad, %{udp: ^udp}}, s -> close(s, triad, {:udp, :closed})
        _other, s -> s
      end)

    {:noreply, if(s.udp == udp, do: %{s | udp: nil}, else: s)}
  end

  def handle_info({:EXIT, acceptor, reason}, %{acceptor: acceptor} = s), do: {:stop, reason, s}

  def handle_info({:EXIT, pid, _reason}, s) when is_map_key(s.sessions, pid),
    do: {:noreply, gone(s, pid)}

  def handle_info(_message, s), do: {:noreply, s}

  @impl true
  def terminate(_reason, s) do
    :gen_tcp.close(s.socket)
    if s.discovery, do: :gen_udp.close(s.discovery)
    for socket <- Map.values(s.senders), do: :gen_udp.close(socket)
    for pid <- Map.keys(s.sessions), do: Process.exit(pid, :kill)
  end

  ## Sessions

  defp evict(s, address) do
    case s.sessions |> Map.keys() |> Enum.flat_map(&:ets.lookup(s.table, {:session, &1})) do
      [] ->
        s

      rows ->
        {:session, pid} = victim(rows, address)
        Process.exit(pid, :kill)
        gone(s, pid)
    end
  end

  # A session's class 3 connections close with it.
  defp gone(s, pid) do
    :ets.delete(s.table, {:session, pid})
    s = %{s | sessions: Map.delete(s.sessions, pid)}

    Enum.reduce(s.connections, s, fn
      {triad, %{session: ^pid}}, s -> close(s, triad, :closed)
      _other, s -> s
    end)
  end

  @doc false
  # The session to close for a new client from `address`, of the rows {{:session, pid}, last
  # message, address}: the one that has gone longest without a message, of the address that
  # holds the most sessions, counting the new one; on a tie, the new client's own address loses
  # one first. A host that connects again and again only pushes out its own sessions.
  def victim(rows, address) do
    groups = Enum.group_by(rows, &elem(&1, 2))
    held = fn {from, group} -> length(group) + if(from == address, do: 1, else: 0) end
    most = groups |> Enum.map(held) |> Enum.max()
    tied = Enum.filter(groups, &(held.(&1) == most))

    {_from, group} =
      Enum.find(tied, fn {from, _group} -> from == address end) ||
        Enum.min_by(tied, fn {_from, group} -> group |> Enum.map(&elem(&1, 1)) |> Enum.min() end)

    group |> Enum.min_by(&elem(&1, 1)) |> elem(0)
  end

  defp accept(server, socket, allow) do
    case :gen_tcp.accept(socket) do
      {:ok, client} ->
        hand_over(server, client, allow)
        accept(server, socket, allow)

      {:error, :closed} ->
        exit(:normal)

      # Out of file descriptors or memory: those connected keep their connections, and an accept
      # a moment later may do better.
      {:error, reason} when reason in [:emfile, :enfile, :enobufs, :enomem, :system_limit] ->
        Process.sleep(10)
        accept(server, socket, allow)

      # A client gone before it was accepted.
      {:error, _reason} ->
        accept(server, socket, allow)
    end
  end

  # A client from an address that isn't allowed is closed before it takes a place.
  defp hand_over(server, client, allow) do
    with {:ok, {address, _port}} <- :inet.peername(client),
         true <- allowed?(address, allow),
         {:ok, pid} <- GenServer.call(server, {:admit, address}, :infinity),
         :ok <- :gen_tcp.controlling_process(client, pid) do
      send(pid, {:socket, client})
    else
      _gone_not_allowed_or_failed -> :gen_tcp.close(client)
    end
  end

  @doc false
  # Whether an address is among those allowed, each an address or {address, prefix length}.
  def allowed?(_address, nil), do: true

  def allowed?(address, allow) do
    Enum.any?(allow, fn
      {net, bits} -> same_net?(address, net, bits)
      net -> same_net?(address, net, 32)
    end)
  end

  defp same_net?({_, _, _, _} = address, {_, _, _, _} = net, bits),
    do: number(address) >>> (32 - bits) == number(net) >>> (32 - bits)

  defp same_net?(_address, _net, _bits), do: false

  defp number({a, b, c, d}), do: (a <<< 24) + (b <<< 16) + (c <<< 8) + d

  ## Discovery

  # Volume 2, 2-4: over UDP, ListIdentity, ListServices and ListInterfaces are answered, any other
  # command but NOP is refused, and a request with a status or options is passed over.
  defp discover(s, address, port, packet) do
    case Encapsulation.decode(packet) do
      {:ok, %Encapsulation{status: :success, options: 0} = message, <<>>} ->
        command(s, address, port, message)

      _other ->
        s
    end
  end

  # A ListIdentity over UDP may be a broadcast, which the adapter answers after a random delay up
  # to the one the request gives, 2 s for 0, at least 500 ms (Volume 2, 2-4.2.3), so that many
  # devices don't all answer at once; and it has a few such replies waiting at most, so that a
  # flood of requests doesn't become one of replies.
  defp command(s, address, port, %Encapsulation{command: :list_identity} = message) do
    if s.replies < 16 do
      <<delay::little-16, _rest::binary>> = message.context

      delay =
        cond do
          delay == 0 -> 2000
          delay <= 500 -> 500
          true -> delay
        end

      Process.send_after(
        self(),
        {:list_identity, address, port, message.context},
        :rand.uniform(delay + 1) - 1
      )

      %{s | replies: s.replies + 1}
    else
      s
    end
  end

  defp command(s, _address, _port, %Encapsulation{command: :nop}), do: s

  defp command(s, address, port, message) do
    {data, status} =
      case message.command do
        :list_services ->
          {EtherNetIP.CPF.encode([
             {:service, EtherNetIP.CPF.service(1, 0x0120, "Communications")}
           ]), :success}

        :list_interfaces ->
          {EtherNetIP.CPF.encode([]), :success}

        _other ->
          {<<>>, :invalid_command}
      end

    reply = Encapsulation.encode(%{message | status: status, data: data})
    _ = :gen_udp.send(s.discovery, address, port, reply)
    s
  end

  defp list_identity(s, address, context) do
    item = Identity.encode_list_identity(identity(s), {local_address(s, address), s.port})

    Encapsulation.encode(%Encapsulation{
      command: :list_identity,
      context: context,
      data: EtherNetIP.CPF.encode([{:identity, item}])
    })
  end

  # The address of this host that a host at `address` reaches it on.
  defp local_address(%{address: {0, 0, 0, 0}}, address) do
    with {:ok, socket} <- :gen_udp.open(0),
         :ok <- :gen_udp.connect(socket, address, 9),
         {:ok, {local, _port}} <- :inet.sockname(socket) do
      :gen_udp.close(socket)
      local
    else
      _error -> {0, 0, 0, 0}
    end
  end

  defp local_address(s, _address), do: s.address

  ## The Identity object's status (Volume 1, 5-2.2.1.5)

  defp identity(s) do
    i = s.identity

    %Identity{
      vendor_id: i.vendor_id,
      device_type: i.device_type,
      product_code: i.product_code,
      revision: i.revision,
      serial_number: i.serial_number,
      product_name: i.product_name,
      status: status(s),
      state: :operational
    }
  end

  # Owned while a scanner owns the outputs, configured once a scanner has configured it, and the
  # extended device status of the I/O connections: one has timed out, one is in run mode, all
  # are idle, or there are none.
  defp status(s) do
    io = for {_triad, %{class: 1} = c} <- s.connections, do: c
    owned = if Enum.any?(io, &(&1.kind == :exclusive_owner)), do: 0x01, else: 0
    configured = if s.configured, do: 0x04, else: 0

    extended =
      cond do
        s.faulted -> 0b0010
        Enum.any?(io, &(&1.run == true)) -> 0b0110
        io != [] -> 0b0111
        true -> 0b0011
      end

    owned + configured + (extended <<< 4)
  end

  ## The message router

  # A request that fails in the adapter, which would be a bug of its own, fails alone: its client
  # gets an error, and the adapter keeps its connections.
  defp safely(request, run, failed) do
    run.()
  rescue
    exception ->
      Logger.error(
        "EtherNetIP.Adapter failed on the request #{inspect(request, limit: :infinity)}:\n" <>
          Exception.format(:error, exception, __STACKTRACE__)
      )

      failed.()
  end

  # A request, and the reply with any items to go with it in the SendRRData.
  defp execute(s, request, ctx) do
    case CIP.decode_request(request) do
      {:ok, {service, path, data}} ->
        case target(path) do
          {:ok, class, instance, attribute} ->
            object(s, service, class, instance, attribute, data, ctx)

          :error ->
            {CIP.reply(service, :path_segment_error), [], s}
        end

      {:error, error} ->
        status = if error == :invalid, do: :path_size_invalid, else: :path_segment_error
        {CIP.reply(service(request), status), [], s}
    end
  end

  defp service(<<_request::1, service::7, _rest::binary>>), do: service
  defp service(<<>>), do: 0

  # A class, and an instance and attribute if any; a connection point is an instance.
  defp target([{:class, class} | rest]) do
    case rest do
      [] ->
        {:ok, class, 0, nil}

      [{type, instance}] when type in [:instance, :connection_point] ->
        {:ok, class, instance, nil}

      [{type, instance}, {:attribute, attribute}] when type in [:instance, :connection_point] ->
        {:ok, class, instance, attribute}

      _other ->
        :error
    end
  end

  defp target(_path), do: :error

  defp object(s, service, class, 0, attribute, _data, _ctx) do
    if class in Objects.classes(),
      do: {reply(service, Objects.class(class, service, attribute, instances(s, class))), [], s},
      else: {CIP.reply(service, :path_destination_unknown), [], s}
  end

  defp object(s, service, 0x01, 1, attribute, data, _ctx) do
    if service == Objects.reset() do
      case Objects.reset_type(data) do
        {:ok, type} ->
          send(self(), {:reset, type})
          {CIP.reply(service, :success), [], s}

        {:error, status} ->
          {CIP.reply(service, status), [], s}
      end
    else
      {reply(service, Objects.identity(service, attribute, identity(s))), [], s}
    end
  end

  defp object(s, @multiple_service_packet, 0x02, 1, nil, data, ctx),
    do: multiple(s, data, ctx)

  defp object(s, service, 0x02, 1, attribute, _data, _ctx),
    do: {reply(service, Objects.message_router(service, attribute, s.max_connections)), [], s}

  defp object(s, service, 0x04, instance, attribute, data, _ctx)
       when is_map_key(s.assemblies, instance),
       do: assembly(s, service, instance, attribute, data)

  defp object(s, service, 0x06, 1, nil, data, ctx),
    do: connection_manager(s, service, data, ctx)

  defp object(s, service, 0xF5, 1, attribute, data, ctx) do
    [{:inactivity, inactivity}] = :ets.lookup(s.table, :inactivity)
    interface = Objects.interface(ctx.local)
    argument = if service == @set_attribute_single, do: data, else: interface

    case Objects.tcp_ip(service, attribute, argument, inactivity) do
      {:set, seconds} ->
        :ets.insert(s.table, {:inactivity, seconds})
        {CIP.reply(service, :success), [], s}

      result ->
        {reply(service, result), [], s}
    end
  end

  defp object(s, service, 0xF6, 1, attribute, _data, ctx),
    do:
      {reply(service, Objects.ethernet_link(service, attribute, Objects.interface(ctx.local))),
       [], s}

  defp object(s, service, _class, _instance, _attribute, _data, _ctx),
    do: {CIP.reply(service, :path_destination_unknown), [], s}

  defp reply(service, {status, data}), do: CIP.reply(service, status, [], data)

  defp instances(s, 0x04), do: Map.keys(s.assemblies)
  defp instances(_s, _class), do: [1]

  # Multiple_Service_Packet (Volume 1, A-4.10): the requests at the offsets it gives, answered in
  # turn, one level deep.
  defp multiple(s, data, ctx) do
    with false <- Map.get(ctx, :embedded, false),
         <<count::little-16, rest::binary>> <- data,
         true <- byte_size(rest) >= count * 2,
         offsets = for(<<offset::little-16 <- binary_part(rest, 0, count * 2)>>, do: offset),
         {:ok, requests} <- embedded(data, offsets) do
      {replies, s} =
        Enum.map_reduce(requests, s, fn request, s ->
          {reply, _items, s} = execute(s, request, Map.put(ctx, :embedded, true))
          {reply, s}
        end)

      start = 2 + count * 2

      {offsets, _end} =
        Enum.map_reduce(replies, start, fn reply, at ->
          {<<at::little-16>>, at + byte_size(reply)}
        end)

      failed =
        Enum.any?(replies, fn <<_service, _reserved, status, _rest::binary>> -> status != 0 end)

      status = if failed, do: :embedded_service_error, else: :success

      {CIP.reply(@multiple_service_packet, status, [], [<<count::little-16>>, offsets, replies]),
       [], s}
    else
      true -> {CIP.reply(@multiple_service_packet, :service_not_supported), [], s}
      _short -> {CIP.reply(@multiple_service_packet, :not_enough_data), [], s}
    end
  end

  defp embedded(data, offsets) do
    ends = Enum.drop(offsets, 1) ++ [byte_size(data)]

    Enum.zip(offsets, ends)
    |> Enum.reduce_while({:ok, []}, fn {from, to}, {:ok, acc} ->
      if from <= to and to <= byte_size(data) and from >= 2,
        do: {:cont, {:ok, [binary_part(data, from, to - from) | acc]}},
        else: {:halt, :error}
    end)
    |> case do
      {:ok, requests} -> {:ok, Enum.reverse(requests)}
      :error -> :error
    end
  end

  ## The Assembly object (Volume 1, 5-5)

  defp assembly(s, @get_attribute_single, instance, 3, _data) do
    [{_key, data}] = :ets.lookup(s.table, {:data, instance})
    {CIP.reply(@get_attribute_single, :success, [], data), [], s}
  end

  defp assembly(s, @get_attribute_single, instance, 4, _data) do
    {_kind, size, _data} = s.assemblies[instance]
    {CIP.reply(@get_attribute_single, :success, [], <<size::little-16>>), [], s}
  end

  defp assembly(s, @get_attribute_single, _instance, _attribute, _data),
    do: {CIP.reply(@get_attribute_single, :attribute_not_supported), [], s}

  # The data of outputs and configuration may be set while no connection has them; inputs are
  # the application's.
  defp assembly(s, @set_attribute_single, instance, 3, data) do
    {kind, size, _initial} = s.assemblies[instance]

    status =
      cond do
        kind not in [:output, :configuration] -> :attribute_not_settable
        in_use?(s, kind, instance) -> :object_state_conflict
        byte_size(data) < size -> :not_enough_data
        byte_size(data) > size -> :too_much_data
        true -> :success
      end

    s =
      if status == :success do
        :ets.insert(s.table, {{:data, instance}, data})

        case kind do
          :output ->
            :ets.insert(s.table, {{:output, instance}, :closed, System.monotonic_time()})
            notify(s, {:outputs, instance, data})
            s

          :configuration ->
            notify(s, {:configuration, instance, data})
            %{s | configured: true}
        end
      else
        s
      end

    {CIP.reply(@set_attribute_single, status), [], s}
  end

  defp assembly(s, @set_attribute_single, _instance, attribute, _data) do
    status = if attribute in [4], do: :attribute_not_settable, else: :attribute_not_supported
    {CIP.reply(@set_attribute_single, status), [], s}
  end

  defp assembly(s, service, _instance, _attribute, _data),
    do: {CIP.reply(service, :service_not_supported), [], s}

  defp in_use?(s, :output, instance),
    do:
      Enum.any?(
        Map.values(s.connections),
        &(&1.kind == :exclusive_owner and &1.output == instance)
      )

  defp in_use?(s, :configuration, instance),
    do: Enum.any?(Map.values(s.connections), &(&1[:config] == instance))

  ## The Connection Manager (Volume 1, 3-5)

  defp connection_manager(s, service, data, ctx)
       when service in [@forward_open, @large_forward_open] do
    large = service == @large_forward_open

    case ConnectionManager.decode_forward_open(data, large) do
      {:ok, request} ->
        case open(s, request, ctx) do
          {:ok, reply, items, s} ->
            {CIP.reply(service, :success, [], reply), items, s}

          {:error, extended, additional} ->
            failure = ConnectionManager.encode_failure(request)
            {CIP.reply(service, :connection_failure, [extended | additional], failure), [], s}
        end

      {:error, :invalid} ->
        fixed = if large, do: 40, else: 36
        {CIP.reply(service, size_status(data, fixed, fixed - 1)), [], s}
    end
  end

  defp connection_manager(s, @forward_close, data, ctx) do
    case ConnectionManager.decode_forward_close(data) do
      {:ok, request} ->
        triad = {request.serial, request.vendor_id, request.originator_serial}
        failure = ConnectionManager.encode_failure(request)

        case Map.fetch(s.connections, triad) do
          {:ok, %{peer: peer}} when peer == ctx.peer ->
            reply = ConnectionManager.encode_forward_close_reply(request)
            {CIP.reply(@forward_close, :success, [], reply), [], close(s, triad, :closed)}

          # Only the host that opened a connection may close it (Volume 2, 3-3.10).
          {:ok, _other} ->
            {CIP.reply(@forward_close, :privilege_violation, [], failure), [], s}

          :error ->
            {CIP.reply(@forward_close, :connection_failure, [0x0107], failure), [], s}
        end

      {:error, :invalid} ->
        {CIP.reply(@forward_close, size_status(data, 12, 10)), [], s}
    end
  end

  # An Unconnected_Send with no route is for the adapter itself; it routes to no other link.
  defp connection_manager(s, @unconnected_send, data, ctx) do
    case data do
      <<_tick, _ticks, size::little-16, request::binary-size(size), rest::binary>> ->
        # A request of an odd size has a pad byte after it.
        rest =
          case {rem(size, 2), rest} do
            {1, <<_pad, rest::binary>>} -> rest
            _even_or_short -> rest
          end

        case rest do
          <<0, _reserved>> ->
            execute(s, request, Map.put(ctx, :embedded, true))

          <<words, _reserved, _route::binary>> ->
            {CIP.reply(@unconnected_send, :connection_failure, [0x0311], <<words, 0>>), [], s}

          _short ->
            {CIP.reply(@unconnected_send, :not_enough_data), [], s}
        end

      _short ->
        {CIP.reply(@unconnected_send, :not_enough_data), [], s}
    end
  end

  defp connection_manager(s, service, _data, _ctx),
    do: {CIP.reply(service, :service_not_supported), [], s}

  # Too little data for the fixed part, or for the path it says follows, or too much; the path's
  # size in words at `at`.
  defp size_status(data, fixed, _at) when byte_size(data) < fixed, do: :not_enough_data

  defp size_status(data, fixed, at) do
    words = :binary.at(data, at)
    if byte_size(data) - fixed > words * 2, do: :too_much_data, else: :not_enough_data
  end

  ## Forward_Open

  defp open(s, request, ctx) do
    triad = {request.serial, request.vendor_id, request.originator_serial}

    with :ok <- check(not Map.has_key?(s.connections, triad), 0x0100),
         {:ok, path} <- application_path(request.path),
         :ok <- keyed(path.key, s.identity),
         {:ok, class} <- transport(request.trigger, path),
         :ok <- check(not request.o_t.redundant_owner, 0x0108),
         :ok <- check(map_size(s.connections) < s.max_connections, 0x0113) do
      c = %{
        triad: triad,
        class: class,
        peer: ctx.peer,
        local: ctx.local,
        o_t_api: request.o_t.rpi,
        t_o_api: request.t_o.rpi,
        multiplier: request.multiplier,
        generation: 0,
        watchdog: nil,
        session: nil,
        udp: nil,
        production: nil,
        output: nil,
        input: nil,
        config: nil,
        run: nil,
        last_sequence: nil,
        last_count: nil,
        last_reply: nil
      }

      case class do
        1 -> open_io(s, request, path, c, ctx)
        3 -> open_explicit(s, request, c, ctx)
      end
    end
  end

  defp check(true, _extended), do: :ok
  defp check(false, extended), do: {:error, extended, []}

  # The electronic key, if any, then a production inhibit time, then the application path: the
  # Message Router for a class 3 connection, or the Assembly object's configuration instance
  # and connection points, with configuration data (Volume 1, 3-5.5.1.10).
  defp application_path(path) do
    with {:ok, segments} <- Path.decode(path),
         {key, segments} <- take(segments, :key),
         {inhibit, segments} <- take(segments, :production_inhibit),
         {:ok, application} <- application(segments) do
      {:ok, Map.merge(application, %{key: key, inhibit: inhibit})}
    else
      _invalid -> {:error, 0x0315, []}
    end
  end

  defp take([{type, _} = segment | rest], type), do: {segment, rest}
  defp take([{:key, _, _, _, _, _, _} = key | rest], :key), do: {key, rest}
  defp take(segments, _type), do: {nil, segments}

  defp application([{:class, 0x02}, {:instance, 1}]), do: {:ok, %{target: :message_router}}

  defp application([{:class, 0x04} | rest]) do
    {data, ids} =
      case Enum.reverse(rest) do
        [{:data, data} | ids] -> {data, Enum.reverse(ids)}
        _none -> {nil, rest}
      end

    if Enum.all?(ids, &match?({type, _} when type in [:instance, :connection_point], &1)) do
      case Enum.map(ids, &elem(&1, 1)) do
        [config, o_t, t_o] ->
          {:ok, %{target: :assembly, config: config, o_t: o_t, t_o: t_o, data: data}}

        [o_t, t_o] when data == nil ->
          {:ok, %{target: :assembly, config: nil, o_t: o_t, t_o: t_o, data: nil}}

        _other ->
          :error
      end
    else
      :error
    end
  end

  defp application(_segments), do: :error

  # Volume 1, C-1.4.2, as the CIP Conformance Test Specification checks it (6.3.2): a vendor id,
  # device type or product code of 0 matches any; an exact key matches a major revision of 0, or
  # this one with a minor of 0 or this one; a compatible key matches this major revision with a
  # minor up to this one.
  defp keyed(nil, _identity), do: :ok

  defp keyed({:key, vendor, type, product, major, minor, compatible}, identity) do
    cond do
      vendor not in [0, identity.vendor_id] -> {:error, 0x0114, []}
      product not in [0, identity.product_code] -> {:error, 0x0114, []}
      type not in [0, identity.device_type] -> {:error, 0x0115, []}
      not revision?(major, minor, compatible, identity.revision) -> {:error, 0x0116, []}
      true -> :ok
    end
  end

  defp revision?(major, minor, true, {ours, our_minor}),
    do: major == ours and minor >= 1 and minor <= our_minor

  defp revision?(major, minor, false, {ours, our_minor}),
    do: major == 0 or (major == ours and minor in [0, our_minor])

  # Class 1 to assemblies, class 3 to the Message Router; cyclic, change of state or application
  # triggered.
  defp transport({_direction, trigger, class}, path) do
    cond do
      trigger not in [:cyclic, :change_of_state, :application] -> {:error, 0x011D, []}
      class == 1 and path.target == :assembly -> {:ok, 1}
      class == 3 and path.target == :message_router -> {:ok, 3}
      true -> {:error, 0x0103, []}
    end
  end

  ## Class 3: explicit messages over the session's TCP connection

  defp open_explicit(s, request, c, ctx) do
    with :ok <- check(request.o_t.type == :point_to_point, 0x0123),
         :ok <- check(request.t_o.type == :point_to_point, 0x0124),
         :ok <- check(request.o_t.rpi > 0 and request.t_o.rpi > 0, 0x0111) do
      {_serial, o_t_id} = EtherNetIP.Application.numbers()

      c =
        Map.merge(c, %{
          kind: :explicit,
          o_t_id: o_t_id,
          t_o_id: request.t_o_id,
          session: ctx.session
        })

      {:ok, granted(c, request), [], opened(s, c)}
    end
  end

  # A request on a class 3 connection of this session; one with the sequence count of the last
  # is the same request again, which gets the same reply without being done twice (Volume 1,
  # 3-4.4.3).
  defp connected(s, id, sequence, request, ctx) do
    with {:ok, triad} <- Map.fetch(s.by_o_t, id),
         %{class: 3, session: session} = c when session == ctx.session <- s.connections[triad] do
      c = watchdog(c, timeout(c))

      if sequence == c.last_sequence,
        do: {{:ok, c.t_o_id, c.last_reply}, put_in(s.connections[triad], c)},
        else: answer(put_in(s.connections[triad], c), c, sequence, request, ctx)
    else
      _unknown -> {:unknown, s}
    end
  end

  # The request may close the connection it came on.
  defp answer(s, c, sequence, request, ctx) do
    {reply, _items, s} = execute(s, request, Map.put(ctx, :items, []))

    case Map.fetch(s.connections, c.triad) do
      {:ok, c} ->
        c = %{c | last_sequence: sequence, last_reply: reply}
        {{:ok, c.t_o_id, reply}, put_in(s.connections[c.triad], c)}

      :error ->
        {{:ok, c.t_o_id, reply}, s}
    end
  end

  ## Class 1: I/O connections to assemblies

  defp open_io(s, request, path, c, ctx) do
    with {:ok, kind} <- kind(s, path),
         :ok <- check(input?(s, path.t_o), 0x0117),
         :ok <- configuration(s, path),
         :ok <- check(request.o_t.type == :point_to_point, 0x0123),
         :ok <- check(request.t_o.type in [:point_to_point, :multicast], 0x0124),
         :ok <- sizes(s, kind, path, request),
         :ok <- rpis(s, request),
         :ok <- inhibit(request, path),
         :ok <- ownership(s, kind, path),
         :ok <- listened(s, kind, path),
         :ok <- same_configuration(s, path),
         {:ok, production} <- production(s, request, path, ctx),
         {:ok, udp} <- subscribe(s),
         {_serial, o_t_id} = EtherNetIP.Application.numbers(),
         :ok <- registered(UDP.register(udp, ctx.peer, o_t_id)) do
      c =
        Map.merge(c, %{
          kind: kind,
          o_t_id: o_t_id,
          t_o_id: production.id,
          udp: udp,
          production: production.key,
          multicast: production.multicast,
          output: path.o_t,
          input: path.t_o,
          config: if(match?({:configuration, _, _}, s.assemblies[path.config]), do: path.config),
          t_o_api: production.rpi
        })

      s = s |> monitor_udp(udp) |> configure(path)
      s = start_production(s, production, c.triad)
      s = opened(s, c)

      # The group of multicast inputs, and the port of outputs when it isn't 2222 (Volume 2,
      # 3-3.9.6).
      items =
        if(production.multicast,
          do: [{:sockaddr, :t_o, {elem(production.to, 0), s.udp_port}}],
          else: []
        ) ++
          if s.udp_port != IOPacket.port(),
            do: [{:sockaddr, :o_t, {{0, 0, 0, 0}, s.udp_port}}],
            else: []

      {:ok, granted(c, request), items, s}
    end
  end

  defp registered(:ok), do: :ok
  defp registered(_error), do: {:error, 0x0303, []}

  # What the O->T connection point makes of the connection (Volume 1, 3-6.4).
  defp kind(s, path) do
    cond do
      match?({:output, _, _}, s.assemblies[path.o_t]) -> {:ok, :exclusive_owner}
      path.o_t == s.input_only -> {:ok, :input_only}
      path.o_t == s.listen_only -> {:ok, :listen_only}
      true -> {:error, 0x0117, []}
    end
  end

  defp input?(s, instance), do: match?({:input, _, _}, s.assemblies[instance])

  # A configuration instance may be any when no data comes with it; data must be for one of the
  # adapter's configuration assemblies, and fit it.
  defp configuration(_s, %{data: nil}), do: :ok

  defp configuration(s, path) do
    case s.assemblies[path.config] do
      {:configuration, size, _initial} when byte_size(path.data) == size -> :ok
      _other -> {:error, 0x0118, []}
    end
  end

  # The sizes the Forward_Open counts, with the sequence count, and the 32-bit header of outputs
  # (Volume 1, 3-6.1): a heartbeat has the sequence count alone.
  defp sizes(s, kind, path, request) do
    o_t =
      case kind do
        :exclusive_owner -> [elem(s.assemblies[path.o_t], 1) + 6]
        _heartbeat -> [2, 0]
      end

    t_o = elem(s.assemblies[path.t_o], 1) + 2

    cond do
      request.o_t.size not in o_t -> {:error, 0x0127, [hd(o_t)]}
      request.t_o.size != t_o -> {:error, 0x0128, [t_o]}
      true -> :ok
    end
  end

  defp rpis(s, request) do
    {min, max} = s.rpi
    check(request.o_t.rpi in min..max and request.t_o.rpi in min..max, 0x0111)
  end

  # Inputs by change of state no more often than the production inhibit time, which must be less
  # than the RPI.
  defp inhibit(%{trigger: {_direction, :cyclic, _class}}, _path), do: :ok
  defp inhibit(_request, %{inhibit: nil}), do: :ok

  defp inhibit(request, %{inhibit: {:production_inhibit, ms}}),
    do: check(ms * 1000 <= request.t_o.rpi, 0x011B)

  # One exclusive owner of an output assembly (Volume 1, 3-6.4.3).
  defp ownership(s, :exclusive_owner, path) do
    check(
      not Enum.any?(
        Map.values(s.connections),
        &(&1.kind == :exclusive_owner and &1.output == path.o_t)
      ),
      0x0106
    )
  end

  defp ownership(_s, _kind, _path), do: :ok

  # A listen only connection depends on another to the same inputs (Volume 1, 3-6.4.1).
  defp listened(s, :listen_only, path),
    do: check(Enum.any?(Map.values(s.connections), &listened?(&1, path.t_o)), 0x0119)

  defp listened(_s, _kind, _path), do: :ok

  defp listened?(c, input), do: c.class == 1 and c.kind != :listen_only and c.input == input

  # Configuration that another connection to it has already given must be the same
  # (Volume 1, 3-6.2).
  defp same_configuration(_s, %{data: nil}), do: :ok

  defp same_configuration(s, path) do
    if Enum.any?(Map.values(s.connections), &(&1[:config] == path.config)) do
      [{_key, current}] = :ets.lookup(s.table, {:data, path.config})
      check(current == path.data, 0x0106)
    else
      :ok
    end
  end

  defp configure(s, %{data: nil}), do: s

  defp configure(s, path) do
    [{_key, current}] = :ets.lookup(s.table, {:data, path.config})

    if current != path.data do
      :ets.insert(s.table, {{:data, path.config}, path.data})
      notify(s, {:configuration, path.config, path.data})
    end

    %{s | configured: true}
  end

  # The production of the inputs: one of their own for point-to-point inputs, to the originator,
  # at the port it gives; multicast inputs share the production of others to the same inputs, if
  # it has the same parameters (CIP Conformance Test Specification, 6.3.5), or start one, to one
  # of the adapter's multicast addresses (Volume 2, 3-5.3).
  defp production(s, request, path, ctx) do
    {_direction, trigger, _class} = request.trigger
    inhibit = with {:production_inhibit, ms} <- path.inhibit, do: ms

    wanted = %{
      point: path.t_o,
      multicast: request.t_o.type == :multicast,
      rpi: request.t_o.rpi,
      size: request.t_o.size,
      fixed: request.t_o.fixed,
      priority: request.t_o.priority,
      trigger: trigger,
      inhibit: inhibit || 0
    }

    shared =
      Enum.find(
        Map.values(s.productions),
        &(&1.multicast and wanted.multicast and &1.point == path.t_o)
      )

    if shared, do: share(shared, wanted), else: {:ok, new_production(s, wanted, request, ctx)}
  end

  # The extended status of the first parameter that differs from those of the production.
  @mismatches [
    rpi: 0x0112,
    size: 0x0134,
    fixed: 0x0135,
    priority: 0x0136,
    trigger: 0x0138,
    inhibit: 0x0139
  ]

  defp share(shared, wanted) do
    case Enum.find(@mismatches, fn {key, _code} -> shared[key] != wanted[key] end) do
      nil -> {:ok, Map.put(shared, :new, false)}
      {_key, code} -> {:error, code, []}
    end
  end

  # The first of the device's multicast addresses that no other production has, or the first
  # when they all have one.
  defp new_production(s, %{multicast: true} = wanted, _request, ctx) do
    {_serial, id} = EtherNetIP.Application.numbers()
    interface = Objects.interface(ctx.local)
    taken = for %{multicast: true, to: {group, _port}} <- Map.values(s.productions), do: group
    groups = Enum.map(0..31, &Objects.multicast_address(interface, &1))
    group = Enum.find(groups, hd(groups), &(&1 not in taken))
    to = {group, s.udp_port}
    Map.merge(wanted, %{key: make_ref(), id: id, to: to, interface: ctx.local, new: true})
  end

  defp new_production(_s, wanted, request, ctx) do
    port =
      Enum.find_value(ctx.items, IOPacket.port(), fn
        {:sockaddr, :t_o, {_address, port}} when port > 0 -> port
        _item -> nil
      end)

    to = {ctx.peer, port}

    Map.merge(wanted, %{
      key: make_ref(),
      id: request.t_o_id,
      to: to,
      interface: ctx.local,
      new: true
    })
  end

  defp subscribe(s) do
    case UDP.ensure(s.udp_port) do
      {:ok, udp} -> {:ok, udp}
      {:error, _reason} -> {:error, 0x0303, []}
    end
  end

  # Each endpoint once.
  defp monitor_udp(%{udp: udp} = s, udp), do: s

  defp monitor_udp(s, udp) do
    Process.monitor(udp)
    %{s | udp: udp}
  end

  defp granted(c, request) do
    ConnectionManager.encode_forward_open_reply(%{
      o_t_id: c.o_t_id,
      t_o_id: c.t_o_id,
      serial: request.serial,
      vendor_id: request.vendor_id,
      originator_serial: request.originator_serial,
      o_t_api: c.o_t_api,
      t_o_api: c.t_o_api
    })
  end

  # A connection waits at least 10 s for its first packet (Volume 1, 3-5.5.2).
  defp opened(s, c) do
    c = watchdog(c, max(10_000, timeout(c)))

    s = %{
      s
      | connections: Map.put(s.connections, c.triad, c),
        by_o_t: Map.put(s.by_o_t, c.o_t_id, c.triad)
    }

    s = if c.class == 1, do: %{s | faulted: false}, else: s
    notify(s, {:opened, info(c)})
    s
  end

  defp info(%{class: 3} = c), do: %{kind: :explicit, originator: c.peer}

  defp info(c) do
    %{
      kind: c.kind,
      originator: c.peer,
      output: c.output,
      input: c.input,
      rpi: {c.o_t_api, c.t_o_api},
      multicast: c.multicast
    }
  end

  # The connection timeout in ms: the multiplier times the O->T packet interval.
  defp timeout(c), do: max(1, div(c.o_t_api * c.multiplier, 1000))

  defp watchdog(c, ms) do
    _ = if c.watchdog, do: Process.cancel_timer(c.watchdog)
    generation = c.generation + 1

    %{
      c
      | generation: generation,
        watchdog: Process.send_after(self(), {:watchdog, c.triad, generation}, ms)
    }
  end

  ## Closing

  # A connection that closes, for any reason, takes its production with it when it was the last
  # to consume it; an exclusive owner that times out takes it in any case, so that its originator
  # sees it gone (Volume 1, 3-6.4.3). Listen only connections that depended on it close too.
  defp close(s, triad, reason) do
    case Map.pop(s.connections, triad) do
      {nil, _connections} ->
        s

      {c, connections} ->
        _ = if c.watchdog, do: Process.cancel_timer(c.watchdog)
        _ = if c.class == 1, do: UDP.unregister(c.udp, c.peer, c.o_t_id)
        s = %{s | connections: connections, by_o_t: Map.delete(s.by_o_t, c.o_t_id)}
        s = if c.class == 1 and reason == :timed_out, do: %{s | faulted: true}, else: s
        notify(s, {:closed, info(c), reason})

        if c.class == 1,
          do: s |> released(c, reason) |> outputs_closed(c) |> orphans(c),
          else: s
    end
  end

  defp released(s, c, reason) do
    case Map.fetch(s.productions, c.production) do
      {:ok, production} ->
        consumers = List.delete(production.consumers, c.triad)

        cond do
          c.kind == :exclusive_owner and reason == :timed_out ->
            s = %{s | productions: Map.delete(s.productions, production.key)}
            Enum.reduce(consumers, s, &close(&2, &1, :owner_timed_out))

          consumers == [] ->
            %{s | productions: Map.delete(s.productions, production.key)}

          true ->
            put_in(s.productions[production.key].consumers, consumers)
        end

      :error ->
        s
    end
  end

  defp outputs_closed(s, %{kind: :exclusive_owner, output: instance}) do
    [{_key, _state, at}] = :ets.lookup(s.table, {:output, instance})
    :ets.insert(s.table, {{:output, instance}, :closed, at})
    notify(s, {:state, instance, :closed})
    s
  end

  defp outputs_closed(s, _c), do: s

  defp orphans(s, %{kind: :listen_only}), do: s

  defp orphans(s, c) do
    if Enum.any?(Map.values(s.connections), &listened?(&1, c.input)) do
      s
    else
      Enum.reduce(s.connections, s, fn
        {triad, %{kind: :listen_only, input: input}}, s when input == c.input ->
          close(s, triad, :orphaned)

        _other, s ->
          s
      end)
    end
  end

  # As if power had been cycled: every connection and session goes, without a word to the
  # originators, which time out; type 1 also restores the configuration and outputs it started
  # with.
  defp reset(s, type) do
    s = Enum.reduce(Map.keys(s.connections), s, &close(&2, &1, :reset))

    _ =
      for {instance, {kind, _size, data}} <- s.assemblies,
          type == 1 and kind in [:configuration, :output],
          do: :ets.insert(s.table, {{:data, instance}, data})

    for pid <- Map.keys(s.sessions), do: send(pid, :close)
    notify(s, {:reset, type})
    %{s | configured: if(type == 1, do: false, else: s.configured)}
  end

  ## Consuming outputs and heartbeats

  defp consume(s, triad, packet) do
    c = s.connections[triad]

    with %{class: 1} <- c,
         {:ok, {_id, sequence, data}} <- IOPacket.decode(packet),
         true <- in_order?(c, sequence),
         {:ok, count, run, outputs} <- packet_data(s, c, data) do
      c = %{watchdog(c, timeout(c)) | last_sequence: sequence}
      new = count != c.last_count
      c = %{c | last_count: count}

      if c.kind == :exclusive_owner, do: outputs(s, c, new, run, outputs)

      c = if c.kind == :exclusive_owner, do: %{c | run: run}, else: c
      put_in(s.connections[triad], c)
    else
      # Discarded packets don't keep the connection alive (Volume 2, 3-4.1).
      _discarded -> s
    end
  end

  # Outputs with the 32-bit run/idle header, of the assembly's size; a heartbeat, the sequence
  # count alone, or anything after it.
  defp packet_data(s, %{kind: :exclusive_owner} = c, data) do
    {:output, size, _initial} = s.assemblies[c.output]

    case IOPacket.decode_class1(data, :header) do
      {:ok, {count, run, outputs}} when byte_size(outputs) == size ->
        {:ok, count, run == :run, outputs}

      _invalid ->
        :error
    end
  end

  defp packet_data(_s, _c, <<count::little-16, _rest::binary>>), do: {:ok, count, nil, <<>>}
  defp packet_data(_s, _c, _data), do: :error

  defp in_order?(%{last_sequence: nil}, _sequence), do: true
  defp in_order?(c, sequence), do: IOPacket.next?(c.last_sequence, sequence, c.multiplier)

  # Outputs in run mode are the application's; idle ones aren't taken (Volume 1, 3-6.1.4).
  defp outputs(s, c, new, run, data) do
    state = if run, do: :run, else: :idle
    if run and new, do: :ets.insert(s.table, {{:data, c.output}, data})
    :ets.insert(s.table, {{:output, c.output}, state, System.monotonic_time()})
    if run and new, do: notify(s, {:outputs, c.output, data})
    if c.run != run, do: notify(s, {:state, c.output, state})
  end

  ## Producing inputs

  defp start_production(s, %{new: false} = production, triad) do
    put_in(s.productions[production.key].consumers, production.consumers ++ [triad])
  end

  defp start_production(s, production, triad) do
    production =
      production
      |> Map.delete(:new)
      |> Map.merge(%{
        consumers: [triad],
        sequence: :rand.uniform(0x1_0000_0000) - 1,
        count: :rand.uniform(0x10000) - 1,
        last: nil,
        tick: 0,
        next: nil,
        sent: nil
      })

    s
    |> Map.update!(:productions, &Map.put(&1, production.key, production))
    |> sender(production)
    |> produce(production.key)
  end

  # Multicast inputs go from a socket of the adapter's own on the interface the originator reached
  # it on, so that they leave by that interface whatever the routes of the host.
  defp sender(s, %{multicast: true, interface: interface})
       when not is_map_key(s.senders, interface) do
    options = [
      :binary,
      active: false,
      multicast_if: interface,
      multicast_ttl: 1,
      multicast_loop: true
    ]

    case :gen_udp.open(0, [{:ip, interface} | options]) do
      {:ok, socket} -> put_in(s.senders[interface], socket)
      {:error, _reason} -> s
    end
  end

  defp sender(s, _production), do: s

  defp produce(s, key) do
    p = s.productions[key]
    [{_key, data}] = :ets.lookup(s.table, {:data, p.point})
    count = if data != p.last, do: band(p.count + 1, 0xFFFF), else: p.count
    sequence = band(p.sequence + 1, 0xFFFF_FFFF)
    packet = IOPacket.encode(p.id, sequence, IOPacket.encode_class1(count, :modeless, true, data))
    {address, port} = p.to

    _ =
      case {p.multicast, s.senders[p.interface]} do
        {true, socket} when socket != nil -> :gen_udp.send(socket, address, port, packet)
        _p2p -> UDP.send(s.udp, address, port, packet)
      end

    # The next an RPI after this one was due, or after now when it's late; by change of state,
    # also when the inputs change.
    now = System.monotonic_time(:microsecond)
    next = if p.next && p.next + p.rpi > now, do: p.next + p.rpi, else: now + p.rpi
    tick = p.tick + 1
    :erlang.send_after(div(next, 1000), self(), {:produce, key, tick}, abs: true)

    p = %{p | count: count, sequence: sequence, last: data, next: next, tick: tick, sent: now}
    put_in(s.productions[key], p)
  end

  # Inputs that changed go at once to the connections that take them by change of state, or as
  # soon as the production inhibit time allows.
  defp changed(s, instance) do
    Enum.reduce(Map.values(s.productions), s, fn
      %{point: ^instance, trigger: trigger} = p, s when trigger != :cyclic ->
        now = System.monotonic_time(:microsecond)
        due = p.sent + p.inhibit * 1000

        if now >= due do
          produce(put_in(s.productions[p.key].next, nil), p.key)
        else
          tick = p.tick + 1
          :erlang.send_after(div(due, 1000) + 1, self(), {:produce, p.key, tick}, abs: true)
          put_in(s.productions[p.key], %{p | tick: tick, next: nil})
        end

      _p, s ->
        s
    end)
  end

  defp notify(%{subscriber: nil}, _event), do: :ok

  defp notify(s, event) do
    send(s.subscriber, {EtherNetIP.Adapter, event})
  rescue
    ArgumentError -> :ok
  end

  defp now, do: System.monotonic_time(:millisecond)
end
