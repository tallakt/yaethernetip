defmodule EtherNetIP.Scanner.Server do
  @moduledoc false
  # The process of a scanner. Over TCP it registers a session and sends unconnected messages in
  # SendRRData, up to max_pending at once, each under a sender context of its own. Its I/O
  # connections are opened with Forward_Open through the same session; then it sends each one's
  # outputs from the shared UDP endpoint every RPI, and the endpoint sends it the inputs. A
  # connection whose inputs stop for its timeout, or that can't be opened, is tried again after a
  # backoff.

  use GenServer

  import Bitwise

  alias EtherNetIP.{CIP, ConnectionManager, Encapsulation, IOPacket, Path, UDP}

  @unconnected_send 0x52

  @impl true
  def init(config) do
    Process.flag(:trap_exit, true)

    s =
      Map.merge(config, %{
        socket: nil,
        connector: nil,
        status: :connecting,
        session: 0,
        buffer: <<>>,
        next: 0,
        pending: %{},
        queue: :queue.new(),
        heard: now(),
        silent: false,
        delay: elem(config.backoff, 0),
        idle: nil,
        address: nil,
        interface: nil,
        udp: nil,
        connections: %{},
        by_id: %{}
      })

    s = Enum.reduce(config.connections, s, fn {name, spec}, s -> add(s, name, spec) end)
    {:ok, connect(s)}
  end

  ## Calls

  @impl true
  def handle_call({:request, request, timeout}, from, s),
    do: {:noreply, submit(s, entry(request, timeout, {:call, from}, s))}

  def handle_call(:status, _from, s), do: {:reply, s.status, s}

  def handle_call(:connections, _from, s),
    do: {:reply, Map.new(s.connections, fn {name, c} -> {name, c.status} end), s}

  def handle_call({:put, name, data}, _from, s) do
    case Map.fetch(s.connections, name) do
      {:ok, %{spec: %{output_size: size}}} when byte_size(data) != size ->
        {:reply, {:error, {:size, size}}, s}

      {:ok, c} ->
        c = %{c | outputs: data, changed: c.changed or data != c.outputs}
        {:reply, :ok, changed(put_in(s.connections[name], c), name)}

      :error ->
        {:reply, {:error, :unknown}, s}
    end
  end

  def handle_call({:run, name, run}, _from, s) do
    case Map.fetch(s.connections, name) do
      {:ok, c} ->
        c = %{c | run: run, changed: c.changed or run != c.run}
        {:reply, :ok, changed(put_in(s.connections[name], c), name)}

      :error ->
        {:reply, {:error, :unknown}, s}
    end
  end

  def handle_call({:inputs, name}, _from, s) do
    reply =
      case Map.fetch(s.connections, name) do
        {:ok, %{state: :open, inputs: nil}} -> {:error, :waiting}
        {:ok, %{state: :open, inputs: inputs}} -> {:ok, inputs}
        {:ok, %{status: {:failed, reason}}} -> {:error, reason}
        {:ok, %{status: status}} -> {:error, status}
        :error -> {:error, :unknown}
      end

    {:reply, reply, s}
  end

  def handle_call({:open, name, spec}, _from, s) do
    if Map.has_key?(s.connections, name),
      do: {:reply, {:error, :exists}, s},
      else: {:reply, :ok, s |> add(name, spec) |> open(name)}
  end

  def handle_call({:close, name}, _from, s) do
    case Map.fetch(s.connections, name) do
      {:ok, c} ->
        s = s |> shut(name) |> forward_close(c)
        {:reply, :ok, %{s | connections: Map.delete(s.connections, name)}}

      :error ->
        {:reply, {:error, :unknown}, s}
    end
  end

  @impl true
  def handle_cast({:request, request, timeout, to, ref}, s),
    do: {:noreply, submit(s, entry(request, timeout, {:send, to, ref}, s))}

  ## The session

  @impl true
  def handle_info({:connected, connector, socket}, %{connector: connector} = s) do
    s = %{s | socket: socket, connector: nil, status: :registering, buffer: <<>>, heard: now()}

    # The interface the device is reached on is the one its multicast comes to.
    with :ok <- :inet.setopts(socket, active: :once),
         {:ok, {address, _port}} <- :inet.peername(socket),
         {:ok, {interface, _port}} <- :inet.sockname(socket),
         :ok <-
           send_message(s, %Encapsulation{
             command: :register_session,
             data: Encapsulation.register_session()
           }) do
      Process.send_after(self(), {:registering, socket}, s.timeout)
      {:noreply, %{s | address: address, interface: interface}}
    else
      {:error, reason} -> {:noreply, drop(s, reason)}
    end
  end

  # A device may take the TCP connection and never answer RegisterSession.
  def handle_info({:registering, socket}, %{socket: socket, status: :registering} = s),
    do: {:noreply, drop(s, :timeout)}

  def handle_info({:connect_failed, connector, reason}, %{connector: connector} = s),
    do: {:noreply, drop(%{s | connector: nil}, reason)}

  def handle_info(:reconnect, %{status: {:disconnected, _}} = s), do: {:noreply, connect(s)}

  def handle_info({:tcp, socket, data}, %{socket: socket} = s) do
    s = messages(%{s | buffer: s.buffer <> data})
    _ = if s.socket, do: :inet.setopts(s.socket, active: :once)
    {:noreply, s}
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = s), do: {:noreply, drop(s, :closed)}

  def handle_info({:tcp_error, socket, reason}, %{socket: socket} = s),
    do: {:noreply, drop(s, reason)}

  def handle_info({:expire, context}, s), do: {:noreply, expire(s, context)}

  def handle_info({:keepalive, ref}, %{idle: ref, status: :connected} = s) do
    # A NOP keeps the device from closing the session for inactivity (Volume 2, 2-5.5.2).
    s =
      case send_message(s, %Encapsulation{command: :nop, session: s.session}) do
        :ok -> keepalive(s)
        {:error, reason} -> drop(s, reason)
      end

    {:noreply, s}
  end

  def handle_info({:EXIT, connector, reason}, %{connector: connector} = s) when reason != :normal,
    do: {:noreply, drop(%{s | connector: nil}, reason)}

  ## I/O connections

  def handle_info({:produce, name, tick}, s) do
    case Map.fetch(s.connections, name) do
      {:ok, %{state: :open, tick: ^tick}} -> {:noreply, produce(s, name)}
      _stale -> {:noreply, s}
    end
  end

  def handle_info({:watchdog, name, generation}, s) do
    case Map.fetch(s.connections, name) do
      {:ok, %{state: :open, generation: ^generation}} -> {:noreply, timed_out(s, name)}
      _stale -> {:noreply, s}
    end
  end

  def handle_info({:retry, name, generation}, s) do
    case Map.fetch(s.connections, name) do
      {:ok, %{generation: ^generation} = c} ->
        {:noreply, open(put_in(s.connections[name], %{c | retry: nil}), name)}

      _stale ->
        {:noreply, s}
    end
  end

  # Connections that consume the same multicast production share its id.
  def handle_info({UDP, id, packet}, s) do
    names = Map.get(s.by_id, id, [])
    {:noreply, Enum.reduce(names, s, &consume(&2, &1, packet))}
  end

  # A UDP endpoint that stopped took the routes of the connections it had: each is closed, and
  # opened again with the next endpoint.
  def handle_info({:DOWN, _ref, :process, udp, _reason}, s) do
    s =
      Enum.reduce(s.connections, s, fn
        {name, %{state: :open, udp: ^udp} = c}, s ->
          s |> shut(name) |> forward_close(c) |> failed(name, {:udp, :closed})

        _other, s ->
          s
      end)

    {:noreply, if(s.udp == udp, do: %{s | udp: nil}, else: s)}
  end

  def handle_info(_message, s), do: {:noreply, s}

  @impl true
  def terminate(_reason, s) do
    if s.connector, do: Process.exit(s.connector, :kill)

    if s.socket do
      # Closes each connection on the way out, without waiting for the replies, those being
      # opened too, which the device may have opened.
      for {_name, %{state: state} = c} <- s.connections,
          state in [:open, :opening] and s.status == :connected do
        context = <<0xFFFF_FFFF::32, c.serial::32>>
        _ = send_request(s, context, forward_close_request(s, c))
      end

      _ = send_message(s, %Encapsulation{command: :unregister_session, session: s.session})
      :gen_tcp.close(s.socket)
    end
  end

  defp connect(s) do
    parent = self()
    %{host: host, port: port, connect_timeout: timeout} = s

    connector =
      spawn_link(fn ->
        options = [:binary, active: false, nodelay: true, send_timeout: timeout]

        case :gen_tcp.connect(host, port, options, timeout) do
          {:ok, socket} ->
            :ok = :gen_tcp.controlling_process(socket, parent)
            send(parent, {:connected, self(), socket})

          {:error, reason} ->
            send(parent, {:connect_failed, self(), reason})
        end
      end)

    %{s | connector: connector, status: :connecting}
  end

  defp drop(s, reason) do
    if s.socket, do: :gen_tcp.close(s.socket)

    s =
      Enum.reduce(Map.keys(s.pending), s, fn context, s ->
        {entry, pending} = Map.pop(s.pending, context)
        finish(%{s | pending: pending}, entry, {:error, :closed})
      end)

    s =
      Enum.reduce(:queue.to_list(s.queue), %{s | queue: :queue.new()}, fn entry, s ->
        finish(s, entry, {:error, :closed})
      end)

    {first, longest} = s.backoff
    Process.send_after(self(), :reconnect, s.delay)

    %{
      s
      | socket: nil,
        status: {:disconnected, reason},
        session: 0,
        buffer: <<>>,
        silent: false,
        idle: nil,
        delay: min(max(s.delay, first) * 2, longest)
    }
  end

  defp messages(s) do
    case Encapsulation.decode(s.buffer) do
      {:ok, message, rest} ->
        messages(message(%{s | buffer: rest, heard: now(), silent: false}, message))

      :more ->
        s
    end
  end

  defp message(%{status: :registering} = s, %Encapsulation{command: :register_session} = message) do
    case message.status do
      :success ->
        s = %{s | status: :connected, session: message.session, delay: elem(s.backoff, 0)}
        s |> keepalive() |> flush() |> open_all()

      status ->
        drop(s, {:register_session, status})
    end
  end

  defp message(%{status: :connected} = s, %Encapsulation{command: :send_rr_data} = message) do
    case Map.pop(s.pending, message.context) do
      {nil, _pending} ->
        s

      {entry, pending} ->
        _ = Process.cancel_timer(entry.timer)
        s = finish(%{s | pending: pending}, entry, reply(entry, message))
        flush(s)
    end
  end

  # NOPs, and anything else the scanner didn't ask for.
  defp message(s, _message), do: s

  defp reply(_entry, %Encapsulation{status: status}) when status != :success,
    do: {:error, {:encapsulation, status}}

  defp reply(entry, message) do
    with {:ok, items} <- Encapsulation.decode_rr_data(message.data),
         {:unconnected_data, data} <- List.keyfind(items, :unconnected_data, 0),
         {:ok, reply} <- CIP.decode_reply(data),
         true <- reply.service in entry.services do
      {:reply, reply, items}
    else
      _invalid -> {:error, :invalid_reply}
    end
  end

  ## Explicit messages

  defp entry(<<service, _rest::binary>> = request, timeout, reply, s) do
    # A reply to a routed request may carry the service of the request inside it.
    services =
      case request do
        <<@unconnected_send, words, _path::binary-size(words * 2), _tick, _ticks, _size::16,
          embedded, _rest::binary>> ->
          [@unconnected_send, band(embedded, 0x7F)]

        _request ->
          [service]
      end

    %{
      request: request,
      services: services,
      items: [],
      timeout: timeout || s.timeout,
      reply: reply,
      timer: nil,
      sent: nil
    }
  end

  defp submit(%{status: {:disconnected, _}} = s, entry), do: finish(s, entry, {:error, :closed})

  defp submit(s, entry) do
    s = %{s | next: s.next + 1}
    context = <<s.next::64>>
    timer = Process.send_after(self(), {:expire, context}, entry.timeout)
    flush(%{s | queue: :queue.in({context, %{entry | timer: timer}}, s.queue)})
  end

  defp flush(%{status: :connected} = s) when map_size(s.pending) < s.max_pending do
    case :queue.out(s.queue) do
      {{:value, {context, entry}}, queue} ->
        case send_request(s, context, entry.request, entry.items) do
          :ok ->
            pending = Map.put(s.pending, context, %{entry | sent: now()})
            flush(keepalive(%{s | queue: queue, pending: pending}))

          {:error, reason} ->
            drop(%{s | queue: :queue.in_r({context, entry}, queue)}, reason)
        end

      {:empty, _queue} ->
        s
    end
  end

  defp flush(s), do: s

  defp expire(s, context) do
    case Map.pop(s.pending, context) do
      {nil, _pending} ->
        # It may still wait its turn.
        case Enum.split_with(:queue.to_list(s.queue), &(elem(&1, 0) == context)) do
          {[{_context, entry}], rest} ->
            finish(%{s | queue: :queue.from_list(rest)}, entry, {:error, :timeout})

          {[], _rest} ->
            s
        end

      {entry, pending} ->
        s = finish(%{s | pending: pending}, entry, {:error, :timeout})

        # Two requests in a row that time out with nothing at all heard since the first was sent
        # mean the connection is dead, as one a rebooted device left half open.
        cond do
          s.heard >= entry.sent -> flush(s)
          s.silent -> drop(s, :timeout)
          true -> flush(%{s | silent: true})
        end
    end
  end

  defp finish(s, %{reply: {:internal, tag}}, result), do: internal(s, tag, result)

  defp finish(s, entry, result) do
    result =
      case result do
        {:reply, %{status: :success, data: data}, _items} -> {:ok, data}
        {:reply, reply, _items} -> {:error, {:cip, reply.status, reply.additional}}
        error -> error
      end

    case entry.reply do
      {:call, from} -> GenServer.reply(from, result)
      {:send, to, ref} -> deliver(to, {EtherNetIP.Scanner, ref, result})
    end

    s
  end

  # To a process, or to a name, which may not be registered, or no longer.
  defp deliver(to, message) do
    send(to, message)
  rescue
    ArgumentError -> message
  end

  defp send_request(s, context, request, items \\ []) do
    data = Encapsulation.rr_data([:null_address, {:unconnected_data, request} | items])

    send_message(s, %Encapsulation{
      command: :send_rr_data,
      session: s.session,
      context: context,
      data: data
    })
  end

  defp send_message(s, message), do: :gen_tcp.send(s.socket, Encapsulation.encode(message))

  defp keepalive(s) do
    ref = make_ref()
    Process.send_after(self(), {:keepalive, ref}, s.keepalive)
    %{s | idle: ref}
  end

  ## I/O connections

  defp add(s, name, spec) do
    c = %{
      name: name,
      spec: spec,
      state: :closed,
      status: :opening,
      generation: 0,
      tick: 0,
      retry: nil,
      delay: elem(s.backoff, 0),
      serial: nil,
      o_t_id: nil,
      t_o_id: nil,
      o_t_api: nil,
      t_o_api: nil,
      o_t_port: IOPacket.port(),
      udp: nil,
      membership: nil,
      outputs: <<0::size(spec.output_size * 8)>>,
      changed: false,
      run: spec.run,
      count: :rand.uniform(0x10000) - 1,
      sequence: :rand.uniform(0x1_0000_0000) - 1,
      last_sequence: nil,
      last_count: nil,
      inputs: nil,
      input_run: nil,
      next: nil,
      watchdog: nil
    }

    put_in(s.connections[name], c)
  end

  defp open_all(s) do
    Enum.reduce(s.connections, s, fn
      {name, %{state: :closed, retry: nil}}, s -> open(s, name)
      _other, s -> s
    end)
  end

  # The UDP endpoint is started first, so that a port that can't be had fails the connection
  # before the device opens it.
  defp open(%{status: :connected} = s, name) do
    c = s.connections[name]

    with %{state: :closed} <- c,
         {:ok, _udp} <- UDP.ensure(s.udp_port) do
      {serial, id} = EtherNetIP.Application.numbers()
      c = %{c | serial: serial, t_o_id: id, generation: c.generation + 1, state: :opening}
      s = put_in(s.connections[name], c)
      request = forward_open_request(s, c)
      entry = entry(request, s.timeout, {:internal, {:forward_open, name, c}}, s)

      # A consumer of point-to-point inputs on another port than 2222 says which (Volume 2,
      # 3-3.9.5).
      items =
        if not c.spec.multicast and s.udp_port != IOPacket.port(),
          do: [{:sockaddr, :t_o, {{0, 0, 0, 0}, s.udp_port}}],
          else: []

      submit(s, %{entry | items: items})
    else
      %{} -> s
      {:error, reason} -> failed(s, name, {:udp, reason})
    end
  end

  # Opened when the session is up.
  defp open(s, _name), do: s

  # The connection as it was when its Forward_Open went, the attempt, comes back with the reply.
  defp internal(s, {:forward_open, name, %{generation: generation} = attempt}, result) do
    case Map.fetch(s.connections, name) do
      {:ok, %{generation: ^generation, state: :opening}} -> opened(s, name, result)
      _gone -> abandon(s, attempt, result)
    end
  end

  defp internal(s, :forward_close, _result), do: s

  defp opened(s, name, {:reply, %{status: :success, data: data}, items}) do
    c = s.connections[name]

    with {:ok, reply} <- granted(s, c, data),
         {:ok, membership} <- membership(c, sockaddr(items, :t_o), s.interface),
         {:ok, udp} <- subscribe(s, reply.t_o_id, membership) do
      o_t_port =
        case sockaddr(items, :o_t) do
          {_address, port} when port > 0 -> port
          _none -> IOPacket.port()
        end

      c = %{
        c
        | state: :open,
          status: :open,
          o_t_id: reply.o_t_id,
          t_o_id: reply.t_o_id,
          o_t_api: reply.o_t_api,
          t_o_api: reply.t_o_api,
          o_t_port: o_t_port,
          udp: udp,
          membership: membership,
          delay: elem(s.backoff, 0),
          last_sequence: nil,
          last_count: nil,
          inputs: nil,
          input_run: nil,
          next: nil
      }

      # Before the first inputs, the watchdog waits at least 10 s (Volume 1, 3-4.5.2).
      c = watchdog(c, max(10_000, timeout(c)))
      by_id = Map.update(s.by_id, c.t_o_id, [name], &[name | &1])
      s = %{put_in(s.connections[name], c) | by_id: by_id}
      notify(c, {:status, :open})
      s |> monitor_udp(udp) |> produce(name)
    else
      {:error, reason} -> s |> release(c) |> failed(name, reason)
    end
  end

  defp opened(
         s,
         name,
         {:reply, %{status: :connection_failure, additional: [extended | rest]}, _}
       ),
       do:
         failed(s, name, {:connection_failure, ConnectionManager.extended_status(extended), rest})

  defp opened(s, name, {:reply, reply, _items}),
    do: failed(s, name, {:cip, reply.status, reply.additional})

  defp opened(s, name, {:error, reason} = result),
    do: s |> abandon(s.connections[name], result) |> failed(name, reason)

  # A Forward_Open the scanner no longer waits for, whose reply came too late or never came, may
  # have opened a connection, which the device would hold until it timed out there, and an
  # exclusive owner's would keep the next Forward_Open out until then: it's closed.
  defp abandon(s, attempt, {:reply, %{status: :success}, _items}), do: release(s, attempt)
  defp abandon(s, attempt, {:error, :timeout}), do: release(s, attempt)
  defp abandon(s, _attempt, _result), do: s

  # A reply must be to this connection's Forward_Open, by its triad, and give packet intervals of
  # at least half the RPIs: a smaller, more rapid, one is for a scheduled connection whose
  # producer goes in steps (Volume 1, 3-5.5.1.2), and one of a few µs would have the scanner
  # flood the device with outputs, or time out at once.
  defp granted(s, c, data) do
    case ConnectionManager.decode_forward_open_reply(data) do
      {:ok, %{serial: serial, vendor_id: vendor_id, originator_serial: originator} = reply}
      when serial == c.serial and vendor_id == s.vendor_id and originator == s.serial_number and
             reply.o_t_api * 2 >= c.spec.output_rpi and reply.t_o_api * 2 >= c.spec.input_rpi ->
        {:ok, reply}

      _invalid ->
        {:error, :invalid_reply}
    end
  end

  defp sockaddr(items, direction) do
    Enum.find_value(items, fn
      {:sockaddr, ^direction, address} -> address
      _item -> nil
    end)
  end

  # A multicast connection's inputs come to the group the device gives (Volume 2, 3-3.9.4), which
  # the scanner joins on the interface of the session.
  defp membership(%{spec: %{multicast: true}}, {{first, _, _, _} = group, _port}, interface)
       when first in 224..239,
       do: {:ok, {group, interface}}

  defp membership(%{spec: %{multicast: true}}, _sockaddr, _interface),
    do: {:error, :invalid_reply}

  defp membership(_c, _sockaddr, _interface), do: {:ok, nil}

  # Has the UDP endpoint send the scanner a connection's inputs.
  defp subscribe(s, id, membership) do
    with {:ok, udp} <- udp(UDP.ensure(s.udp_port)),
         :ok <- join(udp, membership),
         :ok <- udp(UDP.register(udp, s.address, id)),
         do: {:ok, udp}
  end

  defp join(_udp, nil), do: :ok

  defp join(udp, {group, interface}) do
    case UDP.join(udp, group, interface) do
      :ok -> :ok
      {:error, :closed} -> {:error, {:udp, :closed}}
      {:error, reason} -> {:error, {:multicast, group, reason}}
    end
  end

  defp leave(%{membership: nil}), do: :ok
  defp leave(%{membership: {group, interface}} = c), do: UDP.leave(c.udp, group, interface)

  defp udp({:error, reason}), do: {:error, {:udp, reason}}
  defp udp(result), do: result

  # Each endpoint once, and the first is the only one unless it stops.
  defp monitor_udp(%{udp: udp} = s, udp), do: s

  defp monitor_udp(s, udp) do
    Process.monitor(udp)
    %{s | udp: udp}
  end

  defp failed(s, name, reason) do
    c = s.connections[name]
    {_first, longest} = s.backoff
    generation = c.generation + 1
    retry = Process.send_after(self(), {:retry, name, generation}, c.delay)
    status = {:failed, reason}
    if c.status != status, do: notify(c, {:status, status})

    c = %{
      c
      | state: :closed,
        status: status,
        generation: generation,
        retry: retry,
        delay: min(c.delay * 2, longest)
    }

    put_in(s.connections[name], c)
  end

  defp timed_out(s, name) do
    c = s.connections[name]
    s |> shut(name) |> forward_close(c) |> failed(name, :timed_out)
  end

  # Stops sending and taking a connection's data.
  defp shut(s, name) do
    c = s.connections[name]

    if c.state == :open do
      _ = UDP.unregister(c.udp, s.address, c.t_o_id)
      _ = leave(c)
    end

    _ = if c.watchdog, do: Process.cancel_timer(c.watchdog)
    _ = if c.retry, do: Process.cancel_timer(c.retry)

    c = %{c | state: :closed, generation: c.generation + 1, watchdog: nil, retry: nil}

    by_id =
      case Map.get(s.by_id, c.t_o_id, []) -- [name] do
        [] -> Map.delete(s.by_id, c.t_o_id)
        names -> Map.put(s.by_id, c.t_o_id, names)
      end

    %{put_in(s.connections[name], c) | by_id: by_id}
  end

  defp forward_close(s, %{state: :open} = c), do: release(s, c)
  defp forward_close(s, _c), do: s

  # Closes what a connection, or an attempt to open one, has on the device.
  defp release(s, c),
    do: submit(s, entry(forward_close_request(s, c), s.timeout, {:internal, :forward_close}, s))

  # Outputs by change of state go as soon as they change.
  defp changed(s, name) do
    case s.connections[name] do
      %{changed: true, state: :open, spec: %{output_trigger: :change_of_state}} ->
        produce(s, name)

      _c ->
        s
    end
  end

  defp produce(s, name) do
    c = s.connections[name]
    count = if c.changed, do: band(c.count + 1, 0xFFFF), else: c.count
    sequence = band(c.sequence + 1, 0xFFFF_FFFF)
    data = IOPacket.encode_class1(count, c.spec.output_format, c.run, c.outputs)
    _ = UDP.send(c.udp, s.address, c.o_t_port, IOPacket.encode(c.o_t_id, sequence, data))

    # The next goes an RPI after this one was due, or after now when it's late, so that a late
    # one doesn't bring a burst.
    now = System.monotonic_time(:microsecond)
    next = if c.next && c.next + c.o_t_api > now, do: c.next + c.o_t_api, else: now + c.o_t_api
    tick = c.tick + 1
    :erlang.send_after(div(next, 1000), self(), {:produce, name, tick}, abs: true)

    c = %{c | count: count, sequence: sequence, changed: false, next: next, tick: tick}
    put_in(s.connections[name], c)
  end

  defp consume(s, name, packet) do
    c = s.connections[name]

    with {:ok, {_id, sequence, data}} <- IOPacket.decode(packet),
         true <-
           c.last_sequence == nil or IOPacket.next?(c.last_sequence, sequence, c.spec.multiplier),
         {:ok, {count, run, inputs}} <- IOPacket.decode_class1(data, c.spec.input_format),
         true <- fits?(c.spec, inputs) do
      new = count != c.last_count
      if new and run != :idle, do: notify(c, {:inputs, inputs})

      status = if run == :idle, do: :idle, else: :open
      if status != c.status, do: notify(c, {:status, status})

      c = %{
        watchdog(c, timeout(c))
        | last_sequence: sequence,
          last_count: count,
          inputs: if(new and run != :idle, do: inputs, else: c.inputs),
          input_run: run,
          status: status
      }

      put_in(s.connections[name], c)
    else
      # Discarded packets don't keep the connection alive (Volume 2, 3-4.1).
      _discarded -> s
    end
  end

  defp fits?(%{input_format: :heartbeat}, _inputs), do: true

  defp fits?(%{input_format: :zero_length, input_size: size}, inputs),
    do: byte_size(inputs) <= size

  defp fits?(%{input_size: size}, inputs), do: byte_size(inputs) == size

  # The connection timeout, in ms: the inputs' actual packet interval times the multiplier.
  defp timeout(c), do: max(1, div(c.t_o_api * c.spec.multiplier, 1000))

  defp watchdog(c, ms) do
    _ = if c.watchdog, do: Process.cancel_timer(c.watchdog)
    %{c | watchdog: Process.send_after(self(), {:watchdog, c.name, c.generation}, ms)}
  end

  defp notify(%{spec: %{subscriber: nil}}, _event), do: :ok
  defp notify(c, event), do: deliver(c.spec.subscriber, {EtherNetIP.Scanner, c.name, event})

  ## Forward_Open and Forward_Close

  @doc false
  def connection_path(spec) do
    key = if spec.key, do: [spec.key], else: []

    # The device's production of inputs by change of state, at most this often.
    inhibit = if spec.inhibit, do: [{:production_inhibit, spec.inhibit}], else: []

    config = if spec.config, do: [instance: spec.config], else: []
    data = if spec.config_data, do: [{:data, spec.config_data}], else: []

    # Configuration, consumption and production, as Volume 1, Table 3-5.14 has them for the
    # Assembly object: the connection points go with the class, not with the configuration
    # instance.
    Path.encode(
      spec.route ++
        key ++
        inhibit ++
        [class: 4] ++
        config ++ [connection_point: spec.output, connection_point: spec.input] ++ data
    )
  end

  defp size(:header, size), do: size + 6
  defp size(:heartbeat, _size), do: 2
  defp size(_format, size), do: size + 2

  defp forward_open_request(s, c) do
    spec = c.spec
    o_t_size = size(spec.output_format, spec.output_size)
    t_o_size = size(spec.input_format, spec.input_size)

    request = %{
      timeout: s.timeout,
      large: o_t_size > 511 or t_o_size > 511,
      # The target picks the id of point-to-point outputs, and of multicast inputs (Volume 2,
      # Table 3-3.2).
      o_t_id: 0,
      t_o_id: c.t_o_id,
      serial: c.serial,
      vendor_id: s.vendor_id,
      originator_serial: s.serial_number,
      multiplier: spec.multiplier,
      o_t: %{
        rpi: spec.output_rpi,
        size: o_t_size,
        type: :point_to_point,
        priority: spec.priority,
        fixed: spec.output_format != :zero_length,
        redundant_owner: false
      },
      t_o: %{
        rpi: spec.input_rpi,
        size: t_o_size,
        type: if(spec.multicast, do: :multicast, else: :point_to_point),
        priority: spec.priority,
        fixed: spec.input_format != :zero_length,
        redundant_owner: false
      },
      # When the target, the client of the inputs it produces, sends them (Volume 1, 3-4.4.3);
      # the outputs are the scanner's own business.
      trigger: {:client, spec.input_trigger, 1},
      path: connection_path(spec)
    }

    service = if request.large, do: :large_forward_open, else: :forward_open

    CIP.request(
      ConnectionManager.service(service),
      ConnectionManager.path(),
      ConnectionManager.encode_forward_open(request)
    )
  end

  defp forward_close_request(s, c) do
    request = %{
      timeout: s.timeout,
      serial: c.serial,
      vendor_id: s.vendor_id,
      originator_serial: s.serial_number,
      path: connection_path(c.spec)
    }

    CIP.request(
      ConnectionManager.service(:forward_close),
      ConnectionManager.path(),
      ConnectionManager.encode_forward_close(request)
    )
  end

  defp now, do: System.monotonic_time(:millisecond)
end
