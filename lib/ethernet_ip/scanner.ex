defmodule EtherNetIP.Scanner do
  @moduledoc """
  A scanner of one EtherNet/IP device: a session with it over TCP for explicit messages, and the
  I/O connections of its scan list, which it keeps open.

      {:ok, scanner} =
        EtherNetIP.Scanner.start_link(
          host: "10.0.0.20",
          connections: [rack: [config: 1, output: 150, input: 100, output_size: 4, input_size: 8]]
        )

      {:ok, %EtherNetIP.Identity{product_name: name}} = EtherNetIP.Scanner.identity(scanner)
      {:ok, <<1::little-16>>} = EtherNetIP.Scanner.get_attribute_single(scanner, 1, 1, 1)

      :ok = EtherNetIP.Scanner.put(scanner, :rack, <<1, 0, 0, 0>>)
      {:ok, <<_::binary-8>>} = EtherNetIP.Scanner.inputs(scanner, :rack)

  `start_link/1` returns at once, and connects in the background. Every call gets its answer
  within its timeout, as a value: the scanner never exits the caller, and it never logs.

  ## Explicit messages

  `request/5` sends any service to any path as an unconnected message (UCMM), and gives the data
  of the reply:

      {:ok, data} = EtherNetIP.Scanner.request(scanner, :get_attributes_all, class: 1, instance: 1)
      {:error, {:cip, :path_destination_unknown, []}} =
        EtherNetIP.Scanner.request(scanner, :get_attribute_single, class: 0x99, instance: 1, attribute: 1)

  With `route:`, a path of port segments, the request goes through the device's Connection
  Manager with Unconnected_Send, on to another device behind it, as a module in a chassis:
  `route: [{:port, 1, 3}]` for slot 3 of its backplane.

  Up to `:max_pending` requests are on the way at once, told apart by the sender context; more
  wait their turn. `send_request/5` sends one without waiting, the result coming as
  `{EtherNetIP.Scanner, ref, result}`.

  Results are `{:ok, data}` or `{:error, reason}`, the reason one of:

    * `{:cip, status, additional}`: the device's general status (see `EtherNetIP.CIP.status/1`)
      and the words of additional status
    * `{:encapsulation, status}`: the encapsulation layer refused the request
    * `:timeout`, `:closed` while the connection is down, or `:invalid_reply` for a reply that
      doesn't fit its request

  ## I/O connections

  Each connection of `connections:` is opened with a Forward_Open, and the scanner sends its
  outputs every RPI, and takes its inputs as the device sends them. When it times out, because
  inputs stop coming, or can't be opened, the scanner tries again, after 100 ms at first and up
  to 5 seconds between tries (`:backoff`). An I/O connection doesn't need the TCP connection
  once it's open (Volume 2, 3-2.2.3), and goes on while that is down.

  The device's reply to a Forward_Open must be to that Forward_Open, by its connection serial
  number, vendor id and originator serial number, and its packet intervals must be at least half
  the RPIs; one that isn't is refused with `:invalid_reply`. Inputs by multicast come to the group
  it gives, which must be a multicast address, and which the scanner joins on the interface it
  reaches the device on. A connection the scanner gave up opening, whose reply came too late or
  not at all, or wasn't taken, is closed with a Forward_Close, as the device may have opened it.

  A connection is to assemblies of the device, of which its documentation or EDS gives the
  instances and sizes:

    * `:output` and `:input`, the assembly instances, or connection points, of the outputs the
      scanner sends and the inputs it takes; `:output` for an input-only or listen-only connection
      is the device's heartbeat connection point
    * `:output_size` and `:input_size`, the bytes of each, without the sequence count and header
    * `:config`, the configuration assembly instance, if any, and `:config_data`, the
      configuration to send with the Forward_Open, a binary of whole 16-bit words
    * `:rpi`, the requested packet interval in µs (default 10 ms), or `:output_rpi` and
      `:input_rpi` for each direction
    * `:multiplier`, how many RPIs without inputs time the connection out: 4, 8, 16 (default) and
      so on to 512
    * `:output_format` and `:input_format`, the real-time formats (Volume 1, 3-6.1):
      `:header` (default for outputs), a 32-bit run/idle header; `:modeless` (default for
      inputs); `:zero_length`; or `:heartbeat`, no data at all
    * `:multicast`, true for inputs sent by multicast, default false for point-to-point
    * `:input_trigger`, when the device sends its inputs: `:cyclic` (default), every RPI;
      `:change_of_state`, when they change, and at least every RPI; or `:application`, when its
      application decides, and at least every RPI. The Forward_Open asks it of the device.
    * `:inhibit`, for inputs by change of state, the least time between them in ms, 0 to 255
      and less than the RPI (Volume 1, C-1.4.3.3); a quarter of the RPI by default, as the
      device takes it without one
    * `:output_trigger`, when the scanner sends its outputs: `:cyclic` (default), every RPI;
      or `:change_of_state`, at once when `put/3` or `run/3` changes them, and every RPI too
    * `:priority`, `:scheduled` (default), `:high`, `:low` or `:urgent`
    * `:key`, an electronic key segment (see `EtherNetIP.Path`) the device must match
    * `:route`, port segments to a device behind this one
    * `:run`, whether outputs go with the run bit set (default true)
    * `:subscriber`, a process, or a name, to send `{EtherNetIP.Scanner, name, {:inputs, data}}`
      when new inputs come, and `{EtherNetIP.Scanner, name, {:status, status}}` when the
      connection opens or closes

  `put/3` sets the outputs and `inputs/2` gives the latest inputs; `connections/1` says how each
  connection is. Inputs are new when their sequence count changes; a packet that repeats the last
  one still keeps the connection alive, but isn't sent to the subscriber.

  ## Options

    * `:host` - the device's address, as a string or tuple (required)
    * `:port` - its TCP port (default 44818)
    * `:timeout` - how long an explicit request may take, in ms (default 1000); and the
      RegisterSession that starts a session, after which the scanner reconnects
    * `:connect_timeout` - in ms (default 5000)
    * `:backoff` - `{first, longest}` wait between attempts, in ms (default `{100, 5000}`)
    * `:max_pending` - explicit requests on the way at once (default 4)
    * `:keepalive` - a NOP after this long without a request, in ms, so that the device keeps
      the session (default 30 000)
    * `:vendor_id` and `:serial_number` - the scanner's own, which identify it to the device as
      the owner of its connections. The vendor id is 0xFFFF by default, as in the spec's own
      examples; give yours if you have one from ODVA. The serial number is the node's,
      `EtherNetIP.serial_number/0`, the same each time it starts: a device may keep a connection
      whose scanner went without closing it, and then gives it back only to the same vendor id
      and serial number.
    * `:udp_port` - the UDP port of I/O (default 2222)
    * `:connections` - the scan list, a keyword list of names and connections
    * `:name` - to register the process
  """

  alias EtherNetIP.{CIP, Identity, Path}
  alias EtherNetIP.Scanner.Server

  @backoff {100, 5_000}

  @doc false
  def child_spec(opts) do
    %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}
  end

  @doc """
  Starts a scanner, linked to the caller, with the options above. It returns at once, and
  connects in the background. Raises `ArgumentError` for options that don't make sense, and
  for those it doesn't know, as a misspelt one.
  """
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts) do
    config = config!(opts)
    name = if opts[:name], do: [name: opts[:name]], else: []
    GenServer.start_link(Server, config, name)
  end

  @doc "Stops a scanner, closing its I/O connections with Forward_Close first."
  @spec stop(GenServer.server()) :: :ok
  def stop(scanner), do: GenServer.stop(scanner)

  @doc """
  Sends a request and waits for its result: a service by name or code (see `EtherNetIP.CIP`), to
  a path as a list of segments, with its data. `timeout:` and `route:` in `opts`.
  """
  @spec request(GenServer.server(), CIP.service(), Path.t(), iodata, keyword) ::
          {:ok, binary} | {:error, term}
  def request(scanner, service, path, data \\ <<>>, opts \\ []) do
    known!(opts, [:timeout, :route])
    {request, timeout} = prepare!(service, path, data, opts)

    # The scanner answers within the request's timeout, or its own when it has none.
    call_timeout = if timeout, do: timeout + 1_000, else: :infinity

    try do
      GenServer.call(scanner, {:request, request, timeout}, call_timeout)
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, _reason -> {:error, :closed}
    end
  end

  @doc """
  Sends a request without waiting for it, and returns a reference. The result comes as a message
  to the caller, or to `to:` in `opts`: `{EtherNetIP.Scanner, ref, result}`.
  """
  @spec send_request(GenServer.server(), CIP.service(), Path.t(), iodata, keyword) :: reference
  def send_request(scanner, service, path, data \\ <<>>, opts \\ []) do
    known!(opts, [:timeout, :route, :to])
    {request, timeout} = prepare!(service, path, data, opts)
    ref = make_ref()
    to = check!(:to, Keyword.get(opts, :to, self()), &destination?/1, "a pid or a name")
    GenServer.cast(scanner, {:request, request, timeout, to, ref})
    ref
  end

  defp prepare!(service, path, data, opts) do
    timeout = Keyword.get(opts, :timeout)

    unless is_nil(timeout) or (is_integer(timeout) and timeout > 0),
      do: raise(ArgumentError, "timeout: is a positive integer, in ms, got: #{inspect(timeout)}")

    request = CIP.request(service, path, data)

    request =
      case Keyword.get(opts, :route, []) do
        [] ->
          request

        route ->
          cm = EtherNetIP.ConnectionManager

          CIP.request(
            cm.service(:unconnected_send),
            cm.path(),
            cm.encode_unconnected_send(request, route, timeout || 1_000)
          )
      end

    {request, timeout}
  end

  @doc "Reads an attribute of an instance of a class: Get_Attribute_Single."
  @spec get_attribute_single(
          GenServer.server(),
          non_neg_integer,
          non_neg_integer,
          non_neg_integer,
          keyword
        ) ::
          {:ok, binary} | {:error, term}
  def get_attribute_single(scanner, class, instance, attribute, opts \\ []),
    do:
      request(
        scanner,
        :get_attribute_single,
        [class: class, instance: instance, attribute: attribute],
        <<>>,
        opts
      )

  @doc "Writes an attribute of an instance of a class: Set_Attribute_Single."
  @spec set_attribute_single(
          GenServer.server(),
          non_neg_integer,
          non_neg_integer,
          non_neg_integer,
          iodata,
          keyword
        ) ::
          :ok | {:error, term}
  def set_attribute_single(scanner, class, instance, attribute, data, opts \\ []) do
    path = [class: class, instance: instance, attribute: attribute]

    with {:ok, _data} <- request(scanner, :set_attribute_single, path, data, opts), do: :ok
  end

  @doc "Reads every attribute of an instance of a class: Get_Attributes_All."
  @spec get_attributes_all(GenServer.server(), non_neg_integer, non_neg_integer, keyword) ::
          {:ok, binary} | {:error, term}
  def get_attributes_all(scanner, class, instance, opts \\ []),
    do: request(scanner, :get_attributes_all, [class: class, instance: instance], <<>>, opts)

  @doc "The device's identity, from its Identity object (see `EtherNetIP.Identity`)."
  @spec identity(GenServer.server(), keyword) :: {:ok, Identity.t()} | {:error, term}
  def identity(scanner, opts \\ []) do
    with {:ok, data} <- get_attributes_all(scanner, 1, 1, opts) do
      case Identity.decode(data) do
        {:ok, identity} -> {:ok, identity}
        {:error, :invalid} -> {:error, :invalid_reply}
      end
    end
  end

  @doc """
  Sets the outputs of an I/O connection, which go at the next RPI, or at once with
  `output_trigger: :change_of_state`. They must be `:output_size` bytes.
  """
  @spec put(GenServer.server(), atom, binary) ::
          :ok | {:error, :unknown | {:size, non_neg_integer}}
  def put(scanner, name, data) when is_binary(data), do: call(scanner, {:put, name, data})

  @doc "Sets the run/idle bit an I/O connection's outputs go with, for a 32-bit header."
  @spec run(GenServer.server(), atom, boolean) :: :ok | {:error, :unknown}
  def run(scanner, name, run) when is_boolean(run), do: call(scanner, {:run, name, run})

  @doc """
  The latest inputs of an I/O connection: `{:error, :waiting}` while it's open and none has come,
  and `{:error, status}` while it isn't open.
  """
  @spec inputs(GenServer.server(), atom) :: {:ok, binary} | {:error, term}
  def inputs(scanner, name), do: call(scanner, {:inputs, name})

  @doc """
  How each I/O connection is: `:opening`, `:open`, `:idle` when it's open and the device says
  its inputs are idle, or `{:failed, reason}` with why it isn't open. The reason is
  `{:connection_failure, extended, additional}` for a Forward_Open the device refused, with the
  extended status (see `EtherNetIP.ConnectionManager.extended_status/1`) and the words of status
  after it, such as the size the device supports for `:invalid_connection_size`; `:timed_out`
  when inputs stopped coming; `{:udp, reason}` when the UDP port of I/O can't be opened, or
  `{:udp, :closed}` when its endpoint stopped; `{:multicast, group, reason}` when the group of
  multicast inputs can't be joined; or a reason as `request/5` gives. `EtherNetIP.describe/1`
  puts any of them in words.
  """
  @spec connections(GenServer.server()) :: %{atom => term}
  def connections(scanner), do: call(scanner, :connections)

  @doc """
  Opens an I/O connection, added to the scan list under `name`, with the options of a connection
  above. It returns at once; `connections/1` and the subscriber say when it's open.
  """
  @spec open(GenServer.server(), atom, keyword) :: :ok | {:error, :exists}
  def open(scanner, name, spec) when is_atom(name),
    do: call(scanner, {:open, name, connection!(name, spec)})

  @doc "Closes an I/O connection with Forward_Close, and takes it off the scan list."
  @spec close(GenServer.server(), atom) :: :ok | {:error, :unknown}
  def close(scanner, name), do: call(scanner, {:close, name})

  @doc """
  The state of the session: `:connecting`, `:connected`, or `{:disconnected, reason}` while it
  waits to try again.
  """
  @spec status(GenServer.server()) :: term
  def status(scanner), do: call(scanner, :status)

  defp call(scanner, message) do
    GenServer.call(scanner, message)
  catch
    :exit, _reason -> {:error, :closed}
  end

  @options [
    :host,
    :port,
    :timeout,
    :connect_timeout,
    :backoff,
    :max_pending,
    :keepalive,
    :vendor_id,
    :serial_number,
    :udp_port,
    :connections,
    :name
  ]

  @doc false
  def config!(opts) do
    unless Keyword.keyword?(opts),
      do: raise(ArgumentError, "expected keyword options, got: #{inspect(opts)}")

    known!(opts, @options)

    host =
      case Keyword.fetch(opts, :host) do
        {:ok, host} when is_binary(host) ->
          String.to_charlist(host)

        {:ok, host} when is_tuple(host) ->
          check!(:host, host, &:inet.is_ipv4_address/1, "a string or an IPv4 tuple")

        {:ok, other} ->
          raise ArgumentError, "host: is a string or an IPv4 tuple, got: #{inspect(other)}"

        :error ->
          raise ArgumentError, "host: is required"
      end

    connections = Keyword.get(opts, :connections, [])

    unless Keyword.keyword?(connections),
      do: raise(ArgumentError, "connections: is a keyword list, got: #{inspect(connections)}")

    names = Keyword.keys(connections)

    with [name | _] <- names -- Enum.uniq(names),
         do: raise(ArgumentError, "connections: has #{inspect(name)} more than once")

    %{
      host: host,
      port: port!(opts, :port, 0xAF12),
      timeout: positive!(opts, :timeout, 1_000),
      connect_timeout: positive!(opts, :connect_timeout, 5_000),
      backoff:
        check!(
          :backoff,
          Keyword.get(opts, :backoff, @backoff),
          &backoff?/1,
          "{first, longest}, in ms, the first no longer"
        ),
      max_pending: positive!(opts, :max_pending, 4),
      keepalive: positive!(opts, :keepalive, 30_000),
      vendor_id:
        check!(
          :vendor_id,
          Keyword.get(opts, :vendor_id, 0xFFFF),
          &(&1 in 0..0xFFFF),
          "0 to 0xFFFF"
        ),
      serial_number:
        check!(
          :serial_number,
          Keyword.get_lazy(opts, :serial_number, &EtherNetIP.serial_number/0),
          &(&1 in 0..0xFFFF_FFFF),
          "0 to 0xFFFFFFFF"
        ),
      udp_port: port!(opts, :udp_port, EtherNetIP.IOPacket.port()),
      connections: for({name, spec} <- connections, do: {name, connection!(name, spec)})
    }
  end

  defp backoff?({first, longest}),
    do: is_integer(first) and first > 0 and is_integer(longest) and longest >= first

  defp backoff?(_other), do: false

  defp positive!(opts, key, default),
    do:
      check!(
        key,
        Keyword.get(opts, key, default),
        &(is_integer(&1) and &1 > 0),
        "a positive integer"
      )

  defp port!(opts, key, default),
    do: check!(key, Keyword.get(opts, key, default), &(&1 in 1..0xFFFF), "1 to 65535")

  defp check!(key, value, valid?, expected) do
    if valid?.(value),
      do: value,
      else: raise(ArgumentError, "#{key}: is #{expected}, got: #{inspect(value)}")
  end

  # A misspelt option would otherwise go unnoticed, and its default be taken.
  defp known!(opts, known) do
    case opts |> Keyword.keys() |> Enum.reject(&(&1 in known)) |> Enum.uniq() do
      [] -> :ok
      unknown -> raise ArgumentError, "unknown options: #{inspect(unknown)}"
    end
  end

  # The options of a connection that have defaults, besides the RPIs.
  @defaults [
    config: nil,
    config_data: nil,
    output_size: 0,
    input_size: 0,
    multiplier: 16,
    output_format: :header,
    input_format: :modeless,
    multicast: false,
    input_trigger: :cyclic,
    inhibit: nil,
    output_trigger: :cyclic,
    priority: :scheduled,
    key: nil,
    route: [],
    run: true,
    subscriber: nil
  ]

  @expected %{
    output: "an assembly instance, 0 to 0xFFFFFFFF",
    input: "an assembly instance, 0 to 0xFFFFFFFF",
    config: "an assembly instance, 0 to 0xFFFFFFFF, or nil",
    config_data: "a binary of whole 16-bit words, of at most 510 bytes, or nil",
    output_size: "0 to 65529 bytes",
    input_size: "0 to 65529 bytes",
    rpi: "1 to 0xFFFFFFFF µs",
    output_rpi: "1 to 0xFFFFFFFF µs",
    input_rpi: "1 to 0xFFFFFFFF µs",
    multiplier: "4, 8, 16 and so on to 512",
    output_format: ":header, :modeless, :zero_length or :heartbeat",
    input_format: ":header, :modeless, :zero_length or :heartbeat",
    multicast: "true or false",
    input_trigger: ":cyclic, :change_of_state or :application",
    inhibit: "0 to 255 ms, or nil",
    output_trigger: ":cyclic or :change_of_state",
    priority: ":scheduled, :high, :low or :urgent",
    key:
      "an electronic key segment, {:key, vendor_id, device_type, product_code, major, minor, compatible}, or nil",
    route: "a list of port segments, {:port, port, link}",
    run: "true or false",
    subscriber: "a pid or a name, or nil"
  }

  @doc false
  def connection!(name, spec) do
    unless is_atom(name) and Keyword.keyword?(spec),
      do:
        raise(
          ArgumentError,
          "a connection is a name and keyword options, got: #{inspect({name, spec})}"
        )

    known!(spec, Map.keys(@expected))

    for key <- [:output, :input],
        not Keyword.has_key?(spec, key),
        do: raise(ArgumentError, "#{key}: is required, #{@expected[key]}")

    # The RPI goes for both directions, unless either has its own.
    rpi = Keyword.get(spec, :rpi, 10_000)
    connection = Map.new(@defaults ++ [rpi: rpi, output_rpi: rpi, input_rpi: rpi] ++ spec)

    for {key, value} <- connection,
        not valid?(key, value),
        do: raise(ArgumentError, "#{key}: is #{@expected[key]}, got: #{inspect(value)}")

    connection = Map.delete(connection, :rpi)

    if connection.config_data != nil and is_nil(connection.config),
      do: raise(ArgumentError, "config_data: needs config:, the configuration assembly")

    connection = %{connection | inhibit: inhibit!(connection)}

    # Builds the Forward_Open's path now, so that a connection that can't be encoded is refused
    # here and not when it's opened.
    _path = Server.connection_path(connection)
    connection
  end

  defp valid?(key, id) when key in [:output, :input], do: id in 0..0xFFFF_FFFF
  defp valid?(:config, id), do: is_nil(id) or id in 0..0xFFFF_FFFF

  defp valid?(:config_data, data),
    do:
      is_nil(data) or
        (is_binary(data) and rem(byte_size(data), 2) == 0 and byte_size(data) <= 510)

  # The largest a Large_Forward_Open takes, with the sequence count and a run/idle header.
  defp valid?(key, size) when key in [:output_size, :input_size], do: size in 0..0xFFF9
  defp valid?(key, rpi) when key in [:rpi, :output_rpi, :input_rpi], do: rpi in 1..0xFFFF_FFFF
  defp valid?(:multiplier, multiplier), do: multiplier in [4, 8, 16, 32, 64, 128, 256, 512]

  defp valid?(key, format) when key in [:output_format, :input_format],
    do: format in [:header, :modeless, :zero_length, :heartbeat]

  defp valid?(:input_trigger, trigger), do: trigger in [:cyclic, :change_of_state, :application]
  defp valid?(:output_trigger, trigger), do: trigger in [:cyclic, :change_of_state]
  defp valid?(:inhibit, ms), do: is_nil(ms) or ms in 0..255
  defp valid?(:priority, priority), do: priority in [:scheduled, :high, :low, :urgent]
  defp valid?(:key, key), do: is_nil(key) or match?({:key, _, _, _, _, _, _}, key)
  defp valid?(:route, route), do: is_list(route) and Enum.all?(route, &match?({:port, _, _}, &1))
  defp valid?(:subscriber, to), do: is_nil(to) or destination?(to)
  defp valid?(key, flag) when key in [:multicast, :run], do: is_boolean(flag)

  # Where a message may go: a process, or a name, which needn't be registered yet.
  @doc false
  def destination?(to) when is_pid(to), do: true
  def destination?(to) when is_atom(to), do: to not in [nil, true, false]
  def destination?({name, node}), do: is_atom(name) and is_atom(node)
  def destination?(_to), do: false

  # Inputs by change of state come with a production inhibit time, always (Volume 2, 3-3.4), which
  # the device refuses unless it's less than the RPI (Volume 1, C-1.4.3.3).
  defp inhibit!(%{input_trigger: :change_of_state, inhibit: nil, input_rpi: rpi}),
    do: min(div(rpi, 4_000), 255)

  defp inhibit!(%{input_trigger: :change_of_state, inhibit: ms, input_rpi: rpi})
       when ms in 0..255 and ms * 1_000 < rpi,
       do: ms

  defp inhibit!(%{input_trigger: :change_of_state, inhibit: ms, input_rpi: rpi}),
    do:
      raise(
        ArgumentError,
        "inhibit: is 0 to 255 ms and less than the input RPI of #{rpi} µs, got: #{inspect(ms)}"
      )

  defp inhibit!(%{inhibit: nil}), do: nil

  defp inhibit!(_connection),
    do: raise(ArgumentError, "inhibit: is for input_trigger: :change_of_state")
end
