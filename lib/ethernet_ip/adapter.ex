defmodule EtherNetIP.Adapter do
  @moduledoc """
  An EtherNet/IP adapter: a device that scanners, such as PLCs, connect to, to take its inputs
  and set its outputs. It has assemblies of each, which a scanner reaches with I/O connections,
  and answers explicit messages, unconnected and over class 3 connections.

      {:ok, adapter} =
        EtherNetIP.Adapter.start_link(
          identity: [vendor_id: 0xFFFF, product_code: 1, product_name: "Pump skid"],
          inputs: %{100 => 32},
          outputs: %{150 => 32},
          configuration: %{151 => 10},
          subscriber: self()
        )

      :ok = EtherNetIP.Adapter.put(adapter, 100, <<0::256>>)
      {:ok, %{data: <<_::binary-32>>, state: state}} = EtherNetIP.Adapter.outputs(adapter, 150)

  Inputs and outputs are as the device sees them, as a scanner's connection names them: a
  scanner takes the adapter's inputs, which the adapter produces, and sets its outputs, which it
  consumes. `put/3` and `outputs/2` don't wait on the adapter's process: the data of every
  assembly is in a table, which they write and read.

  ## I/O connections

  A scanner opens a connection with a Forward_Open whose path names a configuration assembly, if
  any, then the connection point of the outputs, then that of the inputs: as
  `[class: 4, instance: 151, connection_point: 150, connection_point: 100]`. The outputs' point
  makes the connection what it is (Volume 1, 3-6.4):

    * an output assembly: an exclusive owner, of which each output assembly takes one at a time;
      its outputs come with the 32-bit run/idle header
    * `:input_only`, a heartbeat point: a connection for inputs alone, of which there may be many
    * `:listen_only`, another heartbeat point: a connection for inputs alone that depends on an
      exclusive owner or input only connection to the same inputs, and closes when the last of
      them does

  Inputs go without a header (modeless). They go every RPI, and by change of state when a
  connection asks for that, at once when `put/3` changes them; to the scanner, point to point,
  or to a multicast group of the adapter's (Volume 2, 3-5.3), which every connection to the same
  inputs with the same RPI and size shares. Configuration data that comes with a Forward_Open is
  written to the configuration assembly, unless another connection has configured it otherwise.

  A connection whose packets stop for its timeout is closed. When an exclusive owner's stops,
  its inputs stop too, for every connection that shares them, so that its scanner knows its
  outputs aren't taken (Volume 1, 3-6.4.3); `outputs/2` then says `:closed`.

  ## Events

  With `:subscriber`, a process gets `{EtherNetIP.Adapter, event}`:

    * `{:outputs, instance, data}` when new outputs come, by their sequence count, in run mode
    * `{:state, instance, state}` when the outputs go to `:run`, `:idle` or `:closed`
    * `{:configuration, instance, data}` when a scanner configures the adapter
    * `{:opened, connection}` and `{:closed, connection, reason}` for each connection, as
      `connections/1` gives them, the reason `:closed`, `:timed_out`, `:owner_timed_out`,
      `:orphaned` (a listen only connection whose last other connection closed) or `:reset`
    * `{:reset, type}` when a client resets the device with the Identity object's Reset: every
      connection and session closes, and with type 1 the configuration and outputs go back to
      what they started as

  ## Explicit messages

  The adapter has the objects every EtherNet/IP device has (Volume 2, 6-2): Identity, Message
  Router, Assembly, Connection Manager, TCP/IP Interface and Ethernet Link. The TCP/IP Interface
  and Ethernet Link objects give the host's interface that a request came in on, as the host has
  it; the adapter can't change it, and of the attributes only the Encapsulation Inactivity
  Timeout can be set. The data of output and configuration assemblies may be set with
  Set_Attribute_Single while no connection has them.

  It answers ListIdentity, ListServices and ListInterfaces over UDP on its port too, as for
  discovery; a ListIdentity over UDP after a random delay, as to a broadcast.

  ## Clients

  A plant network should expect anything on the port. The adapter takes at most `:sessions`
  clients, and when one more connects, it closes the one that has gone longest without a
  message, among those of the address that holds the most, so that a host that floods the port
  pushes out only its own. A client with no message for the Encapsulation Inactivity Timeout,
  2 minutes by default, and no class 3 connection, is closed (Volume 2, 2-5.5.2); bytes that
  don't make a whole message don't count. `:allow` limits who may connect at all, and who gets an
  answer over UDP. A request that the adapter fails on, which would be a bug of its own, is
  logged and answered with an error, and the adapter keeps its connections.

  ## Options

    * `:identity` - the Identity object's: `:vendor_id` (0xFFFF by default; yours from ODVA),
      `:device_type` (0, a generic device), `:product_code` (1), `:revision` (`{1, 1}`),
      `:serial_number` (the node's, `EtherNetIP.serial_number/0`) and `:product_name`
      ("yaethernetip", at most 32 characters)
    * `:inputs`, `:outputs` and `:configuration` - the assemblies, as a map of instances and
      sizes in bytes; a configuration assembly may be given its starting data instead of a size
    * `:input_only` and `:listen_only` - the heartbeat connection points of those connections,
      if the adapter takes them
    * `:rpi` - `{min, max}`, the packet intervals it takes, in µs (default `{1_000, 10_000_000}`)
    * `:max_connections` - connections at once, of every kind (default 32)
    * `:port` - the TCP and UDP port, 44818 by default; 0 for any free one, see `port/1`
    * `:address` - the address to listen on (default all of them)
    * `:udp_port` - the UDP port of I/O (default 2222)
    * `:discovery` - whether to answer over UDP on the port (default true)
    * `:sessions` - clients at once (default 16)
    * `:allow` - the client addresses that may connect, or be answered over UDP, each an
      address or `{address, prefix length}`, as `[{{10, 0, 0, 0}, 8}]` (default any)
    * `:inactivity` - the Encapsulation Inactivity Timeout, in seconds, 0 for none (default 120)
    * `:subscriber` - a process to send events to, see above
    * `:name` - to register the process
  """

  alias EtherNetIP.Adapter.{EDS, Server}

  @doc false
  def child_spec(opts) do
    %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}
  end

  @doc """
  Starts an adapter, linked to the caller, with the options above. It's listening when it
  returns; a port that's taken is `{:error, :eaddrinuse}`. Raises `ArgumentError` for options
  that don't make sense, and for those it doesn't know.
  """
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts) do
    config = config!(opts)
    name = if opts[:name], do: [name: opts[:name]], else: []
    Server.start_link(config, name)
  end

  @doc "Stops an adapter. Its connections stop with it, and their scanners time them out."
  @spec stop(GenServer.server()) :: :ok
  def stop(adapter), do: GenServer.stop(adapter)

  @doc "The TCP port the adapter listens on, as when started with `port: 0`."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(adapter), do: GenServer.call(adapter, :port)

  @doc """
  Sets the data of an input assembly, which goes to the scanners at the next RPI, or at once to
  those that take it by change of state. It must be the assembly's size.
  """
  @spec put(GenServer.server(), non_neg_integer, binary) ::
          :ok | {:error, :unknown | :closed | {:size, non_neg_integer}}
  def put(adapter, instance, data) when is_binary(data) do
    with {:ok, pid, table} <- table(adapter),
         do: put(pid, table, instance, data, :ets.lookup(table, {:assembly, instance}))
  end

  # The server hears of a change once, however many puts come before it takes it: the mark in the
  # table says it has yet to.
  defp put(pid, table, instance, data, [{_key, :input, size}]) when byte_size(data) == size do
    [{_key, old}] = :ets.lookup(table, {:data, instance})
    :ets.insert(table, {{:data, instance}, data})

    if old != data and :ets.insert_new(table, {{:changed, instance}}),
      do: send(pid, {:changed, instance})

    :ok
  end

  defp put(_pid, _table, _instance, _data, [{_key, :input, size}]), do: {:error, {:size, size}}
  defp put(_pid, _table, _instance, _data, _other), do: {:error, :unknown}

  @doc "The data of any assembly: inputs as put, outputs as they last came, configuration."
  @spec get(GenServer.server(), non_neg_integer) :: {:ok, binary} | {:error, :unknown | :closed}
  def get(adapter, instance) do
    with {:ok, _pid, table} <- table(adapter) do
      case :ets.lookup(table, {:data, instance}) do
        [{_key, data}] -> {:ok, data}
        [] -> {:error, :unknown}
      end
    end
  end

  @doc """
  An output assembly's data, as it last came in run mode; `:state`, `:run` or `:idle` while an
  exclusive owner has it, as its last packet said, and `:closed` while none does; and `:at`, when
  its last packet came, in `System.monotonic_time/0` units, or nil before any.
  """
  @spec outputs(GenServer.server(), non_neg_integer) ::
          {:ok, %{data: binary, state: :run | :idle | :closed, at: integer | nil}}
          | {:error, :unknown | :closed}
  def outputs(adapter, instance) do
    with {:ok, _pid, table} <- table(adapter) do
      case {:ets.lookup(table, {:output, instance}), :ets.lookup(table, {:data, instance})} do
        {[{_key, state, at}], [{_data, data}]} -> {:ok, %{data: data, state: state, at: at}}
        _other -> {:error, :unknown}
      end
    end
  end

  @doc """
  The open connections: for I/O, `:kind` (`:exclusive_owner`, `:input_only` or `:listen_only`),
  `:originator`, the scanner's address, `:output` and `:input`, the connection points, `:rpi`,
  `{output, input}` packet intervals in µs, and `:multicast`, whether the inputs go by
  multicast; a class 3 connection is `%{kind: :explicit, originator: address}`.
  """
  @spec connections(GenServer.server()) :: [map]
  def connections(adapter), do: GenServer.call(adapter, :connections)

  @doc """
  The adapter's EDS, from the options it's started with, for a scanner's configuration tool
  to add the device by: its identity, its assemblies, and its connections, each exclusive owner
  of an output assembly and an input assembly, and input only and listen only as the adapter has
  those points; all but listen only with the first configuration assembly and its starting data,
  and listen only with multicast inputs. `opts` gives
  what the adapter doesn't know itself: `:vendor_name`, `:catalog`, `:description` (the product
  name by default), `:device_type_name` ("Generic Device"), the file's `:revision` (`{1, 0}`), and
  `:at`, the time it's made (now).

      eds = EtherNetIP.Adapter.eds([inputs: %{100 => 4}, outputs: %{150 => 4}], vendor_name: "Acme")
      File.write!("pump_skid.eds", eds)

  `EtherNetIP.EDS` reads it, and its connections open against the adapter.
  """
  @spec eds(keyword, keyword) :: String.t()
  def eds(opts, eds_opts \\ []), do: EDS.write(config!(opts), eds_opts)

  defp table(adapter) do
    with pid when is_pid(pid) <- GenServer.whereis(adapter),
         [{^pid, table}] <- Registry.lookup(EtherNetIP.Registry, {__MODULE__, pid}) do
      {:ok, pid, table}
    else
      _gone -> {:error, :closed}
    end
  end

  ## Options

  @options [
    :identity,
    :inputs,
    :outputs,
    :configuration,
    :input_only,
    :listen_only,
    :rpi,
    :max_connections,
    :port,
    :address,
    :udp_port,
    :discovery,
    :sessions,
    :allow,
    :inactivity,
    :subscriber,
    :name
  ]

  @identity [:vendor_id, :device_type, :product_code, :revision, :serial_number, :product_name]

  @doc false
  def config!(opts) do
    unless Keyword.keyword?(opts),
      do: raise(ArgumentError, "expected keyword options, got: #{inspect(opts)}")

    known!(opts, @options)
    get = &Keyword.get(opts, &1, &2)

    %{
      identity: identity!(get.(:identity, [])),
      assemblies: assemblies!(opts),
      input_only: get.(:input_only, nil),
      listen_only: get.(:listen_only, nil),
      rpi: check!(:rpi, get.(:rpi, {1_000, 10_000_000}), &rpi?/1, "{min, max} µs, 1 µs up"),
      max_connections:
        check!(:max_connections, get.(:max_connections, 32), &(&1 in 1..0xFFFF), "1 to 65535"),
      port:
        check!(
          :port,
          get.(:port, EtherNetIP.Encapsulation.port()),
          &(&1 in 0..0xFFFF),
          "0 to 65535"
        ),
      address:
        check!(
          :address,
          get.(:address, {0, 0, 0, 0}),
          &:inet.is_ipv4_address/1,
          "an IPv4 address"
        ),
      udp_port:
        check!(
          :udp_port,
          get.(:udp_port, EtherNetIP.IOPacket.port()),
          &(&1 in 1..0xFFFF),
          "1 to 65535"
        ),
      discovery: check!(:discovery, get.(:discovery, true), &is_boolean/1, "true or false"),
      sessions_max:
        check!(:sessions, get.(:sessions, 16), &(is_integer(&1) and &1 >= 2), "2 or more"),
      allow:
        check!(
          :allow,
          get.(:allow, nil),
          &allow?/1,
          "a list of addresses, or {address, prefix length}"
        ),
      inactivity: check!(:inactivity, get.(:inactivity, 120), &(&1 in 0..3600), "0 to 3600 s"),
      subscriber:
        check!(
          :subscriber,
          get.(:subscriber, nil),
          &(is_nil(&1) or EtherNetIP.Scanner.destination?(&1)),
          "a pid or a name"
        )
    }
  end

  defp identity!(identity) do
    unless Keyword.keyword?(identity),
      do: raise(ArgumentError, "identity: is a keyword list, got: #{inspect(identity)}")

    known!(identity, @identity)
    get = &Keyword.get(identity, &1, &2)

    %{
      vendor_id: check!(:vendor_id, get.(:vendor_id, 0xFFFF), &(&1 in 0..0xFFFF), "0 to 0xFFFF"),
      device_type: check!(:device_type, get.(:device_type, 0), &(&1 in 0..0xFFFF), "0 to 0xFFFF"),
      product_code:
        check!(:product_code, get.(:product_code, 1), &(&1 in 0..0xFFFF), "0 to 0xFFFF"),
      revision:
        check!(
          :revision,
          get.(:revision, {1, 1}),
          &revision?/1,
          "{major, minor}, 1 to 127 and 1 to 255"
        ),
      serial_number:
        check!(
          :serial_number,
          Keyword.get_lazy(identity, :serial_number, &EtherNetIP.serial_number/0),
          &(&1 in 0..0xFFFF_FFFF),
          "0 to 0xFFFFFFFF"
        ),
      product_name:
        check!(
          :product_name,
          get.(:product_name, "yaethernetip"),
          &name?/1,
          "a string of at most 32 characters"
        )
    }
  end

  defp revision?({major, minor}), do: major in 1..127 and minor in 1..255
  defp revision?(_other), do: false

  defp name?(name),
    do: is_binary(name) and String.length(name) <= 32 and match?({:ok, _}, latin1(name))

  defp latin1(name) do
    case :unicode.characters_to_binary(name, :utf8, :latin1) do
      binary when is_binary(binary) -> {:ok, binary}
      _error -> :error
    end
  end

  defp rpi?({min, max}),
    do: is_integer(min) and is_integer(max) and min >= 1 and max >= min and max <= 0xFFFF_FFFF

  defp rpi?(_other), do: false

  defp allow?(nil), do: true

  defp allow?(list) when is_list(list) do
    Enum.all?(list, fn
      {address, bits} when bits in 0..32 -> :inet.is_ipv4_address(address)
      address -> :inet.is_ipv4_address(address)
    end)
  end

  defp allow?(_other), do: false

  # Instance → {kind, size, data}: the assemblies, and the heartbeat points as assemblies of no
  # data, each instance once.
  defp assemblies!(opts) do
    heartbeats =
      for key <- [:input_only, :listen_only],
          instance = Keyword.get(opts, key),
          instance != nil,
          do: {instance!(key, instance), {:heartbeat, 0, <<>>}}

    all = Enum.flat_map([:inputs, :outputs, :configuration], &sized!(opts, &1)) ++ heartbeats
    instances = Enum.map(all, &elem(&1, 0))

    with [instance | _] <- instances -- Enum.uniq(instances),
         do: raise(ArgumentError, "instance #{instance} is more than one assembly or point")

    Map.new(all)
  end

  defp sized!(opts, key) do
    value = Keyword.get(opts, key, %{})

    unless is_map(value) or is_list(value),
      do: raise(ArgumentError, "#{key}: is a map of instances and sizes, got: #{inspect(value)}")

    Enum.map(value, fn
      {instance, size} ->
        {instance!(key, instance), assembly!(key, size)}

      other ->
        raise ArgumentError, "#{key}: is a map of instances and sizes, got: #{inspect(other)}"
    end)
  end

  defp instance!(_key, instance) when instance in 1..0xFFFF_FFFF, do: instance

  defp instance!(key, instance),
    do:
      raise(
        ArgumentError,
        "#{key}: has an instance that isn't 1 to 0xFFFFFFFF: #{inspect(instance)}"
      )

  @kinds %{inputs: :input, outputs: :output, configuration: :configuration}

  # The largest a Large_Forward_Open takes, with the sequence count and a run/idle header; and a
  # configuration of one data segment.
  defp assembly!(:configuration, data) when is_binary(data) and byte_size(data) <= 510,
    do: {:configuration, byte_size(data), data}

  defp assembly!(:configuration, size) when size in 0..510,
    do: {:configuration, size, <<0::size(size * 8)>>}

  defp assembly!(key, size) when key in [:inputs, :outputs] and size in 0..0xFFF9,
    do: {@kinds[key], size, <<0::size(size * 8)>>}

  defp assembly!(key, size),
    do: raise(ArgumentError, "#{key}: has a size that doesn't fit, got: #{inspect(size)}")

  defp check!(key, value, valid?, expected) do
    if valid?.(value),
      do: value,
      else: raise(ArgumentError, "#{key}: is #{expected}, got: #{inspect(value)}")
  end

  defp known!(opts, known) do
    case opts |> Keyword.keys() |> Enum.reject(&(&1 in known)) |> Enum.uniq() do
      [] -> :ok
      unknown -> raise ArgumentError, "unknown options: #{inspect(unknown)}"
    end
  end
end
