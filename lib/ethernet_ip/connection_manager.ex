defmodule EtherNetIP.ConnectionManager do
  @moduledoc """
  The services of the Connection Manager, class 6 instance 1 (Volume 1, 3-5), which open and
  close connections, and route unconnected messages on to other links.

  A connection is opened with a Forward_Open, of which this module encodes and decodes the data:

    * `:o_t_id` and `:t_o_id`, the network connection ids of the two directions, of which the
      consumer of each chooses it for a point-to-point connection, and the producer for a
      multicast one (Volume 2, 3-3.7.1)
    * `:serial`, `:vendor_id` and `:originator_serial`, which together tell the connection from
      every other: the connection's serial number, and the originator's vendor id and serial
      number
    * `:multiplier`, the number of RPIs without a packet after which a connection times out: 4,
      8, 16 and so on up to 512
    * `:o_t` and `:t_o`, each direction's parameters as a map: `:rpi`, the requested packet
      interval in µs; `:size`, the bytes of each packet, its sequence count and run/idle header
      included; `:type`, `:null`, `:multicast` or `:point_to_point`; `:priority`, `:low`,
      `:high`, `:scheduled` or `:urgent`; `:fixed`, whether every packet has that size; and
      `:redundant_owner`
    * `:trigger`, `{direction, trigger, class}`: `:client` or `:server`; `:cyclic`,
      `:change_of_state` or `:application`; and the transport class, 0 to 3
    * `:path`, the connection path, its segments or already encoded: the route, then the
      application paths, as `[class: 4, instance: 1, connection_point: 150, connection_point:
      100]` for configuration assembly 1, output assembly 150 and input assembly 100
    * `:timeout`, how long the request may take in ms, which goes as a time tick and a number
      of ticks
    * `:large`, true for a Large_Forward_Open, for connections of more than 511 bytes

  `Large_Forward_Open` differs only in carrying the parameters of each direction in 32 bits.
  """

  import Bitwise

  @doc "The path of the Connection Manager."
  @spec path() :: EtherNetIP.Path.t()
  def path, do: [class: 6, instance: 1]

  # Volume 1, Table 3-5.7.
  @services %{
    forward_close: 0x4E,
    unconnected_send: 0x52,
    forward_open: 0x54,
    get_connection_data: 0x56,
    search_connection_data: 0x57,
    get_connection_owner: 0x5A,
    large_forward_open: 0x5B
  }

  @doc """
  The code of a service of the Connection Manager: `:forward_open`, `:large_forward_open`,
  `:forward_close`, `:unconnected_send`, `:get_connection_data`, `:search_connection_data` or
  `:get_connection_owner`.

      iex> EtherNetIP.ConnectionManager.service(:forward_open)
      0x54
  """
  @spec service(atom) :: 0x4E..0x5B
  def service(name), do: Map.fetch!(@services, name)

  @types %{null: 0, multicast: 1, point_to_point: 2}
  @priorities %{low: 0, high: 1, scheduled: 2, urgent: 3}
  @triggers %{cyclic: 0, change_of_state: 1, application: 2}
  @multipliers %{4 => 0, 8 => 1, 16 => 2, 32 => 3, 64 => 4, 128 => 5, 256 => 6, 512 => 7}

  @type direction :: %{
          rpi: 0..0xFFFF_FFFF,
          size: 0..0xFFFF,
          type: :null | :multicast | :point_to_point,
          priority: :low | :high | :scheduled | :urgent,
          fixed: boolean,
          redundant_owner: boolean
        }

  @type forward_open :: %{
          optional(:timeout) => pos_integer,
          optional(:large) => boolean,
          o_t_id: 0..0xFFFF_FFFF,
          t_o_id: 0..0xFFFF_FFFF,
          serial: 0..0xFFFF,
          vendor_id: 0..0xFFFF,
          originator_serial: 0..0xFFFF_FFFF,
          multiplier: 4 | 8 | 16 | 32 | 64 | 128 | 256 | 512,
          o_t: direction,
          t_o: direction,
          trigger: {:client | :server, :cyclic | :change_of_state | :application, 0..3},
          path: EtherNetIP.Path.t() | binary
        }

  @doc """
  The data of a Forward_Open request, or of a Large_Forward_Open with `large: true`. Raises
  `ArgumentError` for parameters that don't fit.
  """
  @spec encode_forward_open(forward_open) :: binary
  def encode_forward_open(request) do
    large = Map.get(request, :large, false)
    path = encoded(request.path)
    {tick, ticks} = timing(Map.get(request, :timeout, 5_000))

    <<tick, ticks, request.o_t_id::little-32, request.t_o_id::little-32,
      request.serial::little-16, request.vendor_id::little-16,
      request.originator_serial::little-32, multiplier(request.multiplier), 0::24,
      request.o_t.rpi::little-32, parameters(request.o_t, large)::binary,
      request.t_o.rpi::little-32, parameters(request.t_o, large)::binary,
      trigger(request.trigger), EtherNetIP.Path.words(path), path::binary>>
  end

  @doc """
  A Forward_Open request's data, as `encode_forward_open/1` takes it, `:large` saying whether
  it was a Large_Forward_Open, and `:path` given as the path's bytes. `{:error, :invalid}` for
  data of the wrong length, or a reserved connection timeout multiplier.
  """
  @spec decode_forward_open(binary, boolean) :: {:ok, forward_open} | {:error, :invalid}
  def decode_forward_open(data, large \\ false)

  def decode_forward_open(
        <<head::binary-26, o_t::little-16, t_o_rpi::little-32, t_o::little-16, tail::binary>>,
        false
      ),
      do: forward_open(head, o_t, t_o_rpi, t_o, tail, false)

  def decode_forward_open(
        <<head::binary-26, o_t::little-32, t_o_rpi::little-32, t_o::little-32, tail::binary>>,
        true
      ),
      do: forward_open(head, o_t, t_o_rpi, t_o, tail, true)

  def decode_forward_open(_data, _large), do: {:error, :invalid}

  defp forward_open(head, o_t, t_o_rpi, t_o, tail, large) do
    with <<tick, ticks, o_t_id::little-32, t_o_id::little-32, serial::little-16,
           vendor_id::little-16, originator_serial::little-32, multiplier, _reserved::24,
           o_t_rpi::little-32>> <- head,
         <<trigger, words, path::binary-size(words * 2)>> <- tail,
         {multiplier, _code} <- Enum.find(@multipliers, &(elem(&1, 1) == multiplier)) do
      request = %{
        timeout: (1 <<< band(tick, 15)) * ticks,
        large: large,
        o_t_id: o_t_id,
        t_o_id: t_o_id,
        serial: serial,
        vendor_id: vendor_id,
        originator_serial: originator_serial,
        multiplier: multiplier,
        o_t: Map.put(decode_parameters(o_t, large), :rpi, o_t_rpi),
        t_o: Map.put(decode_parameters(t_o, large), :rpi, t_o_rpi),
        trigger: decode_trigger(trigger),
        path: path
      }

      {:ok, request}
    else
      _invalid -> {:error, :invalid}
    end
  end

  @doc """
  The data of a successful reply to a Forward_Open: the connection ids, the triad, and the actual
  packet interval of each direction, in µs, with any application reply.
  """
  @spec encode_forward_open_reply(map) :: binary
  def encode_forward_open_reply(reply) do
    application = Map.get(reply, :application, <<>>)

    <<reply.o_t_id::little-32, reply.t_o_id::little-32, reply.serial::little-16,
      reply.vendor_id::little-16, reply.originator_serial::little-32, reply.o_t_api::little-32,
      reply.t_o_api::little-32, div(byte_size(application), 2), 0, application::binary>>
  end

  @doc """
  The data of a successful reply to a Forward_Open, as `encode_forward_open_reply/1` takes it.

      iex> data = EtherNetIP.ConnectionManager.encode_forward_open_reply(%{o_t_id: 1, t_o_id: 2,
      ...>   serial: 3, vendor_id: 4, originator_serial: 5, o_t_api: 10_000, t_o_api: 20_000})
      iex> EtherNetIP.ConnectionManager.decode_forward_open_reply(data)
      {:ok, %{o_t_id: 1, t_o_id: 2, serial: 3, vendor_id: 4, originator_serial: 5,
        o_t_api: 10_000, t_o_api: 20_000, application: ""}}
  """
  @spec decode_forward_open_reply(binary) :: {:ok, map} | {:error, :invalid}
  def decode_forward_open_reply(
        <<o_t_id::little-32, t_o_id::little-32, serial::little-16, vendor_id::little-16,
          originator_serial::little-32, o_t_api::little-32, t_o_api::little-32, words, _reserved,
          application::binary-size(words * 2)>>
      ) do
    reply = %{
      o_t_id: o_t_id,
      t_o_id: t_o_id,
      serial: serial,
      vendor_id: vendor_id,
      originator_serial: originator_serial,
      o_t_api: o_t_api,
      t_o_api: t_o_api,
      application: application
    }

    {:ok, reply}
  end

  def decode_forward_open_reply(_data), do: {:error, :invalid}

  @doc """
  The data of a failed reply to a Forward_Open or Forward_Close: the triad, and for an error in
  routing, the size of the path where it failed, in words.
  """
  @spec decode_failure(binary) :: {:ok, map} | {:error, :invalid}
  def decode_failure(
        <<serial::little-16, vendor_id::little-16, originator_serial::little-32, rest::binary>>
      ) do
    remaining =
      case rest do
        <<words, _rest::binary>> -> words
        <<>> -> nil
      end

    {:ok,
     %{
       serial: serial,
       vendor_id: vendor_id,
       originator_serial: originator_serial,
       remaining_path: remaining
     }}
  end

  def decode_failure(_data), do: {:error, :invalid}

  @doc """
  The data of a failed reply to a Forward_Open or Forward_Close, from the triad of its request.
  """
  @spec encode_failure(map) :: binary
  def encode_failure(request) do
    <<request.serial::little-16, request.vendor_id::little-16,
      request.originator_serial::little-32, 0, 0>>
  end

  @doc """
  The data of a Forward_Close request, with the triad of the connection, its path, and how long
  it may take in ms.
  """
  @spec encode_forward_close(map) :: binary
  def encode_forward_close(request) do
    path = encoded(request.path)
    {tick, ticks} = timing(Map.get(request, :timeout, 5_000))

    <<tick, ticks, request.serial::little-16, request.vendor_id::little-16,
      request.originator_serial::little-32, EtherNetIP.Path.words(path), 0, path::binary>>
  end

  @doc "A Forward_Close request's data, as `encode_forward_close/1` takes it."
  @spec decode_forward_close(binary) :: {:ok, map} | {:error, :invalid}
  def decode_forward_close(
        <<tick, ticks, serial::little-16, vendor_id::little-16, originator_serial::little-32,
          words, _reserved, path::binary-size(words * 2)>>
      ) do
    request = %{
      timeout: (1 <<< band(tick, 15)) * ticks,
      serial: serial,
      vendor_id: vendor_id,
      originator_serial: originator_serial,
      path: path
    }

    {:ok, request}
  end

  def decode_forward_close(_data), do: {:error, :invalid}

  @doc "The data of a successful reply to a Forward_Close."
  @spec encode_forward_close_reply(map) :: binary
  def encode_forward_close_reply(request) do
    <<request.serial::little-16, request.vendor_id::little-16,
      request.originator_serial::little-32, 0, 0>>
  end

  @doc """
  The data of an Unconnected_Send, which has the Connection Manager send a message router
  request on along `route`, a path of port segments, and wait `timeout` ms for its reply.
  """
  @spec encode_unconnected_send(binary, EtherNetIP.Path.t() | binary, pos_integer) :: binary
  def encode_unconnected_send(request, route, timeout) do
    route = encoded(route)
    {tick, ticks} = timing(timeout)
    pad = if rem(byte_size(request), 2) == 1, do: <<0>>, else: <<>>

    <<tick, ticks, byte_size(request)::little-16, request::binary, pad::binary,
      EtherNetIP.Path.words(route), 0, route::binary>>
  end

  @doc """
  The time tick and number of ticks (Volume 1, 3-5.5.1.3) that come closest above `ms`:

      iex> EtherNetIP.ConnectionManager.timing(200)
      {0, 200}
      iex> EtherNetIP.ConnectionManager.timing(5000)
      {5, 157}
  """
  @spec timing(pos_integer) :: {0..15, 1..255}
  def timing(ms) when is_integer(ms) and ms > 0 do
    tick = Enum.find(0..15, 15, fn tick -> ms <= 255 <<< tick end)
    {tick, min(255, div(ms + (1 <<< tick) - 1, 1 <<< tick))}
  end

  defp multiplier(multiplier) when is_map_key(@multipliers, multiplier),
    do: @multipliers[multiplier]

  defp multiplier(other),
    do:
      raise(
        ArgumentError,
        "a timeout multiplier is 4, 8, 16 and so on to 512, got: #{inspect(other)}"
      )

  defp parameters(direction, large) do
    flags =
      (if(Map.get(direction, :redundant_owner, false), do: 1, else: 0) <<< 15) +
        (Map.fetch!(@types, direction.type) <<< 13) +
        (Map.fetch!(@priorities, direction.priority) <<< 10) +
        (if(direction.fixed, do: 0, else: 1) <<< 9)

    case {large, direction.size} do
      {false, size} when size in 0..511 -> <<flags + size::little-16>>
      {true, size} when size in 0..0xFFFF -> <<(flags <<< 16) + size::little-32>>
      {_large, size} -> raise ArgumentError, "a connection of #{size} bytes needs large: true"
    end
  end

  defp decode_parameters(parameters, large) do
    {flags, size} =
      if large,
        do: {parameters >>> 16, band(parameters, 0xFFFF)},
        else: {band(parameters, 0xFE00), band(parameters, 0x1FF)}

    %{
      size: size,
      type: key(@types, band(flags >>> 13, 3)),
      priority: key(@priorities, band(flags >>> 10, 3)),
      fixed: band(flags, 0x200) == 0,
      redundant_owner: band(flags, 0x8000) != 0
    }
  end

  defp trigger({direction, trigger, class})
       when direction in [:client, :server] and is_map_key(@triggers, trigger) and class in 0..3,
       do: if(direction == :server, do: 0x80, else: 0) + (@triggers[trigger] <<< 4) + class

  defp decode_trigger(byte) do
    direction = if band(byte, 0x80) == 0, do: :client, else: :server
    {direction, key(@triggers, band(byte >>> 4, 7)), band(byte, 15)}
  end

  defp key(map, value), do: Enum.find_value(map, fn {k, v} -> if v == value, do: k end) || value

  defp encoded(path) when is_binary(path), do: path
  defp encoded(path), do: EtherNetIP.Path.encode(path)

  # Volume 1, Table 3-5.29, extended status of general status 0x01, with codes of later editions.
  @extended %{
    0x0100 => :connection_in_use,
    0x0103 => :transport_class_and_trigger_not_supported,
    0x0106 => :ownership_conflict,
    0x0107 => :target_connection_not_found,
    0x0108 => :invalid_network_connection_parameter,
    0x0109 => :invalid_connection_size,
    0x0110 => :target_not_configured,
    0x0111 => :rpi_not_supported,
    0x0113 => :out_of_connections,
    0x0114 => :vendor_id_or_product_code_mismatch,
    0x0115 => :product_type_mismatch,
    0x0116 => :revision_mismatch,
    0x0117 => :invalid_application_path,
    0x0118 => :invalid_configuration_path,
    0x0119 => :non_listen_only_connection_not_opened,
    0x011A => :target_object_out_of_connections,
    0x011B => :rpi_smaller_than_production_inhibit_time,
    # Reserved in edition 3.3, and given by the CIP Conformance Test Specification, 6.3.
    0x0112 => :t_o_rpi_mismatch,
    0x011C => :transport_class_not_supported,
    0x011D => :production_trigger_not_supported,
    0x011E => :direction_not_supported,
    0x0120 => :invalid_t_o_fixed_variable,
    0x0122 => :invalid_t_o_priority,
    0x0123 => :invalid_o_t_connection_type,
    0x0124 => :invalid_t_o_connection_type,
    0x0127 => :invalid_o_t_connection_size,
    0x0128 => :invalid_t_o_connection_size,
    0x0134 => :t_o_connection_size_mismatch,
    0x0135 => :t_o_fixed_variable_mismatch,
    0x0136 => :t_o_priority_mismatch,
    0x0137 => :transport_class_mismatch,
    0x0138 => :t_o_production_trigger_mismatch,
    0x0139 => :t_o_production_inhibit_time_mismatch,
    0x0203 => :connection_timed_out,
    0x0204 => :unconnected_request_timed_out,
    0x0205 => :parameter_error_in_unconnected_request,
    0x0206 => :message_too_large_for_unconnected_send,
    0x0207 => :unconnected_acknowledge_without_reply,
    0x0301 => :no_buffer_memory_available,
    0x0302 => :network_bandwidth_not_available,
    0x0303 => :no_consumed_connection_id_filter_available,
    0x0304 => :not_configured_to_send_scheduled_data,
    0x0305 => :schedule_signature_mismatch,
    0x0306 => :schedule_signature_validation_not_possible,
    0x0311 => :port_not_available,
    0x0312 => :link_address_not_valid,
    0x0315 => :invalid_segment_in_connection_path,
    0x0316 => :error_in_forward_close_path,
    0x0317 => :scheduling_not_specified,
    0x0318 => :link_address_to_self_invalid,
    0x0319 => :secondary_resources_unavailable,
    0x031A => :rack_connection_already_established,
    0x031B => :module_connection_already_established,
    0x031C => :miscellaneous,
    0x031D => :redundant_connection_mismatch,
    0x031E => :no_more_consumer_resources,
    0x031F => :no_consumers_configured,
    0x0800 => :network_link_offline,
    0x0810 => :no_target_application_data,
    0x0811 => :no_originator_application_data,
    0x0812 => :node_address_changed,
    0x0813 => :not_configured_for_off_subnet_multicast
  }
  @extended_codes Map.new(@extended, fn {code, name} -> {name, code} end)

  @doc """
  The extended status of a connection failure, general status 0x01, by name where Volume 1
  names it, and otherwise as its code, as vendor specific ones are.

      iex> EtherNetIP.ConnectionManager.extended_status(0x0106)
      :ownership_conflict
      iex> EtherNetIP.ConnectionManager.extended_status(0x0400)
      0x0400
  """
  @spec extended_status(0..0xFFFF) :: atom | 0..0xFFFF
  def extended_status(code), do: Map.get(@extended, code, code)

  @doc "The code of an extended status of a connection failure, by name or code."
  @spec extended_status_code(atom | 0..0xFFFF) :: 0..0xFFFF
  def extended_status_code(status) when is_map_key(@extended_codes, status),
    do: @extended_codes[status]

  def extended_status_code(code) when code in 0..0xFFFF, do: code
end
