defmodule EtherNetIP.CIP do
  @moduledoc """
  CIP's explicit messages (Volume 1, 2-4): a request to the message router of a device is a
  service code, a path and the service's data; its reply has the service code with bit 7 set, a
  general status, words of additional status, and data.

      iex> request = EtherNetIP.CIP.request(:get_attribute_single, class: 1, instance: 1, attribute: 7)
      <<0x0E, 3, 0x20, 1, 0x24, 1, 0x30, 7>>
      iex> EtherNetIP.CIP.decode_request(request)
      {:ok, {0x0E, [class: 1, instance: 1, attribute: 7], ""}}
      iex> EtherNetIP.CIP.decode_reply(<<0x8E, 0, 0, 0, 4, "Pump">>)
      {:ok, %{service: 0x0E, status: :success, additional: [], data: <<4, "Pump">>}}
      iex> EtherNetIP.CIP.decode_reply(<<0x8E, 0, 0x14, 0>>)
      {:ok, %{service: 0x0E, status: :attribute_not_supported, additional: [], data: ""}}

  The services every object may have (Volume 1, Appendix A) go by name, as `:get_attribute_single`;
  those of one class, as Forward_Open of the connection manager, by their code.
  """

  @services %{
    get_attributes_all: 0x01,
    set_attributes_all: 0x02,
    get_attribute_list: 0x03,
    set_attribute_list: 0x04,
    reset: 0x05,
    start: 0x06,
    stop: 0x07,
    create: 0x08,
    delete: 0x09,
    multiple_service_packet: 0x0A,
    apply_attributes: 0x0D,
    get_attribute_single: 0x0E,
    set_attribute_single: 0x10,
    find_next_object_instance: 0x11,
    restore: 0x15,
    save: 0x16,
    nop: 0x17,
    get_member: 0x18,
    set_member: 0x19,
    insert_member: 0x1A,
    remove_member: 0x1B,
    group_sync: 0x1C
  }

  # Volume 1, Appendix B, Table B-1.1.
  @statuses %{
    0x00 => :success,
    0x01 => :connection_failure,
    0x02 => :resource_unavailable,
    0x03 => :invalid_parameter_value,
    0x04 => :path_segment_error,
    0x05 => :path_destination_unknown,
    0x06 => :partial_transfer,
    0x07 => :connection_lost,
    0x08 => :service_not_supported,
    0x09 => :invalid_attribute_value,
    0x0A => :attribute_list_error,
    0x0B => :already_in_requested_mode,
    0x0C => :object_state_conflict,
    0x0D => :object_already_exists,
    0x0E => :attribute_not_settable,
    0x0F => :privilege_violation,
    0x10 => :device_state_conflict,
    0x11 => :reply_data_too_large,
    0x12 => :fragmentation_of_a_primitive_value,
    0x13 => :not_enough_data,
    0x14 => :attribute_not_supported,
    0x15 => :too_much_data,
    0x16 => :object_does_not_exist,
    0x17 => :service_fragmentation_sequence_not_in_progress,
    0x18 => :no_stored_attribute_data,
    0x19 => :store_operation_failure,
    0x1A => :routing_failure_request_too_large,
    0x1B => :routing_failure_response_too_large,
    0x1C => :missing_attribute_list_entry_data,
    0x1D => :invalid_attribute_value_list,
    0x1E => :embedded_service_error,
    0x1F => :vendor_specific_error,
    0x20 => :invalid_parameter,
    0x21 => :write_once_value_already_written,
    0x22 => :invalid_reply_received,
    0x23 => :buffer_overflow,
    0x24 => :message_format_error,
    0x25 => :key_failure_in_path,
    0x26 => :path_size_invalid,
    0x27 => :unexpected_attribute_in_list,
    0x28 => :invalid_member_id,
    0x29 => :member_not_settable,
    0x2A => :group_2_only_server_general_failure,
    0x2B => :unknown_modbus_error
  }
  @status_codes Map.new(@statuses, fn {code, name} -> {name, code} end)

  @typedoc "A service, by name for the common services, or by code."
  @type service :: atom | 0..0x7F

  @typedoc """
  A general status: an atom for those of Volume 1, Appendix B, or the code for one reserved
  there, such as an object's own in 0xD0 to 0xFF.
  """
  @type status :: atom | 0..255

  @type reply :: %{service: 0..0x7F, status: status, additional: [0..0xFFFF], data: binary}

  @doc """
  The code of a service, by name or code. Raises `ArgumentError` for any other.

      iex> EtherNetIP.CIP.service(:get_attributes_all)
      1
  """
  @spec service(service) :: 0..0x7F
  def service(service) when is_map_key(@services, service), do: @services[service]
  def service(code) when code in 0..0x7F, do: code
  def service(other), do: raise(ArgumentError, "not a CIP service: #{inspect(other)}")

  @doc """
  The name of a common service, or the code of any other.

      iex> EtherNetIP.CIP.service_name(0x0E)
      :get_attribute_single
      iex> EtherNetIP.CIP.service_name(0x54)
      0x54
  """
  @spec service_name(0..0x7F) :: service
  for {name, code} <- @services, do: def(service_name(unquote(code)), do: unquote(name))
  def service_name(code) when code in 0..0x7F, do: code

  @doc """
  A general status by its code, as `t:status/0`.

      iex> EtherNetIP.CIP.status(0x05)
      :path_destination_unknown
      iex> EtherNetIP.CIP.status(0xD0)
      0xD0
  """
  @spec status(0..255) :: status
  def status(code) when code in 0..255, do: Map.get(@statuses, code, code)

  @doc """
  The code of a general status.

      iex> EtherNetIP.CIP.status_code(:service_not_supported)
      8
  """
  @spec status_code(status) :: 0..255
  def status_code(status) when is_map_key(@status_codes, status), do: @status_codes[status]
  def status_code(code) when code in 0..255, do: code
  def status_code(other), do: raise(ArgumentError, "not a CIP general status: #{inspect(other)}")

  @doc """
  A message router request, to `path`, either a list of segments (see `EtherNetIP.Path`) or a
  padded path already encoded.
  """
  @spec request(service, EtherNetIP.Path.t() | binary, iodata) :: binary
  def request(service, path, data \\ <<>>) do
    path = if is_binary(path), do: path, else: EtherNetIP.Path.encode(path)
    words = EtherNetIP.Path.words(path)

    if words > 255,
      do: raise(ArgumentError, "a request path is 255 words at most, got: #{words}")

    IO.iodata_to_binary([service(service), words, path, data])
  end

  @doc """
  The service code, path and data of a message router request, its path as segments.
  `{:error, :invalid}` for one too short for its path; `{:error, {:path, offset}}` for a path
  that isn't one, the offset into it of the first segment that can't be read.
  """
  @spec decode_request(binary) ::
          {:ok, {0..0x7F, EtherNetIP.Path.t(), binary}}
          | {:error, :invalid | {:path, non_neg_integer}}
  def decode_request(<<0::1, service::7, words, path::binary-size(words * 2), data::binary>>) do
    case EtherNetIP.Path.decode(path) do
      {:ok, segments} -> {:ok, {service, segments, data}}
      {:error, {:segment, offset}} -> {:error, {:path, offset}}
    end
  end

  def decode_request(_request), do: {:error, :invalid}

  @doc """
  A message router reply to `service`, with a general status, additional status words and data.

      iex> EtherNetIP.CIP.reply(:get_attribute_single, :success, [], <<1, 0>>)
      <<0x8E, 0, 0, 0, 1, 0>>
  """
  @spec reply(service, status, [0..0xFFFF], iodata) :: binary
  def reply(service, status, additional \\ [], data \\ <<>>) when length(additional) <= 255 do
    words = for word <- additional, into: <<>>, do: <<word::little-16>>

    IO.iodata_to_binary([
      0x80 + service(service),
      0,
      status_code(status),
      length(additional),
      words,
      data
    ])
  end

  @doc """
  A message router reply as a map: the code of the service it answers, the general status, the
  words of additional status, and the data. `{:error, :invalid}` for one that isn't a reply, or
  is cut short.
  """
  @spec decode_reply(binary) :: {:ok, reply} | {:error, :invalid}
  def decode_reply(
        <<1::1, service::7, _reserved, status, size, additional::binary-size(size * 2),
          data::binary>>
      ) do
    additional = for <<word::little-16 <- additional>>, do: word
    {:ok, %{service: service, status: status(status), additional: additional, data: data}}
  end

  def decode_reply(_reply), do: {:error, :invalid}
end
