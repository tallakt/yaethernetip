defmodule EtherNetIP.Encapsulation do
  @moduledoc """
  The encapsulation protocol (Volume 2, chapter 2): every message over TCP to port 44818, and
  to UDP port 44818, is a header of 24 bytes and the data of its command.

    * `command`: `:nop`, `:list_services`, `:list_identity`, `:list_interfaces`,
      `:register_session`, `:unregister_session`, `:send_rr_data` or `:send_unit_data`, or the
      code of any other
    * `session`: the session handle, which a target gives in its reply to RegisterSession
    * `status`: `:success` in every request, and in a reply that went well; see `status/1`
    * `context`: 8 bytes of the sender's, which the receiver copies into its reply
    * `options`: 0 for every command defined so far
    * `data`: what the command carries

  Integers are little-endian, as in all of CIP.

      iex> message = %EtherNetIP.Encapsulation{command: :register_session, data: <<1, 0, 0, 0>>}
      iex> frame = EtherNetIP.Encapsulation.encode(message)
      iex> byte_size(frame)
      28
      iex> EtherNetIP.Encapsulation.decode(frame <> <<0x65>>)
      {:ok, message, <<0x65>>}
      iex> EtherNetIP.Encapsulation.decode(binary_part(frame, 0, 27))
      :more

  A message is 65535 bytes at most, and so its data 65511.
  """

  defstruct command: :nop,
            session: 0,
            status: :success,
            context: <<0::64>>,
            options: 0,
            data: <<>>

  @type command ::
          :nop
          | :list_services
          | :list_identity
          | :list_interfaces
          | :register_session
          | :unregister_session
          | :send_rr_data
          | :send_unit_data
          | 0..0xFFFF

  @type status ::
          :success
          | :invalid_command
          | :insufficient_memory
          | :incorrect_data
          | :invalid_session_handle
          | :invalid_length
          | :unsupported_protocol_version
          | 0..0xFFFF_FFFF

  @type t :: %__MODULE__{
          command: command,
          session: 0..0xFFFF_FFFF,
          status: status,
          context: <<_::64>>,
          options: 0..0xFFFF_FFFF,
          data: binary
        }

  # Volume 2, Table 2-3.2.
  @commands %{
    nop: 0x0000,
    list_services: 0x0004,
    list_identity: 0x0063,
    list_interfaces: 0x0064,
    register_session: 0x0065,
    unregister_session: 0x0066,
    send_rr_data: 0x006F,
    send_unit_data: 0x0070
  }
  @command_names Map.new(@commands, fn {name, code} -> {code, name} end)

  # Volume 2, Table 2-3.3.
  @statuses %{
    0x0000 => :success,
    0x0001 => :invalid_command,
    0x0002 => :insufficient_memory,
    0x0003 => :incorrect_data,
    0x0064 => :invalid_session_handle,
    0x0065 => :invalid_length,
    0x0069 => :unsupported_protocol_version
  }
  @status_codes Map.new(@statuses, fn {code, name} -> {name, code} end)

  @doc "The TCP and UDP port of the encapsulation protocol, 0xAF12."
  @spec port() :: 44818
  def port, do: 0xAF12

  @doc "A message as bytes. Raises `ArgumentError` for data of more than 65511 bytes."
  @spec encode(t) :: binary
  def encode(%__MODULE__{data: data} = message) when byte_size(data) <= 65511 do
    <<command_code(message.command)::little-16, byte_size(data)::little-16,
      message.session::little-32, status_code(message.status)::little-32,
      message.context::binary-8, message.options::little-32, data::binary>>
  end

  def encode(%__MODULE__{data: data}),
    do:
      raise(
        ArgumentError,
        "the data of a message is 65511 bytes at most, got: #{byte_size(data)}"
      )

  @doc """
  The first message in what has come over a connection so far: `{:ok, message, rest}` for a
  whole one, `:more` for the start of one. A header says how much data follows, and the message
  is taken whole, whatever its command and however long, as the spec says, so that the next one
  is found.
  """
  @spec decode(binary) :: {:ok, t, binary} | :more
  def decode(
        <<command::little-16, length::little-16, session::little-32, status::little-32,
          context::binary-8, options::little-32, data::binary-size(length), rest::binary>>
      ) do
    message = %__MODULE__{
      command: Map.get(@command_names, command, command),
      session: session,
      status: Map.get(@statuses, status, status),
      context: context,
      options: options,
      data: data
    }

    {:ok, message, rest}
  end

  def decode(_partial), do: :more

  @doc """
  An encapsulation status by name or code, as a code.

      iex> EtherNetIP.Encapsulation.status_code(:invalid_session_handle)
      0x64
  """
  @spec status_code(status) :: 0..0xFFFF_FFFF
  def status_code(status) when is_map_key(@status_codes, status), do: @status_codes[status]
  def status_code(code) when code in 0..0xFFFF_FFFF, do: code

  defp command_code(command) when is_map_key(@commands, command), do: @commands[command]
  defp command_code(code) when code in 0..0xFFFF, do: code

  @doc """
  The data of a RegisterSession request or reply: the protocol version, 1, and options, 0.

      iex> EtherNetIP.Encapsulation.register_session()
      <<1, 0, 0, 0>>
  """
  @spec register_session(0..0xFFFF, 0..0xFFFF) :: binary
  def register_session(version \\ 1, options \\ 0),
    do: <<version::little-16, options::little-16>>

  @doc """
  The data of a SendRRData or SendUnitData command: an interface handle and a timeout, both 0
  for CIP, and items of the Common Packet Format (see `EtherNetIP.CPF`).
  """
  @spec rr_data([EtherNetIP.CPF.item()]) :: binary
  def rr_data(items), do: <<0::32, 0::16, EtherNetIP.CPF.encode(items)::binary>>

  @doc """
  The items of the data of a SendRRData or SendUnitData command, whatever its interface handle
  and timeout.
  """
  @spec decode_rr_data(binary) :: {:ok, [EtherNetIP.CPF.item()]} | {:error, :invalid}
  def decode_rr_data(<<_interface::little-32, _timeout::little-16, items::binary>>),
    do: EtherNetIP.CPF.decode(items)

  def decode_rr_data(_data), do: {:error, :invalid}

  @doc """
  The sender context of a ListIdentity request, which carries the longest a device that gets it
  by broadcast may wait before it answers, in ms; 0 means 2000, and 1 to 500 mean 500.

      iex> EtherNetIP.Encapsulation.list_identity_context(1000)
      <<0xE8, 3, 0, 0, 0, 0, 0, 0>>
  """
  @spec list_identity_context(0..0xFFFF) :: <<_::64>>
  def list_identity_context(max_delay), do: <<max_delay::little-16, 0::48>>
end
