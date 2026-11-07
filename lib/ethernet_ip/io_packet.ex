defmodule EtherNetIP.IOPacket do
  @moduledoc """
  The UDP packets of class 0 and class 1 I/O connections, to port 2222 (Volume 2, 3-2.2.1): the
  items of the Common Packet Format with no encapsulation header, a sequenced address item with
  the connection id and the encapsulation sequence number, and the connected data.

      iex> packet = EtherNetIP.IOPacket.encode(0x1234, 7, <<1, 0, 0xAA>>)
      iex> EtherNetIP.IOPacket.decode(packet)
      {:ok, {0x1234, 7, <<1, 0, 0xAA>>}}

  In class 1 the data starts with a 16-bit sequence count (Volume 1, 3-4.4.3), which changes only
  with new data, and then follows its real-time format (Volume 1, 3-6.1):

    * `:modeless`, the data alone
    * `:zero_length`, the data, none at all meaning idle
    * `:heartbeat`, no data
    * `:header`, a 32-bit run/idle header before the data

  The encapsulation sequence number goes up by one with every packet, new data or not; a packet
  that isn't newer than the last one taken, or is too far ahead of it, is dropped (Volume 2,
  3-4.1).
  """

  import Bitwise

  @type format :: :modeless | :zero_length | :heartbeat | :header

  @doc "The UDP port of class 0 and 1 I/O, 0x08AE."
  @spec port() :: 2222
  def port, do: 0x08AE

  @doc "A packet of the connection `id`, with an encapsulation sequence number."
  @spec encode(0..0xFFFF_FFFF, 0..0xFFFF_FFFF, binary) :: binary
  def encode(id, sequence, data),
    do: EtherNetIP.CPF.encode([{:sequenced_address, id, sequence}, {:connected_data, data}])

  @doc """
  The connection id, encapsulation sequence number and data of a packet. `{:error, :invalid}`
  for one that isn't a sequenced address item and a connected data item, which the spec says to
  discard.
  """
  @spec decode(binary) ::
          {:ok, {0..0xFFFF_FFFF, 0..0xFFFF_FFFF, binary}} | {:error, :invalid}
  def decode(packet) do
    case EtherNetIP.CPF.decode(packet) do
      {:ok, [{:sequenced_address, id, sequence}, {:connected_data, data}]} ->
        {:ok, {id, sequence, data}}

      _other ->
        {:error, :invalid}
    end
  end

  @doc """
  The data of a class 1 packet: the sequence count, then `data` in `format`, with `run` setting
  the run/idle bit of a 32-bit header. For `:zero_length`, idle sends no data.

      iex> EtherNetIP.IOPacket.encode_class1(5, :header, true, <<0xFF>>)
      <<5, 0, 1, 0, 0, 0, 0xFF>>
      iex> EtherNetIP.IOPacket.encode_class1(6, :zero_length, false, <<0xFF>>)
      <<6, 0>>
  """
  @spec encode_class1(0..0xFFFF, format, boolean, binary) :: binary
  def encode_class1(count, :header, run, data),
    do: <<count::little-16, if(run, do: 1, else: 0)::little-32, data::binary>>

  def encode_class1(count, :zero_length, false, _data), do: <<count::little-16>>
  def encode_class1(count, :heartbeat, _run, _data), do: <<count::little-16>>

  def encode_class1(count, format, _run, data) when format in [:modeless, :zero_length],
    do: <<count::little-16, data::binary>>

  @doc """
  The sequence count, run or idle, and data of a class 1 packet in `format`: `:run` or `:idle`
  as a 32-bit header or zero-length data says, and `nil` for the formats that don't say.

      iex> EtherNetIP.IOPacket.decode_class1(<<5, 0, 0, 0, 0, 0, 0xFF>>, :header)
      {:ok, {5, :idle, <<0xFF>>}}
      iex> EtherNetIP.IOPacket.decode_class1(<<5>>, :modeless)
      {:error, :invalid}
  """
  @spec decode_class1(binary, format) ::
          {:ok, {0..0xFFFF, :run | :idle | nil, binary}} | {:error, :invalid}
  def decode_class1(<<count::little-16, header::little-32, data::binary>>, :header),
    do: {:ok, {count, if(band(header, 1) == 1, do: :run, else: :idle), data}}

  def decode_class1(<<count::little-16>>, :zero_length), do: {:ok, {count, :idle, <<>>}}

  def decode_class1(<<count::little-16, data::binary>>, :zero_length),
    do: {:ok, {count, :run, data}}

  def decode_class1(<<count::little-16, data::binary>>, format)
      when format in [:modeless, :heartbeat],
      do: {:ok, {count, nil, data}}

  def decode_class1(_data, _format), do: {:error, :invalid}

  @doc """
  Whether a packet with the encapsulation sequence number `sequence` is taken after one with
  `last`, for a connection with a timeout multiplier of `multiplier` (4 to 512): it must be newer,
  in modulo 2^32 arithmetic as TCP's, and at most the larger of 16 and `multiplier + 1` ahead.

      iex> EtherNetIP.IOPacket.next?(0xFFFF_FFFF, 3, 4)
      true
      iex> EtherNetIP.IOPacket.next?(5, 5, 4)
      false
      iex> EtherNetIP.IOPacket.next?(5, 22, 4)
      false
  """
  @spec next?(0..0xFFFF_FFFF, 0..0xFFFF_FFFF, pos_integer) :: boolean
  def next?(last, sequence, multiplier) do
    ahead = band(sequence - last, 0xFFFF_FFFF)
    ahead in 1..max(16, multiplier + 1)
  end
end
