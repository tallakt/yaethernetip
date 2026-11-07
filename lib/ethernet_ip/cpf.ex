defmodule EtherNetIP.CPF do
  @moduledoc """
  The Common Packet Format (Volume 2, 2-6): a count of items, each an item type, a length and
  data. Commands carry an address item and then a data item, and a Forward_Open may add Sockaddr
  Info items. An item is one of:

    * `:null_address`, for unconnected messages
    * `{:connected_address, connection_id}`, for class 3 connected messages
    * `{:sequenced_address, connection_id, sequence}`, for class 0 and 1 I/O
    * `{:unconnected_data, message}`, a message router request or reply
    * `{:connected_data, packet}`, a transport packet of a connection
    * `{:sockaddr, :o_t | :t_o, {address, port}}`, the UDP port and address to send I/O to
    * `{:identity, data}`, a device's identity in a ListIdentity reply (see
      `EtherNetIP.Identity.decode_list_identity/1`)
    * `{:service, data}`, a service in a ListServices reply (see `decode_service/1`)
    * `{type, data}` for any other type

      iex> items = [:null_address, {:unconnected_data, <<0x0E, 2, 0x20, 1, 0x24, 1>>}]
      iex> packet = EtherNetIP.CPF.encode(items)
      <<2, 0, 0, 0, 0, 0, 0xB2, 0, 6, 0, 0x0E, 2, 0x20, 1, 0x24, 1>>
      iex> EtherNetIP.CPF.decode(packet)
      {:ok, items}

  The Sockaddr Info items alone are big-endian, after the sockaddr_in of Winsock.
  """

  @type item ::
          :null_address
          | {:connected_address, 0..0xFFFF_FFFF}
          | {:sequenced_address, 0..0xFFFF_FFFF, 0..0xFFFF_FFFF}
          | {:unconnected_data, binary}
          | {:connected_data, binary}
          | {:sockaddr, :o_t | :t_o, {:inet.ip4_address(), :inet.port_number()}}
          | {:identity, binary}
          | {:service, binary}
          | {0..0xFFFF, binary}

  # Volume 2, Table 2-6.3.
  @null_address 0x0000
  @identity 0x000C
  @connected_address 0x00A1
  @connected_data 0x00B1
  @unconnected_data 0x00B2
  @service 0x0100
  @sockaddr_o_t 0x8000
  @sockaddr_t_o 0x8001
  @sequenced_address 0x8002

  # AF_INET
  @inet 2

  @doc "Items as a packet. Raises `ArgumentError` for one that can't be encoded."
  @spec encode([item]) :: binary
  def encode(items) when length(items) <= 0xFFFF,
    do: IO.iodata_to_binary([<<length(items)::little-16>> | Enum.map(items, &item/1)])

  defp item(:null_address), do: <<@null_address::little-16, 0::16>>

  defp item({:connected_address, id}),
    do: <<@connected_address::little-16, 4::little-16, id::little-32>>

  defp item({:sequenced_address, id, sequence}),
    do: <<@sequenced_address::little-16, 8::little-16, id::little-32, sequence::little-32>>

  defp item({:unconnected_data, message}), do: item(@unconnected_data, message)
  defp item({:connected_data, packet}), do: item(@connected_data, packet)
  defp item({:identity, data}), do: item(@identity, data)
  defp item({:service, data}), do: item(@service, data)

  defp item({:sockaddr, direction, {{a, b, c, d}, port}}) when direction in [:o_t, :t_o] do
    type = if direction == :o_t, do: @sockaddr_o_t, else: @sockaddr_t_o
    <<type::little-16, 16::little-16, @inet::16, port::16, a, b, c, d, 0::64>>
  end

  defp item({type, data}) when type in 0..0xFFFF and is_binary(data), do: item(type, data)
  defp item(item), do: raise(ArgumentError, "not a CPF item: #{inspect(item)}")

  defp item(type, data) when byte_size(data) <= 0xFFFF,
    do: <<type::little-16, byte_size(data)::little-16, data::binary>>

  @doc """
  The items of a packet. `{:error, :invalid}` when the packet doesn't hold as many items as it
  says, has bytes after the last, or has an address or Sockaddr Info item of the wrong length.
  """
  @spec decode(binary) :: {:ok, [item]} | {:error, :invalid}
  def decode(<<count::little-16, items::binary>>), do: decode(items, count, [])
  def decode(_packet), do: {:error, :invalid}

  defp decode(<<>>, 0, acc), do: {:ok, Enum.reverse(acc)}

  defp decode(
         <<type::little-16, length::little-16, data::binary-size(length), rest::binary>>,
         n,
         acc
       )
       when n > 0 do
    case decode_item(type, data) do
      {:ok, item} -> decode(rest, n - 1, [item | acc])
      :error -> {:error, :invalid}
    end
  end

  defp decode(_items, _n, _acc), do: {:error, :invalid}

  defp decode_item(@null_address, <<>>), do: {:ok, :null_address}
  defp decode_item(@connected_address, <<id::little-32>>), do: {:ok, {:connected_address, id}}

  defp decode_item(@sequenced_address, <<id::little-32, sequence::little-32>>),
    do: {:ok, {:sequenced_address, id, sequence}}

  defp decode_item(@unconnected_data, message), do: {:ok, {:unconnected_data, message}}
  defp decode_item(@connected_data, packet), do: {:ok, {:connected_data, packet}}
  defp decode_item(@identity, data), do: {:ok, {:identity, data}}
  defp decode_item(@service, data), do: {:ok, {:service, data}}

  defp decode_item(type, <<@inet::16, port::16, a, b, c, d, _zero::binary-8>>)
       when type in [@sockaddr_o_t, @sockaddr_t_o] do
    direction = if type == @sockaddr_o_t, do: :o_t, else: :t_o
    {:ok, {:sockaddr, direction, {{a, b, c, d}, port}}}
  end

  defp decode_item(type, _data)
       when type in [@null_address, @connected_address, @sequenced_address] or
              type in [@sockaddr_o_t, @sockaddr_t_o],
       do: :error

  defp decode_item(type, data), do: {:ok, {type, data}}

  @doc """
  A service of a ListServices reply (Volume 2, 2-4.6): its version, its capability flags and its
  name. The Communications service, type 0x100, has bit 5 set when the device encapsulates CIP,
  and bit 8 when it has class 0 and 1 connections over UDP.

      iex> EtherNetIP.CPF.decode_service(<<1, 0, 0x20, 0x01, "Communications", 0, 0>>)
      {:ok, %{version: 1, flags: 0x0120, name: "Communications"}}
  """
  @spec decode_service(binary) ::
          {:ok, %{version: 0..0xFFFF, flags: 0..0xFFFF, name: binary}} | {:error, :invalid}
  def decode_service(<<version::little-16, flags::little-16, name::binary-16>>) do
    [name | _rest] = :binary.split(name, <<0>>)
    {:ok, %{version: version, flags: flags, name: name}}
  end

  def decode_service(_data), do: {:error, :invalid}

  @doc "The data of a service of a ListServices reply; see `decode_service/1`."
  @spec service(0..0xFFFF, 0..0xFFFF, binary) :: binary
  def service(version, flags, name) when byte_size(name) <= 15,
    do:
      <<version::little-16, flags::little-16, name::binary, 0::size((16 - byte_size(name)) * 8)>>
end
