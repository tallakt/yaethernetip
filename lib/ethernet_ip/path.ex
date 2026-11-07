defmodule EtherNetIP.Path do
  @moduledoc """
  Paths (EPATH, Volume 1, Appendix C-1): what a request is about, and the route to it. A path is
  a list of segments:

    * `{:class, id}`, `{:instance, id}`, `{:attribute, id}`, `{:member, id}` and
      `{:connection_point, id}`, the logical segments, so that a path to an attribute reads as a
      keyword list: `[class: 1, instance: 1, attribute: 7]`
    * `{:port, port, link}`, to leave a device by a port for the device at `link` on it: an
      integer for a one-byte address such as a slot, or a string such as `"10.0.0.20"`
    * `{:key, vendor_id, device_type, product_code, major, minor, compatible}`, an electronic
      key, which the device must match
    * `{:symbol, name}`, an ANSI extended symbol, such as a tag name
    * `{:data, binary}`, a simple data segment of whole 16-bit words, such as configuration data
    * `{:production_inhibit, ms}`, the least time between productions of a connection

  The same path is padded, each segment taking whole 16-bit words as requests have them, or
  packed, with no pad bytes:

      iex> EtherNetIP.Path.encode(class: 5, instance: 2, attribute: 1)
      <<0x20, 5, 0x24, 2, 0x30, 1>>
      iex> EtherNetIP.Path.encode(class: 0x0105, instance: 2)
      <<0x21, 0, 5, 1, 0x24, 2>>
      iex> EtherNetIP.Path.encode([class: 0x0105, instance: 2], :packed)
      <<0x21, 5, 1, 0x24, 2>>
      iex> EtherNetIP.Path.encode([{:port, 1, 4}, {:symbol, "starter"}])
      <<1, 4, 0x91, 7, "starter", 0>>

  Each logical value takes the fewest bytes it fits: 8 bits, 16 bits, or 32 bits for an instance
  or a connection point, the only ones that may have 32.
  """

  @typedoc "A segment of a path."
  @type segment ::
          {:class | :attribute | :member, 0..0xFFFF}
          | {:instance | :connection_point, 0..0xFFFF_FFFF}
          | {:port, 1..0xFFFF, 0..255 | binary}
          | {:key, 0..0xFFFF, 0..0xFFFF, 0..0xFFFF, 0..127, 0..255, boolean}
          | {:symbol, binary}
          | {:data, binary}
          | {:production_inhibit, 0..255}

  @type t :: [segment]

  @logical %{class: 0, instance: 1, member: 2, connection_point: 3, attribute: 4}
  @logical_types Map.new(@logical, fn {name, type} -> {type, name} end)

  @doc """
  A path as bytes, padded unless `:packed` is given. Raises `ArgumentError` for a segment that
  can't be encoded.
  """
  @spec encode(t, :padded | :packed) :: binary
  def encode(path, format \\ :padded) when format in [:padded, :packed],
    do: IO.iodata_to_binary(Enum.map(path, &segment(&1, format)))

  @doc """
  The size of an encoded path in 16-bit words, as requests give it.

      iex> EtherNetIP.Path.words(EtherNetIP.Path.encode(class: 6, instance: 1))
      2
  """
  @spec words(binary) :: non_neg_integer
  def words(path) when rem(byte_size(path), 2) == 0, do: div(byte_size(path), 2)

  defp segment({type, value}, format) when is_map_key(@logical, type) do
    code = 0x20 + Bitwise.bsl(@logical[type], 2)
    pad = if format == :padded, do: <<0>>, else: <<>>

    cond do
      value in 0..0xFF ->
        <<code, value>>

      value in 0..0xFFFF ->
        [<<code + 1>>, pad, <<value::little-16>>]

      value in 0..0xFFFF_FFFF and type in [:instance, :connection_point] ->
        [<<code + 2>>, pad, <<value::little-32>>]

      true ->
        raise ArgumentError, "a #{type} is 0 to #{max(type)}, got: #{inspect(value)}"
    end
  end

  defp segment({:port, port, link}, _format) when port in 1..0xFFFF do
    {identifier, extended} = if port < 15, do: {port, <<>>}, else: {15, <<port::little-16>>}

    case link do
      link when link in 0..0xFF ->
        [<<identifier>>, extended, <<link>>]

      link when is_binary(link) and byte_size(link) in 2..255 ->
        segment = [<<0x10 + identifier, byte_size(link)>>, extended, link]
        if rem(IO.iodata_length(segment), 2) == 1, do: [segment, 0], else: segment

      link ->
        raise ArgumentError,
              "a port's link address is 0 to 255 or a string of 2 to 255 bytes, got: #{inspect(link)}"
    end
  end

  defp segment({:key, vendor, device_type, product, major, minor, compatible}, _format)
       when vendor in 0..0xFFFF and device_type in 0..0xFFFF and product in 0..0xFFFF and
              major in 0..127 and minor in 0..255 and is_boolean(compatible) do
    compatibility = if compatible, do: 0x80, else: 0

    <<0x34, 4, vendor::little-16, device_type::little-16, product::little-16,
      major + compatibility, minor>>
  end

  defp segment({:symbol, name}, _format) when is_binary(name) and byte_size(name) in 1..255 do
    pad = if rem(byte_size(name), 2) == 1, do: <<0>>, else: <<>>
    [<<0x91, byte_size(name)>>, name, pad]
  end

  defp segment({:data, data}, _format)
       when is_binary(data) and rem(byte_size(data), 2) == 0 and byte_size(data) <= 510,
       do: [<<0x80, div(byte_size(data), 2)>>, data]

  defp segment({:production_inhibit, ms}, _format) when ms in 0..255, do: <<0x43, ms>>

  defp segment(segment, _format),
    do: raise(ArgumentError, "not a path segment: #{inspect(segment)}")

  defp max(type) when type in [:instance, :connection_point], do: 0xFFFF_FFFF
  defp max(_type), do: 0xFFFF

  @doc """
  The segments of an encoded path, padded unless `:packed` is given:

      iex> EtherNetIP.Path.decode(<<0x20, 4, 0x24, 3, 0x2C, 1, 0x2C, 2, 0x80, 1, 0, 1>>)
      {:ok, [class: 4, instance: 3, connection_point: 1, connection_point: 2, data: <<0, 1>>]}
      iex> EtherNetIP.Path.decode(<<0x20, 4, 0xE0>>)
      {:error, {:segment, 2}}

  The error gives the offset of the first segment that isn't one of those above, or that is cut
  short.
  """
  @spec decode(binary, :padded | :packed) :: {:ok, t} | {:error, {:segment, non_neg_integer}}
  def decode(path, format \\ :padded) when format in [:padded, :packed],
    do: decode(path, format, 0, [])

  defp decode(<<>>, _format, _offset, acc), do: {:ok, Enum.reverse(acc)}

  defp decode(binary, format, offset, acc) do
    case take(binary, format) do
      {:ok, segment, rest} ->
        decode(rest, format, offset + byte_size(binary) - byte_size(rest), [segment | acc])

      :error ->
        {:error, {:segment, offset}}
    end
  end

  # Logical segments: 0x20 to 0x3F, of which the logical type is bits 2 to 4 and the format bits 0
  # and 1.
  defp take(<<code, rest::binary>>, format) when code in 0x20..0x33 do
    type = @logical_types[Bitwise.band(Bitwise.bsr(code, 2), 7)]
    size = Bitwise.band(code, 3)

    case {size, unpad(rest, format, size)} do
      {0, <<value, rest::binary>>} ->
        {:ok, {type, value}, rest}

      {1, <<value::little-16, rest::binary>>} ->
        {:ok, {type, value}, rest}

      {2, <<value::little-32, rest::binary>>} when type in [:instance, :connection_point] ->
        {:ok, {type, value}, rest}

      _other ->
        :error
    end
  end

  defp take(
         <<0x34, 4, vendor::little-16, device_type::little-16, product::little-16, compatible::1,
           major::7, minor, rest::binary>>,
         _format
       ),
       do: {:ok, {:key, vendor, device_type, product, major, minor, compatible == 1}, rest}

  defp take(<<0::3, 0::1, identifier::4, rest::binary>>, _format) when identifier != 0 do
    with {:ok, port, <<link, rest::binary>>} <- port(identifier, rest),
         do: {:ok, {:port, port, link}, rest}
  end

  defp take(<<0::3, 1::1, identifier::4, size, rest::binary>> = segment, _format)
       when identifier != 0 and size >= 1 do
    case port(identifier, rest) do
      {:ok, port, rest} when byte_size(rest) >= size ->
        link = binary_part(rest, 0, size)
        rest = binary_part(rest, size, byte_size(rest) - size)
        length = byte_size(segment) - byte_size(rest)
        rest = if rem(length, 2) == 1, do: pad(rest), else: rest
        if rest == :error, do: :error, else: {:ok, {:port, port, link}, rest}

      _error ->
        :error
    end
  end

  defp take(<<0x91, size, name::binary-size(size), rest::binary>>, _format) when size > 0 do
    rest = if rem(size, 2) == 1, do: pad(rest), else: rest
    if rest == :error, do: :error, else: {:ok, {:symbol, name}, rest}
  end

  defp take(<<0x80, words, data::binary-size(words * 2), rest::binary>>, _format),
    do: {:ok, {:data, data}, rest}

  defp take(<<0x43, ms, rest::binary>>, _format), do: {:ok, {:production_inhibit, ms}, rest}

  defp take(_binary, _format), do: :error

  defp port(15, <<port::little-16, rest::binary>>) when port > 0, do: {:ok, port, rest}
  defp port(15, _rest), do: :error
  defp port(identifier, rest), do: {:ok, identifier, rest}

  defp pad(<<0, rest::binary>>), do: rest
  defp pad(_rest), do: :error

  # In a padded path, a pad byte comes before a logical value of 16 or 32 bits.
  defp unpad(<<_pad, rest::binary>>, :padded, size) when size in [1, 2], do: rest
  defp unpad(rest, _format, _size), do: rest
end
