defmodule EtherNetIP do
  @moduledoc """
  EtherNet/IP in pure Elixir, written from ODVA's specification: The CIP Networks Library,
  Volume 1 (CIP) and Volume 2 (EtherNet/IP).

    * `EtherNetIP.Scanner`, a session with a device, for explicit messages and the I/O
      connections of a scan list
    * `EtherNetIP.Adapter`, a device that scanners connect to, with assemblies of inputs and
      outputs, and its EDS
    * `EtherNetIP.EDS`, a device's Electronic Data Sheet, which gives the scanner its
      connections by name
    * `EtherNetIP.Path`, `EtherNetIP.CIP`, `EtherNetIP.Encapsulation`, `EtherNetIP.CPF`,
      `EtherNetIP.Identity`, `EtherNetIP.ConnectionManager` and `EtherNetIP.IOPacket`, the
      messages, each encoded and decoded
  """

  alias EtherNetIP.{CIP, ConnectionManager, Encapsulation}

  @doc """
  The node's serial number, which a scanner gives its connections by default: what a device
  takes for the identity of their owner (Volume 1, 3-5.5.1.7), so that a scanner that restarts
  takes back the connections it held, where one with another serial number would be refused.

  It's a hash of the lowest of the node's universally administered hardware addresses, or of any
  of them when it has none, so that it's the same every time the node starts and differs from
  another node's; random for a node with no hardware address at all. It's worked out once while
  the node runs.
  """
  @spec serial_number() :: 0..0xFFFF_FFFF
  def serial_number do
    case :persistent_term.get({__MODULE__, :serial_number}, nil) do
      nil ->
        serial = serial_from(hardware_addresses())
        :persistent_term.put({__MODULE__, :serial_number}, serial)
        serial

      serial ->
        serial
    end
  end

  defp hardware_addresses do
    case :inet.getifaddrs() do
      {:ok, interfaces} ->
        for {_name, opts} <- interfaces,
            [_, _, _, _, _, _] = address <- [opts[:hwaddr]],
            Enum.any?(address, &(&1 != 0)),
            uniq: true,
            do: address

      {:error, _reason} ->
        []
    end
  end

  # The universal ones have bit 1 of the first byte clear.
  defp serial_from([]), do: :rand.uniform(0x1_0000_0000) - 1

  defp serial_from(addresses) do
    {universal, local} =
      Enum.split_with(addresses, fn [first | _] -> Bitwise.band(first, 2) == 0 end)

    address = Enum.min(if universal == [], do: local, else: universal)
    :erlang.phash2(address, 0x1_0000_0000)
  end

  @doc """
  A reason this library gives, for an error or a connection that isn't open, in words, as for a
  log or an operator:

      iex> EtherNetIP.describe({:cip, :path_destination_unknown, []})
      "path destination unknown (general status 0x05)"
      iex> EtherNetIP.describe({:failed, {:connection_failure, :ownership_conflict, []}})
      "the device refused the connection: ownership conflict (extended status 0x0106)"
      iex> EtherNetIP.describe({:connection_failure, :invalid_o_t_connection_size, [38]})
      "the device refused the connection: invalid O->T connection size (extended status 0x0127), it takes 38 bytes, with the sequence count and any run/idle header"
      iex> EtherNetIP.describe({:cip, 0xD0, [1]})
      "general status 0xD0, additional status 0x0001"
      iex> EtherNetIP.describe({:disconnected, :econnrefused})
      "disconnected: connection refused"
      iex> EtherNetIP.describe({:rpi, 10_000, {20_000, nil}})
      "an RPI of 10000 µs is out of the device's range, 20000 to any µs"
  """
  @spec describe(term) :: String.t()
  def describe({:failed, reason}), do: describe(reason)
  def describe({:disconnected, reason}), do: "disconnected: " <> describe(reason)

  def describe({:cip, status, additional}),
    do: named(status, "general status", CIP.status_code(status), 2) <> more(additional)

  @size_errors [
    :invalid_connection_size,
    :invalid_o_t_connection_size,
    :invalid_t_o_connection_size
  ]

  def describe({:connection_failure, extended, additional}) do
    code = ConnectionManager.extended_status_code(extended)

    more =
      case {extended, additional} do
        # The size the device takes may follow (Volume 1, 3-5.5.2), counted as the Forward_Open
        # counts it.
        {size_error, [size]} when size_error in @size_errors ->
          ", it takes #{size} bytes, with the sequence count and any run/idle header"

        _other ->
          more(additional)
      end

    "the device refused the connection: " <> named(extended, "extended status", code, 4) <> more
  end

  def describe({:encapsulation, status}),
    do: "the device refused the message: " <> encapsulation(status)

  def describe({:register_session, status}),
    do: "the device refused the session: " <> encapsulation(status)

  def describe({:udp, :closed}), do: "the UDP endpoint of I/O stopped"
  def describe({:udp, reason}), do: "cannot open the UDP port of I/O: " <> describe(reason)

  def describe({:multicast, group, reason}),
    do: "cannot join multicast group #{:inet.ntoa(group)}: " <> describe(reason)

  def describe({:size, size}), do: "the outputs are #{size} bytes"
  def describe(:timeout), do: "no answer in time"
  def describe(:closed), do: "not connected"
  def describe(:invalid_reply), do: "the device's reply doesn't fit the request"
  def describe(:timed_out), do: "inputs stopped coming"
  def describe(:owner_timed_out), do: "the outputs of the connection that owned them stopped"
  def describe(:orphaned), do: "the last connection that it listened to closed"
  def describe(:reset), do: "the device was reset"
  def describe(:waiting), do: "no inputs yet"
  def describe(:unknown), do: "no such connection"
  def describe(:exists), do: "a connection by that name exists already"

  def describe({:syntax, line, message}), do: "the EDS can't be read, at line #{line}: #{message}"
  def describe(:unknown_connection), do: "the EDS has no such connection"
  def describe({:unknown, {:param, n}}), do: "the EDS has no Param#{n}"
  def describe({:unknown, {:assem, n}}), do: "the EDS has no Assem#{n}"

  def describe({:rpi, rpi, {min, max}}),
    do: "an RPI of #{rpi} µs is out of the device's range, #{min || 0} to #{max || "any"} µs"

  def describe({:unsupported, what}), do: "not supported: " <> inspect(what)

  def describe(reason) when is_atom(reason) do
    case :inet.format_error(reason) do
      ~c"unknown POSIX error" -> words(reason)
      text -> List.to_string(text)
    end
  end

  def describe(reason), do: inspect(reason)

  defp encapsulation(status),
    do: named(status, "encapsulation status", Encapsulation.status_code(status), 4)

  # A status by its name and code, or by its code alone where the spec doesn't name it.
  defp named(name, kind, code, digits) when is_atom(name),
    do: "#{words(name)} (#{kind} 0x#{hex(code, digits)})"

  defp named(_code, kind, code, digits), do: "#{kind} 0x#{hex(code, digits)}"

  defp words(name), do: name |> Atom.to_string() |> String.split("_") |> spell() |> Enum.join(" ")

  defp spell(["o", "t" | rest]), do: ["O->T" | spell(rest)]
  defp spell(["t", "o" | rest]), do: ["T->O" | spell(rest)]
  defp spell(["rpi" | rest]), do: ["RPI" | spell(rest)]
  defp spell([word | rest]), do: [word | spell(rest)]
  defp spell([]), do: []

  defp more([]), do: ""

  defp more(additional),
    do: ", additional status " <> Enum.map_join(additional, " ", &"0x#{hex(&1, 4)}")

  defp hex(code, digits), do: String.pad_leading(Integer.to_string(code, 16), digits, "0")
end
