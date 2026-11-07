defmodule EtherNetIP.Test.Pcap do
  @moduledoc false
  # Writes packets to a pcap of raw IPv4, for tshark to read: each payload in a TCP segment or a
  # UDP datagram of its own, between an originator at 10.0.0.1 and a target at 10.0.0.2. The TCP
  # segments of each direction follow one another in sequence, as one connection.

  @originator {10, 0, 0, 1}
  @target {10, 0, 0, 2}

  # packets: [{:to_target | :to_originator, {:tcp | :udp, port}, payload}]
  def write(path, packets) do
    {records, _seq} =
      packets
      |> Enum.with_index()
      |> Enum.map_reduce(%{to_target: 1, to_originator: 1}, fn {{direction, transport, payload},
                                                                i},
                                                               seq ->
        {packet, seq} = ip(direction, transport, payload, seq)
        size = byte_size(packet)
        {[<<i::little-32, 0::little-32, size::little-32, size::little-32>>, packet], seq}
      end)

    # LINKTYPE_RAW: each packet is an IP packet.
    header =
      <<0xA1B2C3D4::little-32, 2::little-16, 4::little-16, 0::32, 0::32, 65535::little-32,
        101::little-32>>

    File.write!(path, [header | records])
  end

  defp ip(direction, transport, payload, seq) do
    {src, dst} =
      if direction == :to_target, do: {@originator, @target}, else: {@target, @originator}

    {protocol, segment, seq} = segment(direction, transport, payload, seq)
    {a, b, c, d} = src
    {e, f, g, h} = dst

    ip =
      <<0x45, 0, byte_size(segment) + 20::16, 0::16, 0::16, 64, protocol, 0::16, a, b, c, d, e, f,
        g, h, segment::binary>>

    {ip, seq}
  end

  defp segment(direction, {:tcp, port}, payload, seq) do
    {sport, dport} = if direction == :to_target, do: {50000, port}, else: {port, 50000}
    other = if direction == :to_target, do: :to_originator, else: :to_target

    tcp =
      <<sport::16, dport::16, seq[direction]::32, seq[other]::32, 5::4, 0::4, 0x18, 65535::16,
        0::16, 0::16, payload::binary>>

    {6, tcp, Map.update!(seq, direction, &(&1 + byte_size(payload)))}
  end

  defp segment(_direction, {:udp, port}, payload, seq),
    do: {17, <<port::16, port::16, byte_size(payload) + 8::16, 0::16, payload::binary>>, seq}
end
