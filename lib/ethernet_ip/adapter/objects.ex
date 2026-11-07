defmodule EtherNetIP.Adapter.Objects do
  @moduledoc false
  # The objects every EtherNet/IP device has (Volume 2, 6-2) that don't change with its
  # connections: Identity, Message Router, TCP/IP Interface and Ethernet Link, each a function of
  # the service, instance, attribute and data, as the server routes a request to it, giving
  # {status, data}. The TCP/IP Interface and Ethernet Link objects describe the host's interface
  # that a request came in on, as the operating system has it: the adapter can read the host's
  # address, but not set it.

  import Bitwise

  alias EtherNetIP.{CIP, Identity}

  @identity 0x01
  @message_router 0x02
  @assembly 0x04
  @connection_manager 0x06
  @tcp_ip 0xF5
  @ethernet_link 0xF6

  @doc false
  def classes,
    do: [@identity, @message_router, @assembly, @connection_manager, @tcp_ip, @ethernet_link]

  # Each class's revision, class attribute 1: Volume 1, 5-2.1, 5-5.1 and 3-5.1; Volume 2, 5-4.3.1
  # and 5-5.3.1.
  @revisions %{
    @identity => 1,
    @message_router => 1,
    @assembly => 2,
    @connection_manager => 1,
    @tcp_ip => 4,
    @ethernet_link => 4
  }

  @get_attributes_all 0x01
  @get_attribute_single 0x0E
  @set_attribute_single 0x10
  @reset 0x05

  @doc false
  # Class attributes, instance 0: the revision, the largest instance and how many there are.
  def class(class, @get_attribute_single, attribute, instances)
      when is_map_key(@revisions, class) do
    case attribute do
      1 -> {:success, <<@revisions[class]::little-16>>}
      2 -> {:success, <<Enum.max(instances, fn -> 0 end)::little-16>>}
      3 -> {:success, <<length(instances)::little-16>>}
      _other -> {:attribute_not_supported, <<>>}
    end
  end

  def class(_class, _service, _attribute, _instances), do: {:service_not_supported, <<>>}

  ## Identity, Volume 1, 5-2

  @doc false
  def identity(@get_attributes_all, nil, %Identity{} = identity),
    do: {:success, Identity.encode(identity)}

  def identity(@get_attribute_single, attribute, %Identity{} = identity),
    do: identity_attribute(attribute, identity)

  def identity(_service, _attribute, _identity), do: {:service_not_supported, <<>>}

  defp identity_attribute(1, identity), do: {:success, <<identity.vendor_id::little-16>>}
  defp identity_attribute(2, identity), do: {:success, <<identity.device_type::little-16>>}
  defp identity_attribute(3, identity), do: {:success, <<identity.product_code::little-16>>}
  defp identity_attribute(4, %{revision: {major, minor}}), do: {:success, <<major, minor>>}
  defp identity_attribute(5, identity), do: {:success, <<identity.status::little-16>>}
  defp identity_attribute(6, identity), do: {:success, <<identity.serial_number::little-32>>}

  defp identity_attribute(7, identity) do
    name = :unicode.characters_to_binary(identity.product_name, :utf8, :latin1)
    {:success, <<byte_size(name), name::binary>>}
  end

  defp identity_attribute(8, _identity), do: {:success, <<3>>}
  defp identity_attribute(_attribute, _identity), do: {:attribute_not_supported, <<>>}

  @doc false
  # The reset types the adapter can do (Volume 1, Table 5-2.8): 0, as if power had been cycled,
  # the default when none is given; and 1, to the configuration it started with as well.
  def reset_type(<<>>), do: {:ok, 0}
  def reset_type(<<type>>) when type in [0, 1], do: {:ok, type}
  def reset_type(<<_type>>), do: {:error, :invalid_parameter}
  def reset_type(_data), do: {:error, :too_much_data}

  @doc false
  def reset, do: @reset

  ## Message Router, Volume 1, 5-3: the classes it has, and how many connections it takes

  @doc false
  def message_router(@get_attribute_single, 1, _max_connections) do
    classes = for class <- classes(), into: <<>>, do: <<class::little-16>>
    {:success, <<length(classes())::little-16, classes::binary>>}
  end

  def message_router(@get_attribute_single, 2, max_connections),
    do: {:success, <<max_connections::little-16>>}

  def message_router(@get_attribute_single, _attribute, _max),
    do: {:attribute_not_supported, <<>>}

  def message_router(_service, _attribute, _max), do: {:service_not_supported, <<>>}

  ## TCP/IP Interface, Volume 2, 5-4

  @doc false
  # `inactivity` is the Encapsulation Inactivity Timeout in seconds, attribute 13, the only one the
  # adapter lets a client set.
  def tcp_ip(@get_attribute_single, attribute, interface, inactivity),
    do: tcp_ip_attribute(attribute, interface, inactivity)

  def tcp_ip(@set_attribute_single, 13, <<seconds::little-16>>, _inactivity)
      when seconds in 0..3600,
      do: {:set, seconds}

  def tcp_ip(@set_attribute_single, 13, <<_seconds::little-16>>, _inactivity),
    do: {:invalid_attribute_value, <<>>}

  def tcp_ip(@set_attribute_single, 13, data, _inactivity) when byte_size(data) < 2,
    do: {:not_enough_data, <<>>}

  def tcp_ip(@set_attribute_single, 13, _data, _inactivity), do: {:too_much_data, <<>>}

  def tcp_ip(@set_attribute_single, attribute, _data, _inactivity)
      when attribute in [1, 2, 3, 4, 5, 6, 8, 9],
      do: {:attribute_not_settable, <<>>}

  def tcp_ip(@set_attribute_single, _attribute, _data, _inactivity),
    do: {:attribute_not_supported, <<>>}

  def tcp_ip(_service, _attribute, _interface, _inactivity), do: {:service_not_supported, <<>>}

  # Configured, by the host, with no capability to configure it over the network; its link is
  # the Ethernet Link object's instance 1.
  defp tcp_ip_attribute(1, _interface, _inactivity), do: {:success, <<1::little-32>>}
  defp tcp_ip_attribute(2, _interface, _inactivity), do: {:success, <<0::little-32>>}
  defp tcp_ip_attribute(3, _interface, _inactivity), do: {:success, <<0::little-32>>}

  defp tcp_ip_attribute(4, _interface, _inactivity),
    do: {:success, <<2::little-16, 0x20, @ethernet_link, 0x24, 1>>}

  defp tcp_ip_attribute(5, interface, _inactivity), do: {:success, configuration(interface)}
  defp tcp_ip_attribute(6, _interface, _inactivity), do: {:success, string(host_name())}
  defp tcp_ip_attribute(8, _interface, _inactivity), do: {:success, <<1>>}

  defp tcp_ip_attribute(9, interface, _inactivity),
    do: {:success, <<0, 0, 32::little-16, number(multicast_start(interface))::little-32>>}

  defp tcp_ip_attribute(13, _interface, inactivity), do: {:success, <<inactivity::little-16>>}
  defp tcp_ip_attribute(_attribute, _interface, _inactivity), do: {:attribute_not_supported, <<>>}

  # The address and mask; the gateway and name servers aren't known, nor a domain name.
  defp configuration(interface) do
    <<number(interface.address)::little-32, number(interface.netmask)::little-32, 0::32, 0::32,
      0::32, string("")::binary>>
  end

  # A STRING: its length, and its characters padded to an even number of them.
  defp string(text) do
    pad = if rem(byte_size(text), 2) == 1, do: <<0>>, else: <<>>
    <<byte_size(text)::little-16, text::binary, pad::binary>>
  end

  # 64 characters at most.
  defp host_name do
    {:ok, name} = :inet.gethostname()
    binary_part(List.to_string(name), 0, min(length(name), 64))
  end

  @doc false
  # The first of the 32 multicast addresses of the device (Volume 2, 3-5.3), from the host id of
  # its address: the low 10 bits of it, less one, in blocks from 239.192.1.0. Without a mask, the
  # class of the address gives one.
  def multicast_start(%{address: address, netmask: netmask}) do
    mask = number(netmask || class_mask(address))
    host = band(number(address), bnot(mask) &&& 0xFFFF_FFFF)
    index = band(host - 1, 0x3FF)
    address(0xEFC0_0100 + index * 32)
  end

  @doc false
  # The `n`th multicast address of the device, of its 32.
  def multicast_address(interface, n),
    do: address(number(multicast_start(interface)) + rem(n, 32))

  defp class_mask({a, _, _, _}) when a < 128, do: {255, 0, 0, 0}
  defp class_mask({a, _, _, _}) when a < 192, do: {255, 255, 0, 0}
  defp class_mask(_address), do: {255, 255, 255, 0}

  defp number({a, b, c, d}), do: (a <<< 24) + (b <<< 16) + (c <<< 8) + d
  defp number(nil), do: 0

  defp address(n), do: {n >>> 24 &&& 0xFF, n >>> 16 &&& 0xFF, n >>> 8 &&& 0xFF, n &&& 0xFF}

  ## Ethernet Link, Volume 2, 5-5

  @doc false
  def ethernet_link(@get_attribute_single, attribute, interface) do
    case attribute do
      1 -> {:success, <<interface.speed::little-32>>}
      2 -> {:success, <<link_flags(interface)::little-32>>}
      3 -> {:success, interface.hwaddr}
      _other -> {:attribute_not_supported, <<>>}
    end
  end

  def ethernet_link(@get_attributes_all, nil, interface),
    do:
      {:success,
       <<interface.speed::little-32, link_flags(interface)::little-32, interface.hwaddr::binary>>}

  def ethernet_link(_service, _attribute, _interface), do: {:service_not_supported, <<>>}

  # Link up, full duplex, and the speed and duplex negotiated, as far as the host tells.
  defp link_flags(interface) do
    up = if interface.running, do: 1, else: 0
    full = if interface.duplex == :full, do: 2, else: 0
    negotiated = if interface.duplex, do: 3 <<< 2, else: 0
    up + full + negotiated
  end

  @doc false
  # The host's interface with this address, or one of no name, speed or duplex when none has it.
  # Only its own link is read, as the adapter's process waits for it.
  def interface(address) do
    interfaces =
      case :inet.getifaddrs() do
        {:ok, interfaces} -> Enum.flat_map(interfaces, &ipv4/1)
        {:error, _reason} -> []
      end

    case Enum.find(interfaces, &(&1.address == address)) do
      nil ->
        %{
          name: nil,
          address: address,
          netmask: nil,
          hwaddr: <<0::48>>,
          running: true,
          speed: 0,
          duplex: nil
        }

      interface ->
        {speed, duplex} = link(interface.name)
        Map.merge(interface, %{speed: speed, duplex: duplex})
    end
  end

  # An interface's IPv4 addresses, each with the mask that follows it.
  defp ipv4({name, opts}) do
    flags = Keyword.get(opts, :flags, [])

    hwaddr =
      case opts[:hwaddr] do
        [_, _, _, _, _, _] = bytes -> :binary.list_to_bin(bytes)
        _none -> <<0::48>>
      end

    opts
    |> Enum.chunk_every(2, 1, [nil])
    |> Enum.flat_map(fn
      [{:addr, {_, _, _, _} = address}, next] ->
        netmask = with {:netmask, mask} <- next, do: mask

        [
          %{
            name: List.to_string(name),
            address: address,
            netmask: if(is_tuple(netmask), do: netmask),
            hwaddr: hwaddr,
            running: :running in flags
          }
        ]

      _other ->
        []
    end)
  end

  # The speed in Mbps and the duplex, where the host says, as Linux does in /sys; other hosts
  # aren't asked, as a file read may take long.
  defp link(name) do
    case :os.type() do
      {:unix, :linux} -> linux_link(name)
      _other -> {0, nil}
    end
  end

  defp linux_link(name) do
    speed =
      case File.read("/sys/class/net/#{name}/speed") do
        {:ok, text} ->
          case Integer.parse(String.trim(text)) do
            {mbps, ""} when mbps > 0 -> mbps
            _unknown -> 0
          end

        {:error, _reason} ->
          0
      end

    duplex =
      case File.read("/sys/class/net/#{name}/duplex") do
        {:ok, "full" <> _} -> :full
        {:ok, "half" <> _} -> :half
        _unknown -> nil
      end

    {speed, duplex}
  end

  @doc false
  # A reply to a request routed to one of these objects.
  def reply(service, {status, data}), do: CIP.reply(service, status, [], data)
end
