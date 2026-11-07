defmodule EtherNetIP.TsharkTest do
  # Messages this library encodes, decoded by Wireshark's ENIP and CIP dissectors, decoders
  # written independently of this one, field by field.
  use ExUnit.Case, async: true

  alias EtherNetIP.{CIP, ConnectionManager, CPF, Encapsulation, Identity, IOPacket}
  alias EtherNetIP.Test.{Generators, Pcap}

  @moduletag :tshark
  @moduletag :tmp_dir

  @fields ~w(enip.command enip.length enip.session enip.status enip.context enip.options
             enip.cpf.itemcount enip.cpf.typeid enip.cpf.length enip.cpf.sai.connid
             enip.cpf.sai.seq enip.lir.vendor enip.lir.devtype enip.lir.prodcode
             enip.lir.revision enip.lir.status enip.lir.serial enip.lir.name enip.lir.state
             enip.sinaddr enip.sinport cip.sc cip.genstat cip.addstat cip.class cip.instance
             cip.attribute cip.cm.tick_time cip.cm.timeout_tick cip.cm.ot_connid
             cip.cm.to_connid cip.cm.conn_serial_num cip.cm.vendor cip.cm.orig_serial_num
             cip.cm.timeout_multiplier cip.cm.otrpi cip.cm.torpi cip.cm.fwo.consize
             cip.cm.fwo.f_v cip.cm.fwo.prio cip.cm.fwo.type cip.cm.fwo.owner
             cip.cm.transport_type_trigger cip.cm.connpath_size cip.cm.otapi cip.cm.toapi
             cip.cm.app_reply_size cip.cm.msg_req_size cip.cm.route_path_size)

  test "Wireshark reads requests to objects as they were meant", %{tmp_dir: dir} do
    cases =
      for {path, context, session} <-
            Enum.take(
              StreamData.tuple(
                {Generators.object_path(), StreamData.binary(length: 8), Generators.u32()}
              ),
              200
            ) do
        service = if path[:attribute], do: :get_attribute_single, else: :get_attributes_all
        request = CIP.request(service, path)

        expected = %{
          "enip.command" => [0x6F],
          "enip.length" => [6 + 2 + 4 + 4 + byte_size(request)],
          "enip.session" => [session],
          "enip.status" => [0],
          "enip.context" => [Base.encode16(context, case: :lower)],
          "enip.options" => [0],
          "enip.cpf.itemcount" => [2],
          "enip.cpf.typeid" => [0x0000, 0x00B2],
          "enip.cpf.length" => [0, byte_size(request)],
          "cip.sc" => [CIP.service(service)],
          "cip.class" => [path[:class]],
          "cip.instance" => [path[:instance]],
          "cip.attribute" => List.wrap(path[:attribute])
        }

        {[{:to_target, {:tcp, 44818}, send_rr_data(session, context, request)}], [expected]}
      end

    check(dir, cases)
  end

  test "Wireshark reads Forward_Opens and their replies as they were meant", %{tmp_dir: dir} do
    cases =
      for {request, i} <- Enum.with_index(Enum.take(Generators.forward_open(), 200)) do
        service = if request.large, do: :large_forward_open, else: :forward_open
        code = ConnectionManager.service(service)
        data = ConnectionManager.encode_forward_open(request)
        cip = CIP.request(code, ConnectionManager.path(), data)
        {tick, ticks} = ConnectionManager.timing(request.timeout)
        context = <<i::64>>

        reply =
          ConnectionManager.encode_forward_open_reply(%{
            o_t_id: request.o_t_id,
            t_o_id: request.t_o_id,
            serial: request.serial,
            vendor_id: request.vendor_id,
            originator_serial: request.originator_serial,
            o_t_api: request.o_t.rpi,
            t_o_api: request.t_o.rpi
          })

        # Wireshark reads the direction parameters of a Forward_Open, of 16 bits, field by field.
        parameters =
          if request.large,
            do: %{},
            else: %{
              "cip.cm.fwo.consize" => [request.o_t.size, request.t_o.size],
              "cip.cm.fwo.f_v" => [flag(!request.o_t.fixed), flag(!request.t_o.fixed)],
              "cip.cm.fwo.prio" => [prio(request.o_t), prio(request.t_o)],
              "cip.cm.fwo.type" => [type(request.o_t), type(request.t_o)],
              "cip.cm.fwo.owner" => [
                flag(request.o_t.redundant_owner),
                flag(request.t_o.redundant_owner)
              ]
            }

        sent =
          Map.merge(parameters, %{
            "cip.sc" => [code],
            "cip.cm.tick_time" => [tick],
            "cip.cm.timeout_tick" => [ticks],
            "cip.cm.ot_connid" => [request.o_t_id],
            "cip.cm.to_connid" => [request.t_o_id],
            "cip.cm.conn_serial_num" => [request.serial],
            "cip.cm.vendor" => [request.vendor_id],
            "cip.cm.orig_serial_num" => [request.originator_serial],
            "cip.cm.timeout_multiplier" => [multiplier(request.multiplier)],
            "cip.cm.otrpi" => [request.o_t.rpi],
            "cip.cm.torpi" => [request.t_o.rpi],
            "cip.cm.transport_type_trigger" => [trigger(request.trigger)],
            "cip.cm.connpath_size" => [div(byte_size(EtherNetIP.Path.encode(request.path)), 2)]
          })

        answered = %{
          "cip.sc" => [code],
          "cip.genstat" => [0],
          "cip.cm.ot_connid" => [request.o_t_id],
          "cip.cm.to_connid" => [request.t_o_id],
          "cip.cm.otapi" => [request.o_t.rpi],
          "cip.cm.toapi" => [request.t_o.rpi],
          "cip.cm.app_reply_size" => [0]
        }

        packets = [
          {:to_target, {:tcp, 44818}, send_rr_data(1, context, cip)},
          {:to_originator, {:tcp, 44818},
           send_rr_data(1, context, CIP.reply(code, :success, [], reply))}
        ]

        {packets, [sent, answered]}
      end

    check(dir, cases)
  end

  test "Wireshark reads Unconnected_Sends and error replies as they were meant", %{tmp_dir: dir} do
    cases =
      for {{path, route, timeout, status, additional}, i} <-
            Enum.with_index(
              Enum.take(
                StreamData.tuple(
                  {Generators.object_path(),
                   StreamData.list_of(Generators.port_segment(), min_length: 1, max_length: 3),
                   StreamData.integer(1..8_355_840), StreamData.integer(1..0x2B),
                   StreamData.list_of(Generators.u16(), max_length: 4)}
                ),
                200
              )
            ) do
        embedded = CIP.request(:get_attributes_all, path)
        data = ConnectionManager.encode_unconnected_send(embedded, route, timeout)
        code = ConnectionManager.service(:unconnected_send)
        {tick, ticks} = ConnectionManager.timing(timeout)
        context = <<i::64>>
        reply = CIP.reply(:get_attributes_all, status, additional)

        sent = %{
          "cip.sc" => [code, CIP.service(:get_attributes_all)],
          "cip.cm.tick_time" => [tick],
          "cip.cm.timeout_tick" => [ticks],
          "cip.cm.msg_req_size" => [byte_size(embedded)],
          "cip.cm.route_path_size" => [div(byte_size(EtherNetIP.Path.encode(route)), 2)]
        }

        answered = %{
          "cip.genstat" => [status],
          "cip.addstat" => additional
        }

        packets = [
          {:to_target, {:tcp, 44818},
           send_rr_data(1, context, CIP.request(code, ConnectionManager.path(), data))},
          {:to_originator, {:tcp, 44818}, send_rr_data(1, context, reply)}
        ]

        {packets, [sent, answered]}
      end

    check(dir, cases)
  end

  test "Wireshark reads ListIdentity replies as they were meant", %{tmp_dir: dir} do
    cases =
      for {identity, address, port} <-
            Enum.take(
              StreamData.tuple(
                {Generators.identity(), StreamData.list_of(Generators.u8(), length: 4),
                 Generators.u16()}
              ),
              200
            ) do
        address = List.to_tuple(address)
        item = Identity.encode_list_identity(identity, {address, port})
        data = CPF.encode([{:identity, item}])
        {major, minor} = identity.revision

        expected = %{
          "enip.command" => [0x63],
          "enip.length" => [byte_size(data)],
          "enip.cpf.itemcount" => [1],
          "enip.cpf.typeid" => [0x0C],
          "enip.lir.vendor" => [identity.vendor_id],
          "enip.lir.devtype" => [identity.device_type],
          "enip.lir.prodcode" => [identity.product_code],
          "enip.lir.revision" => [major * 256 + minor],
          "enip.lir.status" => [identity.status],
          "enip.lir.serial" => [identity.serial_number],
          # tshark gives no field at all for an empty name.
          "enip.lir.name" => Enum.reject([identity.product_name], &(&1 == "")),
          # The state is the last byte.
          "enip.lir.state" => [:binary.last(Identity.encode(identity))],
          "enip.sinaddr" => [:inet.ntoa(address) |> to_string()],
          "enip.sinport" => [port]
        }

        message = %Encapsulation{command: :list_identity, data: data}
        {[{:to_originator, {:udp, 44818}, Encapsulation.encode(message)}], [expected]}
      end

    check(dir, cases)
  end

  test "Wireshark reads I/O packets as they were meant", %{tmp_dir: dir} do
    cases =
      for {id, sequence, count, data} <-
            Enum.take(
              StreamData.tuple(
                {Generators.u32(), Generators.u32(), Generators.u16(),
                 StreamData.binary(max_length: 100)}
              ),
              200
            ) do
        packet = IOPacket.encode_class1(count, :modeless, true, data)

        expected = %{
          "enip.cpf.itemcount" => [2],
          "enip.cpf.typeid" => [0x8002, 0x00B1],
          "enip.cpf.length" => [8, byte_size(packet)],
          "enip.cpf.sai.connid" => [id],
          "enip.cpf.sai.seq" => [sequence]
        }

        {[{:to_target, {:udp, 2222}, IOPacket.encode(id, sequence, packet)}], [expected]}
      end

    check(dir, cases)
  end

  # The fields of the objects' attributes, in the replies of a live adapter, which Wireshark reads
  # by the requests before them.
  @object_fields ~w(cip.sc cip.genstat cip.id.vendor_id cip.id.device_type cip.id.product_code
                    cip.id.major_rev cip.id.minor_rev cip.id.serial_number cip.id.product_name
                    cip.id.state cip.tcpip.ip_addr cip.tcpip.subnet_mask cip.tcpip.hostname
                    cip.tcpip.mcast.num_mcast cip.tcpip.mcast.addr_start
                    cip.tcpip.encap_inactivity cip.tcpip.ttl_value cip.elink.interface_speed)

  test "Wireshark reads the adapter's replies as they were meant", %{tmp_dir: dir} do
    identity = [
      vendor_id: 0x1234,
      device_type: 0x0C,
      product_code: 77,
      revision: {3, 9},
      serial_number: 0xABCD_EF01,
      product_name: "Adapter"
    ]

    adapter =
      start_supervised!({EtherNetIP.Adapter, port: 0, discovery: false, identity: identity})

    {:ok, socket} =
      :gen_tcp.connect({127, 0, 0, 1}, EtherNetIP.Adapter.port(adapter), [:binary, active: false])

    register = %Encapsulation{command: :register_session, data: Encapsulation.register_session()}
    :ok = :gen_tcp.send(socket, Encapsulation.encode(register))
    {:ok, frame} = :gen_tcp.recv(socket, 28, 1000)
    {:ok, %{session: session}, ""} = Encapsulation.decode(frame)
    {:ok, hostname} = :inet.gethostname()

    requests = [
      {CIP.request(:get_attributes_all, class: 1, instance: 1),
       %{
         "cip.id.vendor_id" => [0x1234],
         "cip.id.device_type" => [0x0C],
         "cip.id.product_code" => [77],
         "cip.id.major_rev" => [3],
         "cip.id.minor_rev" => [9],
         "cip.id.serial_number" => [0xABCD_EF01],
         "cip.id.product_name" => ["Adapter"]
       }},
      {CIP.request(:get_attribute_single, class: 0xF5, instance: 1, attribute: 5),
       %{"cip.tcpip.ip_addr" => ["127.0.0.1"], "cip.tcpip.subnet_mask" => ["255.0.0.0"]}},
      {CIP.request(:get_attribute_single, class: 0xF5, instance: 1, attribute: 6),
       %{"cip.tcpip.hostname" => [to_string(hostname)]}},
      {CIP.request(:get_attribute_single, class: 0xF5, instance: 1, attribute: 8),
       %{"cip.tcpip.ttl_value" => [1]}},
      {CIP.request(:get_attribute_single, class: 0xF5, instance: 1, attribute: 9),
       %{"cip.tcpip.mcast.num_mcast" => [32], "cip.tcpip.mcast.addr_start" => ["239.192.1.0"]}},
      {CIP.request(:get_attribute_single, class: 0xF5, instance: 1, attribute: 13),
       %{"cip.tcpip.encap_inactivity" => [120]}}
    ]

    cases =
      for {{request, fields}, i} <- Enum.with_index(requests) do
        context = <<i::64>>
        sent = send_rr_data(session, context, request)
        :ok = :gen_tcp.send(socket, sent)
        {:ok, <<_::16, length::little-16, _::binary>> = header} = :gen_tcp.recv(socket, 24, 1000)
        {:ok, data} = :gen_tcp.recv(socket, length, 1000)
        <<service, _rest::binary>> = request

        packets = [
          {:to_target, {:tcp, 44818}, sent},
          {:to_originator, {:tcp, 44818}, header <> data}
        ]

        {packets, [%{"cip.sc" => [service]}, Map.merge(%{"cip.genstat" => [0]}, fields)]}
      end

    check(dir, cases, @object_fields)
  end

  defp send_rr_data(session, context, request) do
    Encapsulation.encode(%Encapsulation{
      command: :send_rr_data,
      session: session,
      context: context,
      data: Encapsulation.rr_data([:null_address, {:unconnected_data, request}])
    })
  end

  defp flag(true), do: 1
  defp flag(false), do: 0

  defp prio(direction),
    do: Enum.find_index([:low, :high, :scheduled, :urgent], &(&1 == direction.priority))

  defp type(direction),
    do: Enum.find_index([:null, :multicast, :point_to_point], &(&1 == direction.type))

  defp multiplier(multiplier), do: round(:math.log2(multiplier)) - 2

  defp trigger({direction, trigger, class}) do
    if(direction == :server, do: 0x80, else: 0) +
      Enum.find_index([:cyclic, :change_of_state, :application], &(&1 == trigger)) * 16 + class
  end

  # cases: [{packets, expected}], an expected map of fields for each packet; only the fields it
  # names are compared.
  defp check(dir, cases, fields \\ @fields) do
    packets = Enum.flat_map(cases, &elem(&1, 0))
    expected = Enum.flat_map(cases, &elem(&1, 1))
    path = Path.join(dir, "messages.pcap")
    Pcap.write(path, packets)

    lines = tshark(path, fields)
    assert length(lines) == length(expected)

    for {line, expected, frame} <- Enum.zip([lines, expected, 1..length(expected)]) do
      seen = Map.new(Enum.zip(fields, String.split(line, "|")))

      for {field, values} <- expected do
        assert {frame, field, parse(seen[field], values)} == {frame, field, values}
      end
    end
  end

  defp parse(value, [expected | _]) when is_binary(expected),
    do: String.split(value, ",", trim: true)

  defp parse(value, _expected), do: value |> String.split(",", trim: true) |> Enum.map(&integer/1)

  defp integer("0x" <> hex), do: String.to_integer(hex, 16)

  defp integer(value) do
    case Integer.parse(value) do
      {integer, ""} -> integer
      _hex -> String.to_integer(value, 16)
    end
  end

  defp tshark(path, fields) do
    tshark =
      Enum.find(
        [
          System.get_env("TSHARK"),
          System.find_executable("tshark"),
          "/Applications/Wireshark.app/Contents/MacOS/tshark"
        ],
        &(&1 != nil and File.exists?(&1))
      )

    args =
      ["-r", "-", "-T", "fields", "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"] ++
        Enum.flat_map(fields, &["-e", &1])

    # Through a pipe, as tshark has been refused the file itself on a CI runner, where `cat` reads
    # it: tshark is $0, the file $1, and its arguments the rest.
    script = ~s(tshark="$0"; pcap="$1"; shift; cat "$pcap" | "$tshark" "$@")
    {output, 0} = System.cmd("sh", ["-c", script, tshark, path | args])
    String.split(output, "\n", trim: true)
  end
end
