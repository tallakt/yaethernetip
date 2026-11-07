defmodule EtherNetIP.AdapterTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias EtherNetIP.{
    Adapter,
    CIP,
    ConnectionManager,
    CPF,
    Encapsulation,
    Identity,
    IOPacket,
    Scanner
  }

  alias EtherNetIP.Test.Generators

  # FUZZ_RUNS sets how many cases each property runs, as in the property tests.
  @runs String.to_integer(System.get_env("FUZZ_RUNS", "300"))

  # An adapter of its own on a free port, with a UDP port of I/O of its own, which the test's
  # scanners share with it.
  setup do
    {:ok, probe} = :gen_udp.open(0)
    {:ok, udp_port} = :inet.port(probe)
    :gen_udp.close(probe)
    %{udp_port: udp_port}
  end

  @assemblies [
    inputs: %{100 => 4},
    outputs: %{150 => 4},
    configuration: %{151 => 2},
    input_only: 152,
    listen_only: 153
  ]

  defp adapter(ctx, opts \\ []) do
    opts =
      [port: 0, udp_port: ctx.udp_port, discovery: false, subscriber: self()]
      |> Keyword.merge(@assemblies)
      |> Keyword.merge(opts)

    adapter =
      start_supervised!(
        Supervisor.child_spec({Adapter, opts}, id: make_ref(), restart: :temporary)
      )

    {adapter, Adapter.port(adapter)}
  end

  defp scanner(ctx, port, connections, opts \\ []) do
    opts =
      [host: "127.0.0.1", port: port, udp_port: ctx.udp_port, connections: connections] ++ opts

    start_supervised!(Supervisor.child_spec({Scanner, opts}, id: make_ref(), restart: :temporary))
  end

  @owner [config: 151, output: 150, input: 100, output_size: 4, input_size: 4, rpi: 20_000]
  @input_only [
    output: 152,
    input: 100,
    output_size: 0,
    input_size: 4,
    output_format: :heartbeat,
    rpi: 20_000
  ]
  @listen_only Keyword.put(@input_only, :output, 153)

  defp with_subscriber(connection, more \\ []),
    do: Keyword.merge(connection, [subscriber: self()] ++ more)

  defp await_inputs(name, inputs, timeout \\ 2_000) do
    receive do
      {Scanner, ^name, {:inputs, ^inputs}} -> :ok
      {Scanner, ^name, {:inputs, _other}} -> await_inputs(name, inputs, timeout)
    after
      timeout -> flunk("#{name} never had inputs #{inspect(inputs)}")
    end
  end

  describe "explicit messages" do
    test "the Identity object, with the status of its connections", ctx do
      {_adapter, port} =
        adapter(ctx,
          identity: [
            vendor_id: 0x1234,
            device_type: 0x2B,
            product_code: 7,
            revision: {2, 5},
            serial_number: 0xCAFE,
            product_name: "Pump skid"
          ]
        )

      scanner = scanner(ctx, port, [])

      assert Scanner.identity(scanner) ==
               {:ok,
                %Identity{
                  vendor_id: 0x1234,
                  device_type: 0x2B,
                  product_code: 7,
                  revision: {2, 5},
                  # no I/O connections
                  status: 0x30,
                  serial_number: 0xCAFE,
                  product_name: "Pump skid",
                  state: :operational
                }}

      assert Scanner.get_attribute_single(scanner, 1, 1, 7) == {:ok, <<9, "Pump skid">>}
      assert Scanner.get_attribute_single(scanner, 1, 0, 1) == {:ok, <<1, 0>>}

      assert Scanner.get_attribute_single(scanner, 1, 1, 99) ==
               {:error, {:cip, :attribute_not_supported, []}}

      assert Scanner.get_attribute_single(scanner, 0x99, 1, 1) ==
               {:error, {:cip, :path_destination_unknown, []}}

      assert Scanner.get_attribute_single(scanner, 1, 2, 1) ==
               {:error, {:cip, :path_destination_unknown, []}}
    end

    test "the Message Router's classes, and several requests in one", ctx do
      {_adapter, port} = adapter(ctx)
      scanner = scanner(ctx, port, [])

      assert Scanner.get_attribute_single(scanner, 2, 1, 1) ==
               {:ok,
                <<6::little-16, 1::little-16, 2::little-16, 4::little-16, 6::little-16,
                  0xF5::little-16, 0xF6::little-16>>}

      requests = [
        CIP.request(:get_attribute_single, class: 1, instance: 1, attribute: 1),
        CIP.request(:get_attribute_single, class: 1, instance: 1, attribute: 99)
      ]

      offsets = [6, 6 + byte_size(hd(requests))]
      data = [<<2::little-16>>, for(o <- offsets, do: <<o::little-16>>), requests]

      assert {:error, {:cip, :embedded_service_error, []}} =
               Scanner.request(scanner, :multiple_service_packet, [class: 2, instance: 1], data)

      # the replies, at offsets from the count
      {:ok, reply} =
        Scanner.request(scanner, :multiple_service_packet, [class: 2, instance: 1], [
          <<1::little-16, 4::little-16>>,
          hd(requests)
        ])

      assert reply == <<1::little-16, 4::little-16, 0x8E, 0, 0, 0, 0xFF, 0xFF>>
    end

    test "the TCP/IP Interface object, of the interface the request came in on", ctx do
      {_adapter, port} = adapter(ctx)
      scanner = scanner(ctx, port, [])

      {:ok, <<address::little-32, _mask::little-32, _rest::binary>>} =
        Scanner.get_attribute_single(scanner, 0xF5, 1, 5)

      assert address == 0x7F00_0001

      assert Scanner.get_attribute_single(scanner, 0xF5, 1, 4) ==
               {:ok, <<2, 0, 0x20, 0xF6, 0x24, 1>>}

      # its multicast addresses, from the host id, 1 (Volume 2, 3-5.3)
      assert Scanner.get_attribute_single(scanner, 0xF5, 1, 9) ==
               {:ok, <<0, 0, 32::little-16, 0xEFC0_0100::little-32>>}

      assert Scanner.get_attribute_single(scanner, 0xF5, 1, 13) == {:ok, <<120::little-16>>}
      assert Scanner.set_attribute_single(scanner, 0xF5, 1, 13, <<30::little-16>>) == :ok
      assert Scanner.get_attribute_single(scanner, 0xF5, 1, 13) == {:ok, <<30::little-16>>}

      assert Scanner.set_attribute_single(scanner, 0xF5, 1, 13, <<3601::little-16>>) ==
               {:error, {:cip, :invalid_attribute_value, []}}

      assert Scanner.set_attribute_single(scanner, 0xF5, 1, 5, <<0::160>>) ==
               {:error, {:cip, :attribute_not_settable, []}}

      assert {:ok, <<_speed::32, _flags::32, _mac::binary-6>>} =
               Scanner.get_attributes_all(scanner, 0xF6, 1)
    end

    test "assemblies: inputs as put, and outputs and configuration set while unconnected", ctx do
      {adapter, port} = adapter(ctx)
      scanner = scanner(ctx, port, [])

      :ok = Adapter.put(adapter, 100, <<1, 2, 3, 4>>)
      assert Adapter.put(adapter, 100, <<1>>) == {:error, {:size, 4}}
      assert Adapter.put(adapter, 150, <<1, 2, 3, 4>>) == {:error, :unknown}
      assert Scanner.get_attribute_single(scanner, 4, 100, 3) == {:ok, <<1, 2, 3, 4>>}
      assert Scanner.get_attribute_single(scanner, 4, 100, 4) == {:ok, <<4, 0>>}

      assert Scanner.set_attribute_single(scanner, 4, 100, 3, <<0, 0, 0, 0>>) ==
               {:error, {:cip, :attribute_not_settable, []}}

      assert Scanner.set_attribute_single(scanner, 4, 150, 3, <<5, 6, 7>>) ==
               {:error, {:cip, :not_enough_data, []}}

      :ok = Scanner.set_attribute_single(scanner, 4, 150, 3, <<5, 6, 7, 8>>)
      assert_receive {Adapter, {:outputs, 150, <<5, 6, 7, 8>>}}
      assert {:ok, %{data: <<5, 6, 7, 8>>, state: :closed}} = Adapter.outputs(adapter, 150)

      :ok = Scanner.set_attribute_single(scanner, 4, 151, 3, <<9, 9>>)
      assert_receive {Adapter, {:configuration, 151, <<9, 9>>}}
      assert Adapter.get(adapter, 151) == {:ok, <<9, 9>>}
    end

    test "an Unconnected_Send with no route is for the adapter itself", ctx do
      {_adapter, port} = adapter(ctx)
      scanner = scanner(ctx, port, [])
      request = CIP.request(:get_attribute_single, class: 1, instance: 1, attribute: 1)
      data = ConnectionManager.encode_unconnected_send(request, <<>>, 1000)

      assert Scanner.request(scanner, 0x52, ConnectionManager.path(), data) ==
               {:ok, <<0xFF, 0xFF>>}

      assert Scanner.get_attribute_single(scanner, 1, 1, 1, route: [{:port, 1, 0}]) ==
               {:error, {:cip, :connection_failure, [0x0311]}}

      # a request of an odd size with nothing after it, not even its pad byte
      assert Scanner.request(scanner, 0x52, ConnectionManager.path(), <<0, 0, 1, 0, 0x0E>>) ==
               {:error, {:cip, :not_enough_data, []}}

      assert Scanner.get_attribute_single(scanner, 1, 1, 1) == {:ok, <<0xFF, 0xFF>>}
    end

    test "Reset closes every connection and session", ctx do
      {_adapter, port} = adapter(ctx)

      scanner =
        scanner(ctx, port, [rack: with_subscriber(@owner)], backoff: {50, 50})

      assert_receive {Scanner, :rack, {:status, :open}}, 1000

      assert Scanner.request(scanner, 0x05, [class: 1, instance: 1], <<9>>) ==
               {:error, {:cip, :invalid_parameter, []}}

      assert Scanner.request(scanner, 0x05, class: 1, instance: 1) == {:ok, ""}
      assert_receive {Adapter, {:reset, 0}}
      assert_receive {Adapter, {:closed, %{kind: :exclusive_owner}, :reset}}

      # the scanner connects again, and opens its connection again
      assert_receive {Adapter, {:opened, %{kind: :exclusive_owner}}}, 2000
    end
  end

  describe "the encapsulation layer" do
    defp client(port) do
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      socket
    end

    defp exchange(socket, message) do
      :ok = :gen_tcp.send(socket, Encapsulation.encode(message))
      receive_message(socket)
    end

    defp receive_message(socket, timeout \\ 1000) do
      with {:ok, header} <- :gen_tcp.recv(socket, 24, timeout),
           <<_::16, length::little-16, _::binary>> = header,
           {:ok, data} <-
             if(length == 0, do: {:ok, ""}, else: :gen_tcp.recv(socket, length, timeout)) do
        {:ok, message, ""} = Encapsulation.decode(header <> data)
        message
      end
    end

    defp register(socket) do
      reply =
        exchange(socket, %Encapsulation{
          command: :register_session,
          data: Encapsulation.register_session()
        })

      assert reply.status == :success and reply.session != 0
      reply.session
    end

    test "sessions: one on a connection, of version 1, and requests only in it", ctx do
      {_adapter, port} = adapter(ctx)
      socket = client(port)
      request = Encapsulation.rr_data([:null_address, {:unconnected_data, <<0x0E, 0>>}])

      assert %{status: :invalid_session_handle} =
               exchange(socket, %Encapsulation{command: :send_rr_data, data: request})

      reply =
        exchange(socket, %Encapsulation{
          command: :register_session,
          data: Encapsulation.register_session(2)
        })

      assert {reply.status, reply.data} == {:unsupported_protocol_version, <<1, 0, 0, 0>>}

      session = register(socket)

      assert %{status: :invalid_command} =
               exchange(socket, %Encapsulation{
                 command: :register_session,
                 session: session,
                 data: Encapsulation.register_session()
               })

      # an unknown command is refused, and the session goes on
      assert %{status: :invalid_command, command: 0x0002} =
               exchange(socket, %Encapsulation{command: 0x0002, session: session})

      assert %{status: :success} =
               exchange(socket, %Encapsulation{
                 command: :send_rr_data,
                 session: session,
                 data: request
               })

      # a request with a status gets no answer
      :ok =
        :gen_tcp.send(
          socket,
          Encapsulation.encode(%Encapsulation{command: :list_services, status: :invalid_length})
        )

      assert receive_message(socket, 200) == {:error, :timeout}

      :ok =
        :gen_tcp.send(socket, Encapsulation.encode(%Encapsulation{command: :unregister_session}))

      assert :gen_tcp.recv(socket, 0, 1000) == {:error, :closed}
    end

    test "ListIdentity and ListServices, over TCP and UDP", ctx do
      {_adapter, port} = adapter(ctx, discovery: true, identity: [product_name: "Found"])
      socket = client(port)

      reply = exchange(socket, %Encapsulation{command: :list_identity})
      {:ok, [{:identity, item}]} = CPF.decode(reply.data)
      {:ok, identity} = Identity.decode_list_identity(item)
      assert identity.product_name == "Found"
      assert identity.address == {{127, 0, 0, 1}, port}

      reply = exchange(socket, %Encapsulation{command: :list_services})
      {:ok, [{:service, service}]} = CPF.decode(reply.data)

      assert CPF.decode_service(service) ==
               {:ok, %{version: 1, flags: 0x0120, name: "Communications"}}

      {:ok, udp} = :gen_udp.open(0, [:binary, active: false])
      context = Encapsulation.list_identity_context(1)
      message = %Encapsulation{command: :list_identity, context: context}
      :ok = :gen_udp.send(udp, {127, 0, 0, 1}, port, Encapsulation.encode(message))
      {:ok, {_address, ^port, packet}} = :gen_udp.recv(udp, 0, 1000)
      {:ok, reply, ""} = Encapsulation.decode(packet)
      assert reply.context == context
      {:ok, [{:identity, item}]} = CPF.decode(reply.data)
      assert {:ok, %Identity{product_name: "Found"}} = Identity.decode_list_identity(item)
    end

    test "a full adapter makes room by closing the client longest silent", ctx do
      {_adapter, port} = adapter(ctx, sessions: 2)
      first = client(port)
      register(first)
      second = client(port)
      register(second)
      third = client(port)
      register(third)

      assert :gen_tcp.recv(first, 0, 1000) == {:error, :closed}
      assert %{status: :success} = exchange(second, %Encapsulation{command: :list_services})
    end

    test "a client is closed after the inactivity timeout", ctx do
      {_adapter, port} = adapter(ctx, inactivity: 1)
      socket = client(port)
      register(socket)
      assert :gen_tcp.recv(socket, 0, 3000) == {:error, :closed}
    end

    test "bytes that make no whole message don't keep a client", ctx do
      {_adapter, port} = adapter(ctx, inactivity: 1)
      socket = client(port)
      register(socket)

      # a header begun, a byte every 200 ms for 4 s
      spawn_link(fn ->
        for _byte <- 1..20 do
          Process.sleep(200)
          :gen_tcp.send(socket, <<0>>)
        end
      end)

      assert :gen_tcp.recv(socket, 0, 2500) == {:error, :closed}
    end

    test "hosts that may not connect get no answer over UDP either", ctx do
      {_adapter, port} = adapter(ctx, discovery: true, allow: [{10, 0, 0, 1}])
      {:ok, udp} = :gen_udp.open(0, [:binary, active: false])
      message = Encapsulation.encode(%Encapsulation{command: :list_services})
      :ok = :gen_udp.send(udp, {127, 0, 0, 1}, port, message)
      assert :gen_udp.recv(udp, 0, 300) == {:error, :timeout}

      {_adapter, port} = adapter(ctx, discovery: true, allow: [{{127, 0, 0, 0}, 8}])
      :ok = :gen_udp.send(udp, {127, 0, 0, 1}, port, message)
      assert {:ok, {_address, ^port, _reply}} = :gen_udp.recv(udp, 0, 1000)
    end

    test "class 3 connections: requests in SendUnitData, a repeated one answered again", ctx do
      {adapter, port} = adapter(ctx)
      socket = client(port)
      session = register(socket)

      forward_open = %{
        o_t_id: 0,
        t_o_id: 0x7777,
        serial: 1,
        vendor_id: 0xFFFF,
        originator_serial: 42,
        multiplier: 16,
        o_t: %{rpi: 2_000_000, size: 500, type: :point_to_point, priority: :low, fixed: false},
        t_o: %{rpi: 2_000_000, size: 500, type: :point_to_point, priority: :low, fixed: false},
        trigger: {:server, :application, 3},
        path: [class: 2, instance: 1]
      }

      request =
        CIP.request(
          0x54,
          ConnectionManager.path(),
          ConnectionManager.encode_forward_open(forward_open)
        )

      reply =
        exchange(socket, %Encapsulation{
          command: :send_rr_data,
          session: session,
          data: Encapsulation.rr_data([:null_address, {:unconnected_data, request}])
        })

      {:ok, items} = Encapsulation.decode_rr_data(reply.data)
      {:unconnected_data, data} = List.keyfind(items, :unconnected_data, 0)
      {:ok, %{status: :success, data: data}} = CIP.decode_reply(data)
      {:ok, %{o_t_id: o_t_id, t_o_id: 0x7777}} = ConnectionManager.decode_forward_open_reply(data)
      assert [%{kind: :explicit}] = Adapter.connections(adapter)

      connected = fn sequence, request ->
        reply =
          exchange(socket, %Encapsulation{
            command: :send_unit_data,
            session: session,
            data:
              Encapsulation.rr_data([
                {:connected_address, o_t_id},
                {:connected_data, <<sequence::little-16, request::binary>>}
              ])
          })

        {:ok,
         [
           {:connected_address, 0x7777},
           {:connected_data, <<^sequence::little-16, reply::binary>>}
         ]} =
          Encapsulation.decode_rr_data(reply.data)

        CIP.decode_reply(reply)
      end

      get = CIP.request(:get_attribute_single, class: 1, instance: 1, attribute: 1)
      assert {:ok, %{status: :success, data: <<0xFF, 0xFF>>}} = connected.(1, get)

      set =
        CIP.request(
          :set_attribute_single,
          [class: 4, instance: 150, attribute: 3],
          <<1, 2, 3, 4>>
        )

      assert {:ok, %{status: :success}} = connected.(2, set)
      assert_receive {Adapter, {:outputs, 150, <<1, 2, 3, 4>>}}
      assert {:ok, %{status: :success}} = connected.(2, set)
      refute_receive {Adapter, {:outputs, 150, _}}, 100

      # it goes with its TCP connection
      :gen_tcp.close(socket)
      assert_receive {Adapter, {:closed, %{kind: :explicit}, :closed}}
    end
  end

  describe "I/O connections" do
    test "an exclusive owner: its configuration, outputs both ways and run/idle", ctx do
      {adapter, port} = adapter(ctx)
      :ok = Adapter.put(adapter, 100, <<1, 2, 3, 4>>)

      scanner =
        scanner(ctx, port, rack: with_subscriber(@owner, config_data: <<7, 7>>))

      assert_receive {Adapter, {:configuration, 151, <<7, 7>>}}, 1000
      assert_receive {Adapter, {:opened, %{kind: :exclusive_owner, output: 150, input: 100}}}
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
      await_inputs(:rack, <<1, 2, 3, 4>>)

      :ok = Adapter.put(adapter, 100, <<5, 6, 7, 8>>)
      await_inputs(:rack, <<5, 6, 7, 8>>)

      :ok = Scanner.put(scanner, :rack, <<9, 8, 7, 6>>)
      assert_receive {Adapter, {:state, 150, :run}}, 1000
      assert_receive {Adapter, {:outputs, 150, <<9, 8, 7, 6>>}}, 1000
      assert {:ok, %{data: <<9, 8, 7, 6>>, state: :run, at: at}} = Adapter.outputs(adapter, 150)
      assert is_integer(at)

      # owned, configured, and in run mode
      assert {:ok, %Identity{status: 0x65}} = Scanner.identity(scanner)

      :ok = Scanner.run(scanner, :rack, false)
      assert_receive {Adapter, {:state, 150, :idle}}, 1000

      :ok = Scanner.close(scanner, :rack)
      assert_receive {Adapter, {:closed, %{kind: :exclusive_owner}, :closed}}, 1000
      assert_receive {Adapter, {:state, 150, :closed}}
      assert Adapter.connections(adapter) == []
    end

    test "an output assembly has one exclusive owner", ctx do
      {_adapter, port} = adapter(ctx)
      scanner(ctx, port, rack: with_subscriber(@owner))
      assert_receive {Scanner, :rack, {:status, :open}}, 1000

      scanner(ctx, port, other: with_subscriber(@owner))
      assert_receive {Scanner, :other, {:status, {:failed, reason}}}, 1000
      assert reason == {:connection_failure, :ownership_conflict, []}
    end

    test "configuration another connection gave must be the same", ctx do
      {_adapter, port} = adapter(ctx)
      scanner(ctx, port, rack: with_subscriber(@owner, config_data: <<1, 1>>))
      assert_receive {Scanner, :rack, {:status, :open}}, 1000

      scanner(ctx, port, other: with_subscriber(@input_only, config: 151, config_data: <<2, 2>>))
      assert_receive {Scanner, :other, {:status, {:failed, reason}}}, 1000
      assert reason == {:connection_failure, :ownership_conflict, []}
    end

    test "sizes and RPIs the adapter doesn't take are refused, with the size it does", ctx do
      {_adapter, port} = adapter(ctx, rpi: {10_000, 100_000})

      scanner(ctx, port,
        a: with_subscriber(@owner, output_size: 6),
        b: with_subscriber(@owner, output: 151, config: nil, input_size: 2),
        c: with_subscriber(@owner, rpi: 5_000),
        d: with_subscriber(@owner, output: 99)
      )

      expected = [
        a: {:connection_failure, :invalid_o_t_connection_size, [10]},
        c: {:connection_failure, :rpi_not_supported, []},
        d: {:connection_failure, :invalid_application_path, []}
      ]

      for {name, reason} <- expected,
          do: assert_receive({Scanner, ^name, {:status, {:failed, ^reason}}}, 1000)

      assert_receive {Scanner, :b, {:status, {:failed, {:connection_failure, _, _}}}}, 1000
    end

    test "the electronic key must match", ctx do
      {_adapter, port} = adapter(ctx, identity: [vendor_id: 0x1234, product_code: 7])
      key = {:key, 0x1234, 0, 7, 1, 1, false}
      scanner(ctx, port, good: with_subscriber(@input_only, key: key))
      assert_receive {Scanner, :good, {:status, :open}}, 1000

      scanner(ctx, port, bad: with_subscriber(@input_only, key: put_elem(key, 3, 8)))
      reason = {:connection_failure, :vendor_id_or_product_code_mismatch, []}
      assert_receive {Scanner, :bad, {:status, {:failed, ^reason}}}, 1000

      # a compatible key, of a minor revision this one can be
      scanner(ctx, port, newer: with_subscriber(@input_only, key: {:key, 0, 0, 0, 1, 2, true}))
      reason = {:connection_failure, :revision_mismatch, []}
      assert_receive {Scanner, :newer, {:status, {:failed, ^reason}}}, 1000
    end

    test "input only and listen only connections share multicast inputs", ctx do
      {adapter, port} = adapter(ctx)
      :ok = Adapter.put(adapter, 100, <<1, 1, 1, 1>>)

      # listen only needs another connection to the same inputs
      a = scanner(ctx, port, listen: with_subscriber(@listen_only, multicast: true))
      reason = {:connection_failure, :non_listen_only_connection_not_opened, []}
      assert_receive {Scanner, :listen, {:status, {:failed, ^reason}}}, 1000
      Scanner.close(a, :listen)

      scanner(ctx, port, input: with_subscriber(@input_only, multicast: true))
      scanner(ctx, port, listen: with_subscriber(@listen_only, multicast: true))
      assert_receive {Scanner, :input, {:status, :open}}, 1000
      assert_receive {Scanner, :listen, {:status, :open}}, 1000

      await_inputs(:input, <<1, 1, 1, 1>>)
      await_inputs(:listen, <<1, 1, 1, 1>>)
      :ok = Adapter.put(adapter, 100, <<2, 2, 2, 2>>)
      await_inputs(:input, <<2, 2, 2, 2>>)
      await_inputs(:listen, <<2, 2, 2, 2>>)

      assert [%{multicast: true}, %{multicast: true}] = Adapter.connections(adapter)
    end

    test "inputs by change of state go when they change", ctx do
      {adapter, port} = adapter(ctx)

      scanner(ctx, port,
        rack:
          with_subscriber(@input_only,
            input_trigger: :change_of_state,
            inhibit: 0,
            rpi: 1_000_000
          )
      )

      assert_receive {Scanner, :rack, {:status, :open}}, 1000
      await_inputs(:rack, <<0, 0, 0, 0>>)
      :ok = Adapter.put(adapter, 100, <<3, 3, 3, 3>>)
      await_inputs(:rack, <<3, 3, 3, 3>>, 200)
    end

    # The supervisor reports the scanner killed.
    @tag :capture_log
    test "a connection whose packets stop times out, and the device shows it", ctx do
      {_adapter, port} = adapter(ctx)
      scanner = scanner(ctx, port, rack: with_subscriber(@owner, multiplier: 4))
      assert_receive {Adapter, {:state, 150, :run}}, 1000

      # gone without a Forward_Close
      Process.unlink(scanner)
      Process.exit(scanner, :kill)
      assert_receive {Adapter, {:closed, %{kind: :exclusive_owner}, :timed_out}}, 1000
      assert_receive {Adapter, {:state, 150, :closed}}

      other = scanner(ctx, port, [])
      # at least one faulted I/O connection
      assert {:ok, %Identity{status: status}} = Scanner.identity(other)
      assert Bitwise.band(status, 0xF0) == 0x20
    end

    test "a duplicate Forward_Open is refused, and Forward_Close needs the connection", ctx do
      {_adapter, port} = adapter(ctx)
      scanner = scanner(ctx, port, [])

      forward_open = %{
        o_t_id: 0,
        t_o_id: 0x1111,
        serial: 9,
        vendor_id: 0xFFFF,
        originator_serial: 99,
        multiplier: 16,
        o_t: %{rpi: 20_000, size: 2, type: :point_to_point, priority: :scheduled, fixed: true},
        t_o: %{rpi: 20_000, size: 6, type: :point_to_point, priority: :scheduled, fixed: true},
        trigger: {:client, :cyclic, 1},
        path: [class: 4, connection_point: 152, connection_point: 100]
      }

      data = ConnectionManager.encode_forward_open(forward_open)
      assert {:ok, _reply} = Scanner.request(scanner, 0x54, ConnectionManager.path(), data)

      assert Scanner.request(scanner, 0x54, ConnectionManager.path(), data) ==
               {:error, {:cip, :connection_failure, [0x0100]}}

      close = ConnectionManager.encode_forward_close(Map.put(forward_open, :serial, 10))

      assert Scanner.request(scanner, 0x4E, ConnectionManager.path(), close) ==
               {:error, {:cip, :connection_failure, [0x0107]}}

      close = ConnectionManager.encode_forward_close(forward_open)
      assert {:ok, _reply} = Scanner.request(scanner, 0x4E, ConnectionManager.path(), close)

      # a path to no object
      bad =
        ConnectionManager.encode_forward_open(%{forward_open | path: [class: 0x99, instance: 1]})

      assert Scanner.request(scanner, 0x54, ConnectionManager.path(), bad) ==
               {:error, {:cip, :connection_failure, [0x0315]}}

      # a cut short Forward_Open
      assert Scanner.request(scanner, 0x54, ConnectionManager.path(), binary_part(data, 0, 20)) ==
               {:error, {:cip, :not_enough_data, []}}
    end

    test "a flood of puts reaches the server as one change at a time", ctx do
      {adapter, _port} = adapter(ctx)
      :sys.suspend(adapter)
      for n <- 1..1000, do: :ok = Adapter.put(adapter, 100, <<n::32>>)
      assert Process.info(adapter, :message_queue_len) == {:message_queue_len, 1}
      :sys.resume(adapter)
      assert Adapter.get(adapter, 100) == {:ok, <<1000::32>>}
    end

    test "multicast inputs take a group no other production has", ctx do
      {_adapter, port} = adapter(ctx, inputs: %{100 => 4, 101 => 4})
      socket = client(port)
      session = register(socket)

      open = fn serial, input ->
        forward_open = %{
          o_t_id: 0,
          t_o_id: 0,
          serial: serial,
          vendor_id: 0xFFFF,
          originator_serial: 7,
          multiplier: 512,
          o_t: %{
            rpi: 1_000_000,
            size: 2,
            type: :point_to_point,
            priority: :scheduled,
            fixed: true
          },
          t_o: %{rpi: 1_000_000, size: 6, type: :multicast, priority: :scheduled, fixed: true},
          trigger: {:client, :cyclic, 1},
          path: [class: 4, connection_point: 152, connection_point: input]
        }

        data = ConnectionManager.encode_forward_open(forward_open)

        {reply, items} =
          raw_request(socket, session, CIP.request(0x54, ConnectionManager.path(), data))

        assert {:ok, %{status: :success}} = reply
        {forward_open, Enum.find_value(items, &group/1)}
      end

      {first, group_100} = open.(1, 100)
      {_second, group_101} = open.(2, 101)
      assert group_100 != group_101

      close = ConnectionManager.encode_forward_close(first)

      {reply, _items} =
        raw_request(socket, session, CIP.request(0x4E, ConnectionManager.path(), close))

      assert {:ok, %{status: :success}} = reply

      # the group the first had is free again, and the second's isn't
      assert {_third, ^group_100} = open.(3, 100)
    end

    # The scanner reports the endpoint gone.
    @tag :capture_log
    test "connections close when the UDP endpoint stops, and open again", ctx do
      {_adapter, port} = adapter(ctx)
      _scanner = scanner(ctx, port, [rack: with_subscriber(@owner)], backoff: {50, 50})
      assert_receive {Adapter, {:opened, %{kind: :exclusive_owner}}}, 1000
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
      assert_receive {Adapter, {:state, 150, :run}}, 1000

      [{udp, _value}] = Registry.lookup(EtherNetIP.Registry, {EtherNetIP.UDP, ctx.udp_port})
      Process.exit(udp, :kill)

      assert_receive {Adapter, {:closed, %{kind: :exclusive_owner}, {:udp, :closed}}}, 1000
      assert_receive {Scanner, :rack, {:status, :open}}, 3000
      assert_receive {Adapter, {:opened, %{kind: :exclusive_owner}}}, 1000
      assert_receive {Adapter, {:state, 150, :run}}, 1000
    end
  end

  defp group({:sockaddr, :t_o, {group, _port}}), do: group
  defp group(_item), do: nil

  # A request over a session of the test's own, and the items of its reply.
  defp raw_request(socket, session, request) do
    reply =
      exchange(socket, %Encapsulation{
        command: :send_rr_data,
        session: session,
        data: Encapsulation.rr_data([:null_address, {:unconnected_data, request}])
      })

    {:ok, items} = Encapsulation.decode_rr_data(reply.data)
    {:unconnected_data, data} = List.keyfind(items, :unconnected_data, 0)
    {CIP.decode_reply(data), items}
  end

  describe "whatever it's sent" do
    # Requests to its objects, many of them nearly right: random services, paths and data,
    # Forward_Opens, Multiple_Service_Packets and Unconnected_Sends, and these with a byte changed
    # or cut short. Each is answered as the adapter's rules say, and none fails in it.
    property "every request is answered, and none fails in the adapter", ctx do
      {adapter, port} = adapter(ctx)
      _scanner = scanner(ctx, port, rack: with_subscriber(@owner))

      check all request <- fuzzed_request(), max_runs: @runs do
        reply = fuzz_exchange(port, request)
        assert reply.status == :success
        {:ok, items} = Encapsulation.decode_rr_data(reply.data)
        {:unconnected_data, data} = List.keyfind(items, :unconnected_data, 0)
        assert {:ok, %{service: service, status: status}} = CIP.decode_reply(data)
        # an Unconnected_Send with no route gets the reply of the request in it
        assert service == service_of(request) or service_of(request) == 0x52
        assert status != :vendor_specific_error
      end

      assert Process.alive?(adapter)
    end

    # Packets for an exclusive owner's connection id, from its originator's address: what isn't
    # its outputs, or new, is dropped.
    property "outputs, however mangled, are taken or dropped", ctx do
      {adapter, port} = adapter(ctx)
      scanner = scanner(ctx, port, [])

      forward_open = %{
        o_t_id: 0,
        t_o_id: 0x2222,
        serial: 1,
        vendor_id: 0xFFFF,
        originator_serial: 8,
        multiplier: 512,
        o_t: %{rpi: 1_000_000, size: 10, type: :point_to_point, priority: :scheduled, fixed: true},
        t_o: %{rpi: 1_000_000, size: 6, type: :point_to_point, priority: :scheduled, fixed: true},
        trigger: {:client, :cyclic, 1},
        path: [class: 4, instance: 151, connection_point: 150, connection_point: 100]
      }

      data = ConnectionManager.encode_forward_open(forward_open)
      {:ok, reply} = Scanner.request(scanner, 0x54, ConnectionManager.path(), data)
      {:ok, %{o_t_id: o_t_id}} = ConnectionManager.decode_forward_open_reply(reply)
      {:ok, udp} = :gen_udp.open(0, [:binary])

      check all sequence <- Generators.u32(),
                count <- Generators.u16(),
                run <- boolean(),
                format <- member_of([:header, :modeless, :heartbeat]),
                outputs <- one_of([binary(length: 4), binary(max_length: 8)]),
                mutation <- mutation(),
                max_runs: @runs do
        packet =
          IOPacket.encode(o_t_id, sequence, IOPacket.encode_class1(count, format, run, outputs))

        :ok = :gen_udp.send(udp, {127, 0, 0, 1}, ctx.udp_port, mutate(packet, mutation))
      end

      # the packets have gone through
      Process.sleep(100)
      assert Process.alive?(adapter)
      assert [%{kind: :exclusive_owner}] = Adapter.connections(adapter)
    end
  end

  # Each request with a sender context of its own, so that a reply that comes late is told from
  # the one that answers it.
  defp fuzz_exchange(port, request) do
    {socket, session} = Process.get(:fuzz_session) || fuzz_session(port)
    context = <<System.unique_integer([:positive])::64>>

    message = %Encapsulation{
      command: :send_rr_data,
      session: session,
      context: context,
      data: Encapsulation.rr_data([:null_address, {:unconnected_data, request}])
    }

    with :ok <- :gen_tcp.send(socket, Encapsulation.encode(message)),
         %Encapsulation{} = reply <- reply_to(socket, context) do
      reply
    else
      # closed by a Reset among the requests: again on a new session
      {:error, reason} when reason in [:closed, :econnreset, :epipe, :enotconn] ->
        Process.delete(:fuzz_session)
        fuzz_exchange(port, request)
    end
  end

  defp reply_to(socket, context) do
    case receive_message(socket) do
      %Encapsulation{context: ^context} = reply -> reply
      %Encapsulation{} -> reply_to(socket, context)
      error -> error
    end
  end

  defp fuzz_session(port) do
    socket = client(port)
    session = {socket, register(socket)}
    Process.put(:fuzz_session, session)
    session
  end

  defp service_of(<<_reply::1, service::7, _rest::binary>>), do: service
  defp service_of(<<>>), do: 0

  @services [0x01, 0x05, 0x0A, 0x0E, 0x10, 0x4E, 0x52, 0x54, 0x5B]
  @paths [
    [class: 1, instance: 1],
    [class: 1, instance: 1, attribute: 7],
    [class: 2, instance: 1],
    [class: 2, instance: 1, attribute: 1],
    [class: 4, instance: 0, attribute: 2],
    [class: 4, instance: 100, attribute: 3],
    [class: 4, instance: 150, attribute: 3],
    [class: 4, instance: 151, attribute: 3],
    [class: 6, instance: 1],
    [class: 0xF5, instance: 1, attribute: 13],
    [class: 0xF6, instance: 1]
  ]

  defp fuzzed_request do
    gen all request <- one_of([cip_request(), multiple_request(), unconnected_send()]),
            mutation <- mutation() do
      mutate(request, mutation)
    end
  end

  defp cip_request do
    gen all service <- one_of([member_of(@services), integer(0..0x7F)]),
            path <- one_of([member_of(@paths), Generators.path()]),
            data <- one_of([binary(max_length: 40), Generators.forward_open()]) do
      data = if is_map(data), do: ConnectionManager.encode_forward_open(data), else: data
      CIP.request(service, path, data)
    end
  end

  defp multiple_request do
    gen all requests <- list_of(cip_request(), max_length: 4) do
      count = length(requests)

      {offsets, _end} =
        Enum.map_reduce(requests, 2 + count * 2, &{<<&2::little-16>>, &2 + byte_size(&1)})

      data = IO.iodata_to_binary([<<count::little-16>>, offsets, requests])
      CIP.request(0x0A, [class: 2, instance: 1], data)
    end
  end

  defp unconnected_send do
    gen all request <- cip_request(),
            route <- list_of(Generators.port_segment(), max_length: 2) do
      data = ConnectionManager.encode_unconnected_send(request, route, 1000)
      CIP.request(0x52, ConnectionManager.path(), data)
    end
  end

  defp mutation do
    one_of([
      constant(:none),
      tuple({constant(:change), Generators.u16(), Generators.u8()}),
      tuple({constant(:cut), Generators.u16()})
    ])
  end

  defp mutate(bytes, :none), do: bytes
  defp mutate(<<>>, _mutation), do: <<>>

  defp mutate(bytes, {:change, at, byte}) do
    at = rem(at, byte_size(bytes))
    binary_part(bytes, 0, at) <> <<byte>> <> binary_part(bytes, at + 1, byte_size(bytes) - at - 1)
  end

  defp mutate(bytes, {:cut, at}), do: binary_part(bytes, 0, rem(at, byte_size(bytes)))

  describe "its EDS" do
    test "is read, and gives connections that open against it", ctx do
      opts =
        Keyword.merge(@assemblies, identity: [product_code: 7, product_name: ~s(Pump "skid")])

      text = Adapter.eds(opts, vendor_name: "Acme", at: ~N[2026-10-29 12:34:56])
      {:ok, eds} = EtherNetIP.EDS.parse(text)

      assert eds.device.product_name == ~s(Pump "skid")
      assert eds.device.vendor_name == "Acme"
      assert eds.device.product_code == 7

      assert EtherNetIP.EDS.entry(eds, "Device Classification", "Class1") == [
               {:word, "EtherNetIP"}
             ]

      names = for c <- EtherNetIP.EDS.connections(eds), do: c.name
      assert names == ["Exclusive Owner", "Input Only", "Listen Only"]

      {adapter, port} = adapter(ctx, opts)
      :ok = Adapter.put(adapter, 100, <<4, 3, 2, 1>>)

      connections =
        for {name, as} <- Enum.zip(names, [:owner, :input, :listen]) do
          {:ok, options} = EtherNetIP.EDS.connection(eds, name, subscriber: self(), rpi: 20_000)
          {as, options}
        end

      assert connections[:owner][:config_data] == <<0, 0>>
      assert connections[:listen][:multicast] == true
      assert connections[:listen][:config] == nil

      # the listen only connection depends on the others, and tries again until they're open
      scanner(ctx, port, connections, backoff: {50, 50})

      for as <- [:owner, :input, :listen] do
        assert_receive {Scanner, ^as, {:status, :open}}, 2000
        await_inputs(as, <<4, 3, 2, 1>>)
      end
    end

    test "names connections by their assemblies when there are several" do
      text = Adapter.eds(inputs: %{100 => 4, 101 => 8}, outputs: %{150 => 2})
      {:ok, eds} = EtherNetIP.EDS.parse(text)

      assert for(c <- EtherNetIP.EDS.connections(eds), do: c.name) ==
               ["Exclusive Owner 150 100", "Exclusive Owner 150 101"]
    end
  end

  test "options that don't make sense are refused" do
    for bad <- [
          [inputs: %{0 => 4}],
          [inputs: %{100 => -1}],
          [inputs: %{100 => 4}, outputs: %{100 => 4}],
          [input_only: 100, inputs: %{100 => 4}],
          [identity: [vendor_id: 0x10000]],
          [identity: [product_name: String.duplicate("x", 33)]],
          [identity: [revision: {0, 1}]],
          [rpi: {100, 10}],
          [sessions: 1],
          [inactivity: 4000],
          [prot: 44818]
        ] do
      assert_raise ArgumentError, fn -> Adapter.config!(bad) end
    end
  end
end
