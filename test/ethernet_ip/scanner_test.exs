defmodule EtherNetIP.ScannerTest do
  use ExUnit.Case, async: true

  alias EtherNetIP.{CIP, ConnectionManager, Encapsulation, Identity, IOPacket, Scanner}

  # A target played by the test, a message at a time, to answer as no proper device would.
  defp listen do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    {listen, port}
  end

  defp accept(listen, session \\ 0x1234) do
    {:ok, socket} = :gen_tcp.accept(listen, 2000)
    message = next_message(socket)
    assert message.command == :register_session
    assert message.data == <<1::little-16, 0::little-16>>
    answer(socket, %{message | session: session})
    socket
  end

  defp next_message(socket, timeout \\ 2000) do
    with {:ok, header} <- :gen_tcp.recv(socket, 24, timeout),
         <<_::16, length::little-16, _::binary>> = header,
         {:ok, data} <- recv(socket, length, timeout) do
      {:ok, message, ""} = Encapsulation.decode(header <> data)
      message
    end
  end

  defp recv(_socket, 0, _timeout), do: {:ok, <<>>}
  defp recv(socket, length, timeout), do: :gen_tcp.recv(socket, length, timeout)

  defp answer(socket, message), do: :ok = :gen_tcp.send(socket, Encapsulation.encode(message))

  # The next unconnected request, as {message, service, path, data, items}.
  defp next_request(socket, timeout \\ 2000) do
    case next_message(socket, timeout) do
      %Encapsulation{command: :send_rr_data} = message ->
        {:ok, items} = Encapsulation.decode_rr_data(message.data)
        {:unconnected_data, request} = List.keyfind(items, :unconnected_data, 0)
        {:ok, {service, path, data}} = CIP.decode_request(request)
        {message, service, path, data, items}

      other ->
        other
    end
  end

  defp reply(socket, message, reply, items \\ []) do
    data = Encapsulation.rr_data([:null_address, {:unconnected_data, reply} | items])
    answer(socket, %{message | data: data})
  end

  defp scanner(port, opts \\ []) do
    start_supervised!(
      Supervisor.child_spec({Scanner, [host: "127.0.0.1", port: port] ++ opts},
        id: make_ref(),
        restart: :temporary
      )
    )
  end

  test "reads an attribute" do
    {listen, port} = listen()
    scanner = scanner(port)
    task = Task.async(fn -> Scanner.get_attribute_single(scanner, 1, 1, 7) end)
    socket = accept(listen)

    {message, 0x0E, [class: 1, instance: 1, attribute: 7], "", _items} = next_request(socket)
    assert message.session == 0x1234
    reply(socket, message, CIP.reply(:get_attribute_single, :success, [], <<4, "Pump">>))

    assert Task.await(task) == {:ok, <<4, "Pump">>}
    assert Scanner.status(scanner) == :connected
  end

  test "gives the device's error, with its additional status" do
    {listen, port} = listen()
    scanner = scanner(port)
    task = Task.async(fn -> Scanner.get_attributes_all(scanner, 0x99, 1) end)
    socket = accept(listen)

    {message, _service, _path, _data, _items} = next_request(socket)
    reply(socket, message, CIP.reply(:get_attributes_all, :path_destination_unknown, [7]))
    assert Task.await(task) == {:error, {:cip, :path_destination_unknown, [7]}}
  end

  test "reads the identity" do
    {listen, port} = listen()
    scanner = scanner(port)
    task = Task.async(fn -> Scanner.identity(scanner) end)
    socket = accept(listen)

    identity = %Identity{
      vendor_id: 1,
      device_type: 12,
      product_code: 41,
      revision: {2, 7},
      status: 0x60,
      serial_number: 99,
      product_name: "Coupler",
      state: :operational
    }

    {message, 0x01, [class: 1, instance: 1], "", _items} = next_request(socket)

    reply(
      socket,
      message,
      CIP.reply(:get_attributes_all, :success, [], Identity.encode(identity))
    )

    assert Task.await(task) == {:ok, identity}
  end

  test "several requests on the way at once, answered in any order" do
    {listen, port} = listen()
    scanner = scanner(port, max_pending: 3)

    refs =
      for i <- 1..5,
          do:
            Scanner.send_request(scanner, :get_attribute_single,
              class: 1,
              instance: 1,
              attribute: i
            )

    socket = accept(listen)

    first = for _ <- 1..3, do: next_request(socket)
    # no more than max_pending on the way
    assert next_message(socket, 100) == {:error, :timeout}

    for {message, _, path, _, _} <- Enum.reverse(first),
        do:
          reply(
            socket,
            message,
            CIP.reply(:get_attribute_single, :success, [], <<path[:attribute]>>)
          )

    rest = for _ <- 1..2, do: next_request(socket)

    for {message, _, path, _, _} <- rest,
        do:
          reply(
            socket,
            message,
            CIP.reply(:get_attribute_single, :success, [], <<path[:attribute]>>)
          )

    results =
      for ref <- refs do
        assert_receive {Scanner, ^ref, result}, 2000
        result
      end

    assert results == for(i <- 1..5, do: {:ok, <<i>>})
    contexts = for {message, _, _, _, _} <- first ++ rest, do: message.context
    assert Enum.uniq(contexts) == contexts
  end

  test "a reply to another service is not taken" do
    {listen, port} = listen()
    scanner = scanner(port)
    task = Task.async(fn -> Scanner.get_attribute_single(scanner, 1, 1, 7) end)
    socket = accept(listen)

    {message, _service, _path, _data, _items} = next_request(socket)
    reply(socket, message, CIP.reply(:set_attribute_single, :success, [], <<1>>))
    assert Task.await(task) == {:error, :invalid_reply}
  end

  test "an encapsulation error is the result" do
    {listen, port} = listen()
    scanner = scanner(port)
    task = Task.async(fn -> Scanner.get_attribute_single(scanner, 1, 1, 7) end)
    socket = accept(listen)

    {message, _service, _path, _data, _items} = next_request(socket)
    answer(socket, %{message | status: :invalid_length, data: <<>>})
    assert Task.await(task) == {:error, {:encapsulation, :invalid_length}}
  end

  test "times out, and a late reply is passed over" do
    {listen, port} = listen()
    scanner = scanner(port, timeout: 100)
    task = Task.async(fn -> Scanner.get_attribute_single(scanner, 1, 1, 7) end)
    socket = accept(listen)

    {message, _service, _path, _data, _items} = next_request(socket)
    assert Task.await(task) == {:error, :timeout}
    reply(socket, message, CIP.reply(:get_attribute_single, :success, [], <<1>>))

    task = Task.async(fn -> Scanner.get_attribute_single(scanner, 1, 1, 8) end)

    {message, _service, [class: 1, instance: 1, attribute: 8], _data, _items} =
      next_request(socket)

    reply(socket, message, CIP.reply(:get_attribute_single, :success, [], <<2>>))
    assert Task.await(task) == {:ok, <<2>>}
  end

  test "a routed request goes in an Unconnected_Send, and its reply may be either service" do
    {listen, port} = listen()
    scanner = scanner(port)

    task =
      Task.async(fn ->
        Scanner.request(scanner, :get_attribute_single, [class: 1, instance: 1, attribute: 7], "",
          route: [{:port, 1, 3}],
          timeout: 500
        )
      end)

    socket = accept(listen)
    {message, 0x52, [class: 6, instance: 1], data, _items} = next_request(socket)

    {1, 250, size} =
      {:binary.at(data, 0), :binary.at(data, 1),
       :binary.decode_unsigned(binary_part(data, 2, 2), :little)}

    embedded = binary_part(data, 4, size)

    assert CIP.decode_request(embedded) ==
             {:ok, {0x0E, [class: 1, instance: 1, attribute: 7], ""}}

    assert binary_part(data, byte_size(data) - 4, 4) == <<1, 0, 1, 3>>

    reply(socket, message, CIP.reply(:get_attribute_single, :success, [], <<5>>))
    assert Task.await(task) == {:ok, <<5>>}
  end

  test "reconnects when the device closes the connection, and fails requests meanwhile" do
    {listen, port} = listen()
    scanner = scanner(port, backoff: {50, 50})
    socket = accept(listen)
    wait_for(fn -> Scanner.status(scanner) == :connected end)

    :gen_tcp.close(socket)
    wait_for(fn -> match?({:disconnected, _}, Scanner.status(scanner)) end)
    assert Scanner.get_attribute_single(scanner, 1, 1, 7) == {:error, :closed}

    socket = accept(listen, 0x5678)
    task = Task.async(fn -> Scanner.get_attribute_single(scanner, 1, 1, 7) end)
    {message, _service, _path, _data, _items} = next_request(socket)
    assert message.session == 0x5678
    reply(socket, message, CIP.reply(:get_attribute_single, :success, [], <<1>>))
    assert Task.await(task) == {:ok, <<1>>}
  end

  test "a refused session is retried" do
    {listen, port} = listen()
    scanner = scanner(port, backoff: {50, 50})
    {:ok, socket} = :gen_tcp.accept(listen, 2000)
    message = next_message(socket)
    answer(socket, %{message | status: :unsupported_protocol_version})

    wait_for(fn ->
      Scanner.status(scanner) ==
        {:disconnected, {:register_session, :unsupported_protocol_version}}
    end)

    _socket = accept(listen)
    wait_for(fn -> Scanner.status(scanner) == :connected end)
  end

  test "a device that never answers RegisterSession is disconnected, and tried again" do
    {listen, port} = listen()
    scanner = scanner(port, timeout: 100, backoff: {50, 50})
    {:ok, socket} = :gen_tcp.accept(listen, 2000)
    %Encapsulation{command: :register_session} = next_message(socket)

    wait_for(fn -> Scanner.status(scanner) == {:disconnected, :timeout} end)
    _socket = accept(listen)
    wait_for(fn -> Scanner.status(scanner) == :connected end)
  end

  test "a result for a name that isn't registered is dropped, and the scanner goes on" do
    {listen, port} = listen()
    scanner = scanner(port)
    path = [class: 1, instance: 1, attribute: 7]
    _ref = Scanner.send_request(scanner, :get_attribute_single, path, "", to: :nobody_here)
    socket = accept(listen)
    {message, _service, _path, _data, _items} = next_request(socket)
    reply(socket, message, CIP.reply(:get_attribute_single, :success, [], <<1>>))

    task = Task.async(fn -> Scanner.get_attribute_single(scanner, 1, 1, 7) end)
    {message, _service, _path, _data, _items} = next_request(socket)
    reply(socket, message, CIP.reply(:get_attribute_single, :success, [], <<2>>))
    assert Task.await(task) == {:ok, <<2>>}

    assert_raise ArgumentError, ~r/to: is a pid or a name/, fn ->
      Scanner.send_request(scanner, :get_attribute_single, path, "", to: "me")
    end

    assert_raise ArgumentError, ~r/unknown options: \[:timout\]/, fn ->
      Scanner.request(scanner, :get_attribute_single, path, "", timout: 100)
    end
  end

  test "options that don't make sense are refused at the start" do
    good = [host: "127.0.0.1", connections: [rack: [output: 150, input: 100]]]
    assert %{vendor_id: 0xFFFF} = Scanner.config!(good)

    for bad <- [
          [vendor_id: 0x10000],
          [serial_number: -1],
          [backoff: {100, 50}],
          [backoff: 100],
          [udp_port: 70_000],
          [host: {10, 0, 0, 256}],
          [timout: 100],
          [connections: [rack: [output: 150, input: 100], rack: [output: 151, input: 101]]]
        ] do
      assert_raise ArgumentError, fn -> Scanner.config!(Keyword.merge(good, bad)) end
    end

    connection = &Scanner.connection!(:rack, Keyword.merge([output: 150, input: 100], &1))

    for bad <- [
          [priority: :highest],
          [output_size: -1],
          [input_size: 0x10000],
          [rpi: 0],
          [output_rpi: 0x1_0000_0000],
          [multicast: :yes],
          [run: nil],
          [subscriber: "me"],
          [config: 1, config_data: <<1>>],
          [output: -1],
          [ouput: 150],
          [route: [{:class, 1}]],
          [key: {:key, 1}],
          [key: {:key, 1, 2, 3, 200, 0, true}]
        ] do
      assert_raise ArgumentError, fn -> connection.(bad) end
    end

    assert_raise ArgumentError,
                 ~r/^priority: is :scheduled, :high, :low or :urgent, got: :highest$/,
                 fn ->
                   connection.(priority: :highest)
                 end

    assert_raise ArgumentError, ~r/^input: is required/, fn ->
      Scanner.connection!(:rack, output: 150)
    end
  end

  describe "I/O connections" do
    setup do
      {listen, port} = listen()
      {:ok, udp} = :gen_udp.open(0, [:binary, active: false])
      {:ok, target_udp} = :inet.port(udp)
      # The scanner's own UDP port, free for the test.
      {:ok, probe} = :gen_udp.open(0)
      {:ok, udp_port} = :inet.port(probe)
      :gen_udp.close(probe)
      %{listen: listen, port: port, udp: udp, target_udp: target_udp, udp_port: udp_port}
    end

    @connection [
      config: 1,
      output: 150,
      input: 100,
      output_size: 4,
      input_size: 3,
      rpi: 20_000,
      multiplier: 4
    ]

    # Answers a Forward_Open, with the target's UDP port for outputs; returns the request.
    defp open_connection(socket, ctx, o_t_id \\ 0xAAAA0001),
      do: answer_open(socket, ctx, &%{&1 | o_t_id: o_t_id})

    # Answers a Forward_Open with the reply that `change` makes of a proper one, and more items.
    defp answer_open(socket, ctx, change, items \\ []) do
      {message, request, request_items} = next_open(socket)

      if request.t_o.type == :point_to_point,
        do: assert({:sockaddr, :t_o, {{0, 0, 0, 0}, ctx.udp_port}} in request_items)

      reply = request |> granted() |> change.() |> ConnectionManager.encode_forward_open_reply()

      reply(socket, message, CIP.reply(0x54, :success, [], reply), [
        {:sockaddr, :o_t, {{0, 0, 0, 0}, ctx.target_udp}} | items
      ])

      request
    end

    defp next_open(socket) do
      {message, 0x54, [class: 6, instance: 1], data, items} = next_request(socket)
      {:ok, request} = ConnectionManager.decode_forward_open(data)
      {message, request, items}
    end

    defp granted(request) do
      %{
        o_t_id: 0xAAAA0001,
        t_o_id: request.t_o_id,
        serial: request.serial,
        vendor_id: request.vendor_id,
        originator_serial: request.originator_serial,
        o_t_api: request.o_t.rpi,
        t_o_api: request.t_o.rpi
      }
    end

    # Answers the next request, a Forward_Close, and returns its serial number.
    defp closed(socket) do
      {message, 0x4E, [class: 6, instance: 1], data, _items} = next_request(socket)
      {:ok, close} = ConnectionManager.decode_forward_close(data)
      reply = ConnectionManager.encode_forward_close_reply(close)
      reply(socket, message, CIP.reply(0x4E, :success, [], reply))
      close.serial
    end

    defp next_output(udp, timeout \\ 1000) do
      {:ok, {_address, _port, packet}} = :gen_udp.recv(udp, 0, timeout)
      {:ok, {id, sequence, data}} = IOPacket.decode(packet)
      {:ok, {count, run, outputs}} = IOPacket.decode_class1(data, :header)
      {id, sequence, count, run, outputs}
    end

    defp send_inputs(ctx, request, sequence, count, inputs) do
      packet =
        IOPacket.encode(
          request.t_o_id,
          sequence,
          IOPacket.encode_class1(count, :modeless, true, inputs)
        )

      :ok = :gen_udp.send(ctx.udp, {127, 0, 0, 1}, ctx.udp_port, packet)
    end

    test "opens, sends outputs every RPI, and takes inputs", ctx do
      scanner =
        scanner(ctx.port,
          udp_port: ctx.udp_port,
          connections: [rack: Keyword.merge(@connection, multiplier: 64, subscriber: self())]
        )

      socket = accept(ctx.listen)
      request = open_connection(socket, ctx)

      assert request.o_t.size == 4 + 6
      assert request.t_o.size == 3 + 2
      assert request.o_t.type == :point_to_point and request.t_o.type == :point_to_point
      assert request.trigger == {:client, :cyclic, 1}
      assert request.multiplier == 64

      assert EtherNetIP.Path.decode(request.path) ==
               {:ok, [class: 4, instance: 1, connection_point: 150, connection_point: 100]}

      assert_receive {Scanner, :rack, {:status, :open}}, 1000

      # outputs at once, then every RPI, the sequence number going up by one each time
      {0xAAAA0001, s1, c1, :run, <<0, 0, 0, 0>>} = next_output(ctx.udp)
      {0xAAAA0001, s2, ^c1, :run, <<0, 0, 0, 0>>} = next_output(ctx.udp)
      assert s2 == Bitwise.band(s1 + 1, 0xFFFF_FFFF)

      :ok = Scanner.put(scanner, :rack, <<1, 2, 3, 4>>)
      assert Scanner.put(scanner, :rack, <<1>>) == {:error, {:size, 4}}
      {_, _, c2, :run, <<1, 2, 3, 4>>} = until_output(ctx.udp, <<1, 2, 3, 4>>)
      assert c2 == Bitwise.band(c1 + 1, 0xFFFF)

      assert Scanner.inputs(scanner, :rack) == {:error, :waiting}
      send_inputs(ctx, request, 100, 7, <<9, 8, 7>>)
      assert_receive {Scanner, :rack, {:inputs, <<9, 8, 7>>}}, 1000
      assert Scanner.inputs(scanner, :rack) == {:ok, <<9, 8, 7>>}

      # the same sequence count keeps the connection, and isn't new
      send_inputs(ctx, request, 101, 7, <<9, 8, 7>>)
      refute_receive {Scanner, :rack, {:inputs, _}}, 100

      # an old encapsulation sequence number is passed over
      send_inputs(ctx, request, 99, 8, <<1, 1, 1>>)
      refute_receive {Scanner, :rack, {:inputs, _}}, 100
      assert Scanner.inputs(scanner, :rack) == {:ok, <<9, 8, 7>>}

      assert Scanner.connections(scanner) == %{rack: :open}
    end

    test "times out when inputs stop, closes, and opens again", ctx do
      scanner =
        scanner(ctx.port,
          udp_port: ctx.udp_port,
          backoff: {50, 50},
          connections: [rack: @connection ++ [subscriber: self()]]
        )

      socket = accept(ctx.listen)
      request = open_connection(socket, ctx)
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
      send_inputs(ctx, request, 1, 1, <<1, 2, 3>>)
      assert_receive {Scanner, :rack, {:inputs, <<1, 2, 3>>}}, 1000

      # 4 RPIs of 20 ms without inputs
      assert_receive {Scanner, :rack, {:status, {:failed, :timed_out}}}, 1000
      assert Scanner.inputs(scanner, :rack) == {:error, :timed_out}

      {message, 0x4E, [class: 6, instance: 1], data, _items} = next_request(socket)
      {:ok, close} = ConnectionManager.decode_forward_close(data)
      assert close.serial == request.serial

      reply(
        socket,
        message,
        CIP.reply(0x4E, :success, [], ConnectionManager.encode_forward_close_reply(close))
      )

      request = open_connection(socket, ctx)
      assert request.serial != close.serial
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
    end

    test "a refused Forward_Open says why, and is tried again", ctx do
      scanner(ctx.port,
        udp_port: ctx.udp_port,
        backoff: {50, 50},
        connections: [rack: @connection ++ [subscriber: self()]]
      )

      socket = accept(ctx.listen)
      {message, 0x54, _path, data, _items} = next_request(socket)
      {:ok, request} = ConnectionManager.decode_forward_open(data)
      failure = ConnectionManager.encode_failure(request)
      reply(socket, message, CIP.reply(0x54, :connection_failure, [0x0109, 9], failure))

      assert_receive {Scanner, :rack, {:status, {:failed, reason}}}, 1000
      assert reason == {:connection_failure, :invalid_connection_size, [9]}

      assert EtherNetIP.describe(reason) ==
               "the device refused the connection: invalid connection size (extended status 0x0109), it takes 9 bytes, with the sequence count and any run/idle header"

      open_connection(socket, ctx)
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
    end

    test "connections that consume one multicast production share its id", ctx do
      group = {239, 192, 1, 1}
      connection = Keyword.merge(@connection, multicast: true, subscriber: self())

      scanner =
        scanner(ctx.port, udp_port: ctx.udp_port, connections: [a: connection, b: connection])

      socket = accept(ctx.listen)

      # The producer of a multicast connection chooses its id (Volume 2, Table 3-3.2): one for both.
      for o_t_id <- [0xAAAA0001, 0xAAAA0002] do
        {message, 0x54, _path, data, _items} = next_request(socket)
        {:ok, request} = ConnectionManager.decode_forward_open(data)
        assert request.t_o.type == :multicast

        reply =
          ConnectionManager.encode_forward_open_reply(%{
            o_t_id: o_t_id,
            t_o_id: 0xBBBB0001,
            serial: request.serial,
            vendor_id: request.vendor_id,
            originator_serial: request.originator_serial,
            o_t_api: request.o_t.rpi,
            t_o_api: request.t_o.rpi
          })

        reply(socket, message, CIP.reply(0x54, :success, [], reply), [
          {:sockaddr, :o_t, {{0, 0, 0, 0}, ctx.target_udp}},
          {:sockaddr, :t_o, {group, ctx.udp_port}}
        ])
      end

      assert_receive {Scanner, :a, {:status, :open}}, 1000
      assert_receive {Scanner, :b, {:status, :open}}, 1000

      # joined on the interface of the session, that the device is reached on
      {:ok, udp} = EtherNetIP.UDP.ensure(ctx.udp_port)
      assert Map.keys(:sys.get_state(udp).groups) == [{group, {127, 0, 0, 1}}]

      producer = %{t_o_id: 0xBBBB0001}
      send_inputs(ctx, producer, 1, 1, <<1, 2, 3>>)
      assert_receive {Scanner, :a, {:inputs, <<1, 2, 3>>}}, 1000
      assert_receive {Scanner, :b, {:inputs, <<1, 2, 3>>}}, 1000

      # one closing leaves the other its inputs
      :ok = Scanner.close(scanner, :a)
      send_inputs(ctx, producer, 2, 2, <<4, 5, 6>>)
      assert_receive {Scanner, :b, {:inputs, <<4, 5, 6>>}}, 1000
      refute_receive {Scanner, :a, {:inputs, _}}, 100
    end

    test "asks for inputs by change of state, with a production inhibit time", ctx do
      connection = Keyword.merge(@connection, input_trigger: :change_of_state, inhibit: 5)
      scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: connection])
      socket = accept(ctx.listen)
      request = open_connection(socket, ctx)

      assert request.trigger == {:client, :change_of_state, 1}

      assert EtherNetIP.Path.decode(request.path) ==
               {:ok,
                [
                  production_inhibit: 5,
                  class: 4,
                  instance: 1,
                  connection_point: 150,
                  connection_point: 100
                ]}
    end

    test "sends outputs by change of state at once, and every RPI too", ctx do
      connection = Keyword.merge(@connection, output_trigger: :change_of_state, rpi: 1_000_000)
      scanner = scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: connection])
      socket = accept(ctx.listen)
      request = open_connection(socket, ctx)
      assert request.trigger == {:client, :cyclic, 1}

      {_, s1, c1, :run, <<0, 0, 0, 0>>} = next_output(ctx.udp)

      # an RPI of a second, so these come of the changes
      :ok = Scanner.put(scanner, :rack, <<1, 2, 3, 4>>)
      {_, s2, c2, :run, <<1, 2, 3, 4>>} = next_output(ctx.udp, 200)
      assert {s2, c2} == {next(s1, 32), next(c1, 16)}

      :ok = Scanner.put(scanner, :rack, <<1, 2, 3, 4>>)
      :ok = Scanner.run(scanner, :rack, false)
      {_, s3, c3, :idle, <<1, 2, 3, 4>>} = next_output(ctx.udp, 200)
      assert {s3, c3} == {next(s2, 32), next(c2, 16)}
      assert {:error, :timeout} = :gen_udp.recv(ctx.udp, 0, 200)
    end

    test "a production inhibit time must be less than the RPI, and only for change of state" do
      check = &Scanner.connection!(:rack, Keyword.merge(@connection, &1))

      assert check.(input_trigger: :change_of_state).inhibit == 5
      assert check.(input_trigger: :change_of_state, rpi: 1_000).inhibit == 0
      assert check.(input_trigger: :change_of_state, inhibit: 19).inhibit == 19

      assert_raise ArgumentError, ~r/less than the input RPI/, fn ->
        check.(input_trigger: :change_of_state, inhibit: 20)
      end

      assert_raise ArgumentError, ~r/for input_trigger/, fn -> check.(inhibit: 5) end

      assert_raise ArgumentError, ~r/output_trigger/, fn ->
        check.(output_trigger: :application)
      end
    end

    test "the ids of inputs are the node's, another for each scanner of a device", ctx do
      for _ <- 1..2,
          do: scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: @connection])

      [a, b] = for _ <- 1..2, do: open_connection(accept(ctx.listen), ctx).t_o_id
      assert a != b
      # an incarnation id, and a connection number (Volume 2, 3-3.7.1.2)
      assert Bitwise.bsr(a, 16) == Bitwise.bsr(b, 16)
    end

    test "a reply that doesn't fit the Forward_Open isn't taken, and what it opened is closed",
         ctx do
      scanner(ctx.port,
        udp_port: ctx.udp_port,
        backoff: {50, 50},
        connections: [rack: @connection ++ [subscriber: self()]]
      )

      socket = accept(ctx.listen)

      # another connection's, another originator's, or packet intervals the scanner can't keep to
      for change <- [
            &%{&1 | serial: Bitwise.bxor(&1.serial, 1)},
            &%{&1 | originator_serial: Bitwise.bxor(&1.originator_serial, 1)},
            &%{&1 | o_t_api: 0},
            &%{&1 | t_o_api: div(&1.t_o_api, 2) - 1}
          ] do
        request = answer_open(socket, ctx, change)
        assert closed(socket) == request.serial
      end

      assert_received {Scanner, :rack, {:status, {:failed, :invalid_reply}}}
      refute_received {Scanner, :rack, {:status, :open}}

      # half the RPI is still taken
      answer_open(socket, ctx, &%{&1 | o_t_api: div(&1.o_t_api, 2)})
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
    end

    test "a multicast connection's group must be a multicast address", ctx do
      connection = Keyword.merge(@connection, multicast: true, subscriber: self())
      scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: connection])
      socket = accept(ctx.listen)

      request = answer_open(socket, ctx, & &1, [{:sockaddr, :t_o, {{10, 0, 0, 1}, 2222}}])
      assert_receive {Scanner, :rack, {:status, {:failed, :invalid_reply}}}, 1000
      assert closed(socket) == request.serial
    end

    test "a Forward_Open with no reply in time is closed, as the device may have opened it",
         ctx do
      scanner(ctx.port,
        udp_port: ctx.udp_port,
        timeout: 100,
        backoff: {50, 50},
        connections: [rack: @connection ++ [subscriber: self()]]
      )

      socket = accept(ctx.listen)
      {_message, request, _items} = next_open(socket)
      assert_receive {Scanner, :rack, {:status, {:failed, :timeout}}}, 1000
      assert closed(socket) == request.serial

      open_connection(socket, ctx)
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
    end

    test "a connection closed while it opens is closed on the device when the reply comes", ctx do
      scanner = scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: @connection])
      socket = accept(ctx.listen)
      {message, request, _items} = next_open(socket)
      :ok = Scanner.close(scanner, :rack)

      reply = ConnectionManager.encode_forward_open_reply(granted(request))
      reply(socket, message, CIP.reply(0x54, :success, [], reply))
      assert closed(socket) == request.serial
      assert Scanner.connections(scanner) == %{}
    end

    # The supervisor reports the endpoint killed.
    @tag :capture_log
    test "when the UDP endpoint stops, its connections close, and open with the next", ctx do
      scanner(ctx.port,
        udp_port: ctx.udp_port,
        backoff: {50, 50},
        connections: [rack: @connection ++ [subscriber: self()]]
      )

      socket = accept(ctx.listen)
      request = open_connection(socket, ctx)
      assert_receive {Scanner, :rack, {:status, :open}}, 1000

      {:ok, udp} = EtherNetIP.UDP.ensure(ctx.udp_port)
      Process.exit(udp, :kill)
      assert_receive {Scanner, :rack, {:status, {:failed, {:udp, :closed}}}}, 1000
      assert closed(socket) == request.serial

      request = open_connection(socket, ctx)
      assert_receive {Scanner, :rack, {:status, :open}}, 1000
      send_inputs(ctx, request, 1, 1, <<1, 2, 3>>)
      assert_receive {Scanner, :rack, {:inputs, <<1, 2, 3>>}}, 1000
      assert {:ok, another} = EtherNetIP.UDP.ensure(ctx.udp_port)
      assert another != udp
    end

    test "a subscriber's name that isn't registered doesn't stop the scanner", ctx do
      connection = @connection ++ [subscriber: :nobody_here]
      scanner = scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: connection])
      socket = accept(ctx.listen)
      request = open_connection(socket, ctx)
      wait_for(fn -> Scanner.connections(scanner) == %{rack: :open} end)
      send_inputs(ctx, request, 1, 1, <<1, 2, 3>>)
      wait_for(fn -> Scanner.inputs(scanner, :rack) == {:ok, <<1, 2, 3>>} end)
    end

    test "closes those it opens too when it stops, as the device may have opened them", ctx do
      scanner = scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: @connection])
      socket = accept(ctx.listen)
      {_message, request, _items} = next_open(socket)

      :ok = Scanner.stop(scanner)
      {_message, 0x4E, _path, data, _items} = next_request(socket)
      {:ok, close} = ConnectionManager.decode_forward_close(data)
      assert close.serial == request.serial
    end

    test "closes its connections with Forward_Close when it stops", ctx do
      scanner = scanner(ctx.port, udp_port: ctx.udp_port, connections: [rack: @connection])
      socket = accept(ctx.listen)
      request = open_connection(socket, ctx)
      wait_for(fn -> Scanner.connections(scanner) == %{rack: :open} end)

      :ok = Scanner.stop(scanner)
      {_message, 0x4E, _path, data, _items} = next_request(socket)
      {:ok, close} = ConnectionManager.decode_forward_close(data)
      assert close.serial == request.serial
      assert %Encapsulation{command: :unregister_session} = next_message(socket)
    end
  end

  defp until_output(udp, outputs) do
    case next_output(udp) do
      {_, _, _, _, ^outputs} = output -> output
      _other -> until_output(udp, outputs)
    end
  end

  defp next(n, bits), do: Bitwise.band(n + 1, Bitwise.bsl(1, bits) - 1)

  defp wait_for(fun, tries \\ 100) do
    cond do
      fun.() -> :ok
      tries == 0 -> flunk("never came to be")
      true -> Process.sleep(10) && wait_for(fun, tries - 1)
    end
  end
end
