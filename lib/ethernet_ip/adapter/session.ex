defmodule EtherNetIP.Adapter.Session do
  @moduledoc false
  # A client's TCP connection to the adapter, in a process of its own: it reads the encapsulation
  # messages, answers those of the encapsulation layer itself, and has the server answer the CIP
  # requests they carry, unconnected (SendRRData) and over class 3 connections (SendUnitData). It
  # notes in the server's table when it last had a message, so that a full server knows which
  # connection to close, and it closes the connection after the Encapsulation Inactivity Timeout
  # with no message and no class 3 connection open (Volume 2, 2-5.5.2). Only whole messages
  # count, so that a client can't keep its place by trickling bytes.

  alias EtherNetIP.{CPF, Encapsulation, Identity}

  # Volume 2, Table 2-4.12: CIP over the encapsulation, and class 0 and 1 connections over UDP.
  @capabilities 0x0120

  def start_link(config), do: {:ok, spawn_link(fn -> wait(config) end)}

  defp wait(c) do
    receive do
      {:socket, socket} ->
        with {:ok, {local, port}} <- :inet.sockname(socket),
             {:ok, {peer, _port}} <- :inet.peername(socket) do
          c =
            Map.merge(c, %{
              socket: socket,
              local: local,
              port: port,
              peer: peer,
              session: nil,
              last: now()
            })

          loop(c, <<>>)
        else
          _gone -> :gen_tcp.close(socket)
        end
    after
      5000 -> :ok
    end
  end

  defp loop(c, buffer) do
    socket = c.socket

    case :inet.setopts(socket, active: :once) do
      :ok ->
        receive do
          {:tcp, ^socket, data} -> more(c, buffer <> data)
          {:tcp_closed, ^socket} -> :ok
          {:tcp_error, ^socket, _reason} -> close(c)
          :close -> close(c)
        after
          inactivity(c) -> inactive(c, buffer)
        end

      {:error, _reason} ->
        close(c)
    end
  end

  # A class 3 connection open on this TCP connection is activity of its own.
  defp inactive(c, buffer) do
    if GenServer.call(c.server, {:explicit?, self()}, :infinity),
      do: loop(%{c | last: now()}, buffer),
      else: close(c)
  end

  # What is left of the timeout since the last whole message.
  defp inactivity(c) do
    case :ets.lookup(c.table, :inactivity) do
      [{:inactivity, 0}] -> :infinity
      [{:inactivity, seconds}] -> max(0, c.last + seconds * 1000 - now())
    end
  end

  defp more(c, buffer) do
    case Encapsulation.decode(buffer) do
      {:ok, message, rest} ->
        c = %{c | last: now()}
        :ets.update_element(c.table, {:session, self()}, {2, c.last})

        case message(c, message) do
          {:ok, c} -> more(c, rest)
          :close -> close(c)
        end

      :more ->
        loop(c, buffer)
    end
  end

  # A request with a status, or options, is passed over, as the spec says (Volume 2, 2-3.5 and
  # 2-3.7), and so is a NOP; UnRegisterSession closes the connection, whatever it holds.
  defp message(_c, %Encapsulation{command: :unregister_session}), do: :close
  defp message(c, %Encapsulation{status: status}) when status != :success, do: {:ok, c}
  defp message(c, %Encapsulation{options: options}) when options != 0, do: {:ok, c}
  defp message(c, %Encapsulation{command: :nop}), do: {:ok, c}

  defp message(c, %Encapsulation{command: :list_services} = message) do
    service = CPF.service(1, @capabilities, "Communications")
    reply(c, message, CPF.encode([{:service, service}]))
  end

  defp message(c, %Encapsulation{command: :list_identity} = message) do
    identity = GenServer.call(c.server, :identity, :infinity)
    item = Identity.encode_list_identity(identity, {c.local, c.port})
    reply(c, message, CPF.encode([{:identity, item}]))
  end

  defp message(c, %Encapsulation{command: :list_interfaces} = message),
    do: reply(c, message, CPF.encode([]))

  defp message(c, %Encapsulation{command: :register_session} = message),
    do: register(c, message)

  defp message(%{session: nil} = c, %Encapsulation{command: command} = message)
       when command in [:send_rr_data, :send_unit_data],
       do: reply(c, message, <<>>, :invalid_session_handle)

  defp message(%{session: session} = c, %Encapsulation{command: command, session: other} = m)
       when command in [:send_rr_data, :send_unit_data] and other != session,
       do: reply(c, m, <<>>, :invalid_session_handle)

  defp message(c, %Encapsulation{command: :send_rr_data} = message) do
    with {:ok, items} <- Encapsulation.decode_rr_data(message.data),
         {:unconnected_data, request} <- List.keyfind(items, :unconnected_data, 0) do
      {reply, more} = GenServer.call(c.server, {:request, request, items, context(c)}, :infinity)
      reply(c, message, Encapsulation.rr_data([:null_address, {:unconnected_data, reply} | more]))
    else
      _invalid -> reply(c, message, <<>>, :incorrect_data)
    end
  end

  # A connected request, with its sequence count; one for no connection of this client's is
  # passed over, as nothing answers it.
  defp message(c, %Encapsulation{command: :send_unit_data} = message) do
    with {:ok,
          [{:connected_address, id}, {:connected_data, <<sequence::little-16, request::binary>>}]} <-
           Encapsulation.decode_rr_data(message.data),
         {:ok, t_o_id, reply} <-
           GenServer.call(c.server, {:connected, id, sequence, request, context(c)}, :infinity) do
      data =
        Encapsulation.rr_data([
          {:connected_address, t_o_id},
          {:connected_data, <<sequence::little-16, reply::binary>>}
        ])

      reply(c, message, data)
    else
      _unknown -> {:ok, c}
    end
  end

  # Any other command, as the legacy ones, is refused, and the session goes on (Volume 2, 2-3.2).
  defp message(c, message), do: reply(c, message, <<>>, :invalid_command)

  # Volume 2, 2-4.4: version 1, without options, and one session on a TCP connection.
  defp register(c, message) do
    case message.data do
      _data when c.session != nil ->
        reply(c, message, message.data, :invalid_command)

      <<1::little-16, 0::little-16>> ->
        session = session_handle()
        reply(%{c | session: session}, %{message | session: session}, message.data)

      <<version::little-16, _options::little-16>> ->
        status = :unsupported_protocol_version
        reply(c, message, <<min(version, 1)::little-16, 0::little-16>>, status)

      _other ->
        reply(c, message, <<>>, :invalid_length)
    end
  end

  # Unique among the node's sessions while it runs, and never 0.
  defp session_handle do
    n = System.unique_integer([:positive, :monotonic])
    Bitwise.band(n, 0xFFFF_FFFF) |> max(1)
  end

  defp context(c), do: %{peer: c.peer, local: c.local, session: self()}

  defp reply(c, message, data, status \\ :success) do
    frame = Encapsulation.encode(%{message | status: status, data: data})

    case :gen_tcp.send(c.socket, frame) do
      :ok -> {:ok, c}
      {:error, _reason} -> :close
    end
  end

  defp close(c), do: :gen_tcp.close(c.socket)

  defp now, do: System.monotonic_time(:millisecond)
end
