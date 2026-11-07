defmodule EtherNetIP.PropertyTest do
  # Everything encoded decodes back to what it was; random and mutated bytes go into every
  # decoder, which must answer, not crash. FUZZ_RUNS sets how many cases each property runs.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias EtherNetIP.{CIP, ConnectionManager, CPF, Encapsulation, Identity, IOPacket, Path}
  alias EtherNetIP.Test.Generators

  @runs String.to_integer(System.get_env("FUZZ_RUNS", "300"))

  property "paths decode to their segments, padded and packed" do
    check all path <- Generators.path(),
              format <- member_of([:padded, :packed]),
              max_runs: @runs do
      assert Path.decode(Path.encode(path, format), format) == {:ok, path}
    end
  end

  property "padded paths are whole words" do
    check all path <- Generators.path(), max_runs: @runs do
      assert rem(byte_size(Path.encode(path)), 2) == 0
    end
  end

  property "requests and replies decode to what they were" do
    check all path <- Generators.path(),
              service <- integer(0..0x7F),
              data <- binary(max_length: 50),
              status <- integer(0..255),
              additional <- list_of(Generators.u16(), max_length: 5),
              max_runs: @runs do
      assert CIP.decode_request(CIP.request(service, path, data)) == {:ok, {service, path, data}}

      assert CIP.decode_reply(CIP.reply(service, status, additional, data)) ==
               {:ok,
                %{
                  service: service,
                  status: CIP.status(status),
                  additional: additional,
                  data: data
                }}
    end
  end

  property "messages decode to what they were, however the stream splits them" do
    check all command <-
                one_of([member_of([:nop, :list_identity, :send_rr_data]), Generators.u16()]),
              session <- Generators.u32(),
              status <- Generators.u32(),
              context <- binary(length: 8),
              options <- Generators.u32(),
              data <- binary(max_length: 200),
              split <- integer(0..(24 + 200)),
              max_runs: @runs do
      message = %Encapsulation{
        command: command,
        session: session,
        status: status,
        context: context,
        options: options,
        data: data
      }

      frame = Encapsulation.encode(message)
      {:ok, decoded, ""} = Encapsulation.decode(frame <> "")
      assert Encapsulation.encode(decoded) == frame

      split = min(split, byte_size(frame))
      head = binary_part(frame, 0, split)
      if split < byte_size(frame), do: assert(Encapsulation.decode(head) == :more)
    end
  end

  property "items decode to what they were" do
    item =
      one_of([
        constant(:null_address),
        tuple({constant(:connected_address), Generators.u32()}),
        tuple({constant(:sequenced_address), Generators.u32(), Generators.u32()}),
        tuple({constant(:unconnected_data), binary()}),
        tuple({constant(:connected_data), binary()}),
        tuple(
          {constant(:sockaddr), member_of([:o_t, :t_o]),
           tuple(
             {tuple({Generators.u8(), Generators.u8(), Generators.u8(), Generators.u8()}),
              Generators.u16()}
           )}
        ),
        tuple({constant(:identity), binary()}),
        tuple({constant(:service), binary()})
      ])

    check all items <- list_of(item, max_length: 5), max_runs: @runs do
      assert CPF.decode(CPF.encode(items)) == {:ok, items}
    end
  end

  property "Forward_Opens decode to what they were" do
    check all request <- Generators.forward_open(), max_runs: @runs do
      {:ok, decoded} =
        ConnectionManager.decode_forward_open(
          ConnectionManager.encode_forward_open(request),
          request.large
        )

      {tick, ticks} = ConnectionManager.timing(request.timeout)
      assert decoded.timeout == Bitwise.bsl(1, tick) * ticks
      assert decoded.timeout >= request.timeout
      assert decoded.path == Path.encode(request.path)

      assert Map.drop(decoded, [:timeout, :path]) ==
               Map.drop(%{request | o_t: request.o_t, t_o: request.t_o}, [:timeout, :path])
    end
  end

  property "identities decode to what they were" do
    check all identity <- Generators.identity(),
              address <-
                tuple({Generators.u8(), Generators.u8(), Generators.u8(), Generators.u8()}),
              port <- Generators.u16(),
              max_runs: @runs do
      assert Identity.decode(Identity.encode(identity)) == {:ok, identity}

      assert Identity.decode_list_identity(
               Identity.encode_list_identity(identity, {address, port})
             ) ==
               {:ok, %{identity | address: {address, port}, protocol_version: 1}}
    end
  end

  property "I/O packets decode to what they were" do
    check all id <- Generators.u32(),
              sequence <- Generators.u32(),
              count <- Generators.u16(),
              run <- boolean(),
              data <- binary(max_length: 100),
              max_runs: @runs do
      assert IOPacket.decode(IOPacket.encode(id, sequence, data)) == {:ok, {id, sequence, data}}

      assert IOPacket.decode_class1(IOPacket.encode_class1(count, :header, run, data), :header) ==
               {:ok, {count, if(run, do: :run, else: :idle), data}}
    end
  end

  property "no decoder crashes, whatever it's given" do
    check all bytes <- binary(max_length: 300), max_runs: @runs * 3 do
      for format <- [:padded, :packed], do: assert(match?({_, _}, Path.decode(bytes, format)))
      assert match?({_, _}, CIP.decode_request(bytes))
      assert match?({_, _}, CIP.decode_reply(bytes))

      assert Encapsulation.decode(bytes) == :more or
               match?({:ok, _, _}, Encapsulation.decode(bytes))

      assert match?({_, _}, Encapsulation.decode_rr_data(bytes))
      assert match?({_, _}, CPF.decode(bytes))
      assert match?({_, _}, CPF.decode_service(bytes))
      assert match?({_, _}, Identity.decode(bytes))
      assert match?({_, _}, Identity.decode_list_identity(bytes))
      assert match?({_, _}, IOPacket.decode(bytes))

      for format <- [:modeless, :zero_length, :heartbeat, :header],
          do: assert(match?({_, _}, IOPacket.decode_class1(bytes, format)))

      for large <- [false, true],
          do: assert(match?({_, _}, ConnectionManager.decode_forward_open(bytes, large)))

      assert match?({_, _}, ConnectionManager.decode_forward_open_reply(bytes))
      assert match?({_, _}, ConnectionManager.decode_forward_close(bytes))
      assert match?({_, _}, ConnectionManager.decode_failure(bytes))
    end
  end

  property "a request with a byte changed decodes, or is refused" do
    check all path <- Generators.path(),
              data <- binary(max_length: 20),
              position <- integer(0..1000),
              byte <- Generators.u8(),
              max_runs: @runs do
      request = CIP.request(:get_attribute_single, path, data)
      position = rem(position, byte_size(request))

      mutated =
        binary_part(request, 0, position) <>
          <<byte>> <> binary_part(request, position + 1, byte_size(request) - position - 1)

      assert match?({_, _}, CIP.decode_request(mutated))
    end
  end
end
