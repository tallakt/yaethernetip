defmodule EtherNetIP.EDSTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias EtherNetIP.{EDS, Identity}

  @widget Path.expand("../fixtures/widget.eds", __DIR__)
  @runs String.to_integer(System.get_env("FUZZ_RUNS", "300"))

  setup_all do
    {:ok, eds} = EDS.read(@widget)
    %{eds: eds}
  end

  describe "reading" do
    test "the file and the device", %{eds: eds} do
      assert eds.file == %{
               description: "Widget EDS",
               revision: {1, 10},
               home_url: "http://example.com/widget.eds",
               created: ~D[1994-04-03],
               modified: ~D[1926-10-29]
             }

      assert eds.device == %{
               vendor_id: 65535,
               vendor_name: "Widget-Works, Inc.",
               device_type: 7,
               device_type_name: "General Purpose Discrete I/O",
               product_code: 42,
               revision: {3, 1},
               product_name: ~s(Widget "8DI/8DO"),
               catalog: "WW-88"
             }

      assert eds.classifications == [["EtherNetIP"], ["65535_Widgets", "Discrete"]]
    end

    test "parameters, their values of their types", %{eds: eds} do
      assert %{name: "RPI", units: "µs", type: :udint, size: 4} = eds.params[1]

      assert {eds.params[1].min, eds.params[1].max, eds.params[1].default} ==
               {2000, 1_000_000, 10000}

      assert eds.params[2].path == "20 04 24 64 30 03"
      assert eds.params[2].descriptor == 0x10

      # signed, written in hexadecimal
      assert {eds.params[3].min, eds.params[3].max, eds.params[3].default} == {-128, 127, -1}
      assert {eds.params[4].min, eds.params[4].max, eds.params[4].default} == {-10.5, 1000.0, 2.5}
      assert eds.params[5].enum == [{0, "off"}, {1, "1 ms"}, {2, "3 ms"}, {3, "10 ms"}]
    end

    test "any section, as it was written", %{eds: eds} do
      assert EDS.entry(eds, "65535_widget EXTRAS", "colour") == [[1, [2, 3]], "Grønn"]
      assert EDS.entry(eds, "Device", "ProdCode") == [42]
      assert EDS.entry(eds, "Device", "Nothing") == nil
    end

    test "Latin-1 and CRLF, as files from Windows are" do
      text =
        @widget
        |> File.read!()
        |> String.replace("\n", "\r\n")
        |> :unicode.characters_to_binary(:utf8, :latin1)

      refute String.valid?(text)
      assert {:ok, eds} = EDS.parse(text)
      assert eds.params[1].units == "µs"
    end

    test "matches the identity of its device, whatever the minor revision", %{eds: eds} do
      identity = %Identity{vendor_id: 65535, device_type: 7, product_code: 42, revision: {3, 9}}
      assert EDS.matches?(eds, identity)
      refute EDS.matches?(eds, %{identity | revision: {4, 1}})
      refute EDS.matches?(eds, %{identity | product_code: 43})
    end

    test "what can't be read is an error, with its line" do
      assert EDS.parse("[File]\n DescText = \"Widget;\n") ==
               {:error, {:syntax, 2, "a string is not closed"}}

      assert EDS.parse("DescText = 1;") == {:error, {:syntax, 1, "an entry before any section"}}
      assert EDS.parse("[File\n") == {:error, {:syntax, 1, "a section name is not closed with ]"}}

      assert EDS.parse("[File]\n\n A = {1, {2;\n") ==
               {:error, {:syntax, 3, "a field is not followed by , or }"}}

      assert EDS.parse("[File]\n A = 1 2;") ==
               {:error, {:syntax, 2, "a field is not followed by , or ;"}}
    end
  end

  describe "assemblies" do
    test "lay out their parameters, bits and pads", %{eds: eds} do
      assert {:ok, [input, inputs]} = EDS.layout(eds, 100)
      assert %{name: "Input 0", offset: 0, bits: 1, param: 2, type: :bool} = input
      assert %{name: "Inputs", offset: 8, bits: 8, param: 8} = inputs
    end

    test "within assemblies, and parts of parameters", %{eds: eds} do
      {:ok, members} = EDS.layout(eds, 1)

      assert for(m <- members, do: {m.name, m.offset, m.bits, m.bit}) == [
               {"Offset", 0, 8, nil},
               {"Gain", 8, 32, nil},
               {"Filter", 40, 2, 0}
             ]

      # -1, 2.5 as a REAL, the filter's 1, a pad, and Assem2's 0x1234
      assert EDS.image(eds, 1) == {:ok, <<0xFF, 2.5::float-little-32, 1, 0x34, 0x12>>}

      assert EDS.image(eds, 1, %{3 => 5, 5 => 3}) ==
               {:ok, <<5, 2.5::float-little-32, 3, 0x34, 0x12>>}
    end

    test "that loop, or nest past reason, are refused, and soon" do
      loop = "[Assembly]\n Assem1 = \"Loop\", \"\", ,,,, 8, Assem1;"
      {:ok, eds} = EDS.parse("[File]\n" <> loop)
      assert {:error, {:unsupported, {:depth, _}}} = EDS.layout(eds, 1)

      # Fifty of each within each, eight deep: too many members to count, though no bits at all.
      levels =
        for n <- 1..8 do
          member = if n == 8, do: "0, 7", else: "0, Assem#{n + 1}"
          ~s(Assem#{n} = "", "", ,,,, ) <> Enum.join(List.duplicate(member, 50), ", ") <> ";"
        end

      {:ok, eds} = EDS.parse("[File]\n[Assembly]\n" <> Enum.join(levels, "\n"))
      {time, result} = :timer.tc(fn -> EDS.layout(eds, 1) end)
      assert {:error, {:unsupported, {:size, _}}} = result
      assert time < 2_000_000

      {:ok, eds} = EDS.parse(~s([File]\n[Assembly]\n Assem1 = "", "", ,,,, 4294967295, 1;))
      assert {:error, {:unsupported, {:size, _}}} = EDS.image(eds, 1)
    end
  end

  describe "connections" do
    test "the device's, as they are", %{eds: eds} do
      [owner, input_only, explicit] = EDS.connections(eds)

      assert %{number: 1, name: "Exclusive Owner", application: :exclusive_owner} = owner
      assert {owner.classes, owner.triggers} == {[1], [:cyclic]}
      assert owner.o_t.rpi == {:param, 1} and owner.o_t.format == {:assem, 150}
      assert owner.o_t.real_time == :header and owner.t_o.real_time == :modeless
      assert owner.t_o.types == [:multicast, :point_to_point]
      assert owner.config == [{nil, {:assem, 1}}, {nil, nil}]

      assert input_only.application == :input_only
      assert input_only.triggers == [:cyclic, :change_of_state]
      assert explicit.classes == [3]
    end

    test "give the scanner its options", %{eds: eds} do
      assert EDS.connection(eds, "exclusive owner") ==
               {:ok,
                [
                  config: 1,
                  output: 150,
                  input: 100,
                  output_size: 1,
                  input_size: 2,
                  output_format: :header,
                  input_format: :modeless,
                  config_data: <<0xFF, 2.5::float-little-32, 1, 0x34, 0x12>>,
                  multicast: false,
                  priority: :scheduled,
                  input_trigger: :cyclic,
                  rpi: 10000
                ]}

      {:ok, input_only} = EDS.connection(eds, 2)
      assert input_only[:output] == 152 and input_only[:output_format] == :heartbeat
      assert input_only[:output_size] == 0 and input_only[:multicast] == true
      refute Keyword.has_key?(input_only, :config_data)

      # options pass, and go over the EDS's
      {:ok, c} = EDS.connection(eds, 1, rpi: 20000, subscriber: self(), params: %{6 => 151})
      assert {c[:rpi], c[:subscriber], c[:output]} == {20000, self(), 151}

      # what the scanner makes of it
      assert %{output: 151, config_data: <<_::binary-8>>} =
               EtherNetIP.Scanner.connection!(:widget, c)
    end

    test "refuse what the device doesn't take", %{eds: eds} do
      assert EDS.connection(eds, "Nothing") == {:error, :unknown_connection}
      assert EDS.connection(eds, 1, rpi: 1000) == {:error, {:rpi, 1000, {2000, 1_000_000}}}
      assert EDS.connection(eds, 2, multicast: false) == {:error, {:unsupported, :point_to_point}}
      assert {:ok, _} = EDS.connection(eds, 2, input_trigger: :change_of_state)

      assert EDS.connection(eds, 2, input_trigger: :application) ==
               {:error, {:unsupported, {:input_trigger, :application}}}

      assert EDS.connection(eds, "Explicit") == {:error, {:unsupported, {:transport_class, [3]}}}
    end

    # Volume 1, Figure 7-3.19: a connection point in a parameter, and 32-bit headers both ways.
    test "the spec's own example" do
      {:ok, eds} =
        EDS.parse("""
        [File]
        [Params]
           Param1 = 0, , , 0x0004, 0xC6, 1, "Read", "", "", 64, 95, 64, 1, 1, 1, -63, 0, 0, 0, 0, 0;
           Param2 = 0, , , 0x0004, 0xC6, 1, "Write", "", "", 160, 191, 160, 1, 1, 1, -159, 0, 0, 0, 0, 0;
        [Connection Manager]
           Connection1 =
           0x04010002,     $ trigger & transport
           0x44244401,     $ point/multicast & priority & real time format
           , 16, ,         $ O->T RPI, size, format
           , 12, ,         $ T->O RPI, size, format
           , ,             $ config part 1 (not used)
           , ,             $ config part 2 (not used)
           "read/write",   $ connection name
           "",             $ Help string
           "20 04 24 01 2C [Param2] 2C [Param1]";
        """)

      assert {:ok, c} = EDS.connection(eds, "read/write")
      assert {c[:config], c[:output], c[:input]} == {1, 160, 64}
      assert {c[:output_size], c[:input_size]} == {16, 12}
      assert {c[:output_format], c[:input_format], c[:multicast]} == {:header, :header, true}
      refute Keyword.has_key?(c, :rpi)
    end

    test "paths the scanner can't take are refused" do
      eds = fn path ->
        {:ok, eds} =
          EDS.parse(
            ~s([File]\n[Connection Manager]\n Connection1 = 0x04010002, 0, , , , , , , , , , , "C", "", "#{path}";)
          )

        eds
      end

      assert EDS.connection(eds.("SYMBOL_ANSI"), 1) ==
               {:error, {:unsupported, {:path, "SYMBOL_ANSI"}}}

      assert EDS.connection(eds.("20 64 24 01 30 03"), 1) ==
               {:error, {:unsupported, {:path, "20 64 24 01 30 03"}}}

      assert EDS.connection(eds.("20 04 24 01 2C [Param9] 2C 64"), 1) ==
               {:error, {:unknown, {:param, 9}}}
    end
  end

  # An EDS from outside is read whatever it holds: an answer, never an exception.
  property "no file makes it raise" do
    widget = File.read!(@widget)

    check all bytes <- one_of([binary(max_length: 400), mutated(widget), soup()]),
              max_runs: @runs do
      case EDS.parse(bytes) do
        {:ok, eds} ->
          for c <- eds.connections,
              do:
                assert(match?({tag, _} when tag in [:ok, :error], EDS.connection(eds, c.number)))

          for {n, _assembly} <- eds.assemblies do
            assert match?({tag, _} when tag in [:ok, :error], EDS.layout(eds, n))
            assert match?({tag, _} when tag in [:ok, :error], EDS.image(eds, n))
          end

        {:error, {:syntax, line, message}} ->
          assert is_integer(line) and is_binary(message)
      end
    end
  end

  # The fixture with bytes changed, cut out or put in.
  defp mutated(text) do
    gen all edits <-
              list_of(tuple({integer(0..(byte_size(text) - 1)), integer(0..2), byte()}),
                min_length: 1,
                max_length: 8
              ) do
      Enum.reduce(edits, text, fn {at, kind, byte}, text ->
        at = rem(at, max(byte_size(text), 1))
        {head, rest} = {binary_part(text, 0, at), binary_part(text, at, byte_size(text) - at)}

        case {kind, rest} do
          {0, <<_, rest::binary>>} -> head <> <<byte>> <> rest
          {1, <<_, rest::binary>>} -> head <> rest
          _insert -> head <> <<byte>> <> rest
        end
      end)
    end
  end

  # Entries put together from the pieces an EDS is made of, sense or not.
  defp soup do
    piece =
      member_of([
        "[File]\n",
        "[Params]\n",
        "[Assembly]\n",
        "[Connection Manager]\n",
        "Param1 = ",
        "Param2 = ",
        "Assem1 = ",
        "Assem2 = ",
        "Connection1 = ",
        "Enum1 = ",
        "0x04010002",
        "0x44640405",
        "0xC6",
        "-1",
        "65535",
        "4294967295",
        "1.5",
        "Param1",
        "Param2:7",
        "Assem1",
        "Assem2",
        "Variant1",
        "\"20 04 24 01 2C [Param1] 2C 64\"",
        "\"SYMBOL_ANSI\"",
        "\"\"",
        "L\"\\u00F8\"",
        "{1, {2}}",
        ",",
        ", ",
        ";\n",
        "$ comment\n"
      ])

    gen all pieces <- list_of(piece, max_length: 60), do: "[File]\n" <> Enum.join(pieces)
  end
end
