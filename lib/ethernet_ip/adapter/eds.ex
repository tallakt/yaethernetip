defmodule EtherNetIP.Adapter.EDS do
  @moduledoc false
  # The EDS of an adapter, from its options (Volume 1, chapter 7; Volume 2, chapter 7): its
  # identity, an RPI parameter of the range it takes, a parameter for each byte of its
  # configuration assemblies, its assemblies, and a connection for each output assembly and
  # input assembly, exclusive owner, and for each input assembly, input only and listen only, as
  # the adapter has those points. Each but listen only takes the first configuration assembly, if
  # any.

  import Bitwise

  # Volume 1, 7-3.6.9: the transport class 1, triggered cyclically, by change of state or by the
  # application; and the application type.
  @class_1 0x02
  @triggers 0x07 <<< 16
  @types %{listen_only: 1 <<< 24, input_only: 1 <<< 25, exclusive_owner: 1 <<< 26}

  # Both directions fixed in size, O->T point to point and T->O point to point or multicast, of
  # any priority; outputs with the 32-bit run/idle header, or a heartbeat, and modeless inputs.
  # Listen only inputs are multicast, as they're those of another connection.
  @parameters 0x05 + (0b100 <<< 16) + (0b111 <<< 24) + (0b111 <<< 28)
  @t_o_types %{exclusive_owner: 0b110 <<< 20, input_only: 0b110 <<< 20, listen_only: 0b010 <<< 20}
  @header 4 <<< 8
  @heartbeat 3 <<< 8

  # Volume 1, 5-14: not addressable over the network, as no Parameter object has them.
  @not_addressable 0x0800

  def write(config, opts) do
    identity = config.identity
    {min, max} = config.rpi
    {major, minor} = identity.revision
    now = Keyword.get_lazy(opts, :at, &NaiveDateTime.local_now/0)
    {file_major, file_minor} = Keyword.get(opts, :revision, {1, 0})

    assemblies = Enum.sort(config.assemblies)

    configuration =
      for {instance, {:configuration, size, data}} <- assemblies, do: {instance, size, data}

    {params, config_members} = parameters(configuration)

    """
    $ The EDS of #{identity.product_name}, an adapter of yaethernetip.

    [File]
            DescText = #{string(Keyword.get(opts, :description, identity.product_name))};
            CreateDate = #{date(now)};
            CreateTime = #{time(now)};
            Revision = #{file_major}.#{file_minor};

    [Device]
            VendCode = #{identity.vendor_id};
            VendName = #{string(Keyword.get(opts, :vendor_name, ""))};
            ProdType = #{identity.device_type};
            ProdTypeStr = #{string(Keyword.get(opts, :device_type_name, "Generic Device"))};
            ProdCode = #{identity.product_code};
            MajRev = #{major};
            MinRev = #{minor};
            ProdName = #{string(identity.product_name)};
            Catalog = #{string(Keyword.get(opts, :catalog, ""))};

    [Device Classification]
            Class1 = EtherNetIP;

    [Params]
            Param1 = 0, "", "", 0x#{hex(@not_addressable, 4)}, 0xC8, 4, "RPI", "microsecond", "The requested packet interval",
                #{min}, #{max}, #{default_rpi(min, max)};
    #{Enum.join(params, "\n")}

    [Assembly]
    #{Enum.map_join(assemblies, "\n", &assembly(&1, config_members))}

    [Connection Manager]
    #{Enum.map_join(Enum.with_index(connections(config, assemblies, configuration), 1), "\n", &connection/1)}

    [Port]
            Port1 = TCP, "EtherNet/IP port", "20 F5 24 01", 1;
    """
  end

  # 10 ms, if the adapter takes it.
  defp default_rpi(min, max) when is_integer(min) and is_integer(max),
    do: min |> max(10_000) |> min(max)

  # A USINT for each byte of each configuration assembly, its starting data the default.
  defp parameters(configuration) do
    {params, {_n, members}} =
      Enum.flat_map_reduce(configuration, {2, %{}}, fn {instance, _size, data}, {n, members} ->
        bytes = :binary.bin_to_list(data)

        params =
          for {byte, i} <- Enum.with_index(bytes) do
            ~s(        Param#{n + i} = 0, "", "", 0x#{hex(@not_addressable, 4)}, 0xC6, 1, ) <>
              ~s("Configuration #{instance} byte #{i}", "", "", 0, 255, #{byte};)
          end

        refs = Enum.map(n..(n + length(bytes) - 1)//1, &"Param#{&1}")
        {params, {n + length(bytes), Map.put(members, instance, refs)}}
      end)

    {params, members}
  end

  defp assembly({instance, {kind, size, _data}}, config_members) do
    name =
      case kind do
        :input -> "Inputs #{instance}"
        :output -> "Outputs #{instance}"
        :configuration -> "Configuration #{instance}"
        :heartbeat -> "Heartbeat #{instance}"
      end

    members =
      for ref <- Map.get(config_members, instance, []), do: ", 8, #{ref}"

    path = path(class: 4, instance: instance, attribute: 3)

    ~s(        Assem#{instance} = "#{name}", "#{path}", #{size}, 0x0000, , ) <>
      Enum.join(members) <> ";"
  end

  defp connections(config, assemblies, configuration) do
    inputs = for {instance, {:input, size, _}} <- assemblies, do: {instance, size}
    outputs = for {instance, {:output, size, _}} <- assemblies, do: {instance, size}
    config_assembly = List.first(configuration)
    several = length(inputs) * length(outputs) > 1

    owners =
      for {output, output_size} <- outputs, {input, input_size} <- inputs do
        name = if several, do: "Exclusive Owner #{output} #{input}", else: "Exclusive Owner"
        {:exclusive_owner, name, {output, output_size}, {input, input_size}, config_assembly}
      end

    heartbeats =
      for {kind, label} <- [input_only: "Input Only", listen_only: "Listen Only"],
          point = Map.get(config, kind),
          point != nil,
          {input, input_size} <- inputs do
        name = if length(inputs) > 1, do: "#{label} #{input}", else: label
        # Listen only connections bring no configuration (Volume 1, 3-6.4.1).
        config = if kind == :listen_only, do: nil, else: config_assembly
        {kind, name, {point, 0}, {input, input_size}, config}
      end

    owners ++ heartbeats
  end

  defp connection({{kind, name, {output, output_size}, {input, input_size}, config}, n}) do
    trigger = @class_1 + @triggers + @types[kind]
    format = if kind == :exclusive_owner, do: @header, else: @heartbeat
    parameters = @parameters + @t_o_types[kind] + format

    {config_size, config_format, config_path} =
      case config do
        {instance, size, _data} -> {size, "Assem#{instance}", [instance: instance]}
        nil -> {"", "", []}
      end

    path = path([class: 4] ++ config_path ++ [connection_point: output, connection_point: input])

    """
            Connection#{n} = 0x#{hex(trigger, 8)}, 0x#{hex(parameters, 8)},
                Param1, #{output_size}, Assem#{output}, Param1, #{input_size}, Assem#{input},
                #{config_size}, #{config_format}, , ,
                #{string(name)}, "", "#{path}";\
    """
  end

  defp path(segments) do
    segments
    |> EtherNetIP.Path.encode()
    |> :binary.bin_to_list()
    |> Enum.map_join(" ", &hex(&1, 2))
  end

  defp hex(n, digits), do: n |> Integer.to_string(16) |> String.pad_leading(digits, "0")

  defp date(at), do: "#{pad(at.month)}-#{pad(at.day)}-#{at.year}"
  defp time(at), do: "#{pad(at.hour)}:#{pad(at.minute)}:#{pad(at.second)}"
  defp pad(n), do: n |> Integer.to_string() |> String.pad_leading(2, "0")

  # A quoted string, in ASCII: a character outside it as \xnn, after Latin-1 (Volume 1, 7-3.5.2).
  defp string(text) do
    escaped =
      text
      |> :unicode.characters_to_binary(:utf8, :latin1)
      |> :binary.bin_to_list()
      |> Enum.map_join(fn
        ?" -> ~S(\")
        ?\\ -> ~S(\\)
        c when c in 0x20..0x7E -> <<c>>
        c -> "\\x" <> hex(c, 2)
      end)

    ~s("#{escaped}")
  end
end
