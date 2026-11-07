defmodule EtherNetIP.EDS do
  @moduledoc """
  Electronic Data Sheets (Volume 1, chapter 7): the text file a vendor gives with a device. It
  says what the device is, what parameters it has, how the data blocks of its assemblies are
  laid out, and which I/O connections it takes. With one, a scanner's connection comes from its
  name instead of from numbers read out of a manual:

      {:ok, eds} = EtherNetIP.EDS.read("coupler.eds")
      {:ok, rack} = EtherNetIP.EDS.connection(eds, "Exclusive Owner", subscriber: self())
      {:ok, scanner} = EtherNetIP.Scanner.start_link(host: "10.0.0.20", connections: [rack: rack])

  `parse/1` reads a file into this struct:

    * `file`: `:description`, `:revision` of the file itself, `:home_url`, and `:created` and
      `:modified` as dates
    * `device`: `:vendor_id`, `:vendor_name`, `:device_type`, `:device_type_name`,
      `:product_code`, `:revision` as `{major, minor}`, `:product_name` and `:catalog`, which
      match the device's identity (see `matches?/2`)
    * `classifications`: each a list of names, as `["EtherNetIP"]`
    * `params`: by number, maps of `:name`, `:units`, `:help`, `:type` (as `:usint` or
      `:real`), `:size` in bytes, `:min`, `:max`, `:default`, `:enum` (pairs of a value and its
      name), `:path` and `:descriptor`
    * `assemblies`: by instance, maps of `:name`, `:path`, `:size` in bytes, `:descriptor` and
      `:members`, each `{bits, reference}`; see `layout/2`
    * `connections`: see `connections/1`
    * `sections`: every section as it was read, `{name, [{keyword, fields}]}`, for what the
      above leaves out; see `entry/3`

  A reference to another entry is `{:param, n}`, `{:param, n, bit}` for bits of a parameter,
  `{:assem, n}` or `{:variant, n}`; a field is `nil` when empty, a string, an integer,
  `{:word, text}` for any other word, or a list for fields in braces.

  Files from outside stray from the spec, and are read as leniently as their meaning allows:
  every interpreted field is optional, a value of the wrong kind counts as absent, and what can't
  be read at all is `{:error, {:syntax, line, message}}`. No file makes these functions raise.
  """

  import Bitwise

  alias EtherNetIP.EDS.Syntax

  defstruct file: %{},
            device: %{},
            classifications: [],
            params: %{},
            assemblies: %{},
            connections: [],
            sections: []

  @type ref ::
          {:param, non_neg_integer}
          | {:param, non_neg_integer, non_neg_integer}
          | {:assem, non_neg_integer}
          | {:variant, non_neg_integer}

  @type t :: %__MODULE__{
          file: map,
          device: map,
          classifications: [[String.t()]],
          params: %{non_neg_integer => map},
          assemblies: %{non_neg_integer => map},
          connections: [map],
          sections: [{String.t(), [{String.t(), list}]}]
        }

  # Volume 1, Table C-6.1.
  @types %{
    0xC1 => :bool,
    0xC2 => :sint,
    0xC3 => :int,
    0xC4 => :dint,
    0xC5 => :lint,
    0xC6 => :usint,
    0xC7 => :uint,
    0xC8 => :udint,
    0xC9 => :ulint,
    0xCA => :real,
    0xCB => :lreal,
    0xCC => :stime,
    0xCD => :date,
    0xCE => :time_of_day,
    0xCF => :date_and_time,
    0xD0 => :string,
    0xD1 => :byte,
    0xD2 => :word,
    0xD3 => :dword,
    0xD4 => :lword,
    0xD5 => :string2,
    0xD6 => :ftime,
    0xD7 => :ltime,
    0xD8 => :itime,
    0xD9 => :stringn,
    0xDA => :short_string,
    0xDB => :time,
    0xDC => :epath,
    0xDD => :engunit,
    0xDE => :stringi
  }
  @signed [:sint, :int, :dint, :lint]

  # An assembly is a UINT of bytes at most (Table 7-3.24), and holds assemblies this deep.
  @max_bits 0xFFFF * 8
  @max_depth 8

  @doc """
  An EDS from its text. `{:error, {:syntax, line, message}}` for one that can't be read.

      iex> {:ok, eds} = EtherNetIP.EDS.parse(\"""
      ...> [File]
      ...>   DescText = "Pump";  $ a comment
      ...> [Device]
      ...>   VendCode = 65535; ProdType = 12; ProdCode = 42; MajRev = 1; MinRev = 4;
      ...>   ProdName = "Smart" "-Pump";
      ...> \""")
      iex> eds.device
      %{vendor_id: 65535, vendor_name: nil, device_type: 12, device_type_name: nil,
        product_code: 42, revision: {1, 4}, product_name: "Smart-Pump", catalog: nil}
      iex> EtherNetIP.EDS.parse("[File]\\n DescText = \\"Pump\\"\\n[Device]")
      {:error, {:syntax, 2, "the entry DescText is not ended with ;"}}
  """
  @spec parse(binary) :: {:ok, t} | {:error, {:syntax, pos_integer, String.t()}}
  def parse(text) when is_binary(text) do
    case Syntax.parse(text) do
      {:ok, sections} -> {:ok, interpret(sections)}
      {:error, {line, message}} -> {:error, {:syntax, line, message}}
    end
  end

  @doc "An EDS from a file; see `parse/1`."
  @spec read(Path.t()) :: {:ok, t} | {:error, File.posix() | {:syntax, pos_integer, String.t()}}
  def read(path) do
    with {:ok, text} <- File.read(path), do: parse(text)
  end

  @doc """
  The fields of an entry, by its section and keyword, both in any case; `nil` when there is none.
  """
  @spec entry(t, String.t(), String.t()) :: list | nil
  def entry(%__MODULE__{sections: sections}, section, keyword) do
    {section, keyword} = {String.downcase(section), String.downcase(keyword)}

    Enum.find_value(sections, fn {name, entries} ->
      if String.downcase(name) == section, do: find_entry(entries, keyword)
    end)
  end

  defp find_entry(entries, keyword),
    do:
      Enum.find_value(entries, fn {k, fields} -> if String.downcase(k) == keyword, do: fields end)

  @doc """
  Whether the EDS is the one for a device of this identity: the same vendor, device type,
  product code and major revision (Volume 1, 7-3.6.3). The minor revision doesn't count.
  """
  @spec matches?(t, EtherNetIP.Identity.t()) :: boolean
  def matches?(%__MODULE__{device: device}, %EtherNetIP.Identity{} = identity) do
    {major, _minor} = identity.revision

    device.vendor_id == identity.vendor_id and device.device_type == identity.device_type and
      device.product_code == identity.product_code and match?({^major, _}, device.revision)
  end

  ## Reading

  defp interpret(sections) do
    sections =
      Enum.map(sections, fn {name, _line, entries} ->
        {name, for({keyword, _line, fields} <- entries, do: {keyword, fields})}
      end)

    # Sections by name and entries by keyword, in any case, a section given twice taken as one.
    index =
      Enum.reduce(sections, %{}, fn {name, entries}, index ->
        entries = for {keyword, fields} <- entries, do: {String.downcase(keyword), fields}
        Map.update(index, String.downcase(name), entries, &(&1 ++ entries))
      end)

    %__MODULE__{
      file: file(index),
      device: device(index),
      classifications: classifications(index),
      params: params(index),
      assemblies: assemblies(index),
      connections: read_connections(index),
      sections: sections
    }
  end

  defp file(index) do
    %{
      description: string(one(index, "file", "desctext")),
      revision: revision(one(index, "file", "revision")),
      home_url: string(one(index, "file", "homeurl")),
      created: date(one(index, "file", "createdate")),
      modified: date(one(index, "file", "moddate"))
    }
  end

  defp device(index) do
    get = fn keyword -> one(index, "device", keyword) end

    %{
      vendor_id: integer(get.("vendcode")),
      vendor_name: string(get.("vendname")),
      device_type: integer(get.("prodtype")),
      device_type_name: string(get.("prodtypestr")),
      product_code: integer(get.("prodcode")),
      revision: revision(integer(get.("majrev")), integer(get.("minrev"))),
      product_name: string(get.("prodname")),
      catalog: string(get.("catalog"))
    }
  end

  defp classifications(index) do
    for {"class" <> n, fields} <- Map.get(index, "device classification", []),
        number?(n),
        do: fields |> Enum.map(&text/1) |> Enum.reject(&is_nil/1)
  end

  # Volume 1, Table 7-3.22.
  defp params(index) do
    entries = Map.get(index, "params", [])

    enums =
      for {"enum" <> n, fields} <- entries, number?(n), into: %{} do
        pairs = for [value, name] <- Enum.chunk_every(fields, 2, 2, :discard), do: {value, name}

        {String.to_integer(n),
         for({value, name} <- pairs, is_integer(value), do: {value, string(name)})}
      end

    for {"param" <> n, fields} <- entries, number?(n), into: %{} do
      n = String.to_integer(n)
      field = &Enum.at(fields, &1)
      type = Map.get(@types, field.(4), integer(field.(4)))
      size = count(field.(5))

      param = %{
        name: string(field.(6)),
        units: string(field.(7)),
        help: string(field.(8)),
        type: type,
        size: size,
        min: value(field.(9), type, size),
        max: value(field.(10), type, size),
        default: value(field.(11), type, size),
        enum: Map.get(enums, n, []),
        path: string(field.(2)),
        descriptor: integer(field.(3))
      }

      {n, param}
    end
  end

  # Volume 1, Tables 7-3.24 and 7-3.25.
  defp assemblies(index) do
    for {keyword, fields} <- Map.get(index, "assembly", []),
        {:assem, n} <- [reference({:word, keyword})],
        into: %{} do
      [name, path, size, descriptor, _, _ | rest] = fields ++ List.duplicate(nil, 6)

      members =
        rest
        |> Enum.take(max(length(fields) - 6, 0))
        |> Enum.chunk_every(2, 2, [nil])
        |> Enum.map(fn [bits, member] -> {count(bits), reference(member)} end)

      assembly = %{
        name: string(name),
        path: string(path),
        size: amount(size),
        descriptor: integer(descriptor),
        members: members
      }

      {n, assembly}
    end
  end

  @doc """
  The I/O connections the device takes, from its [Connection Manager] section (Volume 1,
  7-3.6.9), each a map of:

    * `:number`, of its entry, `:name` and `:help`
    * `:application`, `:exclusive_owner`, `:input_only`, `:listen_only` or `:redundant_owner`
    * `:classes`, the transport classes, and `:triggers`, among `:cyclic`, `:change_of_state`
      and `:application`
    * `:o_t` and `:t_o`, each a map of `:rpi`, `:size` and `:format`, as numbers or references;
      `:real_time`, the real-time format, as `EtherNetIP.Scanner` names it; `:types`, among
      `:null`, `:multicast` and `:point_to_point`; `:priorities`, among `:low`, `:high` and
      `:scheduled`; and `:fixed` and `:variable`, the sizes it takes
    * `:config`, the two parts of its configuration data, each `{size, format}`
    * `:path`, the connection path as the EDS writes it
  """
  @spec connections(t) :: [map]
  def connections(%__MODULE__{connections: connections}), do: connections

  defp read_connections(index) do
    for {"connection" <> n, fields} <- Map.get(index, "connection manager", []), number?(n) do
      field = &Enum.at(fields, &1)
      transport = integer(field.(0)) || 0
      parameters = integer(field.(1)) || 0

      %{
        number: String.to_integer(n),
        name: string(field.(12)),
        help: string(field.(13)),
        path: string(field.(14)),
        application:
          Enum.at(
            bits(transport >>> 24, [:listen_only, :input_only, :exclusive_owner, :redundant_owner]),
            0
          ),
        classes: for(class <- 0..6, band(transport, 1 <<< class) != 0, do: class),
        triggers: bits(transport >>> 16, [:cyclic, :change_of_state, :application]),
        o_t: direction(field.(2), field.(3), field.(4), parameters, 0),
        t_o: direction(field.(5), field.(6), field.(7), parameters, 1),
        config: [
          {amount(field.(8)), reference(field.(9))},
          {amount(field.(10)), reference(field.(11))}
        ]
      }
    end
  end

  # Volume 1, Table 7-3.37, for O->T (0) or T->O (1).
  defp direction(rpi, size, format, parameters, which) do
    %{
      rpi: amount(rpi),
      size: amount(size),
      format: reference(format),
      real_time: real_time(band(parameters >>> (8 + 4 * which), 7)),
      types: bits(parameters >>> (16 + 4 * which), [:null, :multicast, :point_to_point]),
      priorities: bits(parameters >>> (24 + 4 * which), [:low, :high, :scheduled]),
      fixed: band(parameters, 1 <<< (2 * which)) != 0,
      variable: band(parameters, 1 <<< (2 * which + 1)) != 0
    }
  end

  defp real_time(0), do: :modeless
  defp real_time(1), do: :zero_length
  defp real_time(3), do: :heartbeat
  defp real_time(4), do: :header
  defp real_time(code), do: code

  defp bits(word, names),
    do: for({name, bit} <- Enum.with_index(names), band(word, 1 <<< bit) != 0, do: name)

  ## Connections for the scanner

  @doc """
  The options of an `EtherNetIP.Scanner` connection, from the connection of the EDS with this
  name, in any case, or number: its assemblies and their sizes, real-time formats, RPI,
  configuration data and the rest. The options in `opts` go over them, and those the EDS says
  the device doesn't take are refused: an RPI out of its range, multicast inputs or
  point-to-point ones, an input trigger.

  `params:` in `opts`, a map of parameter numbers and values, sets the parameters the connection
  is built from, as an RPI or a connection point the EDS leaves to the user; their defaults are
  taken otherwise.

  Errors are `:unknown_connection`; `{:unknown, reference}` for a parameter or assembly it refers
  to and doesn't have; `{:unsupported, what}` for what the scanner doesn't do, such as a
  connection of another class than 1 or a path to another object than assemblies, and for what
  doesn't make sense, such as a size out of range; and `{:rpi, rpi, {min, max}}`.
  """
  @spec connection(t, String.t() | pos_integer, keyword) :: {:ok, keyword} | {:error, term}
  def connection(%__MODULE__{} = eds, which, opts \\ []) do
    {values, opts} = Keyword.pop(opts, :params, %{})

    with {:ok, c} <- find_connection(eds, which),
         :ok <- class(c),
         {:ok, points} <- points(eds, c.path, values),
         {:ok, output_format} <- format(c.o_t.real_time),
         {:ok, input_format} <- format(c.t_o.real_time),
         {:ok, output_size} <- size(eds, c.o_t, values, output_format, 0),
         {:ok, input_size} <- size(eds, c.t_o, values, input_format, header(input_format)),
         {:ok, config_data} <- config_data(eds, c.config, values),
         {:ok, multicast} <- multicast(c, Keyword.get(opts, :multicast)),
         {:ok, priority} <- priority(c),
         {:ok, trigger} <- trigger(c, Keyword.get(opts, :input_trigger)),
         {:ok, rpis} <- rpis(eds, c, values, opts) do
      derived =
        points ++
          [
            output_size: output_size,
            input_size: input_size,
            output_format: output_format,
            input_format: input_format,
            config_data: config_data,
            multicast: multicast,
            priority: priority,
            input_trigger: trigger
          ] ++ rpis

      {:ok, Keyword.merge(Enum.reject(derived, &is_nil(elem(&1, 1))), opts)}
    end
  end

  defp find_connection(eds, which) do
    found =
      Enum.find(eds.connections, fn c ->
        if is_binary(which),
          do: is_binary(c.name) and String.downcase(c.name) == String.downcase(which),
          else: c.number == which
      end)

    if found, do: {:ok, found}, else: {:error, :unknown_connection}
  end

  # The scanner opens class 1 connections; an EDS that doesn't say is taken to mean those.
  defp class(%{classes: classes}) do
    if classes == [] or 1 in classes,
      do: :ok,
      else: {:error, {:unsupported, {:transport_class, classes}}}
  end

  # The scanner's assemblies from the connection path: a route of ports, an electronic key, then
  # the Assembly class, the configuration instance if any, and the connection points of the
  # outputs and the inputs (Volume 1, Table 3-5.14).
  defp points(eds, text, values) do
    with {:ok, bytes} <- path(eds, text || "", values),
         {:ok, segments} <- decode_path(bytes, text) do
      {route, segments} = Enum.split_while(segments, &match?({:port, _, _}, &1))

      {key, segments} =
        case segments do
          [{:key, _, _, _, _, _, _} = key | segments] -> {[key: key], segments}
          segments -> {[], segments}
        end

      route = if route == [], do: [], else: [route: route]

      case assemblies_of(segments) do
        [config, output, input] ->
          {:ok, [config: config, output: output, input: input] ++ key ++ route}

        [output, input] ->
          {:ok, [output: output, input: input] ++ key ++ route}

        _other ->
          {:error, {:unsupported, {:path, text}}}
      end
    end
  end

  defp assemblies_of([{:class, 4} | rest]) do
    ids = for {type, id} <- rest, type in [:instance, :connection_point], do: id
    if length(ids) == length(rest), do: ids, else: []
  end

  defp assemblies_of(_segments), do: []

  defp decode_path(bytes, text) do
    case EtherNetIP.Path.decode(bytes) do
      {:ok, segments} -> {:ok, segments}
      {:error, _reason} -> {:error, {:unsupported, {:path, text}}}
    end
  end

  # Volume 1, 7-3.5.8: bytes in hexadecimal, and parameters, in brackets or not, which give their
  # values in as many bytes as they have, least significant first.
  defp path(eds, text, values) do
    text
    |> String.split()
    |> Enum.reduce_while({:ok, []}, fn token, {:ok, acc} ->
      token = token |> String.trim_leading("[") |> String.trim_trailing("]")

      case path_part(eds, token, values) do
        {:ok, bytes} -> {:cont, {:ok, [acc, bytes]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, iodata} -> {:ok, IO.iodata_to_binary(iodata)}
      error -> error
    end
  end

  defp path_part(eds, token, values) do
    case {Base.decode16(token, case: :mixed), reference({:word, token})} do
      {{:ok, bytes}, _reference} ->
        {:ok, bytes}

      {:error, {:param, n}} ->
        case param_value(eds, n, values) do
          {:ok, value, %{size: size}}
          when is_integer(value) and value >= 0 and size in [1, 2, 4] ->
            {:ok, <<value::little-size(size * 8)>>}

          {:ok, _value, _param} ->
            {:error, {:unsupported, {:path, token}}}

          error ->
            error
        end

      _other ->
        # SYMBOL_ANSI, a symbol the user types in, or what isn't a path.
        {:error, {:unsupported, {:path, token}}}
    end
  end

  defp format(format) when is_atom(format), do: {:ok, format}
  defp format(code), do: {:error, {:unsupported, {:real_time_format, code}}}

  # The format of T->O includes its run/idle header, and its size doesn't (Volume 1, 7-3.6.9.7
  # and 7-3.6.9.8).
  defp header(:header), do: 4
  defp header(_format), do: 0

  # The bytes of one direction, without the sequence count and run/idle header: its size, or the
  # size of its format.
  defp size(_eds, _direction, _values, :heartbeat, _header), do: {:ok, 0}

  defp size(eds, direction, values, _format, header) do
    with {:ok, size} <- amount_value(eds, direction.size, values),
         {:ok, size} <-
           if(size, do: {:ok, size}, else: natural_size(eds, direction.format, values, header)) do
      if size <= 0xFFFF, do: {:ok, size}, else: {:error, {:unsupported, {:size, size}}}
    end
  end

  defp natural_size(eds, format, values, header) do
    with {:ok, bits} <- bits_of(eds, format, values), do: {:ok, max(div(bits + 7, 8) - header, 0)}
  end

  # The configuration data that goes with the Forward_Open: the two parts, each its format's
  # value, cut or padded with zeros to its size (Volume 1, 7-3.6.9.9), as whole words.
  defp config_data(eds, parts, values) do
    parts
    |> Enum.reduce_while({:ok, []}, fn {size, format}, {:ok, acc} ->
      with {:ok, size} <- amount_value(eds, size, values),
           true <- size == nil or size <= 0xFFFF,
           {:ok, bytes} <- bytes_of(eds, format, values) do
        {:cont, {:ok, [acc, fit(bytes, size)]}}
      else
        false -> {:halt, {:error, {:unsupported, {:size, size}}}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, iodata} ->
        case IO.iodata_to_binary(iodata) do
          "" -> {:ok, nil}
          data when rem(byte_size(data), 2) == 1 -> {:ok, data <> <<0>>}
          data -> {:ok, data}
        end

      error ->
        error
    end
  end

  defp fit(bytes, nil), do: bytes
  defp fit(bytes, size) when byte_size(bytes) >= size, do: binary_part(bytes, 0, size)
  defp fit(bytes, size), do: bytes <> <<0::size((size - byte_size(bytes)) * 8)>>

  # Point-to-point inputs where the device takes them, as the scanner's default.
  defp multicast(%{t_o: %{types: []}}, choice), do: {:ok, choice}

  defp multicast(%{t_o: %{types: types}}, nil) do
    cond do
      :point_to_point in types -> {:ok, false}
      :multicast in types -> {:ok, true}
      true -> {:error, {:unsupported, {:t_o_types, types}}}
    end
  end

  defp multicast(%{t_o: %{types: types}}, choice) do
    type = if choice, do: :multicast, else: :point_to_point
    if type in types, do: {:ok, choice}, else: {:error, {:unsupported, type}}
  end

  # One priority for both directions, as the scanner has it: scheduled, high, then low.
  defp priority(%{o_t: %{priorities: o_t}, t_o: %{priorities: t_o}}) do
    both =
      case {o_t, t_o} do
        {[], t_o} -> t_o
        {o_t, []} -> o_t
        {o_t, t_o} -> Enum.filter(o_t, &(&1 in t_o))
      end

    case {o_t ++ t_o, Enum.find([:scheduled, :high, :low], &(&1 in both))} do
      {[], nil} -> {:ok, nil}
      {_said, nil} -> {:error, {:unsupported, {:priorities, o_t, t_o}}}
      {_said, priority} -> {:ok, priority}
    end
  end

  defp trigger(%{triggers: []}, _choice), do: {:ok, nil}

  defp trigger(%{triggers: triggers}, nil),
    do: {:ok, if(:cyclic in triggers, do: :cyclic, else: hd(triggers))}

  defp trigger(%{triggers: triggers}, choice) do
    if choice in triggers,
      do: {:ok, choice},
      else: {:error, {:unsupported, {:input_trigger, choice}}}
  end

  # The RPIs, the EDS's or those of the options, within the range of their parameters.
  defp rpis(eds, c, values, opts) do
    with {:ok, output} <- rpi(eds, c.o_t.rpi, values, opts[:output_rpi] || opts[:rpi]),
         {:ok, input} <- rpi(eds, c.t_o.rpi, values, opts[:input_rpi] || opts[:rpi]) do
      if output == input and output != nil,
        do: {:ok, [rpi: output]},
        else: {:ok, Enum.reject([output_rpi: output, input_rpi: input], &is_nil(elem(&1, 1)))}
    end
  end

  defp rpi(eds, rpi, values, choice) do
    with {:ok, value} <- amount_value(eds, rpi, values),
         do: check_rpi(choice || value, range(eds, rpi))
  end

  defp range(eds, {:param, n}), do: {eds.params[n][:min], eds.params[n][:max]}
  defp range(_eds, _fixed), do: {nil, nil}

  defp check_rpi(nil, _range), do: {:ok, nil}

  defp check_rpi(rpi, _range) when not is_integer(rpi) or rpi not in 1..0xFFFF_FFFF,
    do: {:error, {:unsupported, {:rpi, rpi}}}

  defp check_rpi(rpi, {min, max} = range) do
    if (is_integer(min) and rpi < min) or (is_integer(max) and rpi > max),
      do: {:error, {:rpi, rpi, range}},
      else: {:ok, rpi}
  end

  ## Assemblies

  @doc """
  The members of an assembly that are parameters, where they are in its data: maps of `:offset`
  and `:bits`, in bits from the start, least significant first; `:param`, its number, and
  `:bit`, the first bit of it taken, or `nil` for all of it; and its `:name`, `:type` and
  `:units`. Members of assemblies within it are where they are in the whole.

      iex> {:ok, eds} = EtherNetIP.EDS.parse(\"""
      ...> [File]
      ...> [Params]
      ...>   Param1 = 0,,, 0, 0xC1, 1, "Start", "", "", 0, 1, 0;
      ...>   Param2 = 0,,, 0, 0xC7, 2, "Speed", "rpm", "", 0, 3000, 1500;
      ...> [Assembly]
      ...>   Assem150 = "Outputs", "", 4,,,, 1, Param1, 15,, 16, Param2;
      ...> \""")
      iex> {:ok, [start, speed]} = EtherNetIP.EDS.layout(eds, 150)
      iex> {start.name, start.offset, start.bits, speed.name, speed.offset, speed.bits}
      {"Start", 0, 1, "Speed", 16, 16}
      iex> EtherNetIP.EDS.image(eds, 150)
      {:ok, <<0, 0, 1500::little-16>>}
  """
  @spec layout(t, non_neg_integer) :: {:ok, [map]} | {:error, term}
  def layout(%__MODULE__{} = eds, n) do
    with {:ok, leaves, _bits} <- expand(eds, {:assem, n}, %{}) do
      members =
        for {offset, bits, member} <- leaves, {n, bit} <- [param_of(member)] do
          param = Map.get(eds.params, n, %{})

          %{
            offset: offset,
            bits: bits,
            param: n,
            bit: bit,
            name: param[:name],
            type: param[:type],
            units: param[:units]
          }
        end

      {:ok, members}
    end
  end

  defp param_of({:param, n}), do: {n, nil}
  defp param_of({:param, n, bit}), do: {n, bit}
  defp param_of(_member), do: nil

  @doc """
  The value of an assembly as the device's data would be with every parameter at its default, or
  as `params` sets it: the configuration data of a configuration assembly, for one.
  """
  @spec image(t, non_neg_integer, %{non_neg_integer => term}) :: {:ok, binary} | {:error, term}
  def image(%__MODULE__{} = eds, n, params \\ %{}), do: bytes_of(eds, {:assem, n}, params)

  # The value of what a format or member refers to, as bytes: a parameter's, or an assembly's from
  # those of its members, least significant bit first (Volume 1, 7-3.6.7.2.7).
  defp bytes_of(_eds, nil, _values), do: {:ok, <<>>}

  defp bytes_of(eds, reference, values) when is_tuple(reference) do
    with {:ok, leaves, bits} <- expand(eds, reference, values) do
      value =
        Enum.reduce(leaves, 0, fn {offset, size, member}, acc ->
          acc ||| band(member_value(eds, member, values), (1 <<< size) - 1) <<< offset
        end)

      bytes = div(bits + 7, 8)
      {:ok, <<value::little-size(bytes * 8)>>}
    end
  end

  defp bytes_of(_eds, _other, _values), do: {:ok, <<>>}

  defp bits_of(_eds, nil, _values), do: {:ok, 0}

  defp bits_of(eds, reference, values) do
    with {:ok, _leaves, bits} <- expand(eds, reference, values), do: {:ok, bits}
  end

  # What a reference comes to: its leaves, the members that aren't assemblies, each
  # {offset, bits, member}, and its size in bits. An assembly is its Size field's bytes, or its
  # members' bits when it has none, cut or padded to it (Volume 1, 7-3.6.7.2.3); a member is its
  # Member Size's bits, or what it refers to's. Assemblies within assemblies come to no more than
  # @budget members in all, however they nest, so that no file takes long to read.
  @budget 100_000

  defp expand(eds, reference, values) do
    case place(eds, reference, values, 0, nil, 0, {[], @budget}) do
      {:ok, bits, {leaves, _budget}} -> {:ok, Enum.reverse(leaves), bits}
      error -> error
    end
  end

  # Places a reference at bit `at`, within `room` bits (nil for no limit), and gives its size.
  defp place(eds, {:assem, n}, values, at, room, depth, acc) do
    with {:ok, assembly} <- assembly(eds, n, depth),
         {:ok, size} <- amount_value(eds, assembly.size, values),
         size = if(size, do: size * 8),
         :ok <- within(size, {:assem, n}),
         {:ok, bits, acc} <- members(eds, assembly, values, at, least(room, size), depth, acc) do
      {:ok, size || bits, acc}
    end
  end

  defp place(eds, member, _values, at, room, _depth, {leaves, budget}) do
    bits =
      case member do
        {:param, n, _bit} -> param_bits(eds, n)
        {:param, n} -> param_bits(eds, n)
        _value -> {:ok, 0}
      end

    with {:ok, bits} <- bits do
      bits = least(room, bits)
      leaves = if bits > 0, do: [{at, bits, member} | leaves], else: leaves
      {:ok, bits, {leaves, budget}}
    end
  end

  defp members(eds, assembly, values, at, room, depth, acc) do
    Enum.reduce_while(assembly.members, {:ok, 0, acc}, fn {bits, member}, {:ok, used, acc} ->
      left = if room, do: max(room - used, 0)

      with {:ok, size, acc} <- member(eds, bits, member, values, at + used, left, depth + 1, acc),
           :ok <- within(used + size, assembly.name) do
        {:cont, {:ok, used + size, acc}}
      else
        error -> {:halt, error}
      end
    end)
  end

  # Places a member, and gives the bits it takes: its Member Size, or what it refers to's.
  defp member(_eds, _bits, _member, _values, _at, _left, _depth, {_leaves, 0}),
    do: {:error, {:unsupported, {:size, :too_many_members}}}

  # A number is as wide as its Member Size.
  defp member(_eds, bits, number, _values, at, left, _depth, {leaves, budget})
       when is_integer(bits) and is_integer(number) do
    width = least(left, bits)
    leaves = if width > 0, do: [{at, width, number} | leaves], else: leaves
    {:ok, bits, {leaves, budget - 1}}
  end

  # Any other: its bits, least significant first, then zeros to its Member Size.
  defp member(eds, bits, member, values, at, left, depth, {leaves, budget}) do
    with {:ok, size, acc} <-
           place(eds, member, values, at, least(left, bits), depth, {leaves, budget - 1}),
         do: {:ok, bits || size, acc}
  end

  defp param_bits(eds, n) do
    case eds.params do
      %{^n => %{size: size}} when is_integer(size) -> {:ok, min(size * 8, @max_bits)}
      %{^n => _param} -> {:ok, 0}
      _params -> {:error, {:unknown, {:param, n}}}
    end
  end

  defp within(nil, _what), do: :ok
  defp within(bits, _what) when bits <= @max_bits, do: :ok
  defp within(_bits, what), do: {:error, {:unsupported, {:size, what}}}

  defp least(nil, b), do: b
  defp least(a, nil), do: a
  defp least(a, b), do: min(a, b)

  defp assembly(eds, n, depth) do
    cond do
      depth > @max_depth -> {:error, {:unsupported, {:depth, {:assem, n}}}}
      Map.has_key?(eds.assemblies, n) -> {:ok, eds.assemblies[n]}
      true -> {:error, {:unknown, {:assem, n}}}
    end
  end

  # A leaf's value, as an unsigned integer: a parameter's, its bits from `bit` for a reference
  # to bits of it, or a number; a pad or a path to an attribute is zeros.
  defp member_value(eds, {:param, n, bit}, values),
    do: member_value(eds, {:param, n}, values) >>> bit

  defp member_value(eds, {:param, n}, values) do
    case param_value(eds, n, values) do
      {:ok, value, param} -> raw(value, param)
      _error -> 0
    end
  end

  defp member_value(_eds, value, _values) when is_integer(value) and value >= 0, do: value
  defp member_value(_eds, _member, _values), do: 0

  # A REAL holds no more than this.
  @real_max 3.402_823_466_385_288_6e38

  defp raw(value, %{size: 4}) when is_float(value) and abs(value) <= @real_max,
    do: :binary.decode_unsigned(<<value::float-little-32>>, :little)

  defp raw(value, %{size: 8}) when is_float(value),
    do: :binary.decode_unsigned(<<value::float-little-64>>, :little)

  defp raw(value, %{size: size}) when is_integer(value) and is_integer(size) and size in 1..8,
    do: band(value, (1 <<< (size * 8)) - 1)

  defp raw(value, _param) when is_binary(value) and byte_size(value) <= 0xFFFF,
    do: :binary.decode_unsigned(value, :little)

  defp raw(_value, _param), do: 0

  defp param_value(eds, n, values) do
    case eds.params do
      %{^n => param} -> {:ok, Map.get(values, n, param.default), param}
      _params -> {:error, {:unknown, {:param, n}}}
    end
  end

  # A number, or a parameter's value, which must be a count.
  defp amount_value(_eds, nil, _values), do: {:ok, nil}
  defp amount_value(_eds, n, _values) when is_integer(n), do: {:ok, n}

  defp amount_value(eds, {:param, n}, values) do
    case param_value(eds, n, values) do
      {:ok, value, _param} when is_integer(value) and value >= 0 -> {:ok, value}
      {:ok, nil, _param} -> {:ok, nil}
      {:ok, value, _param} -> {:error, {:unsupported, {{:param, n}, value}}}
      error -> error
    end
  end

  ## Fields

  defp one(index, section, keyword) do
    with entries when is_list(entries) <- Map.get(index, section),
         {_keyword, [field | _]} <- List.keyfind(entries, keyword, 0),
         do: field,
         else: (_none -> nil)
  end

  defp string(text) when is_binary(text), do: text
  defp string(_field), do: nil

  defp integer(n) when is_integer(n), do: n
  defp integer(_field), do: nil

  defp text(text) when is_binary(text), do: text
  defp text({:word, text}), do: text
  defp text(_field), do: nil

  defp number?(digits), do: digits != "" and byte_size(digits) <= 10 and digits =~ ~r/^[0-9]+$/

  defp count(n) when is_integer(n) and n >= 0, do: n
  defp count(_field), do: nil

  # A number, or a reference to the parameter that gives it.
  defp amount(n) when is_integer(n) and n >= 0, do: n

  defp amount(field) do
    case reference(field) do
      {:param, _n} = param -> param
      _other -> nil
    end
  end

  @reference ~r/^(param|proxyparam|assem|assemexa|variant|variantexa)([0-9]{1,10})(?::([0-9]{1,2}))?$/i

  defp reference({:word, text} = word) do
    case Regex.run(@reference, text) do
      [_, kind, n] ->
        {kind(kind), String.to_integer(n)}

      [_, kind, n, bit] ->
        reference(kind(kind), String.to_integer(n), String.to_integer(bit), word)

      nil ->
        word
    end
  end

  defp reference(""), do: nil
  defp reference(field), do: field

  defp reference(:param, n, bit, _word), do: {:param, n, bit}
  defp reference(_kind, _n, _bit, word), do: word

  defp kind(kind) do
    case String.downcase(kind) do
      param when param in ["param", "proxyparam"] -> :param
      assem when assem in ["assem", "assemexa"] -> :assem
      _variant -> :variant
    end
  end

  # A parameter's value of its type: signed ones written in hexadecimal are two's complement
  # (Volume 1, 7-3.5.6), and REALs may be written as decimals.
  defp value(n, type, size) when type in @signed and is_integer(n) and size in [1, 2, 4, 8] do
    bits = size * 8
    if n >= 1 <<< (bits - 1) and n < 1 <<< bits, do: n - (1 <<< bits), else: n
  end

  defp value(n, type, _size) when type in [:real, :lreal] and is_integer(n), do: n * 1.0

  defp value({:word, text}, type, _size) when type in [:real, :lreal] do
    case Float.parse(text) do
      {float, ""} -> float
      _other -> nil
    end
  end

  defp value(value, _type, _size) when is_integer(value) or is_binary(value), do: value
  defp value(_field, _type, _size), do: nil

  defp revision(major, minor) when is_integer(major) and is_integer(minor), do: {major, minor}
  defp revision(_major, _minor), do: nil

  defp revision(major) when is_integer(major), do: {major, 0}

  defp revision({:word, text}) do
    with [major, minor] <- String.split(text, "."),
         {major, ""} <- Integer.parse(major),
         {minor, ""} <- Integer.parse(minor),
         do: {major, minor},
         else: (_other -> nil)
  end

  defp revision(_field), do: nil

  # Volume 1, 7-3.5.11: mm-dd-yyyy, or mm-dd-yy in the 1900s.
  defp date({:word, text}) do
    with [month, day, year] <- String.split(text, "-"),
         [{month, ""}, {day, ""}, {year, ""}] <- Enum.map([month, day, year], &Integer.parse/1),
         year = if(year < 100, do: 1900 + year, else: year),
         {:ok, date} <- Date.new(year, month, day),
         do: date,
         else: (_other -> nil)
  end

  defp date(_field), do: nil
end
