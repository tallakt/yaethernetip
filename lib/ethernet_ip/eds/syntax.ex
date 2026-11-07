defmodule EtherNetIP.EDS.Syntax do
  @moduledoc false
  # The syntax of an EDS (Volume 1, 7-3.3.2 and 7-3.5): sections, each a name in brackets and
  # entries, each a keyword, an equal sign, fields separated by commas, and a semicolon. A field is
  # empty, a string, a word (a number, a reference such as Param4, a date) or fields in braces.
  # Comments run from $ to the end of the line, outside strings; adjacent strings are one.
  #
  # Files from outside stray from the letter of it, and are read as leniently as their meaning
  # allows: a section's name may have any character but brackets, as "[TCP/IP Interface Class]"
  # has; a string may run over lines; an escape the spec doesn't list stays as it is written. What
  # can't be read is an error with its line, never an exception, whatever the bytes.
  #
  # A section is {name, line, entries}, an entry {keyword, line, fields}, and a field nil, a
  # string, an integer, {:word, text} for any other word, or a list of fields for braces.

  # Braces within braces, at most.
  @depth 16

  # Words no longer than this are read as numbers; a longer one stays a word.
  @digits 40

  @spec parse(binary) :: {:ok, [tuple]} | {:error, {pos_integer, String.t()}}
  def parse(text) do
    # Files are 8-bit ASCII, and their strings Latin-1 where a vendor strays from ASCII; one
    # that is UTF-8 throughout is taken as it is.
    text = if String.valid?(text), do: text, else: :unicode.characters_to_binary(text, :latin1)

    with {:ok, tokens} <- lex(text, 1, []), do: sections(tokens, [])
  end

  ## Tokens

  @blank [?\s, ?\t, ?\r, ?\v, ?\f, 0x1A]
  @punctuation %{?= => :=, ?, => :",", ?; => :";", ?{ => :"{", ?} => :"}"}
  @delimiters @blank ++ [?\n, ?$, ?[, ?], ?"] ++ Map.keys(@punctuation)

  defp lex(<<>>, _line, acc), do: {:ok, Enum.reverse(acc)}
  defp lex(<<?\n, rest::binary>>, line, acc), do: lex(rest, line + 1, acc)
  defp lex(<<c, rest::binary>>, line, acc) when c in @blank, do: lex(rest, line, acc)
  defp lex(<<?$, rest::binary>>, line, acc), do: lex(comment(rest), line, acc)

  defp lex(<<c, rest::binary>>, line, acc) when is_map_key(@punctuation, c),
    do: lex(rest, line, [{@punctuation[c], line} | acc])

  defp lex(<<?[, rest::binary>>, line, acc) do
    case :binary.match(rest, ["]", "\n"]) do
      {at, 1} when binary_part(rest, at, 1) == "]" ->
        name = String.trim(binary_part(rest, 0, at))

        lex(binary_part(rest, at + 1, byte_size(rest) - at - 1), line, [
          {:section, name, line} | acc
        ])

      _none ->
        {:error, {line, "a section name is not closed with ]"}}
    end
  end

  defp lex(<<?], _rest::binary>>, line, _acc), do: {:error, {line, "a ] with no ["}}
  defp lex(<<?L, ?", rest::binary>>, line, acc), do: string(rest, line, line, [], acc)
  defp lex(<<?", rest::binary>>, line, acc), do: string(rest, line, line, [], acc)

  defp lex(text, line, acc) do
    size = word_size(text, 0)
    rest = binary_part(text, size, byte_size(text) - size)
    lex(rest, line, [{:word, binary_part(text, 0, size), line} | acc])
  end

  defp comment(text) do
    case :binary.match(text, "\n") do
      {at, _} -> binary_part(text, at, byte_size(text) - at)
      :nomatch -> <<>>
    end
  end

  defp word_size(<<c, _rest::binary>>, n) when c in @delimiters, do: n
  defp word_size(<<_c, rest::binary>>, n), do: word_size(rest, n + 1)
  defp word_size(<<>>, n), do: n

  # A string, up to its closing quote, joined to a string just before it (7-3.5.3).
  defp string(<<?", rest::binary>>, start, line, chars, acc) do
    text = chars |> Enum.reverse() |> List.to_string()

    acc =
      case acc do
        [{:string, before, first} | acc] -> [{:string, before <> text, first} | acc]
        acc -> [{:string, text, start} | acc]
      end

    lex(rest, line, acc)
  end

  defp string(<<?\\, rest::binary>>, start, line, chars, acc) do
    {char, rest} = escape(rest)
    string(rest, start, line, char ++ chars, acc)
  end

  defp string(<<?\n, rest::binary>>, start, line, chars, acc),
    do: string(rest, start, line + 1, [?\n | chars], acc)

  defp string(<<c::utf8, rest::binary>>, start, line, chars, acc),
    do: string(rest, start, line, [c | chars], acc)

  defp string(<<>>, start, _line, _chars, _acc), do: {:error, {start, "a string is not closed"}}

  @escapes %{
    ?\\ => ?\\,
    ?n => ?\n,
    ?t => ?\t,
    ?v => ?\v,
    ?b => ?\b,
    ?r => ?\r,
    ?f => ?\f,
    ?a => 7,
    ?? => ??,
    ?0 => 0,
    ?" => ?",
    ?' => ?'
  }

  # Volume 1, 7-3.5.4. The characters come reversed, as the string's are.
  defp escape(<<c, rest::binary>>) when is_map_key(@escapes, c), do: {[@escapes[c]], rest}

  defp escape(<<?x, hex::binary-2, rest::binary>> = text) do
    case Integer.parse(hex, 16) do
      {byte, ""} -> {[byte], rest}
      _other -> {[?\\], text}
    end
  end

  defp escape(<<?u, hex::binary-4, rest::binary>> = text) do
    case Integer.parse(hex, 16) do
      # A lone half of a surrogate pair is no character.
      {code, ""} when code in 0xD800..0xDFFF -> {[0xFFFD], rest}
      {code, ""} -> {[code], rest}
      _other -> {[?\\], text}
    end
  end

  defp escape(text), do: {[?\\], text}

  ## Sections, entries and fields

  defp sections([{:section, name, line} | tokens], acc) do
    with {:ok, entries, tokens} <- entries(tokens, []),
         do: sections(tokens, [{name, line, entries} | acc])
  end

  defp sections([], acc), do: {:ok, Enum.reverse(acc)}

  defp sections([token | _tokens], _acc),
    do: {:error, {line(token), "an entry before any section"}}

  defp entries([{:word, keyword, line}, {:=, _} | tokens], acc) do
    case fields(tokens, :";", 0, []) do
      {:ok, fields, tokens} -> entries(tokens, [{keyword, line, fields} | acc])
      {:error, :end} -> {:error, {line, "the entry #{keyword} is not ended with ;"}}
      {:error, _reason} = error -> error
    end
  end

  defp entries([{:section, _, _} | _] = tokens, acc), do: {:ok, Enum.reverse(acc), tokens}
  defp entries([], acc), do: {:ok, Enum.reverse(acc), []}

  defp entries([token | _tokens], _acc),
    do: {:error, {line(token), "expected an entry keyword and ="}}

  # Fields up to `close`, each followed by a comma or by `close`.
  defp fields(tokens, close, depth, acc) do
    with {:ok, field, tokens} <- field(tokens, depth) do
      case tokens do
        [{:",", _} | tokens] -> fields(tokens, close, depth, [field | acc])
        [{^close, _} | tokens] -> {:ok, Enum.reverse([field | acc]), tokens}
        # The next section or the end of the file, where the entry should have ended.
        [{:section, _, _} | _] -> {:error, :end}
        [] -> {:error, :end}
        [token | _] -> {:error, {line(token), "a field is not followed by , or #{close}"}}
      end
    end
  end

  defp field([{:string, text, _} | tokens], _depth), do: {:ok, text, tokens}
  defp field([{:word, text, _} | tokens], _depth), do: {:ok, word(text), tokens}

  defp field([{:"{", line} | _tokens], @depth),
    do: {:error, {line, "braces within braces more than #{@depth} deep"}}

  defp field([{:"{", _} | tokens], depth), do: fields(tokens, :"}", depth + 1, [])
  defp field(tokens, _depth), do: {:ok, nil, tokens}

  # Volume 1, 7-3.5.5 to 7-3.5.7: decimal, 0x hexadecimal or 0b binary.
  defp word(text) when byte_size(text) <= @digits do
    {base, digits} =
      case text do
        <<?0, x, digits::binary>> when x in [?x, ?X] -> {16, digits}
        <<?0, b, digits::binary>> when b in [?b, ?B] -> {2, digits}
        digits -> {10, digits}
      end

    case Integer.parse(digits, base) do
      {n, ""} when digits != "" and (base == 10 or n >= 0) -> n
      _other -> {:word, text}
    end
  end

  defp word(text), do: {:word, text}

  defp line({_type, _value, line}), do: line
  defp line({_type, line}), do: line
end
