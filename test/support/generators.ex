defmodule EtherNetIP.Test.Generators do
  @moduledoc false
  # StreamData generators of what the library encodes, for the property and tshark tests.

  import StreamData
  import ExUnitProperties, only: [gen: 1, gen: 2]

  alias EtherNetIP.Identity

  def u8, do: integer(0..0xFF)
  def u16, do: integer(0..0xFFFF)
  def u32, do: integer(0..0xFFFF_FFFF)

  # A value of a logical segment, as often small as large, so that every width comes.
  def logical(max) do
    [0..0xFF, 0x100..0xFFFF, 0x10000..0xFFFF_FFFF]
    |> Enum.filter(&(&1.first <= max))
    |> Enum.map(&integer(&1.first..min(&1.last, max)))
    |> one_of()
  end

  # A path to a class, an instance and maybe an attribute.
  def object_path do
    gen all class <- logical(0xFFFF),
            instance <- logical(0xFFFF_FFFF),
            attribute <- one_of([constant(nil), logical(0xFFFF)]) do
      [class: class, instance: instance] ++ if(attribute, do: [attribute: attribute], else: [])
    end
  end

  def port_segment do
    gen all port <- integer(1..0xFFFF),
            link <- one_of([u8(), ip_string()]) do
      {:port, port, link}
    end
  end

  def ip_string do
    gen all bytes <- list_of(u8(), length: 4), do: Enum.join(bytes, ".")
  end

  def segment do
    one_of([
      tuple({member_of([:class, :attribute, :member]), logical(0xFFFF)}),
      tuple({member_of([:instance, :connection_point]), logical(0xFFFF_FFFF)}),
      port_segment(),
      gen(
        all v <- u16(),
            d <- u16(),
            p <- u16(),
            ma <- integer(0..127),
            mi <- u8(),
            c <- boolean(),
            do: {:key, v, d, p, ma, mi, c}
      ),
      gen(all name <- string(:alphanumeric, min_length: 1, max_length: 40), do: {:symbol, name}),
      gen(all words <- integer(0..20), data <- binary(length: words * 2), do: {:data, data}),
      tuple({constant(:production_inhibit), u8()})
    ])
  end

  def path, do: list_of(segment(), max_length: 8)

  def direction(large) do
    gen all rpi <- u32(),
            size <- integer(0..if(large, do: 0xFFFF, else: 511)),
            type <- member_of([:null, :multicast, :point_to_point]),
            priority <- member_of([:low, :high, :scheduled, :urgent]),
            fixed <- boolean(),
            redundant_owner <- boolean() do
      %{
        rpi: rpi,
        size: size,
        type: type,
        priority: priority,
        fixed: fixed,
        redundant_owner: redundant_owner
      }
    end
  end

  def forward_open do
    gen all large <- boolean(),
            o_t <- direction(large),
            t_o <- direction(large),
            o_t_id <- u32(),
            t_o_id <- u32(),
            serial <- u16(),
            vendor_id <- u16(),
            originator_serial <- u32(),
            multiplier <- member_of([4, 8, 16, 32, 64, 128, 256, 512]),
            trigger <-
              tuple(
                {member_of([:client, :server]),
                 member_of([:cyclic, :change_of_state, :application]), integer(0..3)}
              ),
            timeout <- integer(1..8_355_840),
            route <- list_of(port_segment(), max_length: 2),
            configuration <- logical(0xFFFF),
            consumed <- logical(0xFFFF),
            produced <- logical(0xFFFF) do
      %{
        large: large,
        timeout: timeout,
        o_t_id: o_t_id,
        t_o_id: t_o_id,
        serial: serial,
        vendor_id: vendor_id,
        originator_serial: originator_serial,
        multiplier: multiplier,
        o_t: o_t,
        t_o: t_o,
        trigger: trigger,
        path:
          route ++
            [
              class: 4,
              instance: configuration,
              connection_point: consumed,
              connection_point: produced
            ]
      }
    end
  end

  def identity do
    gen all vendor_id <- u16(),
            device_type <- u16(),
            product_code <- u16(),
            major <- u8(),
            minor <- u8(),
            status <- u16(),
            serial_number <- u32(),
            name <- string(:alphanumeric, max_length: 32),
            state <-
              member_of([
                :self_testing,
                :standby,
                :operational,
                :major_recoverable_fault,
                :major_unrecoverable_fault,
                nil
              ]) do
      %Identity{
        vendor_id: vendor_id,
        device_type: device_type,
        product_code: product_code,
        revision: {major, minor},
        status: status,
        serial_number: serial_number,
        product_name: name,
        state: state
      }
    end
  end
end
