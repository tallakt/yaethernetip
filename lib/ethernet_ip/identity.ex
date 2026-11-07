defmodule EtherNetIP.Identity do
  @moduledoc """
  What a device says it is: the attributes of its Identity object, instance 1 (Volume 1, 5-2),
  as Get_Attributes_All gives them, or as a ListIdentity reply does (Volume 2, 2-4.2), which
  adds the encapsulation protocol version and the device's address and TCP port.

    * `vendor_id`, given by ODVA, and `serial_number`, by the vendor: together unique to the
      device
    * `device_type`, the profile it follows, as 0x0C for a communications adapter
    * `product_code`, the vendor's number for the product
    * `revision`, `{major, minor}`
    * `status`, a word of bits; see `faults/1`
    * `product_name`, at most 32 characters
    * `state`: `:self_testing`, `:standby`, `:operational`, `:major_recoverable_fault`,
      `:major_unrecoverable_fault`, or `nil` for a device that doesn't say
  """

  defstruct [
    :vendor_id,
    :device_type,
    :product_code,
    :revision,
    :status,
    :serial_number,
    :product_name,
    :state,
    :address,
    :protocol_version
  ]

  @type state ::
          :nonexistent
          | :self_testing
          | :standby
          | :operational
          | :major_recoverable_fault
          | :major_unrecoverable_fault
          | nil

  @type t :: %__MODULE__{
          vendor_id: 0..0xFFFF,
          device_type: 0..0xFFFF,
          product_code: 0..0xFFFF,
          revision: {0..255, 0..255},
          status: 0..0xFFFF,
          serial_number: 0..0xFFFF_FFFF,
          product_name: String.t(),
          state: state | 0..254,
          address: {:inet.ip4_address(), :inet.port_number()} | nil,
          protocol_version: 0..0xFFFF | nil
        }

  # Volume 1, Table 5-2.2, attribute 8; 255 is what Get_Attributes_All gives for a device
  # without it.
  @states %{
    0 => :nonexistent,
    1 => :self_testing,
    2 => :standby,
    3 => :operational,
    4 => :major_recoverable_fault,
    5 => :major_unrecoverable_fault,
    255 => nil
  }
  @state_codes Map.new(@states, fn {code, name} -> {name, code} end)

  @doc """
  The identity in the reply to Get_Attributes_All of instance 1. A device need not give the
  attributes after the product name; those it gives after the state are passed over.

      iex> EtherNetIP.Identity.decode(<<1, 0, 0x0C, 0, 0x29, 0, 2, 7, 0x60, 0, 0x78, 0x56, 0x34, 0x12,
      ...>                              4, "Pump", 3>>)
      {:ok, %EtherNetIP.Identity{vendor_id: 1, device_type: 0x0C, product_code: 0x29,
        revision: {2, 7}, status: 0x60, serial_number: 0x12345678, product_name: "Pump",
        state: :operational}}
  """
  @spec decode(binary) :: {:ok, t} | {:error, :invalid}
  def decode(
        <<vendor_id::little-16, device_type::little-16, product_code::little-16, major, minor,
          status::little-16, serial_number::little-32, size, name::binary-size(size),
          rest::binary>>
      ) do
    identity = %__MODULE__{
      vendor_id: vendor_id,
      device_type: device_type,
      product_code: product_code,
      revision: {major, minor},
      status: status,
      serial_number: serial_number,
      # SHORT_STRING is ISO-8859-1 (Volume 1, C-2.1.2).
      product_name: :unicode.characters_to_binary(name, :latin1),
      state: state(rest)
    }

    {:ok, identity}
  end

  def decode(_data), do: {:error, :invalid}

  defp state(<<state, _rest::binary>>), do: Map.get(@states, state, state)
  defp state(<<>>), do: nil

  @doc """
  The identity in the item of a ListIdentity reply (Volume 2, Table 2-4.4), with the device's
  address and TCP port, and its encapsulation protocol version.
  """
  @spec decode_list_identity(binary) :: {:ok, t} | {:error, :invalid}
  def decode_list_identity(
        <<version::little-16, 2::16, port::16, a, b, c, d, _zero::binary-8, identity::binary>>
      ) do
    case decode(identity) do
      {:ok, identity} ->
        {:ok, %{identity | address: {{a, b, c, d}, port}, protocol_version: version}}

      error ->
        error
    end
  end

  def decode_list_identity(_data), do: {:error, :invalid}

  @doc """
  An identity as the reply to Get_Attributes_All of instance 1 gives it, with the attributes up to
  the state.
  """
  @spec encode(t) :: binary
  def encode(%__MODULE__{revision: {major, minor}} = identity) do
    name = :unicode.characters_to_binary(identity.product_name, :utf8, :latin1)

    <<identity.vendor_id::little-16, identity.device_type::little-16,
      identity.product_code::little-16, major, minor, identity.status::little-16,
      identity.serial_number::little-32, byte_size(name), name::binary,
      Map.get(@state_codes, identity.state, identity.state)>>
  end

  @doc """
  The data of the item of a ListIdentity reply, for a device at `address`.
  """
  @spec encode_list_identity(t, {:inet.ip4_address(), :inet.port_number()}) :: binary
  def encode_list_identity(identity, {{a, b, c, d}, port}),
    do: <<1::little-16, 2::16, port::16, a, b, c, d, 0::64, encode(identity)::binary>>

  @doc """
  The faults the status word of a device shows (Volume 1, Table 5-2.3), among
  `:minor_recoverable`, `:minor_unrecoverable`, `:major_recoverable` and `:major_unrecoverable`.

      iex> EtherNetIP.Identity.faults(%EtherNetIP.Identity{status: 0x0500})
      [:minor_recoverable, :major_recoverable]
  """
  @spec faults(t) :: [atom]
  def faults(%__MODULE__{status: status}) do
    for {bit, fault} <- [
          {8, :minor_recoverable},
          {9, :minor_unrecoverable},
          {10, :major_recoverable},
          {11, :major_unrecoverable}
        ],
        Bitwise.band(status, Bitwise.bsl(1, bit)) != 0,
        do: fault
  end
end
