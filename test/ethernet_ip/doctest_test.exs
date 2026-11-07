defmodule EtherNetIP.DoctestTest do
  use ExUnit.Case, async: true

  doctest EtherNetIP
  doctest EtherNetIP.Path
  doctest EtherNetIP.CIP
  doctest EtherNetIP.Encapsulation
  doctest EtherNetIP.CPF
  doctest EtherNetIP.Identity
  doctest EtherNetIP.ConnectionManager
  doctest EtherNetIP.IOPacket
end
