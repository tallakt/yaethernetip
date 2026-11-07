# yaethernetip

[![CI](https://github.com/tallakt/yaethernetip/actions/workflows/ci.yml/badge.svg)](https://github.com/tallakt/yaethernetip/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/yaethernetip.svg)](https://hex.pm/packages/yaethernetip)
[![Documentation](https://img.shields.io/badge/docs-hexdocs-purple.svg)](https://hexdocs.pm/yaethernetip)
[![License](https://img.shields.io/hexpm/l/yaethernetip.svg)](https://github.com/tallakt/yaethernetip/blob/main/LICENSE)

*Implemented by AI under the supervision of Tallak Tveide.*

Yet another EtherNet/IP: an independent EtherNet/IP stack in pure Elixir, for remote I/O such as
Beckhoff and Wago couplers, and any other device that speaks it.

It was written from ODVA's specification, The CIP Networks Library, Volume 1 (CIP, edition 3.3)
and Volume 2 (EtherNet/IP, edition 1.18), not from another stack's code.

**Status:** a scanner, with explicit messages and class 1 I/O connections; an adapter, a device that
scanners connect to; and EDS files, read and written. The scanner is tested against Wireshark's
dissectors, a target played by the tests, and [OpENer](https://github.com/EIPStackGroup/OpENer), an
open-source EtherNet/IP device, across a network; the adapter against the scanner, Wireshark,
clients played by the tests, and [EIPScanner](https://github.com/nimbuscontrols/EIPScanner), an
open-source scanner, across a network. Neither yet against a vendor's device. What's left is under
[What's missing](#whats-missing).

## Scanner

```elixir
{:ok, scanner} =
  EtherNetIP.Scanner.start_link(
    host: "10.0.0.20",
    connections: [rack: [config: 1, output: 150, input: 100, output_size: 4, input_size: 8]]
  )

{:ok, %EtherNetIP.Identity{product_name: name}} = EtherNetIP.Scanner.identity(scanner)
{:ok, data} = EtherNetIP.Scanner.get_attribute_single(scanner, 0xF5, 1, 5)

:ok = EtherNetIP.Scanner.put(scanner, :rack, <<1, 0, 0, 0>>)
{:ok, <<_::binary-8>>} = EtherNetIP.Scanner.inputs(scanner, :rack)
```

A scanner is a session with one device. `request/5` sends any service to any path as an
unconnected message, through a backplane or other port with `route:`, and up to four go at once.
The I/O connections of `connections:` are opened with Forward_Open and kept open: the scanner sends
the outputs every RPI, takes the inputs the device sends, and opens a connection again when its
inputs stop or the device refuses it. A subscriber gets new inputs, and every change of a
connection's state, as messages.

The scanner reconnects by itself, and an I/O connection goes on while its TCP connection is down,
as the spec has it. It never logs, and never exits the caller; `EtherNetIP.describe/1` puts the
reasons it gives in words.

A device keeps a connection whose scanner went without closing it, as when its node failed, and
gives it back only to the same owner. A scanner is that owner by the node's serial number, which
it takes from the node's network hardware address, so that after a restart it gets its connections
back where one with a new serial number would be refused.

The I/O of every scanner and adapter in a node goes through one UDP socket on port 2222, where
multicast inputs come whoever they are for; each packet goes to the connection whose id and
sender it has, and others are dropped. The ids are the node's, so that two scanners of one device
never take each other's inputs, and multicast groups are joined on the interface the device is
reached on, as on a PC with a network card of its own for I/O.

The scanner takes nothing on trust from a device: a reply to a Forward_Open must be to that
Forward_Open, with packet intervals the scanner can keep to, and a device that never answers
RegisterSession is disconnected and tried again. Options are checked when the scanner starts,
and a misspelt one is refused, where its default would otherwise be taken.

## Adapter

```elixir
{:ok, adapter} =
  EtherNetIP.Adapter.start_link(
    identity: [vendor_id: 0xFFFF, product_code: 1, product_name: "Pump skid"],
    inputs: %{100 => 32},
    outputs: %{150 => 32},
    configuration: %{151 => 10},
    input_only: 152,
    listen_only: 153,
    subscriber: self()
  )

:ok = EtherNetIP.Adapter.put(adapter, 100, inputs)
{:ok, %{data: outputs, state: :run, at: at}} = EtherNetIP.Adapter.outputs(adapter, 150)

File.write!("pump_skid.eds", EtherNetIP.Adapter.eds(options, vendor_name: "Acme"))
```

An adapter is the BEAM as a device: a PLC opens connections to its assemblies, takes its inputs
and sets its outputs. It has the objects every EtherNet/IP device has, answers explicit messages
unconnected and over class 3 connections, and ListIdentity over UDP for discovery. Its I/O
connections are exclusive owners, of which an output assembly takes one at a time, input-only and
listen-only; inputs go point to point, or by multicast, which connections to the same inputs share.
It checks a Forward_Open as the CIP conformance tests do, and refuses what doesn't fit with the
extended status they expect.

`put/3` and `outputs/2` don't wait on the adapter's process: the data is in a table, and a put that
changes inputs a connection takes by change of state sends them at once. A subscriber gets new
outputs, run/idle, configuration and every connection opened and closed. When an owner's outputs
stop, `outputs/2` says `:closed`, and its inputs stop too, so that its PLC knows.

`eds/2` writes the adapter's EDS from the same options, for the PLC's tool to add it by; the
scanner's EDS reader reads it, and its connections open against the adapter.

## EDS files

A device's Electronic Data Sheet gives the scanner its connections by name, in place of numbers
read out of a manual: the assemblies and their sizes, the real-time formats, the RPI and its range,
and the configuration data, with the defaults of its parameters or the values you give them.

```elixir
{:ok, eds} = EtherNetIP.EDS.read("coupler.eds")
{:ok, rack} = EtherNetIP.EDS.connection(eds, "Exclusive Owner", rpi: 20_000, subscriber: self())
{:ok, scanner} = EtherNetIP.Scanner.start_link(host: "10.0.0.20", connections: [rack: rack])

{:ok, members} = EtherNetIP.EDS.layout(eds, 100)
```

`EDS.connection/3` refuses what the EDS says the device doesn't take, such as an RPI out of its range
or point-to-point inputs on a listen-only connection. `layout/2` gives where each parameter is in
an assembly's data, with its name, type and units. `matches?/2` tells whether an EDS is the one for
a device's identity.

EDS files from outside stray from the spec, and are read as leniently as their meaning allows. No
file, however broken or hostile, makes the reader raise or take long: what can't be read is an error
with its line, and assemblies nested past reason are refused.

## What's missing

- The scanner: discovery by ListIdentity broadcast, class 3 connected explicit messages, Rockwell
  Logix tags.
- The adapter: multicast outputs (O->T), which few scanners use, and a ListIdentity over UDP is
  answered after a random delay as a broadcast is, unicast or not, since a UDP socket doesn't say
  which it was. Multicast inputs leave by the interface the scanner reached the adapter on.
- Tried against OpENer, EIPScanner and itself only, not yet against a vendor's device or PLC.

## Tests

`test/ethernet_ip/tshark_test.exs` has [Wireshark](https://www.wireshark.org)'s ENIP and CIP
dissectors, decoders written independently of this one, read a thousand generated messages back
field by field: requests with paths of every width, Forward_Opens and their replies, Large
Forward_Opens, Unconnected_Sends and error replies, ListIdentity replies, and I/O packets. They run
where tshark is found: `TSHARK`, the `PATH`, or Wireshark's app on macOS.

The scanner's tests play the target, a message at a time over TCP and UDP. The adapter's tests run
the scanner against it, and play clients for what the scanner doesn't send: encapsulation commands,
class 3 connections, and Forward_Opens it would refuse to send; and the replies of a live adapter go
through Wireshark's dissectors too. They also fuzz a live adapter: random and mutated requests over
a session, Forward_Opens, Multiple_Service_Packets and Unconnected_Sends among them, each of which
must be answered, and mangled I/O packets for an open connection, which must leave it as it was. The property tests fuzz
with [StreamData](https://github.com/whatyouhide/stream_data): everything encoded decodes back to
what it was, and random and mutated bytes go into every decoder, which must not crash. For more
cases:

```
FUZZ_RUNS=10000 mix test test/ethernet_ip/property_test.exs
```

`test/ethernet_ip/opener_test.exs` runs the scanner against OpENer's sample application, used as
a black box, from what its EDS file says and what it answers: explicit messages, an exclusive owner
with point-to-point and with multicast inputs, input-only and listen-only connections beside it, a
connection it refuses, and one a killed scanner left behind. OpENer runs on Linux; build it with
CMake, start it as `OpENer eth0` on another machine, and give the tests its address:

```
OPENER=192.168.0.110 mix test test/ethernet_ip/opener_test.exs
```

`test/ethernet_ip/eipscanner_test.exs` runs EIPScanner against the adapter, used as a black box
through its documented API, in the program of `test/interop/eipscanner`: discovery by broadcast,
the Identity object, an assembly written and read, Forward_Opens refused for their size and for a
second owner, an exclusive owner and an input-only connection whose outputs come back as inputs,
Forward_Close, and a connection left to time out. Install EIPScanner with CMake, build the program
against it with `cmake -DEIPSCANNER=<where it is installed>`, and give the tests the command that
runs it, over ssh for another machine, where nothing else may hold UDP port 2222:

```
EIPSCANNER="ssh 192.168.0.110 build/eip_peer" mix test test/ethernet_ip/eipscanner_test.exs
```

`test/ethernet_ip/eds_corpus_test.exs` reads every EDS file in a folder of vendors' files, which
stay out of this repository: each must be read, and it counts the connections the scanner can't open
by why.

```
EDS_CORPUS=~/eds mix test --only eds_corpus
```

## License

Copyright 2026 Tallak Tveide. Licensed under the Apache License, Version 2.0; see
[LICENSE](LICENSE) and [NOTICE](NOTICE).

The specification isn't in this repository, nor is its text: the code and the docs say what the
protocol does in their own words, and cite its clauses by number. What they take from it is what
any implementation has to match: message layouts, codes and numbers.

yaethernetip isn't made, endorsed or certified by ODVA, and it hasn't been through ODVA's
conformance test. ODVA grants the right to make, use or sell products that implement its
specifications only under its Terms of Usage Agreement; ask ODVA before you build a product on
yaethernetip.

EtherNet/IP™ and CIP™ are trademarks of ODVA, Inc.
