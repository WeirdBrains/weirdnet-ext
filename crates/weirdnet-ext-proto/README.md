# weirdnet-ext-proto

`weirdnet.ext.v1`: the protobuf contract between a Weirdnet extension host and its
extensions, with tonic client and server stubs (protoc is bundled; nothing to install).

The host serves `Host` on a private socket it made for the extension: `Handshake` (one-time
token, extension id, API version), `Events` (Stop, grant changes, pings, app events),
`Call` (app services such as `morph.ext.v1`, checked against the grants), `Log` and
`Health`. App services travel as prost-encoded bytes, so the contract is the same for every
app. See `proto/weirdnet/ext/v1/ext.proto`.

Hosts use [`weirdnet-ext`](https://crates.io/crates/weirdnet-ext); extensions use
[`weirdnet-ext-sdk`](https://crates.io/crates/weirdnet-ext-sdk). BSD-3-Clause.
