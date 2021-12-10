# Nym bidirectional data streaming

This is an experimental repo exploring how to build bidirectional data transfer using SURBs on Nym.
As an example there is currently a SOCKS proxy and exit node implementation.
The SOCKS proxy is the `client` binary, the exit node is the `server` binary.
The client is meant to stay anonymous while the server is a known service provider.