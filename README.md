wgrpc
=====

This is a lightweight gRPC service that can create, read, configure and delete [WireGuard](https://www.wireguard.com) devices, written in C++ with performance and security in mind.

Build
-----

```sh
cmake -Bbuild .
cmake --build build
```
A binary would be avaliable at `./build/wgrpc`.

Usage
-----


> The server requires `CAP_NET_ADMIN` capability to manage network devices. You can either run the binary as root or manually attach this capability, see [capabilities(7)](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).

```
Usage: wgrpc [options]

Options:
  --help                Show help
  --address ip (=[::])  Set address
  --port port (=50051)  Set port
```

This server supports [gRPC Reflection](https://grpc.io/docs/guides/reflection/), so you can interact with server using tools like [gRPCurl](https://github.com/fullstorydev/grpcurl) or [grpc-cli](https://github.com/grpc/grpc/blob/master/doc/command_line_tool.md):
```
$ grpc_cli ls localhost:50051 proto.WireGuardService
CreateDevice
ConfigureDevice
GetDevices
GetDevice
DeleteDevice
GeneratePrivateKey
GeneratePublicKey
GeneratePresharedKey
```
```
$ grpc_cli call localhost:50051 proto.WireGuardService.GeneratePrivateKey
reading request message from stdin...
connecting to localhost:50051
key: "oN7o8iA3E1XvPOSs+W5X7Q5vTjdvOGlBM0UxWHZQT1M="
Rpc succeeded with OK status
```