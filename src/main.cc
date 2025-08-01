#include <print>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <csignal>

#include <arpa/inet.h>
#include <sys/capability.h>
#include <sys/signalfd.h>

#include <boost/program_options.hpp>
#include <grpc++/grpc++.h>
#include <grpc++/ext/proto_server_reflection_plugin.h>

#include <proto/wg.pb.h>
#include <proto/wg.grpc.pb.h>

extern "C" {
    #include "wireguard.h"
}

constexpr std::string DEFAULT_ADDRESS = "[::]";
constexpr in_port_t DEFAULT_PORT = 50051;

using std::println;

using namespace proto;
using namespace grpc;
using namespace grpc::reflection;

namespace po = boost::program_options;

/*
todo:
ipv6 support in endpoint and allowed ips
check if device exists before get/add/del?
Peer::last_handshake_time in seconds is incorrect
authentication (even grpcurl doesn't work with InsecureServerCredentials)
wireguard.c: make errors concise and informative
i'm not sure how shutdown thread is safe
clean up main function (too much responsibility?)
*/

void set_endpoint_m(Endpoint * m, wg_endpoint * endpoint) {
    if (endpoint->addr.sa_family == AF_INET) {
        m->set_ipv4(ntohl(endpoint->addr4.sin_addr.s_addr));
        m->set_port(endpoint->addr4.sin_port);
    } else {
        // unimplemented
    }
}

void set_ip_address_m(IpAddress * m, wg_allowedip * allowed_ip) {
    if (allowed_ip->family == AF_INET) {
        m->set_ipv4(ntohl(allowed_ip->ip4.s_addr));
        m->set_cidr(allowed_ip->cidr);
    } else {
        // unimplemented
    }
}

void set_peer_m(Peer * m, wg_peer * peer) {
    wg_key_b64_string tmp_key;

    if (peer->flags & WGPEER_HAS_PUBLIC_KEY) {
        wg_key_to_base64(tmp_key, peer->public_key);
        m->set_public_key(tmp_key);
    }

    if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
        wg_key_to_base64(tmp_key, peer->preshared_key);
        m->set_preshared_key(tmp_key);
    }

    set_endpoint_m(m->mutable_endpoint(), &peer->endpoint);

    m->set_rx_bytes(peer->rx_bytes);
    m->set_tx_bytes(peer->tx_bytes);

    if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
        m->set_persistent_keepalive_interval(peer->persistent_keepalive_interval);

    auto last_handshake_time = m->mutable_last_handshake_time();
    last_handshake_time->set_tv_nsec(peer->last_handshake_time.tv_nsec);
    last_handshake_time->set_tv_sec(peer->last_handshake_time.tv_sec);

    wg_allowedip* allowed_ip;
    wg_for_each_allowedip(peer, allowed_ip) {
        set_ip_address_m(m->add_allowed_ips(), allowed_ip);
    }
}

void set_device_m(Device * m, const char * device_name, wg_device * device) {
    m->set_name(device_name);

    wg_key_b64_string key;

    if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) {
        wg_key_to_base64(key, device->public_key);
        m->set_public_key(key);
    }

    if (device->flags & WGDEVICE_HAS_PRIVATE_KEY) {
        wg_key_to_base64(key, device->private_key);
        m->set_private_key(key);
    }

    m->set_listen_port(device->listen_port);
    if (device->flags & WGDEVICE_HAS_LISTEN_PORT) {
        m->set_listen_port(device->listen_port);
    }

    if (device->flags & WGDEVICE_HAS_FWMARK) {
        m->set_fwmark(device->fwmark);
    }

    wg_peer* peer;
    wg_for_each_peer(device, peer) {
        set_peer_m(m->add_peers(), peer);
    }
}

wg_allowedip configure_allowed_ip(IpAddress cfg) {
    wg_allowedip allowed_ip = {};
    if (cfg.has_ipv4()) {
        allowed_ip.family = AF_INET;
        allowed_ip.ip4.s_addr = htonl(cfg.ipv4());
        allowed_ip.cidr = cfg.cidr();
    } else if (cfg.has_ipv6()) {
        allowed_ip.family = AF_INET6;
        // unimplemented
    }

    return allowed_ip;
}

wg_endpoint configure_endpoint(Endpoint cfg) {
    wg_endpoint endpoint = {};
    if (cfg.has_ipv4()) {
        endpoint.addr4.sin_family = AF_INET;
        endpoint.addr4.sin_addr.s_addr = htonl(cfg.ipv4());
        endpoint.addr4.sin_port = htons(cfg.port());
    } else if (cfg.has_ipv6()) {
        endpoint.addr6.sin6_family = AF_INET6;
        // unimplemented
    }

    return endpoint;
}

wg_peer configure_peer(PeerConfiguration cfg, std::vector<wg_allowedip> & allowed_ips) {
    wg_peer peer = {};
    int flags = 0;

    flags |= WGPEER_HAS_PUBLIC_KEY;
    wg_key_from_base64(peer.public_key, cfg.public_key().c_str());

    if (cfg.has_preshared_key()) {
        flags |= WGPEER_HAS_PRESHARED_KEY;
        wg_key_from_base64(peer.preshared_key, cfg.preshared_key().c_str());
    }

    if (cfg.has_endpoint()) {
        peer.endpoint = configure_endpoint(cfg.endpoint());
    }

    if (cfg.has_persistent_keepalive_interval()) {
        flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
        peer.persistent_keepalive_interval = cfg.persistent_keepalive_interval();
    }

    flags |= WGPEER_REPLACE_ALLOWEDIPS;
    allowed_ips.reserve(cfg.allowed_ips_size());
    for (auto & allowed_ip_cfg : cfg.allowed_ips()) {
        auto allowed_ip = configure_allowed_ip(allowed_ip_cfg);
        allowed_ips.push_back(allowed_ip);
    }

    for (size_t i = 0; i + 1 < allowed_ips.size(); ++i) {
        allowed_ips[i].next_allowedip = &allowed_ips[i + 1];
    }
    peer.first_allowedip = &allowed_ips[0];
    peer.last_allowedip  = &allowed_ips.back();

    peer.flags = static_cast<wg_peer_flags>(flags);
    return peer;
}

wg_device configure_device(
    std::string_view name, DeviceConfiguration cfg, std::vector<wg_peer> & peers, std::vector<std::vector<wg_allowedip>> & allowed_ips
) {
    wg_device device = {};
    int flags = 0;

    std::strncpy(device.name, name.data(), name.size());
    
    if (cfg.has_listen_port()) {
        flags |= WGDEVICE_HAS_LISTEN_PORT;
        device.listen_port = cfg.listen_port();
    }

    if (cfg.has_fwmark()) {
        flags |= WGDEVICE_HAS_FWMARK;
        device.fwmark = cfg.fwmark();
    }

    peers.reserve(cfg.peers_size());
    for (auto & peer_cfg : cfg.peers()) {
        auto peer = configure_peer(peer_cfg, allowed_ips.emplace_back());
        peers.push_back(peer);
    }

    for (size_t i = 0; i + 1 < peers.size(); ++i) {
        peers[i].next_peer = &peers[i + 1];
    }

    // replace peers every call
    flags |= WGDEVICE_REPLACE_PEERS;
    device.first_peer = &peers[0];
    device.last_peer  = &peers.back();

    device.flags = static_cast<wg_device_flags>(flags);

    return device;
}

class WireGuardServiceImpl : public WireGuardService::Service {
    Status CreateDevice(ServerContext *, const CreateDevice::Request * req, EmptyResponse *) override {
        if (wg_add_device(req->name().c_str()) < 0)
            return Status(StatusCode::UNAVAILABLE, "Unable to add device");
        return Status::OK;
    }

    Status ConfigureDevice(ServerContext * ctx, const ConfigureDevice::Request * req, EmptyResponse *) override {
        std::vector<wg_peer> peers;
        std::vector<std::vector<wg_allowedip>> allowed_ips;

        auto device = configure_device(req->name(), req->config(), peers, allowed_ips);

        if (wg_set_device(&device) < 0)
            return Status(StatusCode::UNAVAILABLE, "Unable to set device");
        
        return Status::OK;
    }

    Status GetDevices(ServerContext * _, const EmptyRequest *, GetDevices::Response * res) override {
        auto device_names = wg_list_device_names();
        if (!device_names) {
            return Status(StatusCode::UNAVAILABLE, "Unable to get device names");
        }

        char * device_name; size_t len;
        wg_for_each_device_name(device_names, device_name, len) {
            wg_device *device;
            if (wg_get_device(&device, device_name) < 0) {
                println(stderr, "Unable to get device: {}", device_name);
                continue;
            }

            set_device_m(res->add_devices(), device_name, device);
            wg_free_device(device);
	    }
        std::free(device_names);

        return Status::OK;
    }
    
    Status GetDevice(ServerContext *, const GetDevice::Request * req, GetDevice::Response * res) override {
        wg_device* device;

        if (wg_get_device(&device, req->name().c_str()) < 0)
            return Status(StatusCode::NOT_FOUND, "Unable to get device");
        
        set_device_m(res->mutable_device(), req->name().c_str(), device);
        wg_free_device(device);
        return Status::OK;
    }

    Status DeleteDevice(ServerContext *, const DeleteDevice::Request * req, EmptyResponse *) override {
        if (wg_del_device(req->name().c_str()) < 0)
            return Status(StatusCode::UNAVAILABLE, "Unable to add device");
        return Status::OK;
    }

    Status GeneratePrivateKey(ServerContext *, const EmptyRequest *, GeneratePrivateKey::Response * res) override {
        uint8_t key;
        wg_key_b64_string key_b64; 
        wg_generate_private_key(&key);
        wg_key_to_base64(key_b64, &key);

        res->set_key(key_b64);
        return Status::OK;
    }

    Status GeneratePublicKey(ServerContext *, const GeneratePublicKey::Request * req, GeneratePublicKey::Response * res) override {
        uint8_t private_key;
        wg_key_b64_string private_key_b64;
        std::strncpy(private_key_b64, req->private_key().data(), sizeof(wg_key_b64_string));
        if (wg_key_from_base64(&private_key, private_key_b64) < 0)
            return Status(StatusCode::INVALID_ARGUMENT, "Invalid public key");

        uint8_t key;
        wg_key_b64_string key_b64; 
        wg_generate_public_key(&key, &private_key);
        wg_key_to_base64(key_b64, &key);

        res->set_key(key_b64);
        return Status::OK;
    }

    Status GeneratePresharedKey(ServerContext *, const EmptyRequest *, GeneratePresharedKey::Response * res) override {
        uint8_t key; char * key_b64; 
        wg_generate_preshared_key(&key);
        wg_key_to_base64(key_b64, &key);

        res->set_key(key_b64);
        return Status::OK;
    }

};

std::unique_ptr<Server> run_server(std::string_view address, in_port_t port, WireGuardServiceImpl * wg_service) {
    InitProtoReflectionServerBuilderPlugin();
    auto server = ServerBuilder()
        .AddListeningPort(std::format("{}:{}", address, port), InsecureServerCredentials())
        .RegisterService(wg_service)
        .BuildAndStart();

    if (server == nullptr)
        throw std::runtime_error("Could not start gRPC server");

    return server;
}

void check_cap_net_admin() {
    auto capabilities = cap_get_proc();
    if (!capabilities)
        throw std::runtime_error("Failed to get process capabilities");

    cap_flag_value_t flag;
    if (cap_get_flag(capabilities, CAP_NET_ADMIN, CAP_PERMITTED, &flag) != 0)
        throw std::runtime_error("Failed to check CAP_NET_ADMIN capability");

    if (flag != CAP_SET)
        throw std::logic_error("CAP_NET_ADMIN capability is required");
}

int setup_signalfd() {
    sigset_t mask {};
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0)
        throw std::runtime_error("Could not set up process signal mask");
    auto sfd = signalfd(-1, &mask, 0);
    if (sfd < 0)
        throw std::runtime_error("Could not set up process signal mask");
    return sfd;
}

int main(int argc, const char * argv[]) {
    try {
        check_cap_net_admin();
    } catch (std::exception & err) {
        println(stderr, "{}", err.what());
        return 1;
    }

    po::options_description description("Options");
    description.add_options()
        ("help", "Show help")
        ("address", po::value<std::string>()->value_name("ip")->default_value(DEFAULT_ADDRESS), "Set address")
        ("port", po::value<in_port_t>()->value_name("port")->default_value(DEFAULT_PORT), "Set port");

    po::variables_map m;
    try {
        po::store(po::parse_command_line(argc, argv, description), m);
    } catch (po::error_with_option_name & err) {
        println(stderr, "{}", err.what());
        println(stderr, "Usage: wgrpc [options]");
        println(stderr);
        description.print(std::cerr);
        return 1;
    }

    po::notify(m);

    if (m.count("help")) {
        println(stderr, "Usage: wgrpc [options]");
        println(stderr);
        description.print(std::cerr);
        return 1;
    }

    auto address = m["address"].as<std::string>();
    auto port = m["port"].as<in_port_t>();

    try {
        auto signalfd = setup_signalfd();
        WireGuardServiceImpl wg_service;
        auto server = run_server(address, port, &wg_service);
        println("Server listening on {}:{}", address, port);

        std::thread shutdown([&signalfd, &server]() {
            struct signalfd_siginfo info;
            if (read(signalfd, &info, sizeof(info)) > 0) {
                println("Shutting down...");
                server->Shutdown();
            }
        });

        server->Wait();
        shutdown.join();
    } catch (std::exception & err) {
        println(stderr, "{}", err.what());
        return 1;
    }
}
