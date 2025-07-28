cmake_minimum_required(VERSION 3.16)

project(wgrpc)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(gRPC CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS program_options)
find_package(Protobuf CONFIG REQUIRED)
find_program(_PROTOBUF_PROTOC protoc)

add_library(wgrpc-proto OBJECT
    "${CMAKE_CURRENT_LIST_DIR}/proto/wg.proto"
)

target_include_directories(wgrpc-proto PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>")
target_link_libraries(wgrpc-proto PUBLIC protobuf::libprotobuf gRPC::grpc++)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/proto)

protobuf_generate(
    TARGET wgrpc-proto
    IMPORT_DIRS "${CMAKE_CURRENT_LIST_DIR}/proto"
    PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto"
)

protobuf_generate(
    TARGET wgrpc-proto
    IMPORT_DIRS "${CMAKE_CURRENT_LIST_DIR}/proto"
    PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto"
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    LANGUAGE grpc
    PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
)

# Gen python
# protoc   -I=proto   --plugin=protoc-gen-grpc_python=$(which grpc_python_plugin)   --python_out=src-client   --grpc_python_out=src-client   proto/*.proto --pyi_out=src-client

# Gen proto doc
# docker run --rm -v $(pwd)/doc:/out -v $(pwd)/proto:/protos pseudomuto/protoc-gen-doc

add_executable(wgrpc
    src/main.cc
    src/wireguard.c
)

target_link_libraries(wgrpc PRIVATE
    cap
    gRPC::grpc++
    gRPC::grpc++_reflection
    Boost::program_options
    wgrpc-proto
)

add_executable(wgrpc-test-client
    src-client/main.cc
)

target_link_libraries(wgrpc-test-client PRIVATE
    gRPC::grpc++
    wgrpc-proto
)