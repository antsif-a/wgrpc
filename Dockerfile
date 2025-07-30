FROM alpine:3.22.1
RUN apk add build-base cmake libcap-dev protobuf-dev grpc-dev boost-dev
WORKDIR  /app
COPY src src
COPY proto proto
COPY CMakeLists.txt CMakeLists.txt
RUN cmake . -Bbuild
RUN cmake --build build
ENTRYPOINT ["./build/wgrpc"]