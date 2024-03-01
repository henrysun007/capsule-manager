FROM secretflow/capsule-manager-ci:0.1.0b as builder

WORKDIR /home/admin/dev

env RUSTUP_DIST_SERVER="https://rsproxy.cn"
env RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"

COPY Cargo.toml ./
COPY capsule-manager ./capsule-manager
COPY capsule-manager-tonic ./capsule-manager-tonic
COPY deployment ./deployment

COPY config /root/.cargo/

RUN cat /root/.cargo/config
RUN apt update && apt install clang -y
RUN openssl genrsa -3 -out private_key.pem 3072 \
    && openssl rsa -in private_key.pem -pubout -out public_key.pem

RUN rustup install 1.75.0 && rustup default 1.75.0
RUN KEY_PATH=private_key.pem bash deployment/build.sh

FROM secretflow/capsule-manager-ci:0.1.0b

COPY --from=builder /home/admin/dev/occlum_release /home/admin/occlum_release

WORKDIR /home/admin/occlum_release
