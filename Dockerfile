FROM rust:latest

WORKDIR /usr/src/app
COPY . .

RUN cargo install --path .
RUN cargo b -r --bin epoxy-server

CMD ["./target/release/epoxy-server", "--help"]
