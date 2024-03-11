FROM rustlang/rust:nightly

WORKDIR /usr/src/app
COPY . .

RUN cargo b -r --bin epoxy-server

EXPOSE 4000

CMD ["./target/release/epoxy-server", "--help"]
