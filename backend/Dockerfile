FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/routershark ./cmd/routershark

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections && apt-get install -y --no-install-recommends tshark ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/routershark /usr/local/bin/routershark
EXPOSE 8080 37008/udp
ENTRYPOINT ["routershark"]
