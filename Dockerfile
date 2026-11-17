FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /morse-seal ./cmd/morse-seal

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /morse-seal /morse-seal
EXPOSE 4141
ENTRYPOINT ["/morse-seal", "--listen", "0.0.0.0:4141"]
