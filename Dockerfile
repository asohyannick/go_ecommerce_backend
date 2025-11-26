# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -tags netgo -ldflags "-s -w" -o server ./cmd/server

# Production stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/server .
CMD ["./server"]
