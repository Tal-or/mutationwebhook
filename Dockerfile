# Use a minimal Go image
FROM golang:1.23 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go source code into the container
COPY . .

# Download dependencies
RUN go mod tidy && go mod vendor

# Build the webhook binary
RUN CGO_ENABLED=0 go build -o webhook cmd/main.go

# Use a lightweight base image
FROM alpine:latest

# Install necessary certificates
#RUN apk add --no-cache ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /app/webhook /bin/webhook

# TLS certificates will be mounted via Kubernetes Secret
RUN mkdir -p /etc/webhook/certs

# Expose the port for Kubernetes API server to reach the webhook
EXPOSE 443

# Run the webhook server
ENTRYPOINT ["/bin/webhook"]
