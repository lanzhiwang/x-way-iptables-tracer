# Run go fmt against code
fmt:
	GOPROXY="https://goproxy.cn,direct" go fmt ./...

# Run go vet against code
vet:
	GOPROXY="https://goproxy.cn,direct" go vet ./...

# Build manager binary
manager: fmt vet
	GOPROXY="https://goproxy.cn,direct" go mod tidy
	GOPROXY="https://goproxy.cn,direct" go build -o bin/iptables-tracer
