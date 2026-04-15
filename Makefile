BINARY   := sssh
VERSION  := 1.1.0
GOFLAGS  := -trimpath -ldflags="-s -w -X main.version=$(VERSION)"
PREFIX   := /usr/local/bin

.PHONY: build test install clean universal

build:
	go build $(GOFLAGS) -o $(BINARY) .

universal:
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(BINARY)-arm64 .
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY)-amd64 .
	lipo -create -output $(BINARY)-universal $(BINARY)-arm64 $(BINARY)-amd64
	rm -f $(BINARY)-arm64 $(BINARY)-amd64

test:
	go test -v ./...

install: build
	sudo install -m 755 $(BINARY) $(PREFIX)/$(BINARY)

install-universal: universal
	sudo install -m 755 $(BINARY)-universal $(PREFIX)/$(BINARY)

clean:
	rm -f $(BINARY) $(BINARY)-arm64 $(BINARY)-amd64 $(BINARY)-universal
