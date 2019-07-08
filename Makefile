SRC := $(shell find . -type f -name '*.go'; echo go.mod)

.PHONY: complete
complete:
	go build -i -buildmode=default -tags '$(TAGS)' -o /dev/null ./cmd/ym/*.go

