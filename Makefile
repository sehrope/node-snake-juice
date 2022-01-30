default: clean build

clean:
	rm -rf lib

deps:
	npm ci

build:
	node_modules/.bin/tsc

test:
	npm test

.PHONY: default clean deps build test
