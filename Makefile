default: clean build

clean:
	rm -rf lib

build:
	node_modules/.bin/tsc

test:
	npm test

.PHONY: default clean build test
