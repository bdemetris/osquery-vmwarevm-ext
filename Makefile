all: build

APP_NAME = vmwarevm.ext
PKGDIR_TMP = ${TMPDIR}golang

.pre-build:
	mkdir -p build

deps:
	go get -u github.com/golang/dep/...
	go get -u github.com/golang/lint/golint
	dep ensure -vendor-only -v

clean:
	rm -rf build/
	rm -rf ${PKGDIR_TMP}_darwin

build: .pre-build
	GOOS=darwin go build -i -o build/${APP_NAME} -pkgdir ${PKGDIR_TMP}