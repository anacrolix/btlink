module github.com/anacrolix/btlink

go 1.18

require (
	github.com/anacrolix/bargle v0.0.0-20220622082028-6c0bfc8b614d
	github.com/anacrolix/dht/v2 v2.11.1-0.20211104092016-7295f2558a39
	github.com/anacrolix/envpprof v1.1.1
	github.com/anacrolix/generics v0.0.0-20220618083756-f99e35403a60
	github.com/anacrolix/torrent v1.35.1-0.20211104223025-f86af21cd2fe
	github.com/dgraph-io/ristretto v0.1.0
	github.com/dustin/go-humanize v1.0.0
	github.com/multiformats/go-base36 v0.1.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/exp v0.0.0-20220602145555-4a0574d9293f
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/text v0.3.7
)

require (
	github.com/anacrolix/log v0.10.0 // indirect
	github.com/anacrolix/missinggo v1.3.0 // indirect
	github.com/anacrolix/missinggo/v2 v2.5.2 // indirect
	github.com/bradfitz/iter v0.0.0-20191230175014-e8f45d346db8 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20211107104306-e0b2ad06fe42 // indirect
)

replace golang.org/x/crypto => github.com/anacrolix/golang-crypto v0.0.0-20220603051934-c408a93b3ef5
