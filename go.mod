module antrea.io/ofnet

go 1.19

require (
	antrea.io/libOpenflow v0.11.0
	github.com/Microsoft/go-winio v0.6.1
	github.com/contiv/libovsdb v0.0.0-20170227191248-d0061a53e358
	github.com/orcaman/concurrent-map/v2 v2.0.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/cenkalti/hub v1.0.1-0.20140529221144-7be60e186e66 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20140912135055-44d0d95e4f52 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.2.0 // indirect
	github.com/kr/pretty v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.100.1 // indirect
)

replace antrea.io/libOpenflow v0.11.0 => github.com/wenyingd/libOpenflow v0.0.0-20230703031726-b8cc9e7eda69
