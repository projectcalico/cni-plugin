module github.com/projectcalico/cni-plugin

go 1.19

require (
	github.com/Microsoft/hcsshim v0.9.8
	github.com/buger/jsonparser v1.1.1
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.9.1
	github.com/gofrs/flock v0.8.1
	github.com/gogo/protobuf v1.3.2
	github.com/howeyc/fsnotify v0.9.0
	github.com/juju/clock v1.0.3
	github.com/juju/errors v1.0.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/natefinch/atomic v1.0.1
	github.com/nmrshll/go-cp v0.0.0-20180115193924-61436d3b7cfa
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.3
	github.com/projectcalico/libcalico-go v1.7.2-0.20211119233600-e3f7c620522a
	github.com/prometheus/common v0.26.0
	github.com/rakelkar/gonetsh v0.3.2
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	golang.org/x/net v0.8.0
	golang.org/x/sys v0.6.0
	google.golang.org/grpc v1.51.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	k8s.io/api v0.20.15
	k8s.io/apimachinery v0.20.15
	k8s.io/client-go v0.20.15
	k8s.io/utils v0.0.0-20230313181309-38a27ef9d749
)

require (
	github.com/juju/mutex v0.0.0-20180619145857-d21b13acf4bf
	go.etcd.io/etcd v3.3.27+incompatible
)

require (
	cloud.google.com/go/compute v1.12.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.1 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.23 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/alexflint/go-filemutex v0.0.0-20171022225611-72bdc8eae2ae // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/containerd/cgroups v1.0.1 // indirect
	github.com/coreos/bbolt v1.3.7 // indirect
	github.com/coreos/etcd v3.3.27+incompatible // indirect
	github.com/coreos/go-iptables v0.5.0 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-logr/logr v1.2.0 // indirect
	github.com/go-playground/locales v0.12.1 // indirect
	github.com/go-playground/universal-translator v0.0.0-20170327191703-71201497bace // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/gnostic v0.4.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/json-iterator/go v1.1.11 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/leodido/go-urn v0.0.0-20181204092800-a67a23e1c1af // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/nxadm/tail v1.4.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/projectcalico/go-json v0.0.0-20161128004156-6219dc7339ba // indirect
	github.com/projectcalico/go-yaml-wrapper v0.0.0-20191112210931-090425220c54 // indirect
	github.com/prometheus/client_golang v1.11.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	github.com/safchain/ethtool v0.0.0-20190326074333-42ed695e3de8 // indirect
	github.com/soheilhy/cmux v0.1.5 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20201229170055-e5319fda7802 // indirect
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	go.opencensus.io v0.23.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/oauth2 v0.6.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/term v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230215201556-9c5414ab4bde // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20221024183307-1bc688fe9f3e // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6 // indirect
	gopkg.in/go-playground/validator.v9 v9.27.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.1.2 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

replace github.com/dgrijalva/jwt-go => github.com/golang-jwt/jwt/v4 v4.4.2

replace github.com/coreos/bbolt => go.etcd.io/bbolt v1.3.7

replace github.com/coreos/etcd/v3 => go.etcd.io/etcd/v3 v3.5.7

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1

//replace github.com/juju/mutex => github.com/juju/mutex/v2 v2.0.0

//replace github.com/golang/mock => github.com/golang/mock v1.6.0

replace cloud.google.com/go/compute/metadata => cloud.google.com/go/compute/metadata v0.2.1
