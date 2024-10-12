module github.com/metalogical/BigFiles/BigFiles

go 1.21

toolchain go1.23.1

require (
	github.com/akrylysov/algnhsa v1.1.0
	github.com/metalogical/BigFiles v0.0.0-20201103191605-ca95c8c717cc
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/aws/aws-lambda-go v1.47.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-chi/chi v4.1.2+incompatible // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.10 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/minio/minio-go/v7 v7.0.77 // indirect
	github.com/rs/xid v1.6.0 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

replace (
	github.com/metalogical/BigFiles => github.com/opensourceways/BigFiles v0.0.0-20241012035610-63e677a865f6
	golang.org/x/crypto => golang.org/x/crypto v0.28.0
	golang.org/x/net => golang.org/x/net v0.30.0
	golang.org/x/sys => golang.org/x/sys v0.26.0
	golang.org/x/text => golang.org/x/text v0.19.0
	gopkg.in/yaml.v3 => gopkg.in/yaml.v3 v3.0.1
)
