# for migrate
# update usage last version of migrate: postgres
go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
# for docker file
migrate -path db/migrations -database "postgres://audit_user:korie123@audit-postgres:5434/audit_db?sslmode=disable" up
#for local(dev)
migrate -path db/migrations -database "postgres://audit_user:korie123@localhost:5434/audit_db?sslmode=disable" up
migrate -path db/migrations -database "postgres://audit_user:korie123@localhost:5434/audit_db?sslmode=disable" down 1




# for generate proto files
go get google.golang.org/grpc
go get google.golang.org/protobuf

protoc --proto_path=internal/gateway/grpc/proto --go_out=paths=source_relative:internal/gateway/grpc/pb --go-grpc_out=paths=source_relative:internal/gateway/grpc/pb internal/gateway/grpc/proto/account.proto

# otelemetry

go get go.opentelemetry.io/otel
go get go.opentelemetry.io/otel/sdk/trace
go get go.opentelemetry.io/otel/sdk/metric
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc
go get go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc
go get github.com/gofiber/contrib/otelfiber
go get go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc
