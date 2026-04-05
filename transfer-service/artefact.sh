# for migrate
# update usage last version of migrate: postgres
go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
# for docker file
migrate -path db/migrations -database "postgres://transfer_user:korie123@transfer-postgres:5434/transfer_db?sslmode=disable" up
#for local(dev)
migrate -path db/migrations -database "postgres://transfer_user:korie123@localhost:5434/transfer_db?sslmode=disable" up
migrate -path db/migrations -database "postgres://transfer_user:korie123@localhost:5434/transfer_db?sslmode=disable" down 1




# for generate proto files
go get google.golang.org/grpc
go get google.golang.org/protobuf

protoc --proto_path=internal/gateway/grpc/proto --go_out=paths=source_relative:internal/gateway/grpc/pb --go-grpc_out=paths=source_relative:internal/gateway/grpc/pb internal/gateway/grpc/proto/account.proto

