# Unit tests only
./mvnw test -Dtest="com.koriebruh.authservice.unit.**"

# Repository integration tests (requires Docker)
./mvnw test -Dtest="com.koriebruh.authservice.integration.RepositoryIntegrationTest"

# All integration tests (requires Docker)
./mvnw test -Dtest="com.koriebruh.authservice.integration.**"

./mvnw test -Dtest="com.koriebruh.authservice.**"