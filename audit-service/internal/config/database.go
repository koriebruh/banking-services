package config

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NewDatabase membuat koneksi database PostgreSQL via GORM.
//
// Schema management menggunakan golang-migrate (bukan GORM AutoMigrate):
//   - Versioned migration files di db/migrations/
//   - Support rollback (down migration)
//   - Proper schema evolution tracking
//   - Dijalankan via entrypoint.sh atau manual CLI
func NewDatabase(cfg *viper.Viper, log *logrus.Logger) *gorm.DB {
	host := cfg.GetString("db.host")
	port := cfg.GetInt("db.port")
	user := cfg.GetString("db.username")
	password := cfg.GetString("db.password")
	dbName := cfg.GetString("db.name")

	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable TimeZone=Asia/Jakarta",
		host, port, user, password, dbName,
	)

	// GORM logger level mapping: Silent=1, Error=2, Warn=3, Info=4
	gormLogLevel := logger.Warn
	if cfg.GetInt("log.level") >= 6 { // logrus Trace/Debug
		gormLogLevel = logger.Info
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(gormLogLevel),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Connection pool settings
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	// Verify connectivity
	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Infof("Database connected (GORM): host=%s port=%d db=%s", host, port, dbName)
	return db
}
