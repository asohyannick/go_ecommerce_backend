package dbconfig
import (
	"fmt"
	"os"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"go_ecommerce/domain/entities/user"
)

var DB *gorm.DB

func ConnectDatabase() error {
	err := godotenv.Load()
	if err != nil {
		return fmt.Errorf("error loading .env file: %w", err)
	}

	// Get the database URL from environment variables
	databaseUrl := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(databaseUrl), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	DB = db
	DB.AutoMigrate(&entities.User{})
	fmt.Println("✅ PostgreSQL connected successfully")
	return nil
}
