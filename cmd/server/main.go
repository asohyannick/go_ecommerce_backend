package main
import (
	"fmt"
	"os"
	"github.com/labstack/echo/v4"
	"go_ecommerce/infrastructure/config/dbconfig"
	userRoutes "go_ecommerce/internal/controller/user"
)

func main() {

	// Connect to PostgreSQL database
	dbconfig.ConnectDatabase()

	// Initialize Echo app
	e := echo.New()

	// REGISTER USER ROUTES HERE 👇
	userRoutes.RegisterUserRoutes(e)

	// Pick port from env OR default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🚀 Server running on port:", port)
	e.Logger.Fatal(e.Start(":" + port))
}
