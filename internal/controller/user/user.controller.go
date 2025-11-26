package controller

import (
	"github.com/labstack/echo/v4"
	"go_ecommerce/domain/services"
	"go_ecommerce/infrastructure/middleware"
)

func RegisterUserRoutes(e *echo.Echo) {
	// Public routes

	e.POST("/register", services.Register)
	e.POST("/login", services.Login)
	e.POST("/logout", services.Logout)
	// Protected routes
	userGroup := e.Group("/users")
	userGroup.Use(middleware.JWTAuthMiddleware)
	userGroup.GET("fetch-users", services.FetchAllUsers)
	userGroup.GET("fetch-user/:id", services.FetchUser)
	userGroup.DELETE("delete-user/:id", services.DeleteUser)
	userGroup.PUT("block-user/:id", services.BlockUser)
	userGroup.PUT("unblock-user/:id", services.UnblockUser)
}
