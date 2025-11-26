package services

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"

	"go_ecommerce/domain/entities/user"
	"go_ecommerce/infrastructure/config/dbconfig"
	"go_ecommerce/pkg/utils"
)

// ---------------- REGISTER ----------------
func Register(c echo.Context) error {
	var input struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)

	user := entities.User{
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Email:     input.Email,
		Password:  string(hash),
	}

	if err := dbconfig.DB.Create(&user).Error; err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, map[string]string{
		"message": "user registered successfully",
	})
}

// ---------------- LOGIN (SETS COOKIES) ----------------
func Login(c echo.Context) error {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	var user entities.User
	if err := dbconfig.DB.Where("email = ?", input.Email).First(&user).Error; err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	}

	// Generate tokens
	userIdStr := strconv.FormatUint(uint64(user.ID), 10)

	accessToken, _ := utils.GenerateAccessToken(userIdStr)
	refreshToken, _ := utils.GenerateRefreshToken(userIdStr)

	// Set Access Token cookie
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
		MaxAge:   60 * 15,
	})

	// Set Refresh Token cookie
	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 30,
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message": "logged in successfully",
	})
}

// ---------------- REFRESH TOKEN ----------------
func RefreshToken(c echo.Context) error {
	refreshCookie, err := c.Cookie("refresh_token")
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing refresh token"})
	}

	token, err := jwt.Parse(refreshCookie.Value, func(t *jwt.Token) (interface{}, error) {
		return utils.JwtSecret, nil
	})

	if err != nil || !token.Valid {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
	}

	claims := token.Claims.(jwt.MapClaims)
	userID := claims["user_id"].(string)

	// Create new access token
	newAccess, _ := utils.GenerateAccessToken(userID)

	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    newAccess,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
		MaxAge:   60 * 15,
	})

	return c.JSON(200, map[string]string{"message": "new access token issued"})
}

// ---------------- LOGOUT ----------------
func Logout(c echo.Context) error {
	// Clear cookies
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message": "user logged out successfully",
	})
}

// ---------------- FETCH ALL USERS ----------------
func FetchAllUsers(c echo.Context) error {
	var users []entities.User
	dbconfig.DB.Find(&users)
	return c.JSON(http.StatusOK, users)
}

// ---------------- FETCH USER ----------------
func FetchUser(c echo.Context) error {
	id := c.Param("id")
	var user entities.User

	if err := dbconfig.DB.First(&user, id).Error; err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}

	return c.JSON(http.StatusOK, user)
}

// ---------------- DELETE USER ----------------
func DeleteUser(c echo.Context) error {
	id := c.Param("id")

	if err := dbconfig.DB.Delete(&entities.User{}, id).Error; err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "user deleted"})
}

// ---------------- BLOCK USER ----------------
func BlockUser(c echo.Context) error {
	id := c.Param("id")

	if err := dbconfig.DB.Model(&entities.User{}).
		Where("id = ?", id).
		Update("is_blocked", true).Error; err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "user account blocked"})
}

// ---------------- UNBLOCK USER ----------------
func UnblockUser(c echo.Context) error {
	id := c.Param("id")

	if err := dbconfig.DB.Model(&entities.User{}).
		Where("id = ?", id).
		Update("is_blocked", false).Error; err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "user account unblocked"})
}
