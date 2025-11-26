package entities
import (
	"time"
	"gorm.io/gorm"
)

type User struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
    FirstName string         `gorm:"unique;not null" json:"first_name"`
	LastName  string         `gorm:"unique;not null" json:"last_name"`
	Email     string         `gorm:"unique;not null" json:"email"`
	Password  string         `gorm:"not null" json:"password"`
	IsBlocked bool           `gorm:"default:false" json:"is_blocked"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}