package main

import (
	"fmt" // Импортируем пакет fmt для форматированного вывода (логирования)
	"log" // Импортируем пакет log для логирования ошибок

	"golang.org/x/crypto/bcrypt"
)

// HashPassword хеширует пароль, используя bcrypt и возвращает хеш и ошибку.
func HashPassword(password string) (string, error) {
	// Проверяем, что пароль не пустой. Пустой пароль не имеет смысла хешировать.
	if password == "" {
		return "", fmt.Errorf("password cannot be empty") // Возвращаем ошибку, если пароль пустой
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// Логируем ошибку, чтобы ее можно было отследить.
		log.Printf("Error hashing password: %v", err)
		return "", fmt.Errorf("failed to hash password: %w", err) // Оборачиваем оригинальную ошибку
	}
	return string(bytes), nil // Возвращаем хеш и nil, если все прошло успешно
}

// CheckPasswordHash сравнивает переданный пароль с хешем, используя bcrypt.
// Возвращает true, если пароль соответствует хешу, и false в противном случае.
func CheckPasswordHash(password, hash string) bool {
	// Проверяем, что хеш не пустой.
	if hash == "" {
		log.Println("Warning: Empty hash provided for password check.") // Логируем предупреждение
		return false                                                    // Если хеш пустой, считаем, что пароль неверный
	}

	// Проверяем, что пароль не пустой.  Пустой пароль всегда будет неверен.
	if password == "" {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		// Если ошибка не связана с несовпадением паролей, логируем ее.
		if err != bcrypt.ErrMismatchedHashAndPassword {
			log.Printf("Error comparing password hash: %v", err)
		}
		return false // Возвращаем false, если пароль не соответствует хешу или произошла ошибка
	}
	return true // Возвращаем true, если пароль соответствует хешу
}
