package main

import (
	
	"database/sql"  // Импортируем пакет для работы с базами данных
	"encoding/json"
	"fmt"           // Импортируем пакет для форматирования строк
	"html/template" // Импортируем пакет для работы с HTML-шаблонами
	"log"           // Импортируем пакет для логирования ошибок
	"net/http"      // Импортируем пакет для работы с HTTP
	//"net/url"		// Импортируем пакет для работы с URL
	"strconv"       // Импортируем пакет для преобразования строк в числа
	//"time"          // Импортируем пакет для работы с временем
	//"math/rand"		// Импортируем пакет для генерации
	"strings"

    //"gopkg.in/gomail.v2" // Ипортируем пакет для отправки электронной почты

	_ "github.com/mattn/go-sqlite3" // Импортируем драйвер SQLite
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB // Глобальная переменная для подключения к базе данных

// User структура для хранения пользовательских данных
type User struct {
	ID       int
	Login    string
	Password string
}

// Notes структура для хранения данных о заказе
type Notes struct {
	ID            int
	UserID        int
	Group         string
	NoteName      string
	NoteURL  	  string
}

type Note struct {
	ID    int    `json:"id"`
	Group string `json:"group"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Инициализируйте подключение к базе данных
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./shop.db") // Открываем соединение с базой данных
	if err != nil {
		log.Fatal(err) //логируем ошибку
	}

	// Инициализируйте таблицы, если они не существуют
	initTables() // Инициализируем таблицы в базе данных

	// Инициализация данных по умолчанию
	initDefaultData() // Заполняем базу данных начальными данными
}

// Инициализация таблиц
func initTables() {
	query := `
	-- Таблица пользователей
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            login VARCHAR(10) NOT NULL,
            password TEXT NOT NULL
        );

        -- Таблица заметок
        CREATE TABLE IF NOT EXISTS notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            note_user_id INTEGER NOT NULL,
            note_group VARCHAR(50) NOT NULL,
            name VARCHAR(50) NOT NULL,
            note_url TEXT NOT NULL,
            FOREIGN KEY (note_user_id) REFERENCES users(user_id)
        );
		`

	_, err := db.Exec(query) //запрос на создание таблиц
	if err != nil {
		log.Fatal(err) // Логируем ошибку
	}
}

// Инициализация данных по умолчанию

// функция initDefaultData проверяет, есть ли уже продукты в базе данных,
// и если нет, добавляет 20 товаров по умолчанию.
func initDefaultData() {
	// Check if products already exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count) // Проверяем, есть ли уже продукты
	if err != nil {
		log.Fatal(err)
	}

	if count == 0 {

		// Заполнение справочников
		_, err := db.Exec(`INSERT INTO users (login, password) VALUES ('adminus', 'dorian221B')`)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Хэширование пароля с солью
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14) // Генерируем хэш пароля с использованием bcrypt
	log.Printf("Paasw0rd is: %s\n", string(bytes))
	return string(bytes), err                                       // Возвращаем хэшированный пароль и ошибку (если есть)
}

// Сравните хэша с предоставленным паролем
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) // Сравниваем хэшированный пароль с введенным
	return err == nil                                                    // Возвращаем true, если пароли совпадают, иначе false
}

// Средство визуализации шаблонов
func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	tmplPath := fmt.Sprintf("templates/%s.html", tmpl)
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		log.Printf("Ошибка загрузки шаблона: %s, путь: %s, ошибка: %v", tmpl, tmplPath, err)
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

// Получение текущего пользователя из файла cookie
func getCurrentUser(r *http.Request) (*User, error) {
	cookie, err := r.Cookie("user_id")
	if err != nil {
		log.Printf("Error 1: %s", err)
		return nil, err
	}

	userID, err := strconv.Atoi(cookie.Value)
	if err != nil {
		log.Printf("Error 2: %s", err)
		return nil, err
	}

	var user User
	err = db.QueryRow("SELECT user_id, login FROM users WHERE user_id = ?", userID).
		Scan(&user.ID, &user.Login)
	if err != nil {
		log.Printf("Error 3: %s", err)
		return nil, err
	}
	return &user, nil
}

// Обработчики

// Обработчик домашней страницы
func homeHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "index", user)
}

// Обработчик входа в систему
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		login := r.FormValue("login")
		password := r.FormValue("password")

		var storedPassword string
		var userID int
		err := db.QueryRow("SELECT user_id, password FROM users WHERE login = ?", login).
			Scan(&userID, &storedPassword)
		/*if err != nil || !checkPasswordHash(password, storedPassword) {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}*/
		if err != nil || (password != storedPassword) {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			log.Printf("Error: %s. Login: %s", err, login)
			return
		}
		// Формирование cookie-файла
		http.SetCookie(w, &http.Cookie{
			Name:  "user_id",
			Value: strconv.Itoa(userID),
			Path:  "/",
		})
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	renderTemplate(w, "login", nil)
}

// Обработчик выхода из системы
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Очищение cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "user_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Обработчик страницы профиля
func profileHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rows, err := db.Query(`SELECT n.note_id, u.login, n.note_group, n.name, n.note_url 
            FROM notes n JOIN users u ON n.note_user_id = u.user_id
            WHERE u.user_id = ?`, user.ID)
	if err != nil {
		http.Error(w, "Ошибка при полечении записей", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	data := struct {
		User   *User
	}{
		User:   user,
	}

	renderTemplate(w, "profile", data)
}

// API: получить заметки пользователя
func apiGetNotesHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := db.Query("SELECT note_id, note_group, name, note_url FROM notes WHERE note_user_id = ?", user.ID)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		err := rows.Scan(&n.ID, &n.Group, &n.Title, &n.URL)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		notes = append(notes, n)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notes)
}

// API: добавить заметку
func apiAddNoteHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var n struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		Group string `json:"group"`
	}
	err = json.NewDecoder(r.Body).Decode(&n)
	if err != nil || n.Title == "" || n.URL == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	_, err = db.Exec("INSERT INTO notes (note_user_id, note_group, name, note_url) VALUES (?, ?, ?, ?)", user.ID, n.Group, n.Title, n.URL)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// API: удалить заметку
func apiDeleteNoteHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/notes/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	_, err = db.Exec("DELETE FROM notes WHERE note_id = ? AND note_user_id = ?", id, user.ID)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	// Инициализация базы данных
	initDB()
	defer db.Close()

	// Обрбаботчики
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/profile", profileHandler)

	http.HandleFunc("/api/notes", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			apiGetNotesHandler(w, r)
		case http.MethodPost:
			apiAddNoteHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/api/notes/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			apiDeleteNoteHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))


	// Запуск сервера
	address := "172.17.2.231:5000"
	log.Printf("Server starting on %s...\n", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
