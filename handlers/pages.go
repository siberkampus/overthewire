// handlers/pages.go
package handlers

import (
	"ctf-platform/models"
	"database/sql"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

func HomePage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		isAuth := false
		var username string

		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			isAuth = true
			username = session.Values["username"].(string)
		}

		data := map[string]interface{}{
			"Title":           "Ana Sayfa - CTF HACK PLATFORMU",
			"IsAuthenticated": isAuth,
			"Username":        username,
		}

		tmpl := template.Must(template.ParseFiles("templates/index.html"))
		tmpl.Execute(w, data)
	}
}

func LoginPage(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

		data := map[string]interface{}{
			"Title": "Giriş Yap - CTF HACK PLATFORMU",
		}

		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, data)
	}
}

func RegisterPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"Title": "Kayıt Ol - CTF HACK PLATFORMU",
		}

		tmpl := template.Must(template.ParseFiles("templates/register.html"))
		tmpl.Execute(w, data)
	}
}

func TerminalPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		machineID := vars["id"]

		session, _ := store.Get(r, "session")
		isAuth := false

		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			isAuth = true
		}

		if !isAuth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		var machine models.Machine
		db.QueryRow(`
            SELECT id, name, description, difficulty, docker_image
            FROM machines WHERE id = $1
        `, machineID).Scan(&machine.ID, &machine.Name, &machine.Description, &machine.Difficulty, &machine.DockerImage)

		data := map[string]interface{}{
			"Title":   machine.Name + " - Terminal",
			"Machine": machine,
		}

		tmpl := template.Must(template.ParseFiles("templates/terminal.html"))
		tmpl.Execute(w, data)
	}
}
