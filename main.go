package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/openpgp"
)

var db *sql.DB
var err error

type hash_request struct {
	Password string `db:"Password" json:"password"`
}

type user_request struct {
	UserID    int64  `db:"UserID" json:"userid"`
	Password  string `db:"Password" json:"password"`
	IP        string `db:"IP" json:"ip"`
	Signature string `db:"Signature" json:"signature"`
}

type session_request struct {
	Token *string `json:"token"`
}

type passwords struct {
	ID          int64   `db:"ID" json:"id"`
	UserID      int64   `db:"UserID" json:"userid"`
	Password    string  `db:"Password" json:"password"`
	LastLogin   int     `db:"LastAccess" json:"lastaccess"`
	LastIP      string  `db:"LastIP" json:"lastip"`
	Secure      *string `db:"Secure" json:"secure"`
	StateChange *int64  `db:"StateChange" json:"statechange"`
}

type sessions struct {
	ID          int64   `db:"ID" json:"id"`
	Token       string  `db:"Token" json:"token"`
	UserID      string  `db:"UserID" json:"userid"`
	ValidFrom   int64   `db:"ValidFrom" json:"validfrom"`
	ValidTo     int64   `db:"ValidTo" json:"validto"`
	Secure      *string `db:"Secure" json:"secure"`
	StateChange int64   `db:"StateChange" json:"statechange"`
}

func init() {
	db, err = sql.Open("sqlite3", "dev_auth.db")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ver := "/v1"
	r := gin.Default()
	r.POST(ver+"/auth/get-token", gettoken)
	r.GET(ver+"/hash", pwdhash)
	r.POST(ver+"/auth/login", login)
	r.POST(ver+"/auth/add", add)
	r.POST(ver+"/auth/change", change)
	r.DELETE(ver+"/auth/logout", logout)
	r.Run("0.0.0.0:80")
}

func change(c *gin.Context) {
	var cr user_request
	c.Bind(&cr)

	// Verify the signature
	verified := addsigverify(cr.UserID, cr.Password, cr.IP, cr.Signature)
	if !verified {
		c.JSON(400, gin.H{"error": "Invalid signature"})
		return
	}

	// Check if the user already has a password with an empty Secure column
	var existingPassword passwords
	err := db.QueryRow("SELECT * FROM passwords WHERE UserID = ? AND Secure IS NULL", cr.UserID).Scan(&existingPassword.ID, &existingPassword.UserID, &existingPassword.Password, &existingPassword.LastIP, &existingPassword.LastLogin, &existingPassword.Secure, &existingPassword.StateChange)
	if err != nil && err != sql.ErrNoRows {
		c.JSON(500, gin.H{"error1": "first phase", "error": err.Error()})
		return
	}

	if existingPassword.ID != 0 {
		// Update the existing password with the new secure value and state change time
		_, err = db.Exec("UPDATE passwords SET Secure = ?, StateChange = ? WHERE ID = ?", "PASSWORD_CHANGE", time.Now().Unix(), existingPassword.ID)
		if err != nil {
			c.JSON(500, gin.H{"error1": "secound phase", "error": err.Error()})
			return
		}
	} else {
		// Hash the new password using a secure hashing algorithm
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cr.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, gin.H{"error1": "third phase", "error": err.Error()})
			return
		}

		// Insert the new password into the passwords table
		_, err = db.Exec("INSERT INTO passwords (UserID, Password, LastLogin, LastIP) VALUES (?, ?, ?, ?)", cr.UserID, hashedPassword, existingPassword.LastLogin, cr.IP)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(200, gin.H{"message": "Password changed successfully"})
}

func add(c *gin.Context) {
	var nwr user_request
	c.Bind(&nwr)

	// Verify the signature
	verified := addsigverify(nwr.UserID, nwr.Password, nwr.IP, nwr.Signature)
	if !verified {
		c.JSON(400, gin.H{"error": "Invalid signature"})
		return
	}

	if nwr.UserID == 0 || nwr.Password == "" || nwr.IP == "" || nwr.Signature == "" {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Check if the user ID already exists in the passwords table
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM passwords WHERE UserID = ?", nwr.UserID).Scan(&count)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if count > 0 {
		c.JSON(400, gin.H{"error": "User ID already exists"})
		return
	}

	// Hash the password using a secure hashing algorithm
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(nwr.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Insert the new user's password into the passwords table
	_, err = db.Exec("INSERT INTO passwords (UserID, Password) VALUES (?, ?)", nwr.UserID, hashedPassword)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "User added successfully"})
}

func logout(c *gin.Context) {
	// Retrieve the refresh token from the request
	var r session_request
	c.Bind(&r)

	// Get the current time in Unix format
	stateChange := time.Now().Unix()

	// Update the session in the database
	result, err := db.Exec("UPDATE sessions SET Secure = 'LOGOUT', StateChange = ? WHERE Token = ?", stateChange, r.Token)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Check if the session was updated successfully
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if rowsAffected == 0 {
		c.JSON(400, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(200, gin.H{"message": "Logout successful"})
}

func gettoken(c *gin.Context) {
	// Retrieve the refresh token from the request
	var r session_request
	c.Bind(&r)
	// Retrieve the session from the database
	var s sessions
	err := db.QueryRow("SELECT UserID, Token, ValidFrom, ValidTo, Secure FROM sessions WHERE Token = ?", r.Token).Scan(&s.UserID, &s.Token, &s.ValidFrom, &s.ValidTo, &s.Secure)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid refresh token", "error2": err.Error(), "debug": r})
		return
	}
	if s.Secure != nil {
		c.JSON(401, gin.H{"error": "Invalid refresh token"})
		return
	}
	// Convert ValidTo and ValidFrom to time.Time values
	validTo := time.Unix(s.ValidTo, 0)
	validFrom := time.Unix(s.ValidFrom, 0)

	// Check if the session is expired
	if time.Now().After(validTo) {
		c.JSON(401, gin.H{"error": "Session expired"})
		return
	}

	// Check if the session is not yet valid
	if time.Now().Before(validFrom) {
		c.JSON(401, gin.H{"error": "Session not yet valid"})
		return
	}

	// Generate a signed JWT token with the UserID and an expiration time of your choice
	// Universal security signing key: AOUTOKQtTDl9JeSLYQHGLkHICLSVO31FWrVpTFQLuvQEcdbpaAsOBXrKlyY6OLdkErs5ZPTSuUacgm92sAAuFyZUdrqZjd61GwYR6Y0pXbdEBuvmogcYbrlAqc0i55RTZXZYIEiAEWiIH7RFf5FZCTSJCIa9kTCWzFSbDJoAVcU29hKqM6melssRSqctmCCglxGX8XTmtzOt8EbwKZ10cwQ8EJLwuarywXDjFfF8EZe4CsQtv6qAEuyv8VOWXO18UT6I
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"UserID": s.UserID,
		"exp":    time.Now().Add(time.Minute * 10).Unix(),
	})
	tokenString, err := token.SignedString([]byte("AOUTOKQtTDl9JeSLYQHGLkHICLSVO31FWrVpTFQLuvQEcdbpaAsOBXrKlyY6OLdkErs5ZPTSuUacgm92sAAuFyZUdrqZjd61GwYR6Y0pXbdEBuvmogcYbrlAqc0i55RTZXZYIEiAEWiIH7RFf5FZCTSJCIa9kTCWzFSbDJoAVcU29hKqM6melssRSqctmCCglxGX8XTmtzOt8EbwKZ10cwQ8EJLwuarywXDjFfF8EZe4CsQtv6qAEuyv8VOWXO18UT6I"))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	// Return the token to the client
	c.JSON(200, gin.H{"token": tokenString})
}

func login(c *gin.Context) {
	var auth user_request
	if err := c.Bind(&auth); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Verify the signature
	verified := addsigverify(auth.UserID, auth.Password, auth.IP, auth.Signature)
	if !verified {
		c.JSON(400, gin.H{"error": "Invalid signature"})
		return
	}
	// Retrieve the password hash for the given UserID from the database
	var p passwords
	err := db.QueryRow("SELECT UserID, Password FROM passwords WHERE UserID = ?", auth.UserID).Scan(&p.UserID, &p.Password)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// Compare the hashed password from the database with the password provided in the auth struct
	err = bcrypt.CompareHashAndPassword([]byte(p.Password), []byte(auth.Password))
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// Update the LastLogin and LastIP fields in the database
	_, err = db.Exec("UPDATE passwords SET LastLogin = ?, LastIP = ? WHERE UserID = ?", time.Now().Unix(), auth.IP, auth.UserID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update database"})
		return
	}

	// Generate a random token
	token, err := generateToken()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	// Save the token in the database with the current time as the start time and a month as the end time
	startTime := time.Now().Unix()
	endTime := time.Now().AddDate(0, 1, 0).Unix()
	_, err = db.Exec("INSERT INTO sessions (UserID, Token, ValidFrom, ValidTo) VALUES (?, ?, ?, ?)", auth.UserID, token, startTime, endTime)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to save token to database", "error2": err.Error()})
		return
	}

	// Return the token in the response
	c.JSON(200, gin.H{"message": "Authentication successful", "token": token})
}

func pwdhash(c *gin.Context) {
	var hash_request hash_request
	c.BindJSON(&hash_request)
	c.JSON(200, gin.H{"hash": hashPassword(hash_request.Password, "")})
}

// Functions that are not directly called

func addsigverify(userID int64, password, ip, signature string) bool {
	data := fmt.Sprintf("%d:%s:%s", userID, password, ip)
	// Get the public key from the file
	publicKey, err := readPublicKeyFromFile("public_intercom_key.pem")
	if err != nil {
		fmt.Println("Failed to read public key from file:" + err.Error())
		return false
	}

	// Decode the signature from base64
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println("Invalid signature:" + err.Error())
		return false
	}

	// Verify the signature using the public key
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(publicKey))
	if err != nil {
		fmt.Println("Failed to read public key:" + err.Error())
		return false
	}
	if len(entityList) != 1 {
		fmt.Println("Invalid public key")
		return false
	}
	entity := entityList[0]
	signedData := strings.NewReader(data)
	entityList = openpgp.EntityList{entity}
	_, err = openpgp.CheckDetachedSignature(entityList, signedData, bytes.NewReader(signatureBytes))
	if err != nil {
		fmt.Println("Invalid signature" + err.Error())
		return false
	}

	// Signature is valid
	return true
}

func readPublicKeyFromFile(filename string) ([]byte, error) {
	// Read the public key from the file
	publicKey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func generateToken() (string, error) {
	// Generate a random byte slice
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	// Encode the byte slice as a base64 string
	token := base64.URLEncoding.EncodeToString(b)

	return token, nil
}

func hashPassword(password string, salt string) string {
	// Hash the password with the given salt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	// Return the hashed password as a string
	fmt.Println(string(hashedPassword))
	return string(hashedPassword)
}
