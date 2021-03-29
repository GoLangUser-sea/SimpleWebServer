package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"crypto/sha512"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)
var srv http.Server
var idleConnsClosed chan struct{}
var connectionID = 0
var hashTag = "/hash/"

type Entry struct{
	password []byte
	time int64
}

var pwdSet map[int]Entry

func main() {
	fmt.Println("Starting simple web server")

	idleConnsClosed = make(chan struct{})
	//Create the default mux
	mux := http.NewServeMux()


	mux.HandleFunc("/hash", hashHandler)
	mux.HandleFunc(hashTag, hashReturnHandler)
	mux.HandleFunc("/stats", statHandler)
	mux.HandleFunc("/shutdown", shutdownHandler)

	srv := &http.Server{
		Addr:           ":8080",
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	pwdSet = make(map[int]Entry)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Printf("HTTP server ListenAndServe: %v", err)
	}

	fmt.Println("Finishing up simple web server")
}

func hashReturnHandler(res http.ResponseWriter, req *http.Request) {
	fmt.Println("Received dynamic URL ")
	var data = []byte("")
	if len(req.RequestURI) == 0{
		return
	}

	refId := 0
	if !convertToId(req.RequestURI, &refId){
		return
	}

	var pwdHash string
	if !getHashFromSetById(refId, &pwdHash){
		return
	}

	data = []byte("Response: " + pwdHash)
	res.Header().Set("Content-Type", "application/text")
	res.WriteHeader(200)
	res.Write(data)
}

func convertToId(str string, recId *int) bool{
	token := strings.TrimPrefix(str,hashTag)
	if (len(token) == 0){
		return false
	}

	id := strings.Split(token,"/")
	if (len(id) == 0){
		return false
	}

	var err error
	*recId, err = strconv.Atoi(id[0])
	if err != nil {
		return false
	}

    return true
}

func hashHandler(res http.ResponseWriter, req *http.Request){

	fmt.Println("Received new client")
	var data = []byte("")
	if req.Method != "POST" {
		return
	}

	if err := req.ParseForm(); err != nil {
		fmt.Println("ParseForm() err: ", err)
		return
	}

	name := req.FormValue("password")
	if name != "" {
		fmt.Println("password = ", name)
		index := 0
		addHashToSet([]byte (name), &index)
        data = []byte("Response: " + strconv.Itoa(index))
	}

	res.Header().Set("Content-Type", "application/text")
	res.WriteHeader(200)
	res.Write(data)
}

func addHashToSet(password []byte, index *int) bool{
	var t =time.Now().Unix()
	var i = len(pwdSet)
	pwdSet[i] = Entry{password,t}
	*index = len(pwdSet)
	return true
}

func getHashFromSetById(id int, pwdHash *string) bool{
	if (id < 1)  || (id > len(pwdSet)){
		return false
	}

	var entry = pwdSet[id-1]
	if (time.Now().Unix()- entry.time) < 5 {
		return false
	}

	var sha512Hasher = sha512.New()
	sha512Hasher.Write(entry.password)
	var hashedPasswordBytes = sha512Hasher.Sum(nil)
	*pwdHash = base64.URLEncoding.EncodeToString(hashedPasswordBytes)
	return true
}


func statHandler(res http.ResponseWriter, req *http.Request){

	fmt.Println("Received new client")
	data := []byte("STATS is here")
	if req.Method != "GET" {
		return
	}
	res.Header().Set("Content-Type", "application/text")
	res.WriteHeader(200)
	res.Write(data)
}

func shutdownHandler(res http.ResponseWriter, req *http.Request){

	fmt.Println("Shutting server down")
	if err := srv.Shutdown(context.Background()); err != nil {
		// Error from closing listeners, or context timeout:
		log.Printf("HTTP server Shutdown: %v", err)
	}
	close(idleConnsClosed)
}