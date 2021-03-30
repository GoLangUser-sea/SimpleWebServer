package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Entry struct{
	password []byte
	time int64
}

type Stat struct {
	Total int
	Average time.Duration
}

var pwdSet map[int]Entry
var hashTag = "/hash/"
var totalTimeNanos time.Duration = 0
var mutex = &sync.Mutex{}

func main() {
	log.SetPrefix("LOG: ")
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Llongfile)
	log.Println("Starting simple web server")

	shutdownNow := make(chan bool,1)
	pwdSet = make(map[int]Entry)

	mux := http.NewServeMux()

	mux.HandleFunc("/hash", hashHandler)
	mux.HandleFunc(hashTag, requestHashByIDHandler)
	mux.HandleFunc("/stats", statHandler)
	mux.HandleFunc("/shutdown", func(res http.ResponseWriter, req *http.Request) {
		shutdownNow <- true	})

	srv := &http.Server{
		Addr:           ":8080",
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		<-shutdownNow
		log.Println("Server is shutting down ..")
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutting down: %v", err)
		}
		close(shutdownNow)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("HTTP server ListenAndServe: %v\n", err)
	}
	log.Println("Sever exited")
}

func requestHashByIDHandler(res http.ResponseWriter, req *http.Request) {
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
	_, _ = res.Write(data)
}

func convertToId(str string, recId *int) bool{
	token := strings.TrimPrefix(str,hashTag)
	if len(token) == 0 {
		return false
	}

	id := strings.Split(token,"/")
	if len(id) == 0 {
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
	log.Println("Received new client password")
	start := time.Now()
	if req.Method != "POST" {
		return
	}

	if err := req.ParseForm(); err != nil {
		log.Println("ParseForm() err: ", err)
		return
	}

	name := req.FormValue("password")
	var data = []byte("")
	if name != "" {
		index := 0
		addHashToSet([]byte (name), &index)
        data = []byte("Response: " + strconv.Itoa(index))
	}

	res.Header().Set("Content-Type", "application/text")
	res.WriteHeader(200)
	_, _ = res.Write(data)
	totalTimeNanos += time.Since(start)
}

func addHashToSet(password []byte, index *int) bool{
	mutex.Lock()
	defer mutex.Unlock()

	var t =time.Now().Unix()
	pwdSet[len(pwdSet)] = Entry{password,t}
	*index = len(pwdSet)
	return true
}

func getHashFromSetById(id int, pwdHash *string) bool{
	if (id < 1)  || (id > len(pwdSet)){
		return false
	}

	mutex.Lock()
	defer mutex.Unlock()

	var entry = pwdSet[id-1]
	if (time.Now().Unix()- entry.time) < 5 {
		return false
	}

	var sha512Hasher = sha512.New()
	sha512Hasher.Write(entry.password)

	var hashedPasswordBytes = sha512Hasher.Sum(nil)
	*pwdHash = base64.URLEncoding.EncodeToString(hashedPasswordBytes)
	log.Println("Reporting hash = ", *pwdHash)
	return true
}

func statHandler(res http.ResponseWriter, req *http.Request){

	if req.Method != "GET" {
		return
	}
	log.Println("Received GET STAT request")

	totalCount := len(pwdSet)
	if totalCount == 0{
		return
	}

	var stat Stat
	stat.Average = totalTimeNanos / (time.Microsecond  * time.Duration(totalCount))
	stat.Total   = totalCount

	out, err := json.MarshalIndent(&stat, "", "     ")
    if err != nil {
    	return
	}

	log.Println(string(out))
	res.Header().Set("Content-Type", "application/text")
	res.WriteHeader(200)
	_, _ = res.Write(out)
}