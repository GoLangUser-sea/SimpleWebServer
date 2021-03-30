# SimpleWebServer
Go-lang test project

/hash - to record new password 
/hash/<id>  - to receive hash of the reported password. The hash returning 5 seconds after the initial call to /hash was made
/stats - to retrieve statistics about 1)number servered requests 2)average time procesing calls to /hash endpoint
/shutdown -  to exit server. It will perform graceful shutdown, waiting for the connections to close before killing any
