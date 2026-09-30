module example.com/app

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/net v0.17.0 // indirect
)

require github.com/stretchr/testify v1.8.4

replace example.com/old => example.com/new v1.0.0
