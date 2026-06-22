module github.com/dcarrero/tlsscan

go 1.22

// Sin dependencias externas en el nucleo: solo la biblioteca estandar de Go.
// crypto/tls, crypto/x509, net y encoding/json cubren todo el path critico.
// Esto garantiza licencia MIT limpia y cero dependencias GPL o de terceros.
