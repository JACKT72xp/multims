const http = require('http');

// Crear un servidor HTTP
const server = http.createServer((req, res) => {
    // Configurar la respuesta HTTP
    res.statusCode = 200; // Código de estado HTTP 200: OK
    res.setHeader('Content-Type', 'text/plain'); // Tipo de contenido: texto plano
    res.end('Hello, World 55!\n'); // Responder con "Hello, World!"
});

// El servidor escucha en el puerto 3000
const port = 3001;
server.listen(port, () => {
    console.log(`Server running at v5 http://localhost:${port}/`);
});


