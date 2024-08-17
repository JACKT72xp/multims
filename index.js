// index.js
const express = require('express');
const app = express();
const port = 3001;

app.get('/', (req, res) => {
  res.send('Hello,Harvey Hello World!');
});


app.listen(port, () => {
  console.log(`Server Demo is running ever ever on http://localhost:${port}`);
});