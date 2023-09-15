
const express = require('express');
const app = express();
require('dotenv').config();
app.use(express.json({limit:'10mb'}))
require('./helpers/cors')(app);
require('./helpers/db')();
require('./helpers/redis');
require('./helpers/routes')(app);
require('./helpers/validations');

const port = process.env.PORT||3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));