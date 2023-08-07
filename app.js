const redis = require('./helpers/redis');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const Queries=require('./helpers/mongofunctions');
const auth=require('./middleware/auth');

require('./helpers/routes')(app);
require('./helpers/db')();
require('./helpers/validations');
require('./helpers/logging');
require('./helpers/redis');
require('./helpers/cors')(app);

const jobQueue = require('./helpers/consumer');
io.on('connection', async (socket) => {
  console.log('New client connected!');

  const token = socket.handshake.query.token;

  if (!token) {
    return socket.emit('error', 'Access denied. No Token provided.');
  }

  try {
    const decoded = jwt.verify(token, process.env.jwtPrivateKey);
    console.log('Received token:', token);


    socket.on('getUserDetails', async (userid, callback) => {
      try {
        const hash = 'register';
        const exists = await redis.redishexists(hash,userid);
        console.log("exists",exists);
      if (exists) {
          const userDetails = await redis.redishget(hash,userid);
          console.log('User details:', userDetails);
          callback(null,userDetails);
        } else {
          callback('User details not found in Redis');
        }
      } catch (error) {
        callback(error.message);
      }
    });

    socket.on('transferBalance', async (data, callback) => {
      try {
        const { senderPhone, receiverPhone, amount, currency } = data;
        const sender = await Queries.findOneDocument({ phone: senderPhone }, 'Register');
        if (!sender) return res.status(400).send('Sender not found');
  
        const receiver = await Queries.findOneDocument({ phone: receiverPhone }, 'Register');
        if (!receiver)  return res.status(400).send('Receiver not found');
      
        const senderBalance = parseInt(sender.balances[currency]);
        if (senderBalance < amount) {
          return callback('Insufficient balance');
        }
        const jobData = { type: 'transfer', senderPhone, receiverPhone, amount, currency };
        const job = await jobQueue.add(jobData, 1);
        if (!job) {
          return callback('Error adding job to queue');
        }
        console.log(`Transfer job added with job id ${job.id}`);
        callback(null, `Transfer job added with job id ${job.id}`);
      
      } catch (error) {
        console.error(error);
        callback('Error processing transfer');
      }
    });
  } catch (error) {
    socket.emit('error', error.message);
  }
});
const port = process.env.PORT||3000;
server.listen(port, () => console.log(`Listening on port ${port}...`));