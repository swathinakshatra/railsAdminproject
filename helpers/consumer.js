const Queue = require('bull');
const bcrypt = require('bcrypt');
const Queries = require('../helpers/mongofunctions');
const { generateUserId } = require("../middleware/userid");
const redisquery=require('../helpers/redis');
const { v4: uuidv4 } = require('uuid');
const jobQueue = new Queue('job-queue', {
  redis: {
    host: '127.0.0.1',
    port: 6379,
  },
});

jobQueue.process(async (job, done) => {
  try {
    console.log(`Processing job ${job.id} of type ${job.data.type}`);
    if (job.data.type === 'register') {
      const { phone, password, username} = job.data;
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const newUser = {
        userid:generateUserId(),
        phone,
        password: hashedPassword,
        username,
      };
      const result = await Queries.insertDocument('Register', newUser);
      if (!result) return res.status(400).send('Registration failed');
      const redisInsert = await redisquery.redishset("register",newUser.userid, JSON.stringify(result));
      console.log(redisInsert, "redisInsert");
    } else if (job.data.type === 'update') {
      console.log(`Processing job ${job.id}`);
      const { phone, currency, balance } = job.data;

      const user = await Queries.findOneDocument({ phone }, 'Register');
      if (!user) return res.status(400).send('User not found');
       user.balances[currency] = (parseInt(user.balances[currency]) + parseInt(balance)).toString();

      const result = await Queries.findOneAndUpdate({ phone }, { $set: { balances: user.balances } }, 'Register');
      if (!result) return res.status(400).send('Error updating user');
      const redisInsert = await redisquery.redishset("register",user.phone, JSON.stringify(result));
      console.log(redisInsert, "redisInsert");

      console.log(`${currency} balance updated successfully`);
    } else if (job.data.type === 'transfer') {
      console.log(`Processing job ${job.id} of type ${job.data.type}`);
      const { senderPhone, receiverPhone, amount, currency } = job.data;
       const sender = await Queries.findOneDocument({ phone: senderPhone }, 'Register');
      if (!sender) return done(new Error('Sender not found'));
      const receiver = await Queries.findOneDocument({ phone: receiverPhone }, 'Register');
      if (!receiver) return done(new Error('Receiver not found'));
      const senderBalance = parseInt(sender.balances[currency]);
      if (senderBalance < amount) {
        return done(new Error('Insufficient balance'));
      }
      receiver.balances[currency] = (parseInt(receiver.balances[currency]) + parseInt(amount)).toString();
      sender.balances[currency] = (senderBalance - parseInt(amount)).toString();
      const senderUpdateResult = await Queries.findOneAndUpdate(
        { phone: senderPhone },
        { $set: { balances: sender.balances } },
        'Register'
      );
      const receiverUpdateResult = await Queries.findOneAndUpdate(
        { phone: receiverPhone },
        { $set: { balances: receiver.balances } },
        'Register' );
     if (!senderUpdateResult || !receiverUpdateResult) {
        return done(new Error('Error updating balances'));
      }
     console.log(`Money transfer from ${senderPhone} to ${receiverPhone} successful`);
     const transactionId = uuidv4();
     const history={
      time: Date.now(), 
      tid: transactionId, 
      phone: senderPhone, 
      userid: sender.userid,
      name: sender.username, 
      receiver_name: receiver.username, 
      coin: currency, 
      type: 'transfer',
      amount: amount, 
      comment: 'Transfer balance', 
      status: 'Pending',
    };
      const saved=await Queries.insertDocument("History",history);
      if(!saved) return res.status(400).send("history not saved");
    
    console.log('Transfer history saved:',saved);
    const updatedHistory = await Queries.findOneAndUpdate(
      { tid: transactionId }, 
      { $set: { status: 'Success' }},"History" , 
      { new: true } 
    );
    console.log('Updated transaction history:', updatedHistory);
    } else {
      return done(new Error('Unknown job type'));
    }
    done();
  } catch (error) {
    console.error(error);
    done(error);
  }
});


module.exports = jobQueue




      