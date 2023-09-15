const {User}=require('../models/user');
const redis = require('redis');
const client = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});
client.connect()
client.on('connect', err => {
    //console.log('Connected to redis..');
})

client.on('error', (err) => {
    console.log(err.message);
})
client.on('end', () => {
    console.log('Client disconnected to redis...');
});
module.exports = {

insertDocumentAndRedisSetex: async function (collectionName, document, key, expiryInSeconds, data) {
    try {
    var tr = eval(collectionName);
    const collection = await tr.create(document);
    console.log("Inserted a document");
    const redisResult = await client.setEx(key, expiryInSeconds, data);
    console.log(`Set data in Redis with key '${key}' and expiration '${expiryInSeconds}' seconds`);
    return { collection, redisResult };
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
  findOneDocumentAndRedisGET:async (query, collectionName, redisKey) => {
    try {
      var tr = eval(collectionName);
      const document = await tr.findOne(query);
      const redisResult = await client.get(redisKey);
      return { document, redisResult };
    } catch (error) {
      console.error(error);
      throw error;
    }
},
};