const mongoose = require('mongoose');
require('dotenv').config();

module.exports=function(){
    mongoose.set('strictQuery', true)
    mongoose
        .connect(process.env.DB_CONNECTION_STRING, { 
            useNewUrlParser: true,
        })
        .then(() => console.log('MongoDB connected...'))
        .catch(err => console.log(err));
}