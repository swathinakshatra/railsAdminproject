const winston=require('winston');
require('winston-mongodb');
require('express-async-errors');
module.exports=function(){
    process.on('uncaughtException',(ex)=>{
        console.log('WE GOT AN UNCAUGHT EXCEPTION' );
        winston.error(ex.message,ex);
        process.exit(1);
      });
      
      process.on('unhandledRejection',(ex)=>{
        console.log('WE GOT AN UNHANDLED REJECTION');
        winston.error(ex.message,ex);
        process.exit(1);
      });
      winston.add(new winston.transports.File({ filename: 'logfile.log' }));
      winston.add(new winston.transports.MongoDB({ db: 'mongodb+srv://swathi:swathijune1993@cluster0.soimuvi.mongodb.net/vidly?retryWrites=true&w=majority',level:'info'}));
}