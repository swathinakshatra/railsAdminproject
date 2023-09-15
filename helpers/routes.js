const express = require('express');
const queue = require('express-queue');
const error=require('../middleware/error');
const admincontrols=require('../routes/admincontrols');
const admin=require('../routes/Admin');
const users=require('../routes/users');

module.exports=function(app){
app.get('/home', async (req, res) => {
return res.status(200).send('RAILS Admin Home route')});
app.use(express.json());
app.use('/api/admincontrols',admincontrols,queue({activelimit:1,queuedlimit:-1}));
app.use('/api/admin',admin,queue({activelimit:1,queuedlimit:-1}));
app.use('/api/users',users,queue({activelimit:1,queuedlimit:-1}));
app.use(error);

}
 