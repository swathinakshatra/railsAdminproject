const express = require('express');
const router = express.Router();
const auth=require('../middleware/auth');
const Queries=require('../helpers/mongofunctions');
const {generatecoinid}=require('../middleware/userid');
const { validateadmincontrols,  updatecoinbalance, validateenc, validatecoins } = require('../helpers/validations');
const crypto=require('../helpers/crypto');
const redisquery=require('../helpers/redis');
const teleg = require("../helpers/telegram");
const { JsonWebTokenError } = require('jsonwebtoken');



router.post('/addcontrols', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Invalid admintype");
    }
    const { error } = validateadmincontrols(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const newobj = {
      Register:'Enable',
      login:'Enable',
      Transfer:'Enable'
    };
const admincontrols = await Queries.insertDocument('AdminControls', newobj);
await redisquery.redishset("AdminControls","Admincontrols",admincontrols)
    if (!admincontrols) {
      return res.status(400).send('Admin controls not added');
    }
     return res.status(200).send('Admin controls added');
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`error addcontrols -->${error}`);
    }
  });

  router.post('/admincontrols',auth,async (req, res) => {
    try {
      if (req.user.admintype !== '1') {
        return res.status(400).send("Invalid admintype");
      }
      const adminControls = await Queries.findselect('AdminControls',{ _id: 0, __v: 0 });
      return res.status(200).send(crypto.encryptobj(adminControls));
    } catch (error) {
      console.log(error);
      return res.status(400).send(`Error: ${error}`);
    }
  });
  router.post('/addcoin', auth, async (req, res) => {
    try {
      // if (req.user.admintype !== '1') {
      //   return res.status(400).send("Invalid admintype");
      // }
      // const { error } = validateenc(req.body);
      // if (error) {
      //   return res.status(400).send(error.details[0].message);
      // } else {
      //   const req.body = crypto.decryptobj(req.body.enc);
      //   console.log("dec",req.body);
        const { error } = validatecoins(req.body);
        if (error) {
          return res.status(400).send(error.details[0].message);
        }
  
        const newCoin = {
          coinId: generatecoinid(),
          coinName: req.body.coinName,
          ticker: req.body.ticker,
          coinStatus: req.body.coinStatus,
          withdrawMin: req.body.withdrawMin,
          withdrawMax: req.body.withdrawMax,
          withdrawFeeType: req.body.withdrawFeeType,
          withdrawFee: req.body.withdrawFee,
          withdrawStatus: req.body.withdrawStatus,
          depositMin: req.body.depositMin,
          depositMax: req.body.depositMax,
          depositFeeType: req.body.depositFeeType,
          depositFee: req.body.depositFee,
          depositStatus: req.body.depositStatus,
          note:req.body.note
        };
        const adminControls = await Queries.findOneDocument({}, "AdminControls");
        if (!adminControls) {
          return res.status(400).send('Admin controls not found');
        }
  
        adminControls.coins.push(newCoin);
        const savedAdminControls = await Queries.insertDocument("AdminControls", adminControls);
        if (!savedAdminControls) {
          return res.status(400).send('Coin not saved in admin controls');
        }
  
        const users = await Queries.findOneDocument({email:req.body.email},"User");
        if (!users || users.length === 0) {
          return res.status(400).send("No  found");
        }
  
        const coinToAdd = {
          coinName: newCoin.coinName,
          ticker: newCoin.ticker,
          balance: '1000',
        };
  
        const updatedUsers = await Queries.findOneAndUpdate(
          { email:req.body.email},
          { $push: { balances: coinToAdd } },
          "User",
          { new: true }
        );
  
        if (!updatedUsers) {
          return res.status(400).send('Failed to update coins');
        }
        const redisusers = await redisquery.ttlupdate('userData',users.email,JSON.stringify(updatedUsers),3600);
        console.log("redisusers",redisusers) 
       if (!redisusers) return res.status(400).send("Failed to insert data into Redis");
      
  
        return res.status(200).send(('Coin added to admin controls and all users balances'));
      
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`Error in addcoins --> ${error}`);
    }
  });
  router.post('/addcoins', auth, async (req, res) => { 
    try {
      // if (req.user.admintype !== '1') {
      //   return res.status(400).send("Invalid admintype");
      // }
      // const { error } = validateenc(req.body);
      // if (error) {
      //   return res.status(400).send(error.details[0].message);
      // } else {
      //   const req.body = crypto.decryptobj(req.body.enc);
      //   console.log("dec",req.body);
        const { error } = validatecoins(req.body);
        if (error) {
          return res.status(400).send(error.details[0].message);
        }
  
        const newCoin = {
          coinId: generatecoinid(),
          coinName: req.body.coinName,
          ticker: req.body.ticker,
          coinStatus: req.body.coinStatus,
          withdrawMin: req.body.withdrawMin,
          withdrawMax: req.body.withdrawMax,
          withdrawFeeType: req.body.withdrawFeeType,
          withdrawFee: req.body.withdrawFee,
          withdrawStatus: req.body.withdrawStatus,
          depositMin: req.body.depositMin,
          depositMax: req.body.depositMax,
          depositFeeType: req.body.depositFeeType,
          depositFee: req.body.depositFee,
          depositStatus: req.body.depositStatus,
          note:req.body.note
        };
        const adminControls = await Queries.findOneDocument({}, "AdminControls");
        if (!adminControls) {
          return res.status(400).send('Admin controls not found');
        }
  
        adminControls.coins.push(newCoin);
        const savedAdminControls = await Queries.insertDocument("AdminControls", adminControls);
        if (!savedAdminControls) {
          return res.status(400).send('Coin not saved in admin controls');
        }
  
        const users = await Queries.find("User");
        if (!users || users.length === 0) {
          return res.status(400).send("No users found");
        }
  
        const coinToAdd = {
          coinName: newCoin.coinName,
          ticker: newCoin.ticker,
          balance: '1000',
        };
  
        const updatedUsers = await Queries.updateMany(
          { users },
          { $push: { balances: coinToAdd } },
          "User",
          { new: true }
        );
  
        if (!updatedUsers) {
          return res.status(400).send('Failed to update coins');
        }
       const  redisupdate=await redisquery.ttlupdate("users",JSON.stringify(updatedUsers),3600);
       if(!redisupdate) return res.status(400).send('failed to update in redis');

  
        return res.status(200).send(('Coin added to admin controls and all users balances'));
      
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`Error in addcoins --> ${error}`);
    }
  });
router.post('/updatecontrols', auth,async (req, res) => {
  try {
  //   const decrypted = crypto.decryptobj(req.body.enc);
  //  if (req.user.admintype !== '1') {
  //     return res.status(400).send('Invalid admintype');
  //   }
   const { Register, login, Transfer } = req.body;
   const { error } = validateadmincontrols(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
     const updated = await Queries.findOneAndUpdate(
      {},
      { Register, login, Transfer }, 
      "AdminControls",
      { new: true, upsert: true });

    if (!updated) {
      return res.status(400).send('Admin controls not updated');
    }
    return res.status(200).send(crypto.encryptobj("admin controls updated"));
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error updatecontrols -->${error}`);
  }
});
router.post('/updatecoinbalance', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Invalid admintype");
    }
    const { email, coinname, amount } = req.body;
    const { error } = updatecoinbalance(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    if (isNaN(amount) || parseFloat(amount) <= 0) {
      return res.status(400).send("Invalid amount");
    }
    const user = await Queries.findOneDocument({ email: email },"User");
    if (!user) {
      return res.status(400).send('User not found');
    }
    console.log('User---->',user.balances);

    const coin = user.balances.find((balance) => balance.coinname === coinname);
    if (!coin) {
      return res.status(400).send('Coin balance not found');
    }
    const numericBalance = parseFloat(coin.balance);
    const numericAmount = parseFloat(amount);
    if (numericAmount < 0) {
      return res.status(400).send("Amount cannot be decremented");
    }
    coin.balance = (numericBalance + numericAmount).toString();
    const updatedUser = await Queries.findOneAndUpdate(
      { email: email },                 
  { $set: { "balances.$[coin].balance": coin.balance } }, 
  "User",{arrayFilters: [{ "coin.coinname": coinname }],new: true,});
   
   if (!updatedUser) return res.status(400).send('Balance not updated');
   console.log('updatedUser---->', updatedUser.balances);
    return res.status(200).send('Coin balance updated successfully');
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error updatecoinbalance -->${error}`);
  }
});
module.exports = router;






