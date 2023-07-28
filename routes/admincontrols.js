const express = require('express');
const router = express.Router();
const addJob = require('../helpers/producer');
const admin=require('../middleware/admin');
const auth=require('../middleware/auth');
const jobQueue = require('../helpers/consumer');
const Queries=require('../helpers/mongofunctions');
const {generatecoinid}=require('../middleware/userid');


router.post('/addcontrols', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Not an admin");
    }

    const newobj = {
      register: req.body.register,
      userlogin: req.body.userlogin,
      transactions: req.body.transactions,
      referral_one: req.body.referral_one
    };

    const saved = await Queries.insertDocument('AdminControls', newobj);
    if (!saved) {
      return res.status(400).send('Admin controls not saved');
    }

    return res.status(200).send('Admin controls saved');
  } catch (error) {
    console.log(error);
    return res.status(400).send(`Error: ${error}`);
  }
});

router.post('/addcoins', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Not an admin");
    }
      const newCoin = {
      coinid: generatecoinid(),
      coinname: req.body.coinname,
      cointype: req.body.cointype,
      ticker: req.body.ticker,
      otcmin: req.body.otcmin,
      otcmax: req.body.otcmax,
      withdrawmin: req.body.withdrawmin,
      withdrawmax: req.body.withdrawmax,
      transmin: req.body.transmin,
      transmax: req.body.transmax,
      status:req.body.status
      
    };

    const adminControls = await Queries.find("AdminControls");
    adminControls.coins.push(newCoin);
    const saved = await adminControls.save();
    if (!saved) {
      return res.status(400).send('Admin controls not saved');
    }
    return res.status(200).send('Admin controls saved');
  } catch (error) {
    console.log(error);
    return res.status(400).send(`Error: ${error}`);
  }
});

router.post('/usercoin', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Not an admin");
    }

    const { userid, coinid } = req.body;

    const adminControls = await Queries.findOneDocument({coinid},"AdminControls");
    if (!adminControls) {
      return res.status(400).send('Coin not found');
    }

    const coin = adminControls.coins.find(coin => coin.coinid === coinid);
    if (!coin) {
      return res.status(400).send('Coin not found');
    }

    const coinToAdd = {
      coinname: coin.coinname,
      cointype: coin.cointype,
      ticker: coin.ticker,       
      balance: '1000',
    };

    const updatedUser = await Queries.findOneAndUpdate(
      { userid: userid },
      { $push: { balances: coinToAdd } },
      "User",
      { new: true }
    );

    if (!updatedUser) {
      return res.status(400).send('User not found');
    }

    return res.status(200).send('Coin added to user balances');
  } catch (error) {
    console.error(error);
    return res.status(400).send(`Error: ${error}`);
  }
});
router.post('/userscoin', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Not an admin");
    }
    const { coinid } = req.body;
    const adminControls = await Queries.findOneDocument({coinid},"AdminControls");
    if (!adminControls) {
      return res.status(400).send('Coin not found');
    }
    const coin = adminControls.coins.find(coin => coin.coinid === coinid);
    if (!coin) {
      return res.status(400).send('Coin not found');
    }

    const coinToAdd = {
      coinname: coin.coinname,
      cointype: coin.cointype,
      ticker: coin.ticker,
      balance: '1000',
    };

    const updatedUsers = await Queries.updateMany({},
      
      { $push: { balances: coinToAdd } },
      "User",{new:true});

    if (!updatedUsers) {
      return res.status(400).send('No users found');
    }

    return res.status(200).send('Coin added to all users balances');
  } catch (error) {
    console.error(error);
    return res.status(400).send(`Error: ${error}`);
  }
});

router.post('/updatecoinbalance', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Not an admin");
    }
    const { email, coinname, amount } = req.body;
    if (isNaN(amount) || parseFloat(amount) <= 0) {
      return res.status(400).send("Invalid amount");
    }
    const user = await Queries.findOneDocument({ email: email },"User");
    if (!user) {
      return res.status(400).send('User not found');
    }
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
      "User",
      { arrayFilters: [{ "coin.coinname": coinname }] },
      
      {new:true}
    );

    if (!updatedUser) return res.status(400).send('Balance not updated');
    return res.status(200).send('Coin balance updated successfully');
  } catch (error) {
    console.error(error);
    return res.status(400).send(`Error: ${error}`);
  }
});


router.post('/userkycstatus', async (req, res) => {
  try {
    const { userid, kycStatus } = req.body; 

    if (!userid || !kycStatus) {
      return res.status(400).send('User ID and KYC status are required');
    }

    const user = await Queries.findOneDocument({ userid },"User");
    if (!user) {
      return res.status(400).send('User not found');
    }

    user.kyc_status = kycStatus;
    await user.save();

    return res.status(200).send(`KYC status changed to ${kycStatus} for user ${userid}`);
  } catch (error) {
    console.error(error);
    return res.status(400).send(`Error: ${error.message}`);
  }
});






module.exports = router;






