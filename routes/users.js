const express = require('express');
const router = express.Router();
const Queries=require('../helpers/mongofunctions');
const query=require('../helpers/universal');
const {twofactorRegistration,
   loginuser,
   validateemail,
   loginverify, verifytwofa, validatelimit}=require('../helpers/validations');
const bcrypt = require("bcrypt");
const { generateId } = require("../middleware/userid");
const redisquery=require('../helpers/redis');
const jwt = require("jsonwebtoken");
const twofactor = require("node-2fa");
const tiger=require('../helpers/tigerbalm');
const auth=require('../middleware/auth');
const moment=require('moment');
const crypto=require('../helpers/crypto');
const teleg=require('../helpers/telegram');





router.post("/userregistration", async (req, res) => {
  try {
    const { error } = twofactorRegistration(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const userexists = await Queries.findOneDocument({ email: req.body.email }, "User");
    if (userexists) return res.status(400).send("User already exists");

    const formattedDate = moment().format("DD-MM-YYYY");
    const newusers = {
      userid: generateId(),
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
      last_login_ip: req.body.last_login_ip,
      fcm_token: req.body.fcm_token,
      referral_one: req.body.referral_one,
      balances: req.body.balances,
      date_registration: formattedDate,
    };

    const salt = await bcrypt.genSalt(10);
    newusers.password = await bcrypt.hash(newusers.password, salt);

    const users = await query.insertDocumentAndRedisSetex("User", newusers, newusers.email, 30, JSON.stringify(newusers));

    if (!users.collection) return res.status(400).send("Failed to register user");

    console.log("redisusers", users.redisResult);

    if (!users.redisResult) return res.status(400).send("Failed to insert data into Redis");

    return res.status(200).send("User Registered successfully");
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error userregistration -->${error}`);
  }
});
router.post("/userregistrations", async (req, res) => {
    try {
     
     const { error } = twofactorRegistration(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const userexists = await Queries.findOneDocument(
        { email: req.body.email},"User");
      if (userexists) return res.status(400).send("User already exists");
      const formattedDate = moment().format("DD-MM-YYYY");
      const newusers = {
        userid: generateId(),
        username: req.body.username,
        email: req.body.email,
        password: req.body.password,
        last_login_ip:req.body.last_login_ip,
        fcm_token:req.body.fcm_token,
        referral_one:req.body.referral_one,
        balances:req.body.balances,
        date_registration: formattedDate,
        };
      const salt = await bcrypt.genSalt(10);
      newusers.password = await bcrypt.hash(newusers.password, salt);
      const users = await Queries.insertDocument("User", newusers);
      if (!users) return res.status(400).send("Failed to register user");
      const redisusers = await redisquery.redisSETEX(newusers.email,30, JSON.stringify(users));
      console.log("redisusers",redisusers) 
     if (!redisusers) return res.status(400).send("Failed to insert data into Redis");
     return res.status(200).send("User Registered successfully");
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`error userregistration -->${error}`);
    }
  });
  router.post('/getredis', async (req, res) => {
    try {
      const email = req.body.email;
      const dataExists = await redisquery.redisexists(email);
     if (dataExists) {
      const data = await redisquery.redisget(email);
        console.log("Data from Redis:", data);
        return res.status(200).send(data);
      } else {
       const user = await Queries.findOneDocument({ email }, "User");
       if (!user) {
          return res.status(400).send("Email not found");
        }
        await redisquery.redisSETEX(email, 60, JSON.stringify(user));
        const cachedData = await redisquery.redisget(email);
        if (!cachedData) {
          return res.status(400).send("Failed to retrieve cached data from Redis");
        }
        console.log("Data from MongoDB:", user);
        return res.status(200).send(cachedData);
      }
    } catch (error) {
      console.error(error);
      return res.status(400).send("Error retrieving data");
    }
  });

 
  router.post("/getusers", async (req, res) => {
    try {
      const decrypted = crypto.decryptobj(req.body.enc);
     console.log("dec",decrypted);
      const { error } =validatelimit(decrypted);
      if (error) return res.status(400).send(error.details[0].message);
      const limit = decrypted.limit;
      const users = await Queries.findlimit("User", limit);
      if (!users) return res.status(400).send("No users found");
      return res.status(200).send(crypto.encryptobj(users));
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`error getusers -->${error}`);
    }
  
  });

  router.post("/userlogin", async (req, res) => {
    try {
      const { error } = loginuser(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) {
        return res.status(400).send("Email not found");
      } else {
        const validpassword = await bcrypt.compare(
          req.body.password,
          user.password
        );
        if (!validpassword) {
          return res.status(400).send("Incorrect password");
        } else {
          const otp = "123456";
          const redisinsert = await redisquery.redisSETEX(user.email, 60, otp);
          if (!redisinsert) {
            return res.status(400).send("Failed to send OTP.");
          }
          return res.status(200).send(crypto.encryptobj({
                twoFaStatus: user.twoFaStatus,
                otp: "OTP sent successfully",
              })
            );
        }
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`error userlogin -->${error}`);
    }
  });
  router.post("/resendotp", async (req, res) => {
    try {
      const { error } = validateemail(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) return res.status(400).send("Email not found");
      const otp = "123456";
      const redisinsert = await redisquery.redisSETEX(user.email, 60, otp);
      if (!redisinsert) {
        return res.status(400).send("Failed to send OTP.");
      }
      return res.status(200).send(crypto.encryptobj("OTP send successfully"));
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`error resendotp -->${error}`);
    }
  });
  router.post("/verifyotp",async(req, res) => {
    try {
      const { error } = loginverify(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument({ email:req.body.email },"User");
      if (!user) return res.status(400).send("Email not found");
      const email = req.body.email;
      const otp = req.body.otp;
      const redisget = await redisquery.redisGET(email);
      if (!redisget) {
        return res.status(400).send("OTP expired");
      }
      if (redisget !== otp) {
        return res.status(400).send("Incorrect OTP");
      }
     if (user.twoFaStatus === "enabled") {
        const twoFaCode = req.body.twoFaCode;
        const decryptedSecret = tiger.decrypt(user.twoFaKey);
        const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
       if (!result) {
          return res.status(400).send("Invalid twoFaCode");
        } else if (result.delta !== 0) {
          return res.status(400).send("TwoFacode Expired");
        }
      }
      const token = jwt.sign(
        {
          userid: user.userid,
          username:user.username,
          email: user.email,
          twofastatus: user.twofastatus
        },
        process.env.jwtPrivateKey,
        { expiresIn: "90d" }
      );
      const encryptedResponse = crypto.encryptobj({
        token: token,
        message: "Login successfully",
      });
      return res.status(200).send(encryptedResponse);
    } catch (error) {
      await teleg.alert_Developers(error);
      console.log(error);
      return res.status(400).send(`Error loginverify --> ${error}`);
    }
  });
  router.post("/twofaenable", auth, async (req, res) => {
    try {
      const { error } = validateemail(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },
        "User");
      if (!user) {
        return res.status(400).send("Email not found");
      }
      const { secret, qr } = twofactor.generateSecret({
        name: "Rails",
        account: user.userid,
      });
      const encryptedSecret = tiger.encrypt(secret);
      const updated = await Queries.findOneAndUpdate(
        { email: req.body.email },
        { twoFaKey: encryptedSecret },
        "User",
        { new: true }
      );
      if (!updated) {
        return res.status(400).send("Failed to update document");
      }
      return res.status(200).send(crypto.encryptobj({ secret: secret, qr }));
    } catch (error) {
      await teleg.alert_Developers(error);
      console.log(error);
      return res.status(400).send(`Error twofaenable: ${error}`);
    }
  }); 
  router.post("/verifyenable", auth, async (req, res) => {
    try {
      const { error } = verifytwofa(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.user.email },
        "User"
      );
      if (!user) {
        return res.status(400).send("Email not found");
      }
      const twoFaCode = req.body.twoFaCode;
      const decryptedSecret = tiger.decrypt(user.twoFaKey);
      const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
     if (result && result.delta === 0) {
        const updated = await Queries.findOneAndUpdate(
          { email: req.user.email },
          { twoFaStatus: "enabled" },
          "User",
          { new: true }
        );
        if (!updated) {
          return res.status(400).send("Failed to update document");
        }
        return res
          .status(200)
          .send(
            crypto.encryptobj({ twofacode: "twoFACode verified successfully" })
          );
      } else if (result && result.delta !== 0) {
        return res.status(400).send("Twofacode has expired");
      } else {
        return res.status(400).send("Invalid Twofacode");
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`error verifyenable -->${error}`);
    }
  });
  router.post("/twofadisable", auth, async (req, res) => {
    try {
      const { error } = validateemail(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) {
        return res.status(400).send("Email not found");
      } else {
        const { secret, qr } = twofactor.generateSecret({
          name: "Rails",
          account: user.userid,
        });
        tiger.encrypt(secret);
        return res.status(200).send(crypto.encryptobj({ secret: secret, qr }));
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      console.log(error);
      return res.status(400).send(`Error 2fadisable: ${error}`);
    }
  });
  
  router.post("/verifydisable",auth,async (req, res) => {
    try {
      const { error } = verifytwofa(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.user.email },
        "User"
      );
      if (!user) {
        return res.status(400).send("Email not found");
      }
      const twoFaCode = req.body.twoFaCode;
      const decryptedSecret = tiger.decrypt(user.twoFaKey);
      const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
      if (result && result.delta === 0) {
        const updated = await Queries.findOneAndUpdate(
          { email: req.user.email },
          { twoFaStatus: "disabled" },
          "User",
          { new: true });
        if (!updated) {
          return res.status(400).send("Failed to update document");
        }
        return res.status(200).send(
            crypto.encryptobj({ twofacode: "TwoFaCode verified successfully" })
          );
      } else if (result && result.delta !== 0) {
        return res.status(400).send("Twofacode has expired");
      } else {
        return res.status(400).send("Invalid twofacode");
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      return res.status(400).send(`error verifydisable -->${error}`);
    }
  });


  




module.exports = router;   