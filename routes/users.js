const express = require('express');
const router = express.Router();
require("dotenv").config();
const path = require('path');
const Queries=require('../helpers/mongofunctions');
const {twofactorRegistration}=require('../helpers/validations');
const bcrypt = require("bcrypt");
const { generateUserId } = require("../middleware/userid");
const redisquery=require('../helpers/redis');
const {loginemployee}=require('../helpers/validations');
const jwt = require("jsonwebtoken");
const twofactor = require("node-2fa");
const tiger=require('../helpers/tigerbalm');
const { User } = require('../models/user');
const sharp = require('sharp');
const fs = require('fs');
const multer = require('multer');
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });



router.post("/registration", async (req, res) => {
    try {
     const { error } = twofactorRegistration(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const userexists = await Queries.findOneDocument(
        { email: req.body.email},"User");
      if (userexists) return res.status(400).send("user already exists");
      
      const newusers = {
        userid: generateUserId(),
        username: req.body.username,
        email: req.body.email,
        password: req.body.password,
        last_login_ip:req.body.last_login_ip,
        fcm_token:req.body.fcm_token,
        referral_one:req.body.referral_one,
        balances:req.body.balances
       
        };
      const salt = await bcrypt.genSalt(10);
      newusers.password = await bcrypt.hash(newusers.password, salt);
      const users = await Queries.insertDocument("User", newusers);
      if (!users) return res.status(400).send("failed to register user");
      // const redisInsert = await redisquery.redishset("user",newusers.email, JSON.stringify(users));
      // console.log(redisInsert, "redisInsert");
      return res.status(200).send("User Registered successfully");
    } catch (error) {
      console.log(error);
      return res.status(400).send(`Error: ${error}`);
    }
  });
  router.post("/login", async (req, res) => {
    try {
      const { error } = loginemployee(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) {
        return res.status(400).send("user not found");
      } else {
        const validpassword = await bcrypt.compare(
          req.body.password,
          user.password
        );
        if (!validpassword) {
          return res.status(400).send("password does not match");
        } else {
        const token = jwt.sign(
            {
              userid: user.userid,
              username: user.username,
              email: user.email,
              twofastatus:user.twofastatus,
            },
            process.env.jwtPrivateKey,
            { expiresIn: "48h" }
          );
         return res.status(200).send(token);
        }
      }
    } catch (error) {
      console.log(error);
      return res.status(400).send( `error login -->${error}` );
    }
});
router.post('/sendotp', async (req, res) => {
  try {
    const user = await Queries.findOneDocument({ email: req.body.email }, "User");
    if (!user) {
      return res.status(400).send("Email not found");
    }
    const otp = "123456";
    const redisinsert = await redisquery.redisSET(user.email, otp);
    if (!redisinsert) {
      return res.status(400).send("Failed to send OTP.");
    }
    const expires = await redisquery.redisexpire(user.email, 60);
    console.log("expires", expires);
    return res.status(200).send("OTP sent successfully");
  } catch (error) { 
    console.log(error);
    return res.status(400).send(`Error: ${error}`);
  }
});
router.post('/generate2facode', async (req, res) => {
  try {
    const user = await Queries.findOneDocument({ userid: req.body.userid }, "User");

    if (!user) {
      return res.status(400).send('user not found');
    }
    const {secret,qr} = twofactor.generateSecret({ 
      name: "rails",
      account: user.userid
    });

    const encryptedSecret = tiger.encrypt(secret);
    const updated = await Queries.findOneAndUpdate(
      { userid: req.body.userid},
      { twofakey: encryptedSecret, twofastatus: "Active" },
      "User",
      { new: true }
    );

    if (!updated) {
      return res.status(400).send("Failed to update document");
    }

    return res.status(200).send({ secret:encryptedSecret,qr, message: "Secret key generated successfully"});
  } catch (error) {
    console.log(error);
    return res.status(400).send(`Error: ${error}`);
  }
});

router.post('/verify2facode', async (req, res) => {
  try {
    const user = await Queries.findOneDocument({userid: req.body.userid}, "User");
    if (!user) {
      return res.status(400).send('user not found');
    }
    const email = req.body.email;
    const otp = req.body.otp;
    const redisget = await redisquery.redisGET(email);

    if (!redisget) { 
      const user = await Queries.findOneDocument({ email }, "User");
      if (!user) {
        return res.status(400).send("Email not found");
      } else {
        return res.status(400).send("OTP expired");
      }
    }

    if (redisget !== otp) {
      return res.status(400).send("Incorrect OTP");
    }

    await redisquery.redisdelete(email);
    const token = req.body.token;
    const decryptedSecret = tiger.decrypt(user.twofakey);
    const result = twofactor.verifyToken(decryptedSecret, token);
    console.log("result",result);
    if (result && result.delta === 0) {
      const updated = await Queries.findOneAndUpdate(
        { userid: req.body.userid },
        { twofastatus: 'enabled' },
        "User",
        { new: true }
      );

      if (!updated) {
        return res.status(400).send('Failed to update document');
      }

      return res.status(200).send({twofacode:'2FA code verified successfully',message:'otp verified successfully'});
    } else {
      return res.status(400).send('Invalid or expired 2FA code');
    }
  } catch (error) {
    console.log(error);
    return res.status(400).send(`Error: ${error}`);
  }
});
router.post('/verify2fa', async (req, res) => {
  try {
    const user = await Queries.findOneDocument({userid: req.body.userid }, "User");
    if (!user) {
      return res.status(400).send('user not found');
    }
    const email = req.body.email;
    const otp = req.body.otp;
    const redisget = await redisquery.redisGET(email);
   if (!redisget) { 
      const user = await Queries.findOneDocument({ email }, "User");
      if (!user) {
        return res.status(400).send("Email not found");
      } else {
        return res.status(400).send("OTP expired");
      }
    }
    if (redisget !== otp) {
      return res.status(400).send("Incorrect OTP");
    }
    await redisquery.redisdelete(email);
    const token = req.body.token;
    const decryptedSecret = tiger.decrypt(user.twoFaKey);
    const result = twofactor.verifyToken(decryptedSecret, token);
    console.log("result",result);
    if (result && result.delta === 0) {
      const updated = await Queries.findOneAndUpdate(
        { userid: req.body.userid },
        { twoFaStatus: 'disabled' },
        "User",
        { new: true });

      if (!updated) {
        return res.status(400).send('Failed to update document');
      }

      return res.status(200).send({twofacode:'2FA code verified successfully',message:'otp verified successfully'});
    } else {
      return res.status(400).send('Invalid or expired 2FA code');
    }
  } catch (error) {
    console.log(error);
    return res.status(400).send(`Error: ${error}`);
  }
});
router.post('/userkyc', upload.array('files'), async (req, res) => {
  try {
    if (!req.body.userid) {
      return res.status(400).send('UserID is required');
    }

    const { userid } = req.body;

    const user = await Queries.findOneDocument({ userid },"User");
    if (!user) {
      return res.status(400).send("User not found");
    }

    const files = req.files;

    if (!files || files.length === 0) {
      return res.status(400).send('No files uploaded');
    }

    for (const file of files) {
      if (file.mimetype.includes('image')) {
        const imgBuffer = fs.readFileSync(file.path);
        const base64Image = imgBuffer.toString('base64');
        user.kyc_details.kyc_image.push(base64Image);
      } else if (file.mimetype === 'application/pdf') {
        const pdfBuffer = fs.readFileSync(file.path);
        const base64Pdf = pdfBuffer.toString('base64');
        user.kyc_details.kyc_pdf.push(base64Pdf);
      } else {
        return res.status(400).send('Invalid file format. Only images and PDFs are allowed.');
      }
    }

    await user.save();

    return res.status(200).send("Files saved in user's KYC details");
  } catch (e) {
    return res.status(400).send(e.message);
  }
});
router.post('/downloadkyc', async (req, res) => {
  try {
    const { userid, index, type } = req.body;
    const user = await Queries.findOneDocument({ userid: userid }, "User");
    if (!user) {
      return res.status(400).send("User not found");
    }
    let data;
    let extension;
    if (type === 'image') {
      data = user.kyc_details.kyc_image[index];
      extension = 'png'; 
    } else if (type === 'pdf') {
      data = user.kyc_details.kyc_pdf[index];
      extension = 'pdf';
    } else {
      return res.status(400).send('Invalid file type');
    }
    const decodedData = Buffer.from(data, 'base64');
    const filename = `${userid}_${index}.${extension}`;
    const filePath = path.join(__dirname, 'downloads', filename);
    const downloads = path.join(__dirname, 'downloads');
   if (!fs.existsSync(downloads)) {
    fs.mkdirSync(downloads);
    }
fs.writeFileSync(filePath, decodedData);
return res.status(200).send({ message: 'File downloaded successfully'});
  } catch (e) {
    return res.status(400).send(e.message);
  }
});







module.exports = router;