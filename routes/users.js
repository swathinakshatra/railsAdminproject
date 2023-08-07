const express = require('express');
const router = express.Router();
require("dotenv").config();
const path = require('path');
const Queries=require('../helpers/mongofunctions');
const {twofactorRegistration, loginuser,validateemail, loginverify}=require('../helpers/validations');
const bcrypt = require("bcrypt");
const { generateUserId } = require("../middleware/userid");
const redisquery=require('../helpers/redis');
const jwt = require("jsonwebtoken");
const twofactor = require("node-2fa");
const tiger=require('../helpers/tigerbalm');
const auth=require('../middleware/auth');
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
      const adminControls = await Queries.findOneDocument({},"AdminControls");
    if (adminControls.Register === 'Disable') {
      return res.status(400).send("Registration is currently disabled.");
    }
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
      return res.status(200).send("User Registered successfully");
    } catch (error) {
      console.log(error);
      return res.status(400).send(`Error: ${error}`);
    }
  });
  
  router.post("/getusers", async (req, res) => {
    try {
      
      const users = await Queries.find("User");

      if(!users) return res.status(400).send("No admin found");
      return res.status(200).send(users);
    } catch (error) {
      console.error(error);
      return res.status(400).send(`Error --> ${error}`);
    }
  });

  router.post("/userlogin", async (req, res) => {
    try {
      const { error } = loginuser(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) {
        return res.status(400).send("email not found");
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
        { email: req.body.email },
        "User"
      );
      if (!user) return res.status(400).send("email not found");
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
  router.post("/verifyotp", async(req, res) => {
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
          return res.status(400).send("twoFacode Expired");
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
        { expiresIn: "30d" }
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
        return res.status(400).send("email not found");
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
        return res.status(400).send("email not found");
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
      console.log(error);
      return res.status(400).send(`Error verifyenable: ${error.message}`);
    }
  });
  router.post("/twofadisable", auth, async (req, res) => {
    try {
      
      const { error } = validateemail(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },
        "User"
      );
      if (!user) {
        return res.status(400).send("email not found");
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
  
  router.post("/verifydisable", auth, async (req, res) => {
    try {
     
      const { error } = verifytwofa(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.user.email },
        "User"
      );
      if (!user) {
        return res.status(400).send("email not found");
      }
      const twoFaCode = req.body.twoFaCode;
      const decryptedSecret = tiger.decrypt(user.twoFaKey);
      const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
      if (result && result.delta === 0) {
        const updated = await Queries.findOneAndUpdate(
          { email: req.user.email },
          { twoFaStatus: "disabled" },
          "User",
          { new: true }
        );
        if (!updated) {
          return res.status(400).send("Failed to update document");
        }
        return res
          .status(200)
          .send(
            crypto.encryptobj({ twofacode: "twoFaCode verified successfully" })
          );
      } else if (result && result.delta !== 0) {
        return res.status(400).send("Twofacode has expired");
      } else {
        return res.status(400).send("Invalid twofacode");
      }
    } catch (error) {
      console.log(error);
      return res.status(400).send(`Error verify2fadisable: ${error.message}`);
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