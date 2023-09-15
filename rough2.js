require("dotenv").config();
const express = require("express");
const router = express.Router();
const Queries = require("../helpers/mongofunctions");
const redisquery = require("../helpers/redis");
const { generateAdminId } = require("../middleware/userid");
const {
  adminValidation,
  loginadmin,
  validateemail,
  loginverify,
  verifytwofa,
  validateNewAdmin,
  validateresetpassword,
  validateadmintype,
} = require("../helpers/validations");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const twofactor = require("node-2fa");
const tiger = require("../helpers/tigerbalm");
const crypto = require("../helpers/crypto");
const teleg = require("../helpers/telegram");
router.post("/adminregistration", async (req, res) => {
  try {
    const { error } = adminValidation(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const emailExists = await Queries.findOneDocument(
      { email: req.body.email },
      "Admin"
    );
    if (emailExists) {
      return res.status(400).send("Email already exists");
    }
    const newAdmin = {
      adminId: generateAdminId(),
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      admintype: req.body.admintype,
    };
    const salt = await bcrypt.genSalt(10);
    newAdmin.password = await bcrypt.hash(newAdmin.password, salt);
    const insertedAdmin = await Queries.insertDocument("Admin", newAdmin);
    if (!insertedAdmin) {
      return res.status(400).send("Failed to register Admin");
    }

    return res.status(200).send("Admin registered successfully");
  } catch (err) {
    await teleg.alert_Developers(err);

    return res.status(400).send(`error Registration -->${err}`);
  }
});
router.post("/adminlogin", async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    const { error } = loginadmin(decrypted);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: decrypted.email },
      "Admin"
    );
    if (!admin) {
      return res.status(400).send("email not found");
    } else {
      const validpassword = await bcrypt.compare(
        decrypted.password,
        admin.password
      );
      if (!validpassword) {
        return res.status(400).send("Incorrect password");
      } else {
        const otp = "123456";
        const redisinsert = await redisquery.redisSETEX(admin.email, 60, otp);
        if (!redisinsert) {
          return res.status(400).send("Failed to send OTP.");
        }
        return res
          .status(200)
          .send(
            crypto.encryptobj({
              twoFaStatus: admin.twoFaStatus,
              otp: "otp sent successfully",
            })
          );
      }
    }
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error adminlogin -->${error}`);
  }
});
router.post("/resendotp", async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    const { error } = validateemail(decrypted);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: decrypted.email },
      "Admin"
    );
    if (!admin) return res.status(400).send("email not found");
    const otp = "123456";
    const redisinsert = await redisquery.redisSETEX(admin.email, 60, otp);
    if (!redisinsert) {
      return res.status(400).send("Failed to send OTP.");
    }
    return res.status(200).send(crypto.encryptobj("OTP send successfully"));
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error resendotp -->${error}`);
  }
});
router.post("/verifylogin", async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    const { error } = loginverify(decrypted);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: decrypted.email },
      "Admin"
    );
    if (!admin) return res.status(400).send("Email not found");
    const email = decrypted.email;
    const otp = decrypted.otp;
    const redisget = await redisquery.redisGET(email);
    if (!redisget) {
      return res.status(400).send("OTP expired");
    }
    if (redisget !== otp) {
      return res.status(400).send("Incorrect OTP");
    }
    await redisquery.redisdelete(email);
    if (admin.twoFaStatus === "enabled") {
      const twoFaCode = decrypted.twoFaCode;
      const decryptedSecret = tiger.decrypt(admin.twoFaKey);
      const result = twofactor.verifyToken(decryptedSecret, twoFaCode);

      if (!result) {
        return res.status(400).send("Invalid twoFaCode");
      } else if (result.delta !== 0) {
        return res.status(400).send("Expired twoFacode");
      }
    }
    const token = jwt.sign(
      {
        adminId: admin.adminId,
        email: admin.email,
        twoFaStatus: admin.twoFaStatus,
        admintype: admin.admintype,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "30d" }
    );
    const encryptedResponse = crypto.encryptobj({
      token: token,
      message: "Login successful",
    });
    return res.status(200).send(encryptedResponse);
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`Error loginverify --> ${error}`);
  }
});
router.post("/2faenable", auth, async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    const { error } = validateemail(decrypted);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: decrypted.email },
      "Admin"
    );
    if (!admin) {
      return res.status(400).send("email not found");
    }
    const { secret, qr } = twofactor.generateSecret({
      name: "Rails",
      account: admin.adminId,
    });
    const encryptedSecret = tiger.encrypt(secret);
    const updated = await Queries.findOneAndUpdate(
      { email: decrypted.email },
      { twoFaKey: encryptedSecret },
      "Admin",
      { new: true }
    );
    if (!updated) {
      return res.status(400).send("Failed to update document");
    }
    return res.status(200).send(crypto.encryptobj({ secret: secret, qr }));
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`Error 2faenable: ${error}`);
  }
});
router.post("/verify2faenable", auth, async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    const { error } = verifytwofa(decrypted);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: req.user.email },
      "Admin"
    );
    if (!admin) {
      return res.status(400).send("email not found");
    }
    const twoFaCode = decrypted.twoFaCode;
    const decryptedSecret = tiger.decrypt(admin.twoFaKey);
    console.log("Decrypted secret:", decryptedSecret);
    const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
    console.log("Verification result:", result);
    if (result && result.delta === 0) {
      const updated = await Queries.findOneAndUpdate(
        { email: req.user.email },
        { twoFaStatus: "enabled" },
        "Admin",
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
    return res.status(400).send(`Error verify2faenable: ${error.message}`);
  }
});
router.post("/2fadisable", auth, async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    const { error } = validateemail(decrypted);
    if (error) return res.status(400).send(error.details[0].message);

    const admin = await Queries.findOneDocument(
      { email: decrypted.email },
      "Admin"
    );
    if (!admin) {
      return res.status(400).send("email not found");
    } else {
      const { secret, qr } = twofactor.generateSecret({
        name: "Rails",
        account: admin.adminId,
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

router.post("/verify2fadisable", auth, async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("disabledecrypted", decrypted);
    const { error } = verifytwofa(decrypted);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: req.user.email },
      "Admin"
    );
    if (!admin) {
      return res.status(400).send("email not found");
    }
    const twoFaCode = decrypted.twoFaCode;
    const decryptedSecret = tiger.decrypt(admin.twoFaKey);
    const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
    console.log("Verification disableresult:", result);
    if (result && result.delta === 0) {
      const updated = await Queries.findOneAndUpdate(
        { email: req.user.email },
        { twoFaStatus: "disabled" },
        "Admin",
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
router.post("/addAdmin", auth, async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    const { error } = validateNewAdmin(decrypted);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    if (req.user.admintype !== "1") {
      return res.status(400).send("Not an admin");
    }

    const emailExists = await Queries.findOneDocument(
      { email: decrypted.email },
      "Admin"
    );
    if (emailExists) {
      return res.status(400).send("Email already exists");
    }
    const newAdmin = {
      adminId: generateAdminId(),
      name: decrypted.name,
      email: decrypted.email,
      password: decrypted.password,
      admintype: decrypted.admintype,
    };
    const salt = await bcrypt.genSalt(10);
    newAdmin.password = await bcrypt.hash(newAdmin.password, salt);
    const insertedAdmin = await Queries.insertDocument("Admin", newAdmin);
    if (!insertedAdmin) {
      return res.status(400).send("Failed to register Admin");
    }
    return res.status(200).send(crypto.encryptobj("Admin added successfully"));
  } catch (err) {
    await teleg.alert_Developers(err);
    return res.status(400).send(`error Registration -->${err}`);
  }
});

router.post("/changepassword", auth, async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    if (req.user.admintype !== "1") {
      return res.status(400).send("Not an superadmin");
    }
    const { adminId, newPassword } = decrypted;
    const { error } = validateresetpassword(decrypted);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const admin = await Queries.findOneDocument({ adminId }, "Admin");
    if (!admin) {
      return res.status(400).send("Admin not found");
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    const updatedAdmin = await Queries.findOneAndUpdate(
      { adminId: decrypted.adminId },
      { password: hashedPassword },
      "Admin",
      { new: true }
    );
    if (!updatedAdmin) {
      return res.status(400).send("Failed to update password");
    }

    return res
      .status(200)
      .send(crypto.encryptobj("Password changed successfully"));
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`Error in changepassword --> ${error}`);
  }
});

router.post("/getAdmins", async (req, res) => {
  try {
    const admins = await Queries.find("Admin");
    return res.status(200).send(crypto.encryptobj(admins));
  } catch (error) {
    console.error(error);
    return res.status(400).send(`Error --> ${error}`);
  }
});
router.post("/changeAdminType", auth, async (req, res) => {
  try {
    const decrypted = crypto.decryptobj(req.body.enc);
    console.log("decrypted", decrypted);
    if (req.user.admintype !== "1") {
      return res.status(400).send("Not an Admin");
    }
    const { error } = validateadmintype(decrypted);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const { adminId, admintype } = decrypted;
    const updatedAdmin = await Queries.findOneAndUpdate(
      { adminId: adminId },
      { $set: { admintype: admintype } },
      "Admin",
      { new: true }
    );

    if (!updatedAdmin) {
      return res.status(400).send("Failed to update admin");
    }

    return res
      .status(200)
      .send(crypto.encryptobj("Admin type updated successfully"));
  } catch (err) {
    await teleg.alert_Developers(err);
    return res.status(400).send(`Error updating admin type --> ${err}`);
  }
});

module.exports = router;
