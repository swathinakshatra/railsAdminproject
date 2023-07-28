router.post('/adminlogins',async(req,res)=>{
  try {
    
      const { error } = loginadmin(req.body);
      if (error) return res.status(400).send(error.details[0].message);
      const admin = await Queries.findOneDocument(
        { email: req.body.email },"Admin");
      if (!admin) {
        return res.status(400).send("email not found");
      } else {
        const validpassword = await bcrypt.compare(
          req.body.password,
          admin.password
        );
        if (!validpassword) {
          return res.status(400).send("Incorrect password");
        } else {
          const otp = "123456";
          const redisinsert = await redisquery.redisSETEX(admin.email,60,otp);
          if (!redisinsert) {
            return res.status(400).send("Failed to send OTP.");
          }
         return res.status(200).send(({twoFaStatus: admin.twoFaStatus,
            otp: "otp sent successfully" }));
        }
      }
    } catch (error) { 
      await teleg.alert_Developers(error);
      return res.status(400).send( `error adminlogin -->${error}` );
    }
});
router.post("/resendotps", async (req, res) => {
  try {
    
    const { error } = validateemail(req.body);
      if (error) return res.status(400).send(error.details[0].message);
   const admin = await Queries.findOneDocument(
      { email: req.body.email },"Admin");
    if (!admin) return res.status(400).send("email not found");
    const otp = "123456";
    const redisinsert = await redisquery.redisSETEX(admin.email,60,otp);
    if (!redisinsert) {
      return res.status(400).send("Failed to send OTP.");
    }
    return res.status(200).send(("OTP send successfully"));
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error resendotp -->${error}`);
  }
});
router.post('/verifylogins',async (req, res) => {
  try {
    
    const { error } = loginverify(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument({ email:req.body.email }, "Admin");
    if (!admin) return res.status(400).send("Email not found");
    const email = req.body.email;
    const otp = req.body.otp;
    const redisget = await redisquery.redisGET(email);
    if (!redisget) {
      return res.status(400).send("OTP expired");
    }
    if (redisget !== otp) {
      return res.status(400).send("Incorrect OTP");
    }
    await redisquery.redisdelete(email);
    if (admin.twoFaStatus === 'enabled') {
      const twoFaCode = req.body.twoFaCode; 
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
        admintype:admin.admintype
      },
      process.env.jwtPrivateKey,
      { expiresIn: "30d" });
      const encryptedResponse =({token:token,message:'Login successful'});
  return res.status(200).send(encryptedResponse);
  
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`Error loginverify --> ${error}`);
  }
});
router.post('/2faenables',auth,async (req, res) => {
  try {
    
    const { error } = validateemail(req.body);
    if (error) return res.status(400).send(error.details[0].message);
  const admin = await Queries.findOneDocument({email:req.body.email}, "Admin");
  if (!admin) {
      return res.status(400).send('email not found');
    }
    const {secret,qr} = twofactor.generateSecret({ 
      name: "Rails",
      account: admin.adminId
    });
    const encryptedSecret = tiger.encrypt(secret); 
    const updated = await Queries.findOneAndUpdate(
      {email:req.body.email},
      { twoFaKey: encryptedSecret},
      "Admin",
      { new: true });
      if (!updated) {
      return res.status(400).send("Failed to update document");
    }
    return res.status(200).send(({ secret:secret,qr}));
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`Error 2faenable: ${error}`);
  }
});
router.post('/verify2faenables',auth,async (req, res) => {
  try {
    
    const { error } = verify2fa(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument({email: req.user.email}, "Admin");
    if (!admin) {
      return res.status(400).send('email not found'); 
    }
    const twoFaCode =req.body.twoFaCode;
    const decryptedSecret = tiger.decrypt(admin.twoFaKey);
    console.log("Decrypted secret:", decryptedSecret);
    const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
    console.log("Verification result:", result);
   if (result && result.delta === 0) {
      const updated = await Queries.findOneAndUpdate(
        {email:req.user.email},
        { twoFaStatus: 'enabled' },
        "Admin",
        { new: true });
     if (!updated) {
        return res.status(400).send('Failed to update document');
      }
    return res.status(200).send(({ twofacode: 'twoFACode verified successfully'}));
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
router.post('/2fadisables', auth,async (req, res) => {
  try {
   
    const { error } = validateemail(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const admin = await Queries.findOneDocument({ email:req.body.email }, "Admin");
    if (!admin) {
      return res.status(400).send('email not found');
    } else {
      const { secret, qr } = twofactor.generateSecret({
        name: "Rails",
        account: admin.adminId
      });
      const encryptedSecret = tiger.encrypt(secret);
      const updated = await Queries.findOneAndUpdate(
        { email: req.body.email },
        { twoFaKey: encryptedSecret},
        "Admin",
        { new: true });

      if (!updated) {
        return res.status(400).send("Failed to update document");
      }

      return res.status(200).send(({ secret: secret, qr}));
    }
  } catch (error) {  
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`Error 2fadisable: ${error}`);
  }
});





router.post('/verify2fadisables',auth,async (req, res) => {
  try {
   
    const { error } = verify2fa(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument({email: req.user.email}, "Admin");
    if (!admin) {
      return res.status(400).send('email not found'); 
    }
    const twoFaCode = req.body.twoFaCode;
    const decryptedSecret = tiger.decrypt(admin.twoFaKey);
    const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
    console.log("Verification disableresult:", result);
   if (result && result.delta === 0) {
      const updated = await Queries.findOneAndUpdate(
        {email:req.user.email},
        { twoFaStatus: 'disabled' },
        "Admin",
        { new: true }
      );
     if (!updated) {
        return res.status(400).send('Failed to update document');
      }
    return res.status(200).send(({ twofacode: 'twoFaCode verified successfully'}));
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

  


  module.exports=router;
  