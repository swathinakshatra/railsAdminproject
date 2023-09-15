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
router.post('/forgotpassword', async (req, res) => {
  try {
    const { error } = validateemail(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
      const admin = await Queries.findOneDocument({ email: req.body.email }, "Admin");
      if (!admin) return res.status(400).send({ message: "email not found" });
      
      const otp = "123456";
      const redisinsert = await redisquery.redisSETEX(admin.email,60,otp);
      if (!redisinsert) {
        return res.status(400).send("Failed to send OTP.");
      }
      return res.status(200).send({twoFaStatus: admin.twoFaStatus,
        otp: "otp sent successfully" });
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`error in forgotpassword -->${error}`);
  }
});
router.post("/adminlogins", async (req, res) => {
  try {
    
    const { error } = loginadmin(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: req.body.email },
      "Admin"
    );
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
        const loginOtp = "123456";
        const loginRedisKey = `login_otp_${admin.email}`;
        
        const redisInsert = await redisquery.redisSETEX(
          loginRedisKey,
          60,
          loginOtp
        );
        
        if (!redisInsert) {
          return res.status(400).send("Failed to send login OTP.");
        }

        return res.status(200).send(
          ({
          
            otp: "login otp sent successfully",
          })
        );
      }
    }
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error adminlogin -->${error}`);
  }
});

router.post("/transaction", async (req, res) => {
  try {
    const admin = await Queries.findOneDocument(
      { email: req.body.email },
      "Admin"
    );
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

    const transOtp ="123456"; 
    const transRedisKey = `transaction_otp_${admin.email}`;
    
    const redisInsert = await redisquery.redisSETEX(
      transRedisKey,
      60,
      transOtp
    );
    
    if (!redisInsert) {
      return res.status(400).send("Failed to send transaction OTP.");
    }

    return res.status(200).send(
      ({
       otp: "transaction otp sent successfully",
      })
      );
    }
  }
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error transaction -->${error}`);
  }
});

router.post("/verifyloginotp", async (req, res) => {
  try {
    const { email, otp } = req.body; 
    const loginRedisKey = `login_otp_${email}`;
    const admin = await Queries.findOneDocument(
      { email: req.body.email },
      "Admin"
    );
    if (!admin) {
      return res.status(400).send("email not found");
    } else {
    const storedOTP = await redisquery.redisGET(loginRedisKey); 
    
    if (!storedOTP) {
      return res.status(400).send("OTP not found or expired");
    }
    
    if (otp !== storedOTP) {
      return res.status(400).send("Incorrect OTP. Please try again.");
    }
    
   
    await redisquery.redisdelete(loginRedisKey);

    return res.status(200).send("Login successful.");
  }
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error verifyloginotp -->${error}`);
  }
});

router.post("/verifytransactionotp", async (req, res) => {
  try {
    const { email, otp} = req.body; 
    const transactionRedisKey = `transaction_otp_${email}`;
    const admin = await Queries.findOneDocument(
      { email: req.body.email },"Admin");
    if (!admin) {
      return res.status(400).send("email not found");
    } else {
    const storedOTP = await redisquery.redisGET(transactionRedisKey); 
    if (!storedOTP) {
      return res.status(400).send("OTP not found or expired. Please request a new OTP.");
    }
    if (otp !== storedOTP) {
      return res.status(400).send("Incorrect OTP. Please try again.");
    }
    await redisquery.redisdelete(transactionRedisKey);
    return res.status(200).send("Transaction successful.");
  }
  } catch (error) {
    await teleg.alert_Developers(error);
    return res.status(400).send(`error verifytransactionotp -->${error}`);
  }
});





router.post('/changep', async (req, res) => {
  try {
    const { error } = validateemail(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
      const admin = await Queries.findOneDocument({ email: req.body.email }, "Admin");
      if (!admin) return res.status(400).send({ message: "email not found" });
      
      const otp = "123456";
      const redisinsert = await redisquery.redisSETEX(admin.email,60,otp);
      if (!redisinsert) {
        return res.status(400).send("Failed to send OTP.");
      }
      return res.status(200).send({twoFaStatus: admin.twoFaStatus,
        otp: "otp sent successfully" });
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`error in forgotpassword -->${error}`);
  }
});

router.post('/changepa',auth,async (req, res) => {
  try {
    const {oldPassword, newPassword, otp,twoFaCode} = req.body;
    const { error } = changepassword(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const email = await Queries.findOneDocument({email:req.user.email}, "Admin");
    if (!email) {
      return res.status(400).send('User not found');
    }
    const isPasswordValid = await bcrypt.compare(oldPassword, email.password);
    if (!isPasswordValid) {
      return res.status(400).send('Invalid old password');
    }
    
    const storedOTP = await redisquery.redisget(email);
    if (storedOTP !== otp) {
      return res.status(400).send('Invalid OTP');
    }
    if(!storedOTP) return res.status(400).send('otp expired');
    const decryptedSecret = tiger.decrypt(email.twoFaKey);
    if (email.twoFaStatus === 'enabled') {
      const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
      if (!result || result.delta !== 0) {
        return res.status(400).send(`error changepassword -->${error}`);
      }
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    const updatedAdmin = await Queries.findOneAndUpdate(
      { email:req.user.email },
      { password: hashedPassword },
      "Admin",
      { new: true });
   if (!updatedAdmin) {
      return res.status(400).send('Failed to update admin password');
    }
    await redisquery.redisdelete(email);
    return res.status(200).send('Password changed successfully');
  } catch (error) { 
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send('Error in changing password');
  }
});


router.post('/passwordreset', async (req, res) => {
  try {
    const { email, otp, twoFaCode, newPassword } = req.body;
    const { error } = resetpassword(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const admin = await Queries.findOneDocument({ email: req.body.email }, "Admin");
    if (!admin) {
      return res.status(400).send("Email not found");
    }
    const redisget = await redisquery.redisGET(email);
    console.log("redisget", redisget);
    if (!redisget) {
      return res.status(400).send("OTP expired");
    }
      
    if (redisget !== otp) {
      return res.status(400).send("Incorrect OTP");
    }
    await redisquery.redisdelete(email);
    if (admin.twoFaStatus === 'enabled') {
      const decryptedSecret = tiger.decrypt(admin.twoFaKey);
      const result = twofactor.verifyToken(decryptedSecret, twoFaCode);
    if (!result) {
        return res.status(400).send("Invalid twoFaCode");
      } else if (result.delta !== 0) {
        return res.status(400).send("Expired twoFaCode");
      }
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    const updatedAdmin = await Queries.findOneAndUpdate(
      { email: req.body.email },
      { password: hashedPassword },
      "Admin",
      { new: true });

    if (!updatedAdmin) {
      return res.status(400).send('Failed to update password');
    }

    return res.status(200).send('Password reset successful');
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return res.status(400).send(`Error in resetpassword --> ${error}`);
  }
});


router.post('/addcoins', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Invalid admintype");
    }
    const { error } = validatecoins(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
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
      status: req.body.status
    };
    const adminControls = await Queries.findOneDocument({},"AdminControls");
    if (!adminControls) {
      return res.status(400).send('Admin controls not found');
    }
    adminControls.coins.push(newCoin);
    const saved = await adminControls.save();
    if (!saved) {
      return res.status(400).send('coin not saved');
    } 
    return res.status(200).send('coin added to admincontrols');
  } catch (error) {
    console.log(error);
    return res.status(400).send(`Error: ${error}`);
  }
});

router.post('/usercoin', auth, async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Invalid admintype");
    }
    const { userid,coinid } = req.body;
    const { error } = validatecoin(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);

    }
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
      { new: true });

    if (!updatedUser) {
      return res.status(400).send('failed to update balances');
    }

    return res.status(200).send('Coin added to user balances');
  } catch (error) {
    console.error(error);
    return res.status(400).send(`Error: ${error}`);
  }
});
router.post('/userscoin', auth,async (req, res) => {
  try {
    if (req.user.admintype !== '1') {
      return res.status(400).send("Invalid admintype");
    }
    const { coinid } = req.body;
    const { error } = validateuserscoin(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
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


  


  module.exports=router;
  