const randomstring = require("randomstring");
const { Member } = require("../models/member");
module.exports = {
  generateUserId: () => {
    const timestamp = Date.now();
    const randomNumber = Math.floor(Math.random() * 900) + 100;
    const userid = `user-${timestamp}-${randomNumber}`;
    return userid;
  },

  generatedeviceId: () => {
    const timestamp = Date.now();
    const randomNumber = Math.floor(Math.random() * 900) + 100;
    const device_id = `${timestamp}-${randomNumber}`;
    return device_id;
  },
  generatefcmtoken: () => {
    const timestamp = Date.now();
    const randomNumber = Math.floor(Math.random() * 900) + 100;
    const fcm_token = `${timestamp}-${randomNumber}`;
    return fcm_token;
  },
};