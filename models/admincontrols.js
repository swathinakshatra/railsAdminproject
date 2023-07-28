const mongoose = require('mongoose');

const adminControlsSchema = new mongoose.Schema({
  register: {
    type: String,
    required: true,
    enum: ['Enable', 'Disable'],
    default: 'Disable'
  },
  userlogin: {
    type: String,
    required: true,
    enum: ['Enable', 'Disable'],
    default: 'Disable'
  },
  transactions: {  
    type: String,
    required: true,
    enum: ['Enable', 'Disable'],
    default: 'Disable'
  },
  referral_one:{
    type:String,
    required:true
    
  },
  coins:[]
 
  
});


const AdminControls = mongoose.model('AdminControls', adminControlsSchema);
exports.AdminControls = AdminControls;
    