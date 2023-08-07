const mongoose = require('mongoose');

const adminControlsSchema = new mongoose.Schema({
  Register: {
    type: String,
    required: true,
    enum: ['Enable', 'Disable'],
    default: 'Disable'
  },
  login: {
    type: String,
    required: true,
    enum: ['Enable', 'Disable'],
    default: 'Disable'
  },
  Transfer: {  
    type: String,
    required: true,
    enum: ['Enable', 'Disable'],
    default: 'Disable'
  },
  referral_one: {
    status: { type: String, required: true, default: 'Enable' },
    level: { type: String, required: true, default: 1 }
  },
  coins: { type:Array, default: [] }
});
  


const AdminControls = mongoose.model('AdminControls', adminControlsSchema);
exports.AdminControls = AdminControls;
    