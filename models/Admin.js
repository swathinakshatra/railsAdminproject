const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema({
  adminId: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  date: { type: Date, required: true, default: Date.now },
  admintype: { type: String, required: true },
  twoFaKey: { type: String, default: '0' },
  twoFaStatus: {type: String,required: true,enum: ['disabled', 'enabled'],default: 'disabled'},
});

const Admin = mongoose.model('Admin', AdminSchema);
exports.Admin=Admin;
