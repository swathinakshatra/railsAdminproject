const mongoose = require('mongoose');

const seatingSchema = new mongoose.Schema({
  name: Array,
  seatNumber: {
    type: Number,
    min: 1,
    max: 13,
    unique: true
  },
});

const Seating = mongoose.model('Seating',seatingSchema);
exports.Seating=Seating;