const io = require('socket.io-client');

const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InN3YXRoaSIsInBob25lIjoiOTA1MjU1Njg4NyIsInBhc3N3b3JkIjoiJDJiJDEwJHZlaHVRUlhtdVg4UkhoZ2lLOXN6VE9YSlVOcUczZ3FBck5ySDJwR25hendXL2JEajhCNzl5IiwiaWF0IjoxNjg4MzY5OTAxfQ.8di90vwrn6upvuvpH3UnIJQvvW_gj8D9xN2Ig2y1TXA';
const socket = io('http://localhost:3000', {
  query: { token: token },
});

socket.on('welcome', (data) => {
  console.log('Message:', data);
});

const userid = 'tw77pg3973sq3yjanwpkrs';

socket.emit('getUserDetails', userid, (error, userDetails) => {
  if (error) {
    console.log('Error fetching details:', error);
  } else {
    console.log('User details:', userDetails);
  }
});
const senderPhone = '9052556887';
const receiverPhone = '9052556888';
const amount = 30;
const currency = 'peso';
socket.emit('transferBalance', { senderPhone, receiverPhone, amount, currency }, (error, result) => {
  if (error) {
    console.log('Error transferring balance:', error);
  } else {
    console.log('Balance transfer successful:', result);
  }
});

















