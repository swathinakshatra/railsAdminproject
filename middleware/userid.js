const generateUserId = () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let userid = '';
  for (let i = 0; i < 10; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    userid += characters.charAt(randomIndex);
  }
  
  const numbers = '0123456789';
  let randomNumbers = '';
  for (let i = 0; i < 6; i++) {
    const randomIndex = Math.floor(Math.random() * numbers.length);
    randomNumbers += numbers.charAt(randomIndex);
  }

  userid = `${userid}${randomNumbers}@RA`;
  return userid;
};
const generateAdminId = () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let adminId = '';
  for (let i = 0; i < 10; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    adminId += characters.charAt(randomIndex);
  }
  
  const numbers = '0123456789';
  let randomNumbers = '';
  for (let i = 0; i < 6; i++) {
    const randomIndex = Math.floor(Math.random() * numbers.length);
    randomNumbers += numbers.charAt(randomIndex);
  }

  adminId = `${adminId}${randomNumbers}@RAILS`;
  return adminId;
};
const generatecoinid = () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let coinid = '';
  for (let i = 0; i < 16; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    coinid += characters.charAt(randomIndex);
  }
  return coinid;
};







module.exports = { generateUserId,generateAdminId,generatecoinid };