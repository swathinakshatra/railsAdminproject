const teleg = require("../helpers/telegram");
module.exports = function (handler) {
  return async (req, res, next) => {
    try {
      await handler(req, res);
    } catch (ex) {
      console.log("ex",ex);
      await teleg.alert_Developers(ex.stack);
     next(ex);
    }
  };
};