const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
module.exports = (app) => {
  app.use(helmet());
  app.use(compression());
  app.use(cors())
 
}