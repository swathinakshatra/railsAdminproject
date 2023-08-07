const express = require("express");
const router = express.Router();
const Queries = require("../helpers/mongofunctions")


router.post('/generate', async (req, res) => {
  try {
    const { names } = req.body;

    const generatedSeatAssignments = [];
    if (!Array.isArray(names)) {
      return res.status(400).send({ message: 'Invalid request format. Names should be an array.' });
    }
    for (const name of names) {
      let seatNumber;
      do {
        seatNumber = Math.floor(Math.random() * 13) + 1;
      } while (await Queries.findOneDocument({ seatNumber }, 'Seating'));

      const seating = {
        name,
        seatNumber,
      };

      const insert = await Queries.insertDocument('Seating', seating);
      if (!insert) return res.status(400).send('failed to insert');
      
       generatedSeatAssignments.push(seating);
    }
    
    return res.status(200).send("success");

  } catch (err) {
    console.log(err);
    return res.status(400).send(`Error  --> ${err}`);
  }
});
router.post('/getplaces',async(req,res)=>{
  const get=await Queries.find('Seating');
  if(!get) return res.status(200).send('no details found');
  return res.status(200).send(get);
})

module.exports = router;
