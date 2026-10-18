// This is the file Vercel actually runs. It just hands every request to the
// same Express app defined in server.js, so all your routes work exactly
// the same way whether you're running locally (`node server.js`) or deployed
// on Vercel.
module.exports = require('../server.js');
