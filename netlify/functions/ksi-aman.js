const serverless = require('serverless-http');
const app = require('../../aman/server.js');

exports.handler = serverless(app, {
  binary: ['application/pdf', 'application/zip', 'application/octet-stream']
});
