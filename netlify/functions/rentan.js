const serverless = require('serverless-http');
const app = require('../../rentan/server');

exports.handler = serverless(app, {
  binary: ['application/pdf', 'application/zip', 'application/octet-stream']
});
