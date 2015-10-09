'use strict';

const request = require('request');
const utils = require('./auth');

exports.registerMediator = (options, mediatorConfig, callback) => {
  // define login credentails for authorization
  const username = options.username;
  const password = options.password;
  const apiURL = options.apiURL;

  // authenticate the username
  utils.authenticate({username, apiURL}, (err) => {
    if (err) {
      return callback(err);
    }
    let headers = utils.genAuthHeaders({username, password});

    // define request headers with auth credentails
    let reqOptions = {
      url: `${apiURL}/mediators`,
      json: true,
      headers: headers,
      body: mediatorConfig
    };

    // POST mediator to API for creation/update
    request.post(reqOptions, (err, resp) => {
      if (err){
        return callback(err);
      }

      // check the response status from the API server
      if (resp.statusCode === 201) {
        // successfully created/updated
        callback();
      } else {
        callback(new Error(`Recieved a non-201 response code, the response body was: ${resp.body}`));
      }
    });
  });
};
