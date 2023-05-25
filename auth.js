"use strict";

import fetch from "node-fetch";
import https from "https";

const authUserMap = new Map();

export const authenticate = async (options, callback) => {
  // authenticate the username
  let reqOptions = {
    url: `${options.apiURL}/authenticate/${options.username}`,
    rejectUnauthorized: !options.trustSelfSigned,
  };
  // continue to support old option name for backwards compatibility
  if (options.rejectUnauthorized == false) {
    reqOptions.rejectUnauthorized = false;
  }

  const httpsAgent = new https.Agent({
    rejectUnauthorized: reqOptions.rejectUnauthorized,
  });

  try {
    const res = await fetch(reqOptions.url, {
      method: "GET",
      agent: httpsAgent,
    });

    if (res.status !== 200) {
      return callback(
        new Error(
          `User ${options.username} not found when authenticating with core API`
        )
      );
    }

    const body = await res.json();

    authUserMap.set(options.username, body.salt);

    await callback(null, body);
  } catch (error) {
    return callback(error);
  }
};

export const genAuthHeaders = (options) => {

  const { username, password } = options;
  const basicAuthHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

  return {
    Authorization: basicAuthHeader,
  };
};

export const appendHeader = (original, { key, value }) => {
  let newHeaders = original;

  Object.keys(newHeaders).push(key);
  newHeaders[key] = value;

  return newHeaders;
};
