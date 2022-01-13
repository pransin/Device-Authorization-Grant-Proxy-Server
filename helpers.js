exports.base64Encode = (str) => {
  return str.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

exports.sha256 = (buffer) => {
  return crypto.createHash('sha256').update(buffer).digest();
}

exports.generateRandomString = (length = 6) => {
  return Math.random().toString(36).substring(2, length + 2);;
}

exports.build_auth_url = (baseURL, params) => {
  Object.keys(params).forEach(key => (params[key] === undefined ? delete params[key] : {}));
  const queryString = Object.keys(params)
    .map(key => `${key}=${params[key]}`)
    .join('&');
  const url = `${baseURL}?${queryString}`;
  return url;
}

// console.log(generateRandomString(4));