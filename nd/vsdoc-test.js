/// <reference path="node-vsdoc.js" />


var hello = require('../hello')

/*
http
  .cat('http://localhost:3000/')
  .addCallback(function (data) {
      callbackFired = true;
      assert.equal('hello world', data);
      hello.server.close();
  });

process.addListener('exit', function () {
    assert.ok(callbackFired);
});
*/