module.exports = function() {
  return {
    basePath: '../',
    frameworks: ['jasmine'],
    reporters: ['progress'],
    browsers: ['Chrome'],
    autoWatch: true,

    // these are default values anyway
    singleRun: false,
    colors: true,
    
    files : [
      //3rd Party Code
      'bower_components/angular/angular.js',

      //App-specific Code
      'angular-ecdsa.js'

      //Test-Specific Code
//      'node_modules/chai/chai.js',
//      'test/lib/chai-should.js',
//      'test/lib/chai-expect.js'
    ]
  }
};
