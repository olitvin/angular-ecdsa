module.exports = function(grunt) {

  // Load grunt tasks automatically
  require('load-grunt-tasks')(grunt);

  // Time how long tasks take. Can help when optimizing build times
  require('time-grunt')(grunt);

  grunt.loadNpmTasks('grunt-shell');
  grunt.loadNpmTasks('grunt-open');
  grunt.loadNpmTasks('grunt-contrib-watch');
//  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-karma');
  grunt.loadNpmTasks('grunt-browserify');

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    bwr: grunt.file.readJSON('bower.json'),
    files: {
      '<%= bwr.name %>.min.js': ['./src/index.js', './src/*/*.js']
    },

    browserify: {
/*      vendor: {
        src: [],
        dest: 'build/libs.js',
        options: {
          require: ['ecdsa']
        }
      },*/

      //standalone browserify watch - do NOT use with grunt-watch
      client: {
        src: ['src/*.js', 'src/lib/*.js'],
        dest: 'build/app.js'
      },

      //working with grunt-watch - do NOT use with keepAlive above
      watchClient: {
        src: ['src/*.js','src/**/*.js'],
        dest: 'build/app.js',
        options: {
          external: ['ecdsa'],
          watch: true
        }
      }
    },

    watch: {
      concat: {
        //note that we target the OUTPUT file from watchClient, and don't trigger browserify
        //the module watching and rebundling is handled by watchify itself
        files: ['src/*.js', 'src/lib/*.js'],
        tasks: ['concat']
      },
    },

    shell: {
      options : {
        stdout: true
      },
      npm_install: {
        command: 'npm install'
      },
      bower_install: {
        command: './node_modules/.bin/bower install'
      }
    },

    open: {
      devserver: {
        path: 'http://localhost:8888'
      },
      coverage: {
        path: 'http://localhost:5555'
      }
    },

    karma: {
      unit: {
        configFile: './test/karma-unit.conf.js',
        autoWatch: false,
        singleRun: true
      }
    },

    // Watches files for changes and runs tasks based on the changed files
    watch: {
      bower: {
        files: ['bower.json'],
        tasks: ['wiredep']
      },
      js: {
        files: ['src/**/*.js'],
        tasks: ['newer:jshint:all'],
        options: {
          livereload: true
        }
      },
      gruntfile: {
        files: ['Gruntfile.js'],
        tasks: ['ngconstant:development']
      }
    },
    concat: {
      dist:{}
    },
    // ngAnnotate tries to make the code safe for minification automatically by
    // using the Angular long form for dependency injection.
    ngAnnotate: {
      dist: {}
    },
    uglify: {
      options: {
        report: 'min',
        enclose: {
          'this': 'window',
          'this.angular': 'angular',
          'this.Math': 'Math',
          'void 0': 'undefined'
        },
        banner: '/*\n  <%= pkg.name %> - v<%= pkg.version %> \n  ' +
          '<%= grunt.template.today("yyyy-mm-dd") %>\n*/\n'+
        '',
      },
      dist: {
        options: {
          beautify: false,
          mangle: false, // true of ngmin
          compress: {
            global_defs: {
              'DEBUG': false
            },
            dead_code: true
          },
          sourceMap: '<%= bwr.name %>.min.js.map'
        },
        files: {
          '<%= bwr.name %>.min.js': ['./build/*.js']
        },
      },
      src: {
        options: {
          beautify: true,
          mangle: false,
          compress: false
        },
        files: {
          '<%= bwr.name %>.js': ['./build/*.js']
        },
      }
    }

  });

  grunt.registerTask('build', ['browserify:client', 'concat','ngAnnotate','uglify']);
  grunt.registerTask('test', ['build', 'karma:unit']);
  grunt.registerTask('autotest', ['autotest:unit']);
  grunt.registerTask('install', ['shell:npm_install','shell:bower_install']);
  grunt.registerTask('default', ['build']);


};
