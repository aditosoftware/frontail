'use strict';

const exec = require('child_process').exec;
const connect = require('connect');
const cookieParser = require('cookie');
const crypto = require('crypto');
const path = require('path');
const socketio = require('socket.io');
const tail = require('./lib/tail');
const connectBuilder = require('./lib/connect_builder');
const program = require('./lib/options_parser');
const serverBuilder = require('./lib/server_builder');
const daemonize = require('./lib/daemonize');

/**
 * Parse args
 */
program.parse(process.argv);
if (program.args.length === 0) {
  console.error('Arguments needed, use --help');
  process.exit();
}

/**
 * Validate params
 */
const doAuthorization = !!(program.user && program.password);
const doSecure = !!(program.key && program.certificate);
const sessionSecret = String(+new Date()) + Math.random();
const sessionKey = 'sid';
const files = program.args.join(' ');
const filesNamespace = crypto.createHash('md5').update(files).digest('hex');

if (program.daemonize) {
  daemonize(__filename, program, {
    doAuthorization,
    doSecure,
  });
} else {
  /**
   * HTTP(s) server setup
   */
  const appBuilder = connectBuilder();
  if (doAuthorization) {
    appBuilder.session(sessionSecret, sessionKey);
    appBuilder.authorize(program.user, program.password);
  }
  appBuilder
    .static(path.join(__dirname, 'lib/web/assets'))
    .index(path.join(__dirname, 'lib/web/index.html'), files, filesNamespace, program.theme);

  const builder = serverBuilder();
  if (doSecure) {
    builder.secure(program.key, program.certificate);
  }
  const server = builder
    .use(appBuilder.build())
    .port(program.port)
    .host(program.host)
    .build();

  /**
   * socket.io setup
   */
  const io = socketio.listen(server, {
    log: false,
  });

  if (doAuthorization) {
    io.use((socket, next) => {
      const handshakeData = socket.request;
      if (handshakeData.headers.cookie) {
        const cookie = cookieParser.parse(handshakeData.headers.cookie);
        const sessionId = connect.utils.parseSignedCookie(cookie[sessionKey], sessionSecret);
        if (sessionId) {
          return next(null);
        }
        return next(new Error('Invalid cookie'), false);
      }

      return next(new Error('No cookie in header'), false);
    });
  }

  var allClients = [];
  var traceStarted = false;
  var traceCommand = '';

  /**
   * Setup UI highlights
   */
  let highlightConfig;
  if (program.uiHighlight) {
    highlightConfig = require(path.resolve(__dirname, program.uiHighlightPreset)); // eslint-disable-line
  }

  /**
   * When connected send starting data
   */
  const tailer = tail(program.args, {
    buffer: program.number,
  });

  const filesSocket = io.of(`/${filesNamespace}`).on('connection', (socket) => {
    socket.emit('options:lines', program.lines);

    if (program.uiHideTopbar) {
      socket.emit('options:hide-topbar');
    }

    if (!program.uiIndent) {
      socket.emit('options:no-indent');
    }

    if (program.uiHighlight) {
      socket.emit('options:highlightConfig', highlightConfig);
    }

    tailer.getBuffer().forEach((line) => {
      socket.emit('line', line);
    });

    socket.on('iptrace', function (command) {
      traceStarted = true;
      traceCommand = command;

      //start trace
      var traceCom = 'sudo shorewall iptrace ' + command;
      var traceComm = exec(traceCom, function (error, stdout, stderr) {
        if (error !== null) {
          console.log('exec error: ' + error);
          traceStarted = false;
          traceCommand = '';
          socket.emit("tracestarted", {
            'err': true,
            'out': stderr
          })
        } else {
          socket.emit("tracestarted", {
            'err': false,
            'out': stdout
          })
        }

      });
    })

    socket.on('checkStartTrace', function () {
      //socket.emit("statusTrace", traceStarted);
      socket.emit("statusTrace", {
        'stat': traceStarted,
        'command': traceCommand
      });
    })

    allClients.push(socket);
    console.log("Client connected.Now: " + allClients.length);

    var stopTraceComm = function () {
      //stop trace
      console.log("stop trace");
      var cmd = "sudo shorewall reload";
      var stopCommand = exec(cmd, function (error, stdout, stderr) {
        if (error !== null) {
          console.log('exec error: ' + error);
          socket.emit("tracestopped", {
            'err': true,
            'out': stderr
          })
        } else {
          socket.emit("tracestopped", {
            'err': false,
            'out': stdout
          })
        }

      });
    }

    socket.on('traceStop', function () {
      traceStarted = false;
      traceCommand = "";
      stopTraceComm();
    });

    socket.on('disconnect', function () {
      console.log('Got disconnect!');

      var i = allClients.indexOf(socket);
      allClients.splice(i, 1);

      var waitToStopTrace = function () {
        setTimeout(function () {
          if (allClients.length <= 0) {
            traceStarted = false;
            traceCommand = "";
            stopTraceComm();
          }
        }, 3000);
      }

      console.log("Now: " + allClients.length);
      if (allClients.length <= 0) {
        waitToStopTrace();
      }
    });


  });

  /**
   * Send incoming data
   */
  tailer.on('line', (line) => {
    filesSocket.emit('line', line);
  });

  /**
   * Handle signals
   */
  const cleanExit = () => {
    process.exit();
  };
  process.on('SIGINT', cleanExit);
  process.on('SIGTERM', cleanExit);
}