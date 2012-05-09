(function () {
    var require = this.require = function (modelName) {
        ///<summary>
        ///To require modules.
        ///</summary>
        ///<param name="modelName" type="String">
        ///A reference to the current module
        ///</param>
        var model;
        eval("model=" + modelName);
        return model;
    }

    require.resolve = function(){};
    require.cache = function(){};

    
    this.process = {
        EventEmitter:function(){},
        addListener:function(){},
        arch:'',
        argv:{},
        assert:function(){},
        binding:function(){},
        chdir:function(){},
        createChildProcess:function(){},
        cwd:function(){},
        debug:function(){},
        dlopen:function(){},
        emit:function(){},
        env:{},
        error:function(){},
        execPath:'',
        exit:function(){},
        features:{},
        inherits:function(){},
        kill:function(){},
        listeners:function(){},
        memoryUsage:function(){},
        mixin:function(){},
        moduleLoadList:{},
        nextTick:function(){},
        once:function(){},
        on:function(){},
        openStdin:function(){},
        pid:Number(),
        platform:'',
        reallyExit:function(){},
        removeAllListeners:function(){},
        removeListener:function(){},
        setMaxListeners:function(){},
        stderr:{},
        stdin:{},
        stdout:{},
        title:'',
        umask:function(){},
        unwatchFile:function(){},
        uptime:function(){},
        uvCounters:function(){},
        versions:{},
        version:'',
        watchFile:function(){}
    };


     this.console = {
         assert:function(){},
         dir:function(obj){},
         error:function(){},
         info:function(){},
         log:function(){},
         timeEnd:function(){},
         time:function(label){},
         trace:function(label){},
         warn:function(){} 
    }

    var Buffers = {
        byteLength:function(){},
        isBuffer:function(){},
        poolSize:0
    }

    Buffers.prototype = {
        write : function(string, offset, length, encoding) { },
        toString : function(encoding, start, end) { },
        copy : function(targetBuffer, targetStart, sourceStart, sourceEnd) { },
        slice : function(start, end) { },
        readUInt8 : function(offset, noAssert) { },
        readUInt16LE : function(offset, noAssert) { },
        readUInt16BE : function(offset, noAssert) { },
        readUInt32LE : function(offset, noAssert) { },
        readUInt32BE : function(offset, noAssert) { },
        readInt8 : function(offset, noAssert) { },
        readInt16LE : function(offset, noAssert) { },
        readInt16BE : function(offset, noAssert) { },
        readInt32LE : function(offset, noAssert) { },
        readInt32BE : function(offset, noAssert) { },
        readFloatLE : function(offset, noAssert) { },
        readFloatBE : function(offset, noAssert) { },
        readDoubleLE : function(offset, noAssert) { },
        readDoubleBE : function(offset, noAssert) { },
        writeUInt8 : function(value, offset, noAssert) { },
        writeUInt16LE : function(value, offset, noAssert) { },
        writeUInt16BE : function(value, offset, noAssert) { },
        writeUInt32LE : function(value, offset, noAssert) { },
        writeUInt32BE : function(value, offset, noAssert) { },
        writeInt8 : function(value, offset, noAssert) { },
        writeInt16LE : function(value, offset, noAssert) { },
        writeInt16BE : function(value, offset, noAssert) { },
        writeInt32LE : function(value, offset, noAssert) { },
        writeInt32BE : function(value, offset, noAssert) { },
        writeFloatLE : function(value, offset, noAssert) { },
        writeFloatBE : function(value, offset, noAssert) { },
        writeDoubleLE : function(value, offset, noAssert) { },
        writeDoubleBE : function(value, offset, noAssert) { },
        fill : function(value, offset, length) { },
        length : null

    };
   

    this.__filename = null;
    this.__dirname = null;
    this.module = {exports:{}};


    var util = {
        format: function () { },
        debug: function (string) { },
        log: function (string) { },
        inspect: function (object, showHidden, depth) { },
        pump: function (readableStream, writableStream, callback) { },
        inherits: function (constructor, superConstructor) { }
    };

    var events = {
        EventEmitter: {
            addListener: function (event, listener) { },
            on: function (event, listener) { },
            once: function (event, listener) { },
            removeListener: function (event, listener) { },
            removeAllListeners: function (event) { },
            setMaxListeners: function (n) { },
            listeners: function (event) { },
            emit: function (event, arg1, arg2, argn) { }
        }
    };

    

    var streams = {
        setEncoding : function(encoding) { },
        pause : function() { },
        resume : function() { },
        destroy : function() { },
        destroySoon : function() { },
        pipe : function(destination, options) { },
        write : function(string, encoding='utf8', fd) { },
        end : function() { },
        end : function(string, encoding) { },
        end : function(buffer) { },
        destroy : function() { },
        destroySoon : function() { }
    };


    var crypto = {
        Hash:{
            update : function(data) { },
            digest : function(encoding='binary') { }
        },
        Hmac:{
            update : function(data) { },
            digest : function(encoding='binary') { }
        },
        Cipher:{
            update : function(data, input_encoding='binary', output_encoding='binary') { },
            final : function(output_encoding='binary') { }
        },
        Decipher:{
            update : function(data, input_encoding='binary', output_encoding='binary') { },
            final : function(output_encoding='binary') { }
        },
        Sign:{
            update : function(data) { },
            sign : function(private_key, output_format='binary') { }
        },
        Verify:{
            update : function(data) { },
            verify : function(object, signature, signature_format='binary') { }
        },
        DiffieHellman:{
            generateKeys : function(encoding='binary') { },
            computeSecret : function(other_public_key, input_encoding='binary', output_encoding=input_encoding) { },
            getPrime : function(encoding='binary') { },
            getGenerator : function(encoding='binary') { },
            getPublicKey : function(encoding='binary') { },
            getPrivateKey : function(encoding='binary') { },
            setPublicKey : function(public_key, encoding='binary') { },
            setPrivateKey : function(public_key, encoding='binary') { }
        },
        createCredentials : function(details) { },
        createHash : function(algorithm) { return this.Hash;},
        createHmac : function(algorithm, key) { return this.Hmac;},
        createCipher : function(algorithm, password) { return this.Cipher;},
        createCipheriv : function(algorithm, key, iv) { return this.Cipher;},
        createDecipher : function(algorithm, password) { return this.Decipher;},
        createDecipheriv : function(algorithm, key, iv) { return this.Decipher;},
        createSign : function(algorithm) { return this.Sign;},
        createVerify : function(algorithm) { return this.Verify;},
        createDiffieHellman : function(prime_length) { }
    };

    var tls = {
        Server:{
            listen : function(port, host, callback) { },
            close : function() { },
            addContext : function(hostname, credentials) { },
            maxConnections:null,
            connections:null
        },
        CleartextStream:{            
            authorized:null,
            authorizationError:null,
            getPeerCertificate : function() { }
        },
        connect : function(port, host, options, callback) { },
        createSecurePair : function(credentials, isServer, requestCert, rejectUnauthorized) { },
        createServer : function(options, secureConnectionListener) { }
    };

    var fs = {
        rename : function(path1, path2, [callback]) { },
        renameSync : function(path1, path2) { },
        truncate : function(fd, len, [callback]) { },
        truncateSync : function(fd, len) { },
        chown : function(path, uid, gid, [callback]) { },
        chownSync : function(path, uid, gid) { },
        fchown : function(path, uid, gid, [callback]) { },
        fchownSync : function(path, uid, gid) { },
        lchown : function(path, uid, gid, [callback]) { },
        lchownSync : function(path, uid, gid) { },
        chmod : function(path, mode, [callback]) { },
        chmodSync : function(path, mode) { },
        fchmod : function(fd, mode, [callback]) { },
        fchmodSync : function(path, mode) { },
        lchmod : function(fd, mode, [callback]) { },
        lchmodSync : function(path, mode) { },
        stat : function(path, [callback]) { },
        lstat : function(path, [callback]) { },
        fstat : function(fd, [callback]) { },
        statSync : function(path) { },
        lstatSync : function(path) { },
        fstatSync : function(fd) { },
        link : function(srcpath, dstpath, [callback]) { },
        linkSync : function(srcpath, dstpath) { },
        symlink : function(linkdata, path, [callback]) { },
        symlinkSync : function(linkdata, path) { },
        readlink : function(path, [callback]) { },
        readlinkSync : function(path) { },
        realpath : function(path, [callback]) { },
        realpathSync : function(path) { },
        unlink : function(path, [callback]) { },
        unlinkSync : function(path) { },
        rmdir : function(path, [callback]) { },
        rmdirSync : function(path) { },
        mkdir : function(path, mode, [callback]) { },
        mkdirSync : function(path, mode) { },
        readdir : function(path, [callback]) { },
        readdirSync : function(path) { },
        close : function(fd, [callback]) { },
        closeSync : function(fd) { },
        open : function(path, flags, [mode], [callback]) { },
        openSync : function(path, flags, [mode]) { },
        utimes : function(path, atime, mtime, callback) { },
        utimesSync : function(path, atime, mtime) { },
        futimes : function(path, atime, mtime, callback) { },
        futimesSync : function(path, atime, mtime) { },
        fsync : function(fd, callback) { },
        fsyncSync : function(fd) { },
        write : function(fd, buffer, offset, length, position, [callback]) { },
        writeSync : function(fd, buffer, offset, length, position) { },
        writeSync : function(fd, str, position, encoding='utf8') { },
        read : function(fd, buffer, offset, length, position, [callback]) { },
        readSync : function(fd, buffer, offset, length, position) { },
        readSync : function(fd, length, position, encoding) { },
        readFile : function(filename, encoding, callback) {
            ///<summary>
            ///Asynchronously reads the entire contents of a file
            ///</summary>
            ///<param name="encoding" type="[option]String"></param>
            ///<param name="callback" type="[option]Function"></param>
         },
        readFileSync : function(filename, [encoding]) { },
        writeFile : function(filename, data, encoding='utf8', [callback]) { },
        writeFileSync : function(filename, data, encoding='utf8') { },
        watchFile : function(filename, [options], listener) { },
        unwatchFile : function(filename) { },
        createReadStream : function(path, [options]) { },
        createWriteStream : function(path, [options]) { },
        Stats:null,
        ReadStream:null,
        WriteStream:null
    };

    var path = {
        normalize : function(p) { },
        join : function(path1, path2, pathn) { },
        resolve : function(from, to) { },
        relative : function(from, to) { },
        dirname : function(p) { },
        basename : function(p, ext) { },
        extname : function(p) { },
        exists : function(p, callback) { },
        existsSync : function(p) { }
    };

    var net = {
        Server: {
            listen: function (port, host, callback) {
                ///<summary>
                ///Begin accepting connections on the specified port and host.
                ///If the host is omitted, the server will accept connections directed to any IPv4 address (INADDR_ANY).
                ///</summary>
                ///<param name="port" type="Number">
                ///[option]
                ///</param>
                ///<param name="host" type="Number">
                ///[option]
                ///</param>
                ///<param name="callback" type="Function">
                ///[option]
                ///</param>
            },
            listenFD : function(fd) { },
            pause : function(msecs) { },
            close : function() { },
            address : function() { },
            maxConnections:null,
            connections:null
        },
        createServer: function (options, connectionListener) {
            ///<summary>
            ///Creates a new TCP server. 
            ///</summary>
            ///<param name="options" type="Object">
            ///options is an object with the following defaults:
            ///{ allowHalfOpen: false}
            ///</param>
            ///<param name="connectionListener" type="Object">
            /// The connectionListener argument is automatically set as a listener for the 'connection' event.
            ///</param>
            ///<returns type="net.Server"/>
            return this.Server;
        },
        createConnection : function(arguments) { },
        isIP : function(input) { },
        isIPv4 : function(input) { },
        isIPv6 : function(input) { }
    };

    net.Socket = function(){};
    net.Socket.prototype = {
        connect : function(port, [host], [callback]) { },
        connect : function(path, [callback]) { },
        bufferSize : null,
        setEncoding : function(encoding=null) { },
        setSecure : function() { },
        write : function(data, [encoding], [callback]) { },
        write : function(data, [encoding], [fileDescriptor], [callback]) { },
        end : function([data], [encoding]) { },
        destroy : function() { },
        pause : function() { },
        resume : function() { },
        setTimeout : function(timeout, [callback]) { },
        setNoDelay : function(noDelay=true) { },
        setKeepAlive : function(enable=false, [initialDelay]) { },
        address : function() { },
        remoteAddress:null,
        remotePort:null,
        bytesRead:null,
        bytesWritten:null
    };

    var dgram = {
        createSocket : function(type, callback) { },
        send : function(buf, offset, length, port, address, callback) { },
        bind : function(port, address) { },
        close : function() { },
        address : function() { },
        setBroadcast : function(flag) { },
        setTTL : function(ttl) { },
        setMulticastTTL : function(ttl) { },
        setMulticastLoopback : function(flag) { },
        addMembership : function(multicastAddress, multicastInterface) { },
        dropMembership : function(multicastAddress, multicastInterface) { }
    };

    var dns = {
        lookup : function(domain, family=null, callback) { },
        resolve : function(domain, rrtype='A', callback) { },
        resolve4 : function(domain, callback) { },
        resolve6 : function(domain, callback) { },
        resolveMx : function(domain, callback) { },
        resolveTxt : function(domain, callback) { },
        resolveSrv : function(domain, callback) { },
        reverse : function(ip, callback) { },
        resolveNs : function(domain, callback) { },
        resolveCname : function(domain, callback) { }
    };

    var http = {
        Server:{
            listen : function(port, hostname, callback) { },
            close : function() { }
        },
        ServerRequest:{
            method : null,
            url : null,
            headers : null,
            trailers : null,
            httpVersion : null,
            setEncoding : function(encoding=null) { },
            pause : function() { },
            resume : function() { },
            connection : null
        },
        ServerResponse:{
            writeContinue : function() { },
            writeHead : function(statusCode, reasonPhrase, headers) { },
            statusCode : null,
            setHeader : function(name, value) { },
            getHeader : function(name) { },
            removeHeader : function(name) { },
            write : function(chunk, encoding='utf8') { },
            addTrailers : function(headers) { },
            end : function(data, encoding) { }
        },
        createServer:function(requestListener){ return this.Server},
        request : function(options, callback) { },
        get : function(options, callback) { },
        Agent : {
            maxSockets : null,
            sockets : null,
            requests : null
        },
        globalAgent : {
            maxSockets : null,
            sockets : null,
            requests : null
        },
        ClientRequest:{
            write : function(chunk, encoding='utf8') { },
            end : function(data, encoding) { },
            abort : function() { },
            setTimeout : function(timeout, callback) { },
            setNoDelay : function(noDelay=true) { },
            setSocketKeepAlive : function(enable=false, initialDelay) { }
        },
        ClientResponse:{
            statusCode : null,
            httpVersion : null,
            headers : null,
            trailers : null,
            setEncoding : function(encoding=null) { },
            pause : function() { },
            resume : function() { }
        }
    };

    var https = {
        Server: tls.Server,
        createServer : function(options, requestListener) { return this.Server;},
        request : function(options, callback) { },
        get : function(options, callback) { }
    };

    var url = {
        parse : function(urlStr, parseQueryString=false, slashesDenoteHost=false) { },
        format : function(urlObj) { },
        resolve : function(from, to) { }
    };

    window.querystring = {
        stringify : function(obj, sep='&', eq='=') { },
        parse : function(str, sep='&', eq='=') { },
        escape : null,
        unescape : null
    };

    var readline = {
        createInterface : function(input, output, completer) { },
        setPrompt : function(prompt, length) { },
        prompt : function() { },
        question : function(query, callback) { },
        close : function() { },
        pause : function() { },
        resume : function() { },
        write : function() { }
    };

    var repl = {
        start : function(prompt, stream) { }
    };

    var vm = {
        Script:{
            runInThisContext : function() { },
            runInNewContext : function(sandbox) { }
        },
        runInThisContext : function(code, filename) { },
        runInNewContext : function(code, sandbox, filename) { },
        runInContext : function(code, context, filename) { },
        createContext : function(initSandbox) { },
        createScript : function(code, filename) { return this.Script;}
    };

    var child_process = {
        spawn : function(){return this.child;},
        child:{
            stdout : null,
            stderr : null,
            pid : null,
            kill : function(signal='SIGTERM'){}
        },
        spawn : function(command, args, options) { },
        exec : function(command, options, callback) { },
        fork : function(modulePath, arguments, options) { }
    };

    var assert = {
        fail : function(actual, expected, message, operator) { },
        ok : function(value, message) { },
        equal : function(actual, expected, message) { },
        notEqual : function(actual, expected, message) { },
        deepEqual : function(actual, expected, message) { },
        notDeepEqual : function(actual, expected, message) { },
        strictEqual : function(actual, expected, message) { },
        notStrictEqual : function(actual, expected, message) { },
        throws : function(block, error, message) { },
        doesNotThrow : function(block, error, message) { },
        ifError : function(value) { }
    };

    var tty = {
        open : function(path, args) { },
        isatty : function(fd) { },
        setRawMode : function(mode) { },
        setWindowSize : function(fd, row, col) { },
        getWindowSize : function(fd) { }
    };

    var os = {
        hostname : function() { },
        type : function() { },
        platform : function() { },
        arch : function() { },
        release : function() { },
        uptime : function() { },
        loadavg : function() { },
        totalmem : function() { },
        freemem : function() { },
        cpus : function() { },
        getNetworkInterfaces : function() { }
    };

    var assert = {
        fail : function(actual, expected, message, operator) { },
        ok : function(value, message) { },
        equal : function(actual, expected, message) { },
        notEqual : function(actual, expected, message) { },
        deepEqual : function(actual, expected, message) { },
        notDeepEqual : function(actual, expected, message) { },
        strictEqual : function(actual, expected, message) { },
        notStrictEqual : function(actual, expected, message) { },
        throws : function(block, error, message) { },
        doesNotThrow : function(block, error, message) { },
        ifError : function(value) { }
    };

})();