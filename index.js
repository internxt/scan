/* eslint-disable prettier/prettier */
/* eslint-disable no-useless-catch */
/* eslint-disable prefer-destructuring */
/* eslint-disable no-plusplus */
/* eslint-disable no-await-in-loop */
/* eslint-disable no-restricted-syntax */
/* eslint-disable consistent-return */
/* eslint-disable no-loop-func */
/* eslint-disable no-control-regex */
/* eslint-disable no-async-promise-executor */
/*!
 * Node - Clam
 * Copyright(c) 2013-2024 Kyle Farris <kylefarris@gmail.com>
 * MIT Licensed
 */

// Module dependencies.
const os = require('os');
const net = require('net');
const fs = require('fs');
const nodePath = require('path'); // renamed to prevent conflicts in `scanDir`
const tls = require('tls');
const { promisify } = require('util');
const { execFile } = require('child_process');
const { Readable } = require('stream');
const { Socket } = require('dgram');
const fsPromises = require('fs').promises;
const NodeClamError = require('./lib/NodeClamError');
const NodeClamTransform = require('./lib/NodeClamTransform');
const getFiles = require('./lib/getFiles');
const isPermissionError = require('./lib/isPermissionError');

// Re-named `fs` promise methods to prevent conflicts while keeping short names
const fsAccess = fsPromises.access;
const fsReadfile = fsPromises.readFile;
// const fsReaddir = fsPromises.readdir;
const fsStat = fsPromises.stat;

// Convert some stuff to promises
const cpExecFile = promisify(execFile);

/**
 * NodeClam class definition.
 *
 * @class
 * @public
 * @typicalname NodeClam
 */
class NodeClam {
    /**
     * This sets up all the defaults of the instance but does not
     * necessarily return an initialized instance. Use `.init` for that.
     */
    constructor() {
        this.initialized = false;
        this.debugLabel = 'inxt-clamScan';
        this.defaultScanner = 'clamdscan';
        this.activeSockets = [];

        // Configuration Settings
        this.defaults = Object.freeze({
            removeInfected: false,
            quarantineInfected: false,
            scanLog: null,
            debugMode: false,
            fileList: null,
            scanRecursively: true,
            clamscan: {
                path: '/usr/bin/clamscan',
                scanArchives: true,
                db: null,
                active: true,
            },
            clamdscan: {
                socket: false,
                host: false,
                port: false,
                timeout: 180000,
                localFallback: true,
                path: '/usr/bin/clamdscan',
                configFile: null,
                multiscan: true,
                reloadDb: false,
                active: true,
                bypassTest: false,
                tls: false,
            },
            preference: this.defaultScanner,
        });

        this.settings = { ...this.defaults };
    }

    /**
     * Initialization method.
     *
     * @public
     * @param {object} [options] - User options for the Clamscan module
     * @param {boolean} [options.removeInfected=false] - If true, removes infected files when found
     * @param {boolean|string} [options.quarantineInfected=false] - If not false, should be a string to a path to quarantine infected files
     * @param {string} [options.scanLog=null] - Path to a writeable log file to write scan results into
     * @param {boolean} [options.debugMode=false] - If true, *a lot* of info will be spewed to the logs
     * @param {string} [options.fileList=null] - Path to file containing list of files to scan (for `scanFiles` method)
     * @param {boolean} [options.scanRecursively=true] - If true, deep scan folders recursively (for `scanDir` method)
     * @param {object} [options.clamscan] - Options specific to the clamscan binary
     * @param {string} [options.clamscan.path='/usr/bin/clamscan'] - Path to clamscan binary on your server
     * @param {string} [options.clamscan.db=null] - Path to a custom virus definition database
     * @param {boolean} [options.clamscan.scanArchives=true] - If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...)
     * @param {boolean} [options.clamscan.active=true] - If true, this module will consider using the clamscan binary
     * @param {object} [options.clamdscan] - Options specific to the clamdscan binary
     * @param {string} [options.clamdscan.socket=false] - Path to socket file for connecting via TCP
     * @param {string} [options.clamdscan.host=false] - IP of host to connec to TCP interface
     * @param {string} [options.clamdscan.port=false] - Port of host to use when connecting via TCP interface
     * @param {number} [options.clamdscan.timeout=60000] - Timeout for scanning files
     * @param {boolean} [options.clamdscan.localFallback=false] - If false, do not fallback to a local binary-method of scanning
     * @param {string} [options.clamdscan.path='/usr/bin/clamdscan'] - Path to the `clamdscan` binary on your server
     * @param {string} [options.clamdscan.configFile=null] - Specify config file if it's in an usual place
     * @param {boolean} [options.clamdscan.multiscan=true] - If true, scan using all available cores
     * @param {boolean} [options.clamdscan.reloadDb=false] - If true, will re-load the DB on ever call (slow)
     * @param {boolean} [options.clamdscan.active=true] - If true, this module will consider using the `clamdscan` binary
     * @param {boolean} [options.clamdscan.bypassTest=false] - If true, check to see if socket is avaliable
     * @param {boolean} [options.clamdscan.tls=false] - If true, connect to a TLS-Termination proxy in front of ClamAV
     * @param {object} [options.preference='clamdscan'] - If preferred binary is found and active, it will be used by default
     * @param {Function} [cb = null] - Callback method. Prototype: `(err, <instance of NodeClam>)`
     * @returns {Promise<object>} An initated instance of NodeClam
     * @example
     */
    async init(options = {}, cb = null) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError(
                'Invalid cb provided to init method. Second paramter, if provided, must be a function!'
            );
        } else if (cb && typeof cb === 'function') {
            hasCb = true;
        }

        return new Promise(async (resolve, reject) => {
            // No need to re-initialize
            if (this.initialized === true) return hasCb ? cb(null, this) : resolve(this);

            // Override defaults with user preferences
            const settings = {};
            if (Object.prototype.hasOwnProperty.call(options, 'clamscan') && Object.keys(options.clamscan).length > 0) {
                settings.clamscan = { ...this.defaults.clamscan, ...options.clamscan };
                delete options.clamscan;
            }
            if (
                Object.prototype.hasOwnProperty.call(options, 'clamdscan') &&
                Object.keys(options.clamdscan).length > 0
            ) {
                settings.clamdscan = { ...this.defaults.clamdscan, ...options.clamdscan };
                delete options.clamdscan;
            }
            this.settings = { ...this.defaults, ...settings, ...options };

            if (this.settings && 'debugMode' in this.settings && this.settings.debugMode === true)
                console.log(`${this.debugLabel}: DEBUG MODE ON`);

            // Backwards compatibilty section
            if ('quarantinePath' in this.settings && this.settings.quarantinePath) {
                this.settings.quarantineInfected = this.settings.quarantinePath;
            }

            // Determine whether to use clamdscan or clamscan
            this.scanner = this.defaultScanner;

            // If scanner preference is not defined or is invalid, fallback to streaming scan or completely fail
            if (
                ('preference' in this.settings && typeof this.settings.preference !== 'string') ||
                !['clamscan', 'clamdscan'].includes(this.settings.preference)
            ) {
                // If no valid scanner is found (but a socket/port/host is), disable the fallback to a local CLI scanning method
                if (this.settings.clamdscan.socket || this.settings.clamdscan.port || this.settings.clamdscan.host) {
                    this.settings.clamdscan.localFallback = false;
                } else {
                    const err = new NodeClamError(
                        'Invalid virus scanner preference defined and no valid socket/port/host option provided!'
                    );
                    return hasCb ? cb(err, null) : reject(err);
                }
            }

            // Set 'clamscan' as the scanner preference if it's specified as such and activated
            // OR if 'clamdscan is the preference but inactivated and clamscan is activated
            if (
                // If preference is 'clamscan' and clamscan is active
                ('preference' in this.settings &&
                    this.settings.preference === 'clamscan' &&
                    'clamscan' in this.settings &&
                    'active' in this.settings.clamscan &&
                    this.settings.clamscan.active === true) || // OR ... // If preference is 'clamdscan' and it's NOT active but 'clamscan' is...
                (this.settings.preference === 'clamdscan' &&
                    'clamdscan' in this.settings &&
                    'active' in this.settings.clamdscan &&
                    this.settings.clamdscan.active !== true &&
                    'clamscan' in this.settings &&
                    'active' in this.settings.clamscan &&
                    this.settings.clamscan.active === true)
            ) {
                // Set scanner to clamscan
                this.scanner = 'clamscan';
            }

            // Check to make sure preferred scanner exists and actually is a clamscan binary
            try {
                // If scanner binary doesn't exist...
                if (!(await this._isClamavBinary(this.scanner))) {
                    // Fall back to other option:
                    if (
                        this.scanner === 'clamdscan' &&
                        this.settings.clamscan.active === true &&
                        (await this._isClamavBinary('clamscan'))
                    ) {
                        this.scanner = 'clamscan';
                    } else if (
                        this.scanner === 'clamscan' &&
                        this.settings.clamdscan.active === true &&
                        (await this._isClamavBinary('clamdscan'))
                    ) {
                        this.scanner = 'clamdscan';
                    } else {
                        // If preferred scanner is not a valid binary but there is a socket/port/host option, disable
                        // failover to local CLI implementation
                        if (
                            !this.settings.clamdscan.socket &&
                            !this.settings.clamdscan.port &&
                            !this.settings.clamdscan.host
                        ) {
                            const err = new NodeClamError(
                                'No valid & active virus scanning binaries are active and available and no socket/port/host option provided!'
                            );
                            return hasCb ? cb(err, null) : reject(err);
                        }

                        this.settings.clamdscan.localFallback = false;
                    }
                }
            } catch (err) {
                return hasCb ? cb(err, null) : reject(err);
            }

            // Make sure quarantineInfected path exists at specified location
            if (
                !this.settings.clamdscan.socket &&
                !this.settings.clamdscan.port &&
                !this.settings.clamdscan.host &&
                ((this.settings.clamdscan.active === true && this.settings.clamdscan.localFallback === true) ||
                    this.settings.clamscan.active === true) &&
                this.settings.quarantineInfected
            ) {
                try {
                    await fsAccess(this.settings.quarantineInfected, fs.constants.R_OK);
                } catch (e) {
                    if (this.settings.debugMode) console.log(`${this.debugLabel} error:`, e);
                    const err = new NodeClamError(
                        { err: e },
                        `Quarantine infected path (${this.settings.quarantineInfected}) is invalid.`
                    );
                    return hasCb ? cb(err, null) : reject(err);
                }
            }

            // If using clamscan, make sure definition db exists at specified location
            if (
                !this.settings.clamdscan.socket &&
                !this.settings.clamdscan.port &&
                !this.settings.clamdscan.host &&
                this.scanner === 'clamscan' &&
                this.settings.clamscan.db
            ) {
                try {
                    await fsAccess(this.settings.clamscan.db, fs.constants.R_OK);
                } catch (err) {
                    if (this.settings.debugMode) console.log(`${this.debugLabel} error:`, err);
                    // throw new Error(`Definitions DB path (${this.settings.clamscan.db}) is invalid.`);
                    this.settings.clamscan.db = null;
                }
            }

            // Make sure scanLog exists at specified location
            if (
                ((!this.settings.clamdscan.socket && !this.settings.clamdscan.port && !this.settings.clamdscan.host) ||
                    ((this.settings.clamdscan.socket || this.settings.clamdscan.port || this.settings.clamdscan.host) &&
                        this.settings.clamdscan.localFallback === true &&
                        this.settings.clamdscan.active === true) ||
                    (this.settings.clamdscan.active === false && this.settings.clamscan.active === true) ||
                    this.preference) &&
                this.settings.scanLog
            ) {
                try {
                    await fsAccess(this.settings.scanLog, fs.constants.R_OK);
                } catch (err) {
                    // console.log("DID NOT Find scan log!");
                    // foundScanLog = false;
                    if (this.settings.debugMode) console.log(`${this.debugLabel} error:`, err);
                    // throw new Error(`Scan Log path (${this.settings.scanLog}) is invalid.` + err);
                    this.settings.scanLog = null;
                }
            }

            // Check the availability of the clamd service if socket or host/port are provided
            if (
                this.scanner === 'clamdscan' &&
                this.settings.clamdscan.bypassTest === false &&
                (this.settings.clamdscan.socket || this.settings.clamdscan.port || this.settings.clamdscan.host)
            ) {
                if (this.settings.debugMode)
                    console.log(`${this.debugLabel}: Initially testing socket/tcp connection to clamscan server.`);
                try {
                    const client = await this.ping();
                    client.end();
                    if (this.settings.debugMode)
                        console.log(`${this.debugLabel}: Established connection to clamscan server!`);
                } catch (err) {
                    return hasCb ? cb(err, null) : reject(err);
                }
            }

            // if (foundScanLog === false) console.log("No Scan Log: ", this.settings);

            // Build clam flags
            this.clamFlags = this._buildClamFlags(this.scanner, this.settings);

            // if (foundScanLog === false) console.log("No Scan Log: ", this.settings);

            // This ClamScan instance is now initialized
            this.initialized = true;

            // Return instance based on type of expected response (callback vs promise)
            return hasCb ? cb(null, this) : resolve(this);
        });
    }

    /**
     * Allows one to create a new instances of clamscan with new options.
     *
     * @public
     * @param {object} [options = {}] - Same options as the `init` method
     * @param {Function} [cb = null] - What to do after reset (repsponds with reset instance of NodeClam)
     * @returns {Promise<object>} A reset instance of NodeClam
     */
    reset(options = {}, cb = null) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError(
                'Invalid cb provided to `reset`. Second paramter, if provided, must be a function!'
            );
        } else if (cb && typeof cb === 'function') {
            hasCb = true;
        }

        this.initialized = false;
        this.settings = { ...this.defaults };

        return new Promise(async (resolve, reject) => {
            try {
                await this.init(options);
                return hasCb ? cb(null, this) : resolve(this);
            } catch (err) {
                return hasCb ? cb(err, null) : reject(err);
            }
        });
    }

    // *****************************************************************************
    // Builds out the args to pass to execFile
    // -----
    // @param    String|Array    item        The file(s) / directory(ies) to append to the args
    // @api        Private
    // *****************************************************************************
    /**
     * Builds out the args to pass to `execFile`.
     *
     * @private
     * @param {string|Array} item - The file(s) / directory(ies) to append to the args
     * @returns {string|Array} The string or array of arguments
     * @example
     * this._buildClamArgs('--version');
     */
    _buildClamArgs(item) {
        let args = this.clamFlags.slice();

        if (typeof item === 'string') args.push(item);
        if (Array.isArray(item)) args = args.concat(item);

        return args;
    }

    /**
     * Builds out the flags based on the configuration the user provided.
     *
     * @private
     * @param {string} scanner - The scanner to use (clamscan or clamdscan)
     * @param {object} settings - The settings used to build the flags
     * @returns {string} The concatenated clamav flags
     * @example
     * // Build clam flags
     * this.clamFlags = this._buildClamFlags(this.scanner, this.settings);
     */
    _buildClamFlags(scanner, settings) {
        const flagsArray = ['--no-summary'];

        // Flags specific to clamscan
        if (scanner === 'clamscan') {
            flagsArray.push('--stdout');

            // Remove infected files
            if (settings.removeInfected === true) {
                flagsArray.push('--remove=yes');
            } else {
                flagsArray.push('--remove=no');
            }

            // Database file
            if (
                'clamscan' in settings &&
                typeof settings.clamscan === 'object' &&
                'db' in settings.clamscan &&
                settings.clamscan.db &&
                typeof settings.clamscan.db === 'string'
            )
                flagsArray.push(`--database=${settings.clamscan.db}`);

            // Scan archives
            if (settings.clamscan.scanArchives === true) {
                flagsArray.push('--scan-archive=yes');
            } else {
                flagsArray.push('--scan-archive=no');
            }

            // Recursive scanning (flag is specific, feature is not)
            if (settings.scanRecursively === true) {
                flagsArray.push('-r');
            } else {
                flagsArray.push('--recursive=no');
            }
        }

        // Flags specific to clamdscan
        else if (scanner === 'clamdscan') {
            flagsArray.push('--fdpass');

            // Remove infected files
            if (settings.removeInfected === true) flagsArray.push('--remove');

            // Specify a config file
            if (
                'clamdscan' in settings &&
                typeof settings.clamdscan === 'object' &&
                'configFile' in settings.clamdscan &&
                settings.clamdscan.configFile &&
                typeof settings.clamdscan.configFile === 'string'
            )
                flagsArray.push(`--config-file=${settings.clamdscan.configFile}`);

            // Turn on multi-threaded scanning
            if (settings.clamdscan.multiscan === true) flagsArray.push('--multiscan');

            // Reload the virus DB
            if (settings.clamdscan.reloadDb === true) flagsArray.push('--reload');
        }

        // ***************
        // Common flags
        // ***************

        // Remove infected files
        if (settings.removeInfected !== true) {
            if (
                'quarantineInfected' in settings &&
                settings.quarantineInfected &&
                typeof settings.quarantineInfected === 'string'
            ) {
                flagsArray.push(`--move=${settings.quarantineInfected}`);
            }
        }

        // Write info to a log
        if ('scanLog' in settings && settings.scanLog && typeof settings.scanLog === 'string')
            flagsArray.push(`--log=${settings.scanLog}`);

        // Read list of files to scan from a file
        if ('fileList' in settings && settings.fileList && typeof settings.fileList === 'string')
            flagsArray.push(`--file-list=${settings.fileList}`);

        // Build the String
        return flagsArray;
    }

    /**
     * Create socket connection to a remote(or local) clamav daemon.
     *
     * @private
     * @param {string} [label] - A label you can provide for debugging
     * @returns {Promise<Socket>} A Socket/TCP connection to ClamAV
     * @example
     * const client = this._initSocket('whatever');
     */
    _initSocket(label = '') {
        return new Promise((resolve, reject) => {
            if (this.settings.debugMode)
                console.log(`${this.debugLabel}: Attempting to establish socket/TCP connection for "${label}"`);

            // Create a new Socket connection to Unix socket or remote server (in that order)
            let client;

            // Setup socket connection timeout (default: 20 seconds).
            const timeout = this.settings.clamdscan.timeout ? this.settings.clamdscan.timeout : 20000;

            // The fastest option is a local Unix socket
            if (this.settings.clamdscan.port) {
                // If a host is specified (usually for a remote host)
                if (this.settings.clamdscan.host) {
                    if (this.settings.clamdscan.tls) {
                        client = tls.connect({
                            host: this.settings.clamdscan.host,
                            port: this.settings.clamdscan.port,
                            // Activate SNI
                            // servername: this.settings.clamdscan.host,
                            timeout,
                        });
                    } else {
                        client = net.createConnection({
                            host: this.settings.clamdscan.host,
                            port: this.settings.clamdscan.port,
                            timeout,
                        });
                    }
                }
                // Host can be ignored since the default is `localhost`
                else if (this.settings.tls) {
                    client = tls.connect({ port: this.settings.clamdscan.port, timeout });
                } else {
                    client = net.createConnection({ port: this.settings.clamdscan.port, timeout });
                }
            }

            // No valid option to connection can be determined
            else
                throw new NodeClamError(
                    'Unable not establish connection to clamd service: No socket or host/port combo provided!'
                );

            // Set the socket timeout if specified
            if (this.settings.clamdscan.timeout) client.setTimeout(this.settings.clamdscan.timeout);

            this.activeSockets.push(client);

            // Setup socket client listeners
            client
                .on('connect', () => {
                    // Some basic debugging stuff...
                    // Determine information about what server the client is connected to
                    if (client.remotePort && client.remotePort.toString() === this.settings.clamdscan.port.toString()) {
                        if (this.settings.debugMode)
                            console.log(
                                `${this.debugLabel}: using remote server: ${client.remoteAddress}:${client.remotePort}`
                            );
                    } else if (this.settings.clamdscan.socket) {
                        if (this.settings.debugMode)
                            console.log(
                                `${this.debugLabel}: using local unix domain socket: ${this.settings.clamdscan.socket}`
                            );
                    } else if (this.settings.debugMode) {
                        const { port, address } = client.address();
                        console.log(`${this.debugLabel}: meta port value: ${port} vs ${client.remotePort}`);
                        console.log(`${this.debugLabel}: meta address value: ${address} vs ${client.remoteAddress}`);
                        console.log(`${this.debugLabel}: something is not working...`);
                    }

                    resolve(client);
                })
                .on('timeout', () => {
                    if (this.settings.debugMode) console.log(`${this.debugLabel}: Socket/Host connection timed out.`);
                    reject(new Error('Connection to host has timed out.'));
                    client.end();
                })
                .on('close', () => {
                    if (this.settings.debugMode) console.log(`${this.debugLabel}: Socket/Host connection closed.`);
                })
                .on('error', (e) => {
                    console.log('ERROR IN INIT SOCKET: ', e);
                    if (this.settings.debugMode) console.error(`${this.debugLabel}: Socket/Host connection failed:`, e);
                    reject(e);
                });
        });
    }

    closeAllSockets() {
        return new Promise((resolve) => {
            for (const socket of this.activeSockets) {
                if (!socket.destroyed) {
                    console.log('DESTROYING SOCKETS');
                    socket.destroy();
                }
            }
            this.activeSockets = [];
            resolve('');
        });
    }

    /**
     * Checks to see if a particular binary is a clamav binary. The path for the
     * binary must be specified in the NodeClam config at `init`. If you have a
     * config file in an unusual place, make sure you specify that in `init` configs
     * as well.
     *
     * @private
     * @param {string} scanner - The ClamAV scanner (clamscan or clamdscan) to verify
     * @returns {Promise<boolean>} True if binary is a ClamAV binary, false if not.
     * @example
     * const clamscanIsGood = this._isClamavBinary('clamscan');
     */
    async _isClamavBinary(scanner) {
        const { path = null, configFile = null } = this.settings[scanner];
        if (!path) {
            if (this.settings.debugMode) console.log(`${this.debugLabel}: Could not determine path for clamav binary.`);
            return false;
        }

        const versionCmds = {
            clamdscan: ['--version'],
            clamscan: ['--version'],
        };

        if (configFile) {
            versionCmds[scanner].push(`--config-file=${configFile}`);
        }

        try {
            await fsAccess(path, fs.constants.R_OK);
            const { stdout } = await cpExecFile(path, versionCmds[scanner]);
            if (stdout.toString().match(/ClamAV/) === null) {
                if (this.settings.debugMode) console.log(`${this.debugLabel}: Could not verify the ${scanner} binary.`);
                return false;
            }
            return true;
        } catch (err) {
            if (this.settings.debugMode)
                console.log(`${this.debugLabel}: Could not verify the ${scanner} binary.`, err);
            return false;
        }
    }

    /**
     * Test to see if ab object is a readable stream.
     *
     * @private
     * @param {object} obj - Object to test "streaminess" of
     * @returns {boolean} Returns `true` if provided object is a stream; `false` if not.
     * @example
     * // Yay!
     * const isStream = this._isReadableStream(someStream);
     *
     * // Nay!
     * const isString = this._isReadableString('foobar');
     */
    _isReadableStream(obj) {
        if (!obj || typeof obj !== 'object') return false;
        return typeof obj.pipe === 'function' && typeof obj._readableState === 'object';
    }

    /**
     * Alias `ping()` for backwards-compatibility with older package versions.
     *
     * @private
     * @alias ping
     * @param {Function} [cb] - Callback function
     * @returns {Promise<object>} A copy of the Socket/TCP client
     */
    _ping(cb = null) {
        return this.ping(cb);
    }

    /**
     * This is what actually processes the response from clamav.
     *
     * @private
     * @param {string} result - The ClamAV result to process and interpret
     * @param {string} [file=null] - The name of the file/path that was scanned
     * @returns {object} Contains `isInfected` boolean and `viruses` array
     * @example
     * const args = this._buildClamArgs('/some/file/here');
     * execFile(this.settings[this.scanner].path, args, (err, stdout, stderr) => {
     *     const { isInfected, viruses } = this._processResult(stdout, file);
     *     console.log('Infected? ', isInfected);
     * });
     */
    _processResult(result, file = null) {
        let timeout = false;

        // The result value must be a string otherwise we can't parse it
        if (typeof result !== 'string') {
            if (this.settings.debugMode)
                console.log(`${this.debugLabel}: Invalid stdout from scanner (not a string): `, result);

            console.log('RESULT IS NOT A STRING: ', result);
            throw new Error('Invalid result to process (not a string)');
        }

        // Clean up the result string so that its predictably parseable
        result = result.trim();

        // If the result string looks like 'Anything Here: OK\n', the scanned file is not infected
        // eslint-disable-next-line no-control-regex
        if (/:\s+OK(\u0000|[\r\n])?$/.test(result)) {
            if (this.settings.debugMode) console.log(`${this.debugLabel}: File is OK!`);
            return { isInfected: false, viruses: [], file, resultString: result, timeout };
        }

        // If the result string looks like 'Anything Here: SOME VIRUS FOUND\n', the file is infected
        // eslint-disable-next-line no-control-regex
        if (/:\s+(.+)FOUND(\u0000|[\r\n])?/gm.test(result)) {
            if (this.settings.debugMode) {
                if (this.settings.debugMode) console.log(`${this.debugLabel}: Scan Response: `, result);
                if (this.settings.debugMode) console.log(`${this.debugLabel}: File is INFECTED!`);
            }

            // Parse out the name of the virus(es) found...
            const viruses = Array.from(
                new Set(
                    result
                        // eslint-disable-next-line no-control-regex
                        .split(/(\u0000|[\r\n])/)
                        .map((v) => (/:\s+(.+)FOUND$/gm.test(v) ? v.replace(/(.+:\s+)(.+)FOUND/gm, '$2').trim() : null))
                        .filter((v) => !!v)
                )
            );

            return { isInfected: true, viruses, file, resultString: result, timeout };
        }

        // If the result of the scan ends with "ERROR", there was an error (file permissions maybe)
        if (/^(.+)ERROR(\u0000|[\r\n])?/gm.test(result)) {
            const error = result.replace(/^(.+)ERROR/gm, '$1').trim();
            if (this.settings.debugMode) {
                if (this.settings.debugMode) console.log(`${this.debugLabel}: Error Response: `, error);
                if (this.settings.debugMode) console.log(`${this.debugLabel}: File may be INFECTED!`);
            }
            console.log('ERROR IN PROCESS RESULT: ', error);
            return new NodeClamError({ error }, `An error occurred while scanning the piped-through stream: ${error}`);
        }

        // This will occur in the event of a timeout (rare)
        if (result === 'COMMAND READ TIMED OUT') {
            timeout = true;
            if (this.settings.debugMode) {
                if (this.settings.debugMode)
                    console.log(`${this.debugLabel}: Scanning file has timed out. Message: `, result);
                if (this.settings.debugMode) console.log(`${this.debugLabel}: File may be INFECTED!`);
            }
            return { isInfected: null, viruses: [], file, resultString: result, timeout };
        }

        if (this.settings.debugMode) {
            if (this.settings.debugMode) console.log(`${this.debugLabel}: Error Response: `, result);
            if (this.settings.debugMode) console.log(`${this.debugLabel}: File may be INFECTED!`);
        }

        return { isInfected: false, viruses: [], file, resultString: result, timeout };
    }

    /**
     * Quick check to see if the remote/local socket is working. Callback/Resolve
     * response is an instance to a ClamAV socket client.
     *
     * @public
     * @name ping
     * @param {Function} [cb] - What to do after the ping
     * @returns {Promise<object>} A copy of the Socket/TCP client
     */
    ping(cb) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function')
            throw new NodeClamError('Invalid cb provided to ping. Second parameter must be a function!');

        // Making things simpler
        if (cb && typeof cb === 'function') hasCb = true;

        // Setup the socket client variable
        let client;

        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            try {
                client = await this._initSocket('ping');

                if (this.settings.debugMode)
                    console.log(`${this.debugLabel}: Established connection to clamscan server!`);

                client.write('PING');

                let dataReceived = false;
                client.on('end', () => {
                    if (!dataReceived) {
                        const err = new NodeClamError('Did not get a PONG response from clamscan server.');
                        if (hasCb) cb(err, null);
                        else reject(err);
                    }
                });

                client.on('data', (data) => {
                    if (data.toString().trim() === 'PONG') {
                        dataReceived = true;
                        if (this.settings.debugMode) console.log(`${this.debugLabel}: PONG!`);
                        return hasCb ? cb(null, client) : resolve(client);
                    }

                    // I'm not even sure this case is possible, but...
                    const err = new NodeClamError(
                        data,
                        'Could not establish connection to the remote clamscan server.'
                    );
                    return hasCb ? cb(err, null) : reject(err);
                });
                client.on('error', (err) => {
                    if (this.settings.debugMode) {
                        console.log(`${this.debugLabel}: Could not connect to the clamscan server.`, err);
                    }
                    return hasCb ? cb(err, null) : reject(err);
                });
            } catch (err) {
                return hasCb ? cb(err, false) : reject(err);
            }
        });
    }

    /**
     * Establish the clamav version of a local or remote clamav daemon.
     *
     * @public
     * @param {Function} [cb] - What to do when version is established
     * @returns {Promise<string>} - The version of ClamAV that is being interfaced with
     * @example
     * // Callback example
     * clamscan.getVersion((err, version) => {
     *     if (err) return console.error(err);
     *     console.log(`ClamAV Version: ${version}`);
     * });
     *
     * // Promise example
     * const clamscan = new NodeClam().init();
     * const version = await clamscan.getVersion();
     * console.log(`ClamAV Version: ${version}`);
     */
    getVersion(cb) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function')
            throw new NodeClamError('Invalid cb provided to scanStream. Second paramter must be a function!');

        // Making things simpler
        if (cb && typeof cb === 'function') hasCb = true;

        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            // Function for falling back to running a scan locally via a child process

            // If user wants to connect via socket or TCP...
            if (
                this.scanner === 'clamdscan' &&
                (this.settings.clamdscan.socket || this.settings.clamdscan.port || this.settings.clamdscan.host)
            ) {
                const chunks = [];
                let client;

                try {
                    client = await this._initSocket('getVersion');
                    client.write('nVERSION\n');
                    // ClamAV is sending stuff to us
                    client.on('data', (chunk) => chunks.push(chunk));
                    client.on('end', () => {
                        const response = Buffer.concat(chunks);
                        client.end();
                        return hasCb ? cb(null, response.toString()) : resolve(response.toString());
                    });
                } catch (err) {
                    if (client && 'readyState' in client && client.readyState) client.end();

                    return hasCb ? cb(err, null) : reject(err);
                }
            }
        });
    }

    /**
     * This method allows you to scan a single file. It supports a callback and Promise API.
     * If no callback is supplied, a Promise will be returned. This method will likely
     * be the most common use-case for this module.
     *
     * @public
     * @param {string} file - Path to the file to check
     * @param {Function} [cb = null] - What to do after the scan
     * @returns {Promise<object>} Object like: `{ file: String, isInfected: Boolean, viruses: Array }`
     * @example
     * // Callback Example
     * clamscan.isInfected('/a/picture/for_example.jpg', (err, file, isInfected, viruses) => {
     *     if (err) return console.error(err);
     *
     *     if (isInfected) {
     *         console.log(`${file} is infected with ${viruses.join(', ')}.`);
     *     }
     * });
     *
     * // Promise Example
     * clamscan.isInfected('/a/picture/for_example.jpg').then(result => {
     *     const {file, isInfected, viruses} =  result;
     *     if (isInfected) console.log(`${file} is infected with ${viruses.join(', ')}.`);
     * }).then(err => {
     *     console.error(err);
     * });
     *
     * // Async/Await Example
     * const {file, isInfected, viruses} = await clamscan.isInfected('/a/picture/for_example.jpg');
     */
    async isInfected(file = '') {
        // At this point for the hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        // eslint-disable-next-line consistent-return

        // Verify string is passed to the file parameter
        if (typeof file !== 'string' || (typeof file === 'string' && file.trim() === '')) {
            const err = new NodeClamError({ file }, 'Invalid or empty file name provided.');
            throw err;
        }
        // Clean file name
        file = file.trim();

        // See if we can find/read the file
        // -----
        // NOTE: Is it even valid to do this since, in theory, the
        // file's existance or permission could change between this check
        // and the actual scan (even if it's highly unlikely)?
        //-----

        try {
            const handle = await fsPromises.open(file, 'r');
            await handle.close();
        } catch (e) {
            const err = new NodeClamError({ err: e, file }, 'Could not access file to scan!');
            console.log('ACCESS ERROR:', e);
            throw err;
        }

        try {
            await fsAccess(file, fs.constants.R_OK);
        } catch (e) {
            const err = new NodeClamError({ err: e, file }, 'Could not find file to scan!');
            throw err;
        }
        // Make sure the "file" being scanned is actually a file and not a directory (or something else)
        try {
            const stats = await fsStat(file);
            const isDirectory = stats.isDirectory();
            const isFile = stats.isFile();

            // If it's not a file or a directory, fail now
            if (!isFile && !isDirectory) {
                throw Error(`${file} is not a valid file or directory.`);
            }

            // If it's a directory/path, scan it using the `scanDir` method instead
            else if (!isFile && isDirectory) {
                const { isInfected } = await this.scanDir(file);
                return { file, isInfected, viruses: [] };
            }
        } catch (err) {
            throw err;
        }

        // If user wants to scan via socket or TCP...
        if (this.settings.clamdscan.port || this.settings.clamdscan.host) {
            let stream;
            try {
                // Convert file to stream
                stream = await fs.createReadStream(file);

                const isInfected = await this.scanStream(stream);
                // Attempt to scan the stream.

                return { ...isInfected, file };
            } catch (err) {
                const error = new NodeClamError(
                    { err, file },
                    `ERROR WHILE SCANNING FILES VIA STREAM IN IS INFECTED FUNCTION: ${err}`
                );
                console.log('ERROR SCANNING STREAM: ', error);
                throw error;
            } finally {
                if (stream && !stream.destroyed) {
                    stream.destroy();
                }
            }
        }
    }

    async scanFile(filePath) {
        try {
            const scannedFile = await this.isInfected(filePath);

            return scannedFile;
        } catch (err) {
            let error = err;
            if (err instanceof NodeClamError && err.data?.err instanceof Error) {
                error = err.data.err;
            }

            if (!isPermissionError(error)) {
                console.error(`Error scanning file ${filePath}:`, error);
                throw error;
            }
        }
    }

    /**
     * Scans an array of files or paths. You must provide the full paths of the
     * files and/or paths. Also enables the ability to scan a file list.
     *
     * This is essentially a wrapper for isInfected that simplifies the process
     * of scanning many files or directories.
     *
     * **NOTE:** The only way to get per-file notifications is through the callback API.
     *
     * @public
     * @param {Array} files - A list of files or paths (full paths) to be scanned
     * @param {Function} [endCb] - What to do after the scan completes
     * @param {Function} [fileCb] - What to do after each file has been scanned
     * @returns {Promise<object>} Object like: `{ goodFiles: Array, badFiles: Array, errors: Object, viruses: Array }`
     */
    scanFiles(files = [], endCb = null, fileCb = null) {
        const self = this;
        let hasCb = false;

        // Verify third param, if supplied, is a function
        if (fileCb && typeof fileCb !== 'function')
            throw new NodeClamError(
                'Invalid file callback provided to `scanFiles`. Third parameter, if provided, must be a function!'
            );

        // Verify second param, if supplied, is a function
        if (endCb && typeof endCb !== 'function') {
            throw new NodeClamError(
                'Invalid end-scan callback provided to `scanFiles`. Second parameter, if provided, must be a function!'
            );
        } else if (endCb && typeof endCb === 'function') {
            hasCb = true;
        }

        // We should probably have some reasonable limit on the number of files to scan
        if (files && Array.isArray(files) && files.length > 1000000)
            throw new NodeClamError(
                { numFiles: files.length },
                'NodeClam has halted because more than 1 million files were about to be scanned. We suggest taking a different approach.'
            );

        // At this point for a hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        return new Promise(async (resolve, reject) => {
            const errors = {};
            let goodFiles = [];
            let badFiles = [];
            let origNumFiles = 0;

            // This is the function that actually scans the files
            // eslint-disable-next-line consistent-return
            const doScan = async (theFiles) => {
                const numFiles = theFiles.length;

                if (self.settings.debugMode)
                    console.log(`${this.debugLabel}: Scanning a list of ${numFiles} passed files.`, theFiles);

                // Slower but more verbose/informative way...
                if (fileCb && typeof fileCb === 'function') {
                    // Scan files in parallel chunks of 10
                    const chunkSize = 10;
                    let results = [];
                    let scannedCount = 0;

                    while (theFiles.length > 0) {
                        const chunk = theFiles.length > chunkSize ? theFiles.splice(0, chunkSize) : theFiles.splice(0);

                        const chunkResults = [];

                        for (const file of chunk) {
                            try {
                                const result = await this.isInfected(file);

                                scannedCount++;
                                const progressRatio = ((scannedCount / numFiles) * 100).toFixed(2);

                                fileCb(null, file, result.isInfected, result.viruses, scannedCount, progressRatio);

                                chunkResults.push({ ...result, file });
                            } catch (err) {
                                let error = err;
                                if (err instanceof NodeClamError && err.data?.err instanceof Error) {
                                    error = err.data.err;
                                }

                                if (isPermissionError(error)) {
                                    console.warn(`File ${file} skipped due to EBUSY or permission issue.`);
                                    scannedCount++;
                                    const progressRatio = ((scannedCount / numFiles) * 100).toFixed(2);

                                    fileCb(null, file, false, [], scannedCount, progressRatio);

                                    chunkResults.push({ file, isInfected: false, viruses: [] });
                                } else {
                                    console.error(`Error scanning file ${file}:`, error);
                                    reject(error);
                                }
                            }
                        }

                        results = results.concat(chunkResults);
                    }

                    // Build out the good and bad files arrays
                    results.forEach((v) => {
                        if (v[1] === true) badFiles.push(v[0]);
                        else if (v[1] === false) goodFiles.push(v[0]);
                        else if (v[1] instanceof Error) {
                            // eslint-disable-next-line prefer-destructuring
                            errors[v[0]] = v[1];
                        }
                    });

                    // Make sure the number of results matches the original number of files to be scanned
                    if (numFiles !== results.length) {
                        const errMsg = 'The number of results did not match the number of files to scan!';
                        return hasCb
                            ? endCb(new NodeClamError(errMsg), goodFiles, badFiles, {}, [])
                            : reject(new NodeClamError({ goodFiles, badFiles }, errMsg));
                    }

                    // Make sure the list of bad and good files is unique...(just for good measure)
                    badFiles = Array.from(new Set(badFiles));
                    goodFiles = Array.from(new Set(goodFiles));

                    if (self.settings.debugMode) {
                        console.log(`${self.debugLabel}: Scan Complete!`);
                        console.log(`${self.debugLabel}: Num Bad Files: `, badFiles.length);
                        console.log(`${self.debugLabel}: Num Good Files: `, goodFiles.length);
                    }

                    return hasCb
                        ? endCb(null, goodFiles, badFiles, {}, [])
                        : resolve({ goodFiles, badFiles, errors: null, viruses: [] });
                }
            };

            // If string is provided in files param, forgive them... create a single element array
            if (typeof files === 'string' && files.trim().length > 0) {
                files = files
                    .trim()
                    .split(',')
                    .map((v) => v.trim());
            }

            // If the files array is actually an array, do some additional validation
            if (Array.isArray(files)) {
                // Keep track of the original number of files specified
                origNumFiles = files.length;

                // Remove any empty or non-string elements
                files = files.filter((v) => !!v).filter((v) => typeof v === 'string');

                // If any items specified were not valid strings, fail...
                if (files.length < origNumFiles) {
                    const err = new NodeClamError(
                        { numFiles: files.length, origNumFiles },
                        "You've specified at least one invalid item to the files list (first parameter) of the `scanFiles` method."
                    );
                    return hasCb ? endCb(err, [], [], {}, []) : reject(err);
                }
            }

            // Do some parameter validation
            if (!Array.isArray(files) || files.length === 0) {
                // Before failing completely, check if there is a file list specified
                if (!('fileList' in this.settings) || !this.settings.fileList) {
                    const emptyResult = {
                        goodFiles: [],
                        badFiles: [],
                        errors: {},
                        viruses: [],
                    };
                    return hasCb
                        ? endCb(null, emptyResult.goodFiles, emptyResult.badFiles, emptyResult.viruses)
                        : resolve(emptyResult);
                }

                // If the file list is specified, read it in and scan listed files...
                try {
                    const data = (await fsReadfile(this.settings.fileList)).toString().split(os.EOL);
                    return doScan(data);
                } catch (e) {
                    const err = new NodeClamError(
                        { err: e, fileList: this.settings.fileList },
                        `No files provided and file list was provided but could not be found! ${e}`
                    );
                    return hasCb ? endCb(err, [], [], {}, []) : reject(err);
                }
            }
            return doScan(files);
        });
    }

    /**
     * Scans an entire directory. Provides 3 params to end callback: Error, path
     * scanned, and whether its infected or not. To scan multiple directories, pass
     * them as an array to the `scanFiles` method.
     *
     * This obeys your recursive option even for `clamdscan` which does not have a native
     * way to turn this feature off. If you have multiple paths, send them in an array
     * to `scanFiles`.
     *
     * NOTE: While possible, it is NOT advisable to use the `fileCb` parameter when
     * using the `clamscan` binary. Doing so with `clamdscan` is okay, however. This
     * method also allows for non-recursive scanning with the clamdscan binary.
     *
     * @public
     * @param {string} path - The directory to scan files of
     * @param {Function} [endCb] - What to do when all files have been scanned
     * @param {Function} [fileCb] - What to do after each file has been scanned
     * @returns {Promise<object>} Object like: `{ path: String, isInfected: Boolean, goodFiles: Array, badFiles: Array, viruses: Array }`
     * @example
     * // Callback Method
     * clamscan.scanDir('/some/path/to/scan', (err, goodFiles, badFiles, viruses, numGoodFiles) {
     *     if (err) return console.error(err);
     *
     *     if (badFiles.length > 0) {
     *         console.log(`${path} was infected. The offending files (${badFiles.map(v => `${v.file} (${v.virus})`).join (', ')}) have been quarantined.`);
     *         console.log(`Viruses Found: ${viruses.join(', ')}`);
     *     } else {
     *         console.log('Everything looks good! No problems here!.');
     *     }
     * });
     *
     * // Async/Await Method
     * const {path, isInfected, goodFiles, badFiles, viruses} = await clamscan.scanDir('/some/path/to/scan');
     */
    scanDir(path = '', endCb = null, fileCb = null) {
        // const self = this;
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (endCb && typeof endCb !== 'function') {
            throw new NodeClamError(
                'Invalid end-scan callback provided to `scanDir`. Second paramter, if provided, must be a function!'
            );
        } else if (endCb && typeof endCb === 'function') {
            hasCb = true;
        }

        // At this point for the hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            // Verify `path` provided is a string
            if (typeof path !== 'string' || (typeof path === 'string' && path.trim() === '')) {
                const err = new NodeClamError({ path }, 'Invalid path provided! Path must be a string!');
                return hasCb ? endCb(err, [], []) : reject(err);
            }

            // Normalize and then trim trailing slash
            path = nodePath.normalize(path).replace(/\/$/, '');

            // Make sure path exists...
            try {
                await fsAccess(path, fs.constants.R_OK);
            } catch (e) {
                const err = new NodeClamError({ path, err: e }, 'Invalid path specified to scan!');
                return hasCb ? endCb(err, [], []) : reject(err);
            }

            // Get all files recursively using `scanFiles`
            if (this.settings.scanRecursively === true && (typeof fileCb === 'function' || !hasCb)) {
                try {
                    const files = await getFiles(path, true);

                    const { goodFiles, badFiles, viruses, errors } = await this.scanFiles(files, null, fileCb);
                    return hasCb
                        ? endCb(null, goodFiles, badFiles, viruses)
                        : resolve({ goodFiles, badFiles, viruses, errors });
                } catch (e) {
                    const err = new NodeClamError({ path, err: e }, 'There was an issue scanning the path specified!');
                    return hasCb ? endCb(err, [], []) : reject(err);
                }
            }
        });
    }

    /**
     * Allows you to scan a binary stream.
     *
     * **NOTE:** This method will only work if you've configured the module to allow the
     * use of a TCP or UNIX Domain socket. In other words, this will not work if you only
     * have access to a local ClamAV binary.
     *
     * @public
     * @param {Readable} stream - A readable stream to scan
     * @param {Function} [cb] - What to do when the socket response with results
     * @returns {Promise<object>} Object like: `{ file: String, isInfected: Boolean, viruses: Array } `
     * @example
     * const NodeClam = require('clamscan');
     *
     * // You'll need to specify your socket or TCP connection info
     * const clamscan = new NodeClam().init({
     *     clamdscan: {
     *         socket: '/var/run/clamd.scan/clamd.sock',
     *         host: '127.0.0.1',
     *         port: 3310,
     *     }
     * });
     * const Readable = require('stream').Readable;
     * const rs = Readable();
     *
     * rs.push('foooooo');
     * rs.push('barrrrr');
     * rs.push(null);
     *
     * // Async/Await Example
     * const { isInfected, viruses } = await clamscan.scanStream(stream);
     */
    scanStream(stream) {
        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            let finished = false;

            // Verify stream is passed to the first parameter
            if (!this._isReadableStream(stream)) {
                const err = new NodeClamError({ stream }, 'Invalid stream provided to scan.');
                reject(err);
            }
            if (this.settings.debugMode) console.log(`${this.debugLabel}: Provided stream is readable.`);

            // Verify that they have a valid socket or host/port config
            if (!this.settings.clamdscan.socket && !this.settings.clamdscan.port && !this.settings.clamdscan.host) {
                const err = new NodeClamError(
                    { clamdscanSettings: this.settings.clamdscan },
                    'Invalid information provided to connect to clamav service. A unix socket or port (+ optional host) is required!'
                );
                reject(err);
            }

            // Get an instance of our stream transform that coddles
            // the chunks from the incoming stream to what ClamAV wants
            const transform = new NodeClamTransform({}, this.settings.debugMode);
            // Get a socket
            const socket = await this._initSocket('scanStream');
            // Pipe the stream through our transform and into the ClamAV socket
            // stream.pipe(transform).pipe(socket);
            transform
                // Writing data into ClamAV socket
                .on('data', (data) => {
                    socket.write(data);
                })
                // The transform stream has dried up
                .on('end', () => {
                    if (this.settings.debugMode) console.log(`${this.debugLabel}: The transform stream has ended.`);
                })
                .on('error', (err) => {
                    console.error(`${this.debugLabel}: Error emitted from transform stream: `, err);
                    socket.end();
                    const error = new NodeClamError(
                        { err },
                        `No files provided and file list was provided but could not be found! ${err}`
                    );
                    reject(error);
                });

            // Setup the listeners for the stream
            stream
                // The stream is writting data into transform stream
                .on('data', (data) => {
                    transform.write(data);
                })
                // The stream has dried up
                .on('end', () => {
                    if (this.settings.debugMode) console.log(`${this.debugLabel}: The input stream has dried up.`);
                    finished = true;
                    transform.end();
                })
                // There was an error with the stream (ex. uploader closed browser)
                .on('error', (err) => {
                    if (this.settings.debugMode) {
                        console.log(
                            `${this.debugLabel}: There was an error with the input stream(maybe uploader closed browser ?).`,
                            err
                        );
                    }
                    if (isPermissionError(err)) {
                        resolve({
                            isInfected: false,
                            viruses: [],
                            file: null,
                            resultString: 'stream: OK\x00',
                            timeout: false,
                        });
                    } else {
                        reject(err);
                    }
                });
            // Where to buffer string response (not a real "Buffer", per se...)
            const chunks = [];
            // Read output of the ClamAV socket to see what it's saying and when
            // it's done saying it (FIN)
            socket
                // ClamAV is sending stuff to us
                .on('data', (chunk) => {
                    if (this.settings.debugMode) console.log(`${this.debugLabel}: Received output from ClamAV Socket.`);
                    if (!stream.isPaused()) stream.pause();
                    chunks.push(chunk);
                })
                .on('close', (hadError) => {
                    socket.end();
                    if (this.settings.debugMode)
                        console.log(`${this.debugLabel}: ClamAV socket has been closed!`, hadError);
                })
                .on('error', (err) => {
                    console.log('ERROR FROM SOCKET: ', err);
                    console.error(`${this.debugLabel}: Error emitted from ClamAV socket: `, err);
                    socket.end();
                    transform.destroy();
                    const error = new NodeClamError(
                        { err },
                        `No files provided and file list was provided but could not be found! ${err}`
                    );

                    if (isPermissionError(error)) {
                        resolve({
                            isInfected: false,
                            viruses: [],
                            file: null,
                            resultString: 'stream: OK\x00',
                            timeout: false,
                        });
                    } else {
                        reject(error);
                    }
                })
                // ClamAV is done sending stuff to us
                .on('end', () => {
                    if (this.settings.debugMode) console.log(`${this.debugLabel}: ClamAV is done scanning.`);
                    // Fully close up the socket
                    socket.destroy();
                    transform.destroy();
                    // Concat all the response chunks into a single buffer
                    const response = Buffer.concat(chunks);
                    // If the scan didn't finish, throw error
                    if (!finished) {
                        const err = new NodeClamError(`Scan aborted. Reply from server: ${response.toString('utf8')} `);
                        reject(err);
                    }
                    // The scan finished
                    if (this.settings.debugMode)
                        console.log(`${this.debugLabel}: Raw Response:  ${response.toString('utf8')} `);
                    const result = this._processResult(response.toString('utf8'), null);

                    if (result instanceof Error) {
                        const error = new NodeClamError(
                            { err: result },
                            `No files provided and file list was provided but could not be found! ${result}`
                        );

                        reject(error);
                    }
                    resolve(result);
                });
        });
    }
}

module.exports = NodeClam;
